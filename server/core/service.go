// Package core 提供传输无关的业务逻辑层。
// HTTP 和 gRPC 服务器都委托给这个 Service。
package core

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aegis-c2/aegis/server/agent"
	"github.com/aegis-c2/aegis/server/audit"
	"github.com/aegis-c2/aegis/server/builder"
	"github.com/aegis-c2/aegis/server/canary"
	"github.com/aegis-c2/aegis/server/config"
	servercrypto "github.com/aegis-c2/aegis/server/crypto"
	"github.com/aegis-c2/aegis/server/db"
	"github.com/aegis-c2/aegis/server/dispatcher"
	"github.com/aegis-c2/aegis/server/event"
	"github.com/aegis-c2/aegis/server/gateway"
	"github.com/aegis-c2/aegis/server/listener"
	"github.com/aegis-c2/aegis/server/operator"
	"github.com/aegis-c2/aegis/server/profile"
	"github.com/aegis-c2/aegis/server/stage"
	"github.com/aegis-c2/aegis/server/webhook"
	"github.com/aegis-c2/aegis/server/weaponize"
	"github.com/aegis-c2/aegis/shared/types"
)

// Service 是所有业务逻辑的集中入口，传输无关。
type Service struct {
	AgentMgr      *agent.Manager
	Dispatcher    *dispatcher.Dispatcher
	EventBroker   *event.Broker
	OperatorMgr   *operator.Manager
	Builder       *builder.Builder
	Audit         *audit.Logger
	Database      *db.DB
	ListenerMgr   *listener.Manager
	WeaponBuilder *weaponize.Builder
	ProfileMgr    *profile.Manager
	ProfileValid  *profile.Validator
	Gateway       *gateway.Gateway
	Webhook       *webhook.Notifier
	RsaKeyPair    *servercrypto.RSAKeyPair
	EcdhKeyPair   *servercrypto.ECDHKeyPair
	NonceCache    *servercrypto.AgentNonceCache
	Cfg           *config.ServerConfig
	StageRegistry *stage.Registry
	CanaryDetector *canary.CanaryDetector // DNS canary tracking (requires external DNS server for query reception)
}

// New 初始化所有子组件。
func New(cfg *config.ServerConfig) (*Service, error) {
	rsaKeys, err := servercrypto.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	ecdhKeys, err := servercrypto.GenerateECDHKeyPair()
	if err != nil {
		return nil, err
	}

	nonceCache := servercrypto.NewAgentNonceCache(0)

	auditLog, err := audit.New("audit.log")
	if err != nil {
		return nil, fmt.Errorf("audit log initialization failed: %w", err)
	}

	gw := gateway.NewGateway(cfg, nonceCache)

	buildsDir := filepath.Join("builds")
	os.MkdirAll(buildsDir, 0755)
	projectRoot, _ := filepath.Abs(".")
	pl := builder.NewWithECDH(rsaKeys, ecdhKeys, "", buildsDir, projectRoot)

	database, err := db.Open("aegis.db")
	if err != nil {
		return nil, fmt.Errorf("database initialization failed: %w", err)
	}

	eventBroker := event.NewBroker(1000)

	webhookNotifier := webhook.NewNotifier(&webhook.Config{
		Provider: webhook.Discord,
		Username: "Aegis C2",
		Timeout:  10 * time.Second,
	})

	listenerMgr := listener.NewManager()
	operatorMgr := operator.NewManager()

	weaponDir := filepath.Join("weaponize")
	os.MkdirAll(weaponDir, 0755)
	weaponBuilder := weaponize.New(weaponDir)

	profileMgr := profile.NewManager()
	profileValid := profile.NewValidator(profileMgr.Active())

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

	return &Service{
		AgentMgr:      agent.NewManager(database),
		Dispatcher:    dispatcher.NewDispatcher(database, eventBroker),
		EventBroker:   eventBroker,
		OperatorMgr:   operatorMgr,
		Builder:       pl,
		Audit:         auditLog,
		Database:      database,
		ListenerMgr:   listenerMgr,
		WeaponBuilder: weaponBuilder,
		ProfileMgr:    profileMgr,
		ProfileValid:  profileValid,
		Gateway:       gw,
		Webhook:       webhookNotifier,
		RsaKeyPair:    rsaKeys,
		EcdhKeyPair:   ecdhKeys,
		NonceCache:    nonceCache,
		Cfg:           cfg,
		StageRegistry:  stage.NewRegistry(),
		CanaryDetector: canary.NewCanaryDetector("canary.aegis.internal"),
	}, nil
}

// === Agent 管理 ===

// ListAgents 返回所有 Agent。
func (s *Service) ListAgents() []*types.Agent {
	return s.AgentMgr.ListAgents()
}

// GetAgent 返回指定 Agent。
func (s *Service) GetAgent(id string) (*types.Agent, bool) {
	return s.AgentMgr.GetAgent(id)
}

// MarkAgentOffline 标记 Agent 为离线。
func (s *Service) MarkAgentOffline(id string) error {
	s.AgentMgr.MarkOffline(id)
	return nil
}

// === 任务 ===

// CreateTask 创建任务并提交到调度器。
func (s *Service) CreateTask(agentID, command, args string, priority int, timeout int, auditTag string) *types.Task {
	t := s.Dispatcher.Submit(agentID, command, args, timeout, priority, auditTag)
	return t
}

// GetTask 返回指定任务。
func (s *Service) GetTask(taskID string) (*types.Task, bool) {
	t := s.Dispatcher.GetTask(taskID)
	return t, t != nil
}

// ListTasks 返回所有任务，可按 agentID 过滤。
func (s *Service) ListTasks(agentID string) []*types.Task {
	all := s.Dispatcher.ListTasks()
	if agentID == "" {
		return all
	}
	var filtered []*types.Task
	for _, t := range all {
		if t.AgentID == agentID {
			filtered = append(filtered, t)
		}
	}
	return filtered
}

// === 事件 ===

// SubscribeAll 订阅所有事件类型。
func (s *Service) SubscribeAll(subscriberID string) (<-chan *event.Event, error) {
	return s.EventBroker.SubscribeAll(subscriberID)
}

// Subscribe 订阅指定事件类型。
func (s *Service) Subscribe(eventType event.Type, subscriberID string) (<-chan *event.Event, error) {
	return s.EventBroker.Subscribe(eventType, subscriberID)
}

// History 返回最近 n 条事件。
func (s *Service) History(n int) []*event.Event {
	return s.EventBroker.History(n)
}

// === 操作员 ===

// ListOperators 返回所有操作员。
func (s *Service) ListOperators() []*operator.Operator {
	return s.OperatorMgr.List()
}

// RegisterOperator 注册新操作员。
func (s *Service) RegisterOperator(name, role string) (*operator.Operator, error) {
	return s.OperatorMgr.Register(name, operator.Role(role))
}

// === Listener ===

// ListListeners 返回所有 Listener。
func (s *Service) ListListeners() []*listener.Listener {
	return s.ListenerMgr.List()
}

// StartListener 启动 Listener（仅标记为 running，实际绑定由 http server 处理）。
func (s *Service) StartListener(name, proto, host string, port int) (*listener.Listener, error) {
	var l *listener.Listener
	var err error
	switch proto {
	case "http":
		l, err = s.ListenerMgr.CreateHTTP(name, host, port)
	case "https":
		l, err = s.ListenerMgr.CreateHTTPS(name, host, port, "", "")
	case "mtls":
		l, err = s.ListenerMgr.CreateMTLS(name, host, port)
	case "dns":
		l, err = s.ListenerMgr.CreateDNS(name, host, "")
	case "named_pipe":
		l, err = s.ListenerMgr.CreateNamedPipe(name, host)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", proto)
	}
	if err != nil {
		return nil, err
	}
	s.ListenerMgr.Start(l.ID, nil)
	return l, nil
}

// StopListener 停止 Listener。
func (s *Service) StopListener(id string) error {
	return s.ListenerMgr.Stop(id)
}

// === Profile ===

// ListProfiles 返回所有 Profile 名称。
func (s *Service) ListProfiles() []string {
	return s.ProfileMgr.List()
}

// SetActiveProfile 设置活跃的 Malleable Profile。
func (s *Service) SetActiveProfile(name string) error {
	if ok := s.ProfileMgr.SetActive(name); !ok {
		return fmt.Errorf("profile not found: %s", name)
	}
	if p, _ := s.ProfileMgr.Get(name); p != nil {
		s.ProfileValid = profile.NewValidator(p)
	}
	return nil
}

// ActiveProfile 返回活跃的 Profile 名称。
func (s *Service) ActiveProfile() string {
	return s.ProfileMgr.Active().Name
}

// === 其他 ===

// GetRSAPublicKeyPEM 返回 RSA 公钥 PEM 编码。
func (s *Service) GetRSAPublicKeyPEM() ([]byte, error) {
	return s.RsaKeyPair.PublicKeyPEM(), nil
}

// GetECDHPublicKeyHex 返回 ECDH 公钥十六进制编码。
func (s *Service) GetECDHPublicKeyHex() string {
	return s.EcdhKeyPair.PublicKeyHex()
}
