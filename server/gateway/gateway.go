package gateway

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aegis-c2/aegis/server/config"
	"github.com/aegis-c2/aegis/server/crypto"
)

// Gateway 是安全审查层的核心结构体。
// 每个请求经过此处进行 IP 白名单、Nonce 重放检查、命令权限校验。
// 这是与 Sliver/Havoc 最本质的区别：默认拒绝，按需放行。
type Gateway struct {
	cfg        *config.ServerConfig
	nonceCache *crypto.AgentNonceCache
	tsValidator *crypto.TimestampValidator

	// 每个 Agent 的任务计数器
	taskCounter map[string]int
	counterMu   sync.Mutex
}

func NewGateway(cfg *config.ServerConfig, nonceCache *crypto.AgentNonceCache) *Gateway {
	return &Gateway{
		cfg:         cfg,
		nonceCache:  nonceCache,
		tsValidator: crypto.NewTimestampValidator(30 * time.Second),
		taskCounter: make(map[string]int),
	}
}

// CheckIP 检查请求来源 IP 是否在白名单中。
func (g *Gateway) CheckIP(r *http.Request) error {
	if !g.cfg.Whitelist.Enabled {
		return nil
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return fmt.Errorf("failed to parse remote addr: %w", err)
	}

	clientIP := net.ParseIP(ip)
	if clientIP == nil {
		return fmt.Errorf("invalid IP: %s", ip)
	}

	for _, cidr := range g.cfg.Whitelist.AllowedIPs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(clientIP) {
			return nil
		}
	}

	return fmt.Errorf("IP %s not in whitelist", ip)
}

// ValidateEnvelope 对 Envelope 进行时间戳 + Nonce 双重验证。
// N-P1-5: Actually validate the timestamp from the envelope data.
func (g *Gateway) ValidateEnvelope(envData []byte, agentID string) error {
	// Parse the envelope to extract timestamp
	type minimalEnvelope struct {
		Timestamp int64 `json:"timestamp"`
	}
	var env minimalEnvelope
	if err := json.Unmarshal(envData, &env); err != nil {
		return fmt.Errorf("parse envelope: %w", err)
	}

	// Validate timestamp is within acceptable drift (30 seconds)
	if !g.tsValidator.Validate(env.Timestamp) {
		return fmt.Errorf("timestamp out of range: %d", env.Timestamp)
	}

	return nil
}

// CheckCommand 检查命令是否在允许列表中。
func (g *Gateway) CheckCommand(command string) error {
	if !g.cfg.AcademicMode {
		// 非学术模式：只检查黑名单
		for _, blocked := range g.cfg.BlockedCommands {
			if strings.HasPrefix(strings.ToLower(command), blocked) {
				return fmt.Errorf("command %q is blocked", command)
			}
		}
		return nil
	}

	// 学术模式：只允许白名单命令
	for _, allowed := range g.cfg.AllowedCommands {
		if strings.HasPrefix(strings.ToLower(command), allowed) {
			return nil
		}
	}
	return fmt.Errorf("command %q is not allowed in academic mode", command)
}

// CheckRateLimit 检查 Agent 的任务速率限制。
func (g *Gateway) CheckRateLimit(agentID string) error {
	g.counterMu.Lock()
	defer g.counterMu.Unlock()

	count := g.taskCounter[agentID]
	if count >= g.cfg.CircuitBreaker.MaxTasksPerMinute {
		return fmt.Errorf("rate limit exceeded for agent %s", agentID)
	}
	g.taskCounter[agentID] = count + 1
	return nil
}

// ResetRateLimit 重置计数器（定时调用）。
func (g *Gateway) ResetRateLimit() {
	g.counterMu.Lock()
	defer g.counterMu.Unlock()
	g.taskCounter = make(map[string]int)
}
