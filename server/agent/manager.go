package agent

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/aegis-c2/aegis/server/db"
	"github.com/aegis-c2/aegis/shared/protocol"
	"github.com/aegis-c2/aegis/shared/types"
)

// Manager 管理所有 Agent 的生命周期。
type Manager struct {
	registry *types.AgentRegistry
	database *db.DB
	regMu    sync.Mutex // guards check-and-create to prevent TOCTOU race
}

func NewManager(database *db.DB) *Manager {
	return &Manager{
		registry: types.NewAgentRegistry(),
		database: database,
	}
}

// Register 处理 Agent 的注册请求。
func (m *Manager) Register(payload *protocol.RegisterPayload, remoteIP string) (*types.Agent, error) {
	agent := &types.Agent{
		ID:            payload.AgentID,
		Hostname:      payload.Hostname,
		OS:            payload.OS,
		Arch:          payload.Arch,
		Username:      payload.Username,
		PID:           payload.PID,
		IP:            remoteIP,
		State:         types.StateOnline,
		FirstSeen:     time.Now(),
		LastHeartbeat: time.Now(),
	}
	m.registry.Register(agent)

	// 持久化到数据库
	if m.database != nil {
		if err := m.database.CreateAgent(&db.Agent{
			ID: agent.ID, Hostname: agent.Hostname, OS: agent.OS,
			Arch: agent.Arch, Username: agent.Username, PID: agent.PID,
			State: string(agent.State), FirstSeen: agent.FirstSeen,
			LastSeen: agent.LastHeartbeat,
		}); err != nil {
			log.Printf("[WARN] failed to persist agent to db: %v", err)
		}
	}

	log.Printf("[AGENT] registered: id=%s hostname=%s os=%s ip=%s",
		agent.ID, agent.Hostname, agent.OS, agent.IP)
	return agent, nil
}

// RegisterIfAbsent 原子化检查并注册（防 TOCTOU 竞争）。
// N-P1-2: 用 regMu 锁住 check-and-create，防止并发注册覆盖。
func (m *Manager) RegisterIfAbsent(payload *protocol.RegisterPayload, remoteIP string) (*types.Agent, bool, error) {
	m.regMu.Lock()
	defer m.regMu.Unlock()

	// 原子检查是否已存在
	if _, exists := m.registry.Get(payload.AgentID); exists {
		return nil, false, nil
	}

	agent, err := m.Register(payload, remoteIP)
	return agent, true, err
}

// ProcessHeartbeat 处理 Agent 心跳（含序列号校验）。
func (m *Manager) ProcessHeartbeat(agentID string, seqNum uint64) (*types.Agent, error) {
	agent, ok := m.registry.Get(agentID)
	if !ok {
		return nil, fmt.Errorf("unknown agent: %s", agentID)
	}
	// 使用带序列号校验的心跳更新，检测重放/乱序
	if _, err := agent.UpdateHeartbeatWithSeq(seqNum); err != nil {
		// 序列号乱序 — 记录但不拒绝（可能是 Agent 重启）
		agent.UpdateHeartbeat()
	}

	// 更新数据库状态
	if m.database != nil {
		if err := m.database.UpdateAgentState(agentID, "online"); err != nil {
			log.Printf("[WARN] failed to update agent state in db: %v", err)
		}
	}
	return agent, nil
}

// GetAgent 查询指定 Agent。
func (m *Manager) GetAgent(id string) (*types.Agent, bool) {
	return m.registry.Get(id)
}

// ListAgents 返回所有 Agent 列表。
func (m *Manager) ListAgents() []*types.Agent {
	return m.registry.List()
}

// MarkOffline 将心跳超时的 Agent 标记为离线。
func (m *Manager) MarkOffline(agentID string) {
	agent, ok := m.registry.Get(agentID)
	if !ok {
		return
	}
	agent.SetState(types.StateOffline)

	// 更新数据库状态
	if m.database != nil {
		if err := m.database.UpdateAgentState(agentID, "offline"); err != nil {
			log.Printf("[WARN] failed to update agent state in db: %v", err)
		}
	}
	log.Printf("[AGENT] marked offline: id=%s", agentID)
}

// IsDead 检查指定 Agent 是否已死亡（心跳超时超过 maxInterval）。
func (m *Manager) IsDead(agentID string, maxInterval time.Duration) bool {
	agent, ok := m.registry.Get(agentID)
	if !ok {
		return true
	}
	if agent.State == types.StateOffline {
		return true
	}
	return time.Since(agent.LastHeartbeat) > maxInterval
}

// CheckDeadAgents 遍历所有 Agent，将心跳超时超过 maxInterval 的标记为离线。
func (m *Manager) CheckDeadAgents(maxInterval time.Duration) {
	agents := m.registry.List()
	for _, a := range agents {
		if a.GetState() == types.StateOffline {
			continue
		}
		if a.TimeSinceLastHeartbeat() > maxInterval {
			m.MarkOffline(a.ID)
		}
	}
}
