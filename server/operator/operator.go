// Package operator 提供多操作符支持。
// 借鉴 Sliver 的多用户架构 — 多个操作符可以同时连接到 Server，共享 Agent 会话。
//
// 面试要点：
// 1. 单用户 vs 多用户 C2：
//    - 单用户 (Cobalt Strike teamserver)：一个 Server，多个客户端共享
//    - 多用户 (Sliver)：Operator 注册、权限管理、会话共享
// 2. 架构设计：
//    - Server 维护 Operator 列表和连接状态
//    - 每个 Operator 有独立的认证凭据
//    - Operator 通过 WebSocket/SSE 接收事件通知
// 3. 事件模型：
//    - Agent 上线/离线事件
//    - 任务提交/完成事件
//    - 操作符加入/离开事件
// 4. 防御视角：
//    - 每个 Operator 的操作都应被审计
//    - Operator 权限应细粒度控制
package operator

import (
	"fmt"
	"sync"
	"time"

	"github.com/aegis-c2/aegis/shared"
)

// Operator 表示一个连接的操作符。
type Operator struct {
	ID        string
	Name      string
	Role      Role       // 角色权限
	Connected bool
	LastSeen  time.Time
	IPAddress string
}

// Role 定义操作符角色。
type Role string

const (
	RoleAdmin   Role = "admin"   // 完全权限
	RoleOperator Role = "operator" // 标准操作
	RoleObserver Role = "observer" // 只读
)

// Event 是操作事件。
type Event struct {
	ID        string
	Type      string     // event type
	OperatorID string
	AgentID   string
	Timestamp time.Time
	Payload   string     // 事件详情
}

// EventType 定义事件类型。
const (
	EventAgentOnline    = "agent_online"
	EventAgentOffline   = "agent_offline"
	EventTaskSubmitted  = "task_submitted"
	EventTaskCompleted  = "task_completed"
	EventOperatorJoin   = "operator_join"
	EventOperatorLeave  = "operator_leave"
)

// Manager 管理多操作符会话。
type Manager struct {
	mu         sync.RWMutex
	operators  map[string]*Operator
	subscribers map[string]chan *Event // operatorID → event channel
}

// NewManager 创建操作符管理器。
func NewManager() *Manager {
	return &Manager{
		operators:   make(map[string]*Operator),
		subscribers: make(map[string]chan *Event),
	}
}

// Register 注册新操作符。
func (m *Manager) Register(name string, role Role) (*Operator, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, op := range m.operators {
		if op.Name == name {
			return nil, fmt.Errorf("operator with name %q already exists", name)
		}
	}

	id := generateID()
	op := &Operator{
		ID:        id,
		Name:      name,
		Role:      role,
		Connected: false,
		LastSeen:  time.Now(),
	}

	m.operators[id] = op
	return op, nil
}

// Connect 操作符连接上线。
func (m *Manager) Connect(operatorID, ipAddress string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	op, ok := m.operators[operatorID]
	if !ok {
		return fmt.Errorf("operator not found: %s", operatorID)
	}

	op.Connected = true
	op.IPAddress = ipAddress
	op.LastSeen = time.Now()

	// 广播加入事件
	m.broadcast(&Event{
		ID:        generateID(),
		Type:      EventOperatorJoin,
		OperatorID: operatorID,
		Timestamp: time.Now(),
		Payload:   fmt.Sprintf("%s connected", op.Name),
	})

	return nil
}

// Disconnect 操作符断开。
func (m *Manager) Disconnect(operatorID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	op, ok := m.operators[operatorID]
	if !ok {
		return
	}

	op.Connected = false
	op.LastSeen = time.Now()

	m.broadcast(&Event{
		ID:        generateID(),
		Type:      EventOperatorLeave,
		OperatorID: operatorID,
		Timestamp: time.Now(),
		Payload:   fmt.Sprintf("%s disconnected", op.Name),
	})
}

// Subscribe 订阅事件流。
func (m *Manager) Subscribe(operatorID string) (<-chan *Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	ch := make(chan *Event, 100)
	m.subscribers[operatorID] = ch
	return ch, nil
}

// Unsubscribe 取消订阅。
func (m *Manager) Unsubscribe(operatorID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if ch, ok := m.subscribers[operatorID]; ok {
		close(ch)
		delete(m.subscribers, operatorID)
	}
}

// Broadcast 向所有订阅者广播事件。
func (m *Manager) Broadcast(event *Event) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.broadcast(event)
}

func (m *Manager) broadcast(event *Event) {
	for _, ch := range m.subscribers {
		select {
		case ch <- event:
		default:
			// 通道满了，丢弃
		}
	}
}

// List 列出所有操作符。
func (m *Manager) List() []*Operator {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*Operator
	for _, op := range m.operators {
		result = append(result, op)
	}
	return result
}

// HasPermission 检查操作符是否有指定权限。
func (m *Manager) HasPermission(operatorID string, action string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	op, ok := m.operators[operatorID]
	if !ok {
		return false
	}

	switch op.Role {
	case RoleAdmin:
		return true
	case RoleOperator:
		return action != "delete_agent" && action != "manage_operators"
	case RoleObserver:
		return action == "view_agents" || action == "view_tasks" || action == "view_events"
	}
	return false
}

func generateID() string {
	return shared.GenID("")
}
