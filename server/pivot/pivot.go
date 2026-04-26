// Package pivot 提供 Agent 间跳转（Pivoting）支持。
// 借鉴 Sliver 的 pivoting 和 Havoc 的 demon-to-demon 通信。
//
// 面试要点：
// 1. Pivoting 是什么：通过已控 Agent 作为跳板，访问其所在网络的内网目标
// 2. TCP Pivot：Agent 监听 TCP 端口，转发流量到目标
// 3. Named Pipe Pivot (Windows)：通过 SMB Named Pipe 进行 Agent 间通信
// 4. 工作原理：
//    - 在 Agent A 上创建 Pivot Listener（监听端口）
//    - 外部客户端连接该端口
//    - Agent A 将流量封装为 C2 消息 → Server → Agent B → 目标
// 5. 防御视角：
//    - 检测异常的本地监听端口
//    - 检测 Agent 间的 C2 通信模式
//    - EDR 监控 Named Pipe 创建和访问
package pivot

import (
	"fmt"
	"sync"
	"time"

	"github.com/aegis-c2/aegis/shared"
)

// PivotType 定义 Pivot 类型。
type PivotType string

const (
	PivotTCP       PivotType = "tcp"
	PivotNamedPipe PivotType = "named_pipe"
	PivotUDP       PivotType = "udp"
)

// PivotListener 是 Agent 上创建的 Pivot 监听器。
type PivotListener struct {
	ID        string
	Type      PivotType
	BindAddr  string // 绑定地址 (如 "0.0.0.0:8443" 或 "\\.\pipe\aegis")
	Running   bool
	AgentID   string    // 创建此 Pivot 的 Agent ID
	CreatedAt time.Time
	Sessions  []*PivotSession
	mu        sync.Mutex
}

// PivotSession 表示通过 Pivot 建立的连接。
type PivotSession struct {
	ID        string
	ListenerID string
	SrcAddr   string    // 来源地址
	DstAddr   string    // 目标地址
	CreatedAt time.Time
	BytesSent int64
	BytesRecv int64
	Active    bool
}

// PivotPeer 描述网络中的一个 Pivot 节点。
type PivotPeer struct {
	AgentID   string
	Address   string    // 内网地址 (如 "192.168.1.100:8443")
	Type      PivotType
	Connected bool
}

// PivotManager 管理所有 Pivot 监听器和会话。
type PivotManager struct {
	listeners map[string]*PivotListener
	peers     map[string]*PivotPeer // agentID → PivotPeer
	mu        sync.RWMutex
}

// NewPivotManager 创建 Pivot 管理器。
func NewPivotManager() *PivotManager {
	return &PivotManager{
		listeners: make(map[string]*PivotListener),
		peers:     make(map[string]*PivotPeer),
	}
}

// CreateTCPListener 创建 TCP Pivot 监听器。
func (m *PivotManager) CreateTCPListener(agentID, bindAddr string) (*PivotListener, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := generateID()
	listener := &PivotListener{
		ID:        id,
		Type:      PivotTCP,
		BindAddr:  bindAddr,
		Running:   false,
		AgentID:   agentID,
		CreatedAt: time.Now(),
	}

	m.listeners[id] = listener
	return listener, nil
}

// CreateNamedPipeListener 创建 Named Pipe Pivot 监听器。
func (m *PivotManager) CreateNamedPipeListener(agentID, pipeName string) (*PivotListener, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := generateID()
	listener := &PivotListener{
		ID:        id,
		Type:      PivotNamedPipe,
		BindAddr:  fmt.Sprintf(`\\.\pipe\%s`, pipeName),
		Running:   false,
		AgentID:   agentID,
		CreatedAt: time.Now(),
	}

	m.listeners[id] = listener
	return listener, nil
}

// Start 启动 Pivot 监听器。
func (m *PivotManager) Start(listenerID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	listener, ok := m.listeners[listenerID]
	if !ok {
		return fmt.Errorf("listener not found: %s", listenerID)
	}

	listener.Running = true
	return nil
}

// Stop 停止 Pivot 监听器。
func (m *PivotManager) Stop(listenerID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	listener, ok := m.listeners[listenerID]
	if !ok {
		return fmt.Errorf("listener not found: %s", listenerID)
	}

	listener.Running = false
	return nil
}

// AddPeer 注册一个 Pivot Peer（可通过其到达的节点）。
func (m *PivotManager) AddPeer(agentID, address string, pivotType PivotType) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.peers[agentID] = &PivotPeer{
		AgentID:   agentID,
		Address:   address,
		Type:      pivotType,
		Connected: true,
	}
}

// RemovePeer 移除一个 Pivot Peer。
func (m *PivotManager) RemovePeer(agentID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.peers, agentID)
}

// GetPeer 查找指定 Agent 的 Pivot 地址。
func (m *PivotManager) GetPeer(agentID string) (*PivotPeer, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	peer, ok := m.peers[agentID]
	if !ok {
		return nil, fmt.Errorf("peer not found: %s", agentID)
	}
	return peer, nil
}

// ListListeners 列出所有 Pivot 监听器。
func (m *PivotManager) ListListeners() []*PivotListener {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*PivotListener
	for _, l := range m.listeners {
		result = append(result, l)
	}
	return result
}

// ListPeers 列出所有 Pivot Peers。
func (m *PivotManager) ListPeers() []*PivotPeer {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*PivotPeer
	for _, p := range m.peers {
		result = append(result, p)
	}
	return result
}

// generateID 生成简短唯一 ID。
func generateID() string {
	return shared.GenID("pivot")
}

// PivotNetwork 描述整个 Pivot 网络拓扑。
// 用于面试中展示路由图和 Agent 间通信关系。
type PivotNetwork struct {
	Nodes  []*PivotPeer
	Edges  []PivotEdge
}

// PivotEdge 描述两个 Pivot 节点之间的连接。
type PivotEdge struct {
	From  string // 源 Agent ID
	To    string // 目标 Agent ID
	Type  PivotType
	Addr  string // 连接地址
}
