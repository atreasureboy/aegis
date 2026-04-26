// Package forwarder 提供端口转发（Agent 端）。
// 借鉴 Sliver 的 forwarder/rportfwd — Agent 作为端口转发中间件。
//
// 面试要点：
// 1. 正向端口转发：外部 → Agent → 内网目标
// 2. 反向端口转发：内网服务 → Agent → C2 → 外部
// 3. Agent 端实现：
//    - 监听本地端口
//    - 接受连接
//    - 将数据通过 C2 通道转发
//    - 接收响应并回传
package forwarder

import (
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/aegis-c2/aegis/shared"
)

// Forward 是一个端口转发规则。
type Forward struct {
	ID         string
	BindAddr   string // 绑定地址 (如 "127.0.0.1:8080")
	TargetAddr string // 目标地址 (如 "10.0.0.5:443")
	Running    bool
	BytesSent  int64
	BytesRecv  int64
	mu         sync.Mutex
}

// Manager 管理端口转发规则。
type Manager struct {
	forwards map[string]*Forward
	mu       sync.RWMutex
	listeners map[string]net.Listener
}

// NewManager 创建转发管理器。
func NewManager() *Manager {
	return &Manager{
		forwards:  make(map[string]*Forward),
		listeners: make(map[string]net.Listener),
	}
}

// AddTCP 添加 TCP 端口转发。
func (m *Manager) AddTCP(bindAddr, targetAddr string) (*Forward, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := generateID()
	f := &Forward{
		ID:         id,
		BindAddr:   bindAddr,
		TargetAddr: targetAddr,
	}

	m.forwards[id] = f
	return f, nil
}

// Start 启动端口转发。
func (m *Manager) Start(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	f, ok := m.forwards[id]
	if !ok {
		return fmt.Errorf("forward not found: %s", id)
	}

	listener, err := net.Listen("tcp", f.BindAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", f.BindAddr, err)
	}

	m.listeners[id] = listener
	f.Running = true

	go m.acceptLoop(id, listener)
	return nil
}

func (m *Manager) acceptLoop(id string, listener net.Listener) {
	defer func() {
		m.mu.Lock()
		if f, ok := m.forwards[id]; ok {
			f.Running = false
		}
		delete(m.listeners, id)
		m.mu.Unlock()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}

		go m.handleConnection(id, conn)
	}
}

func (m *Manager) handleConnection(id string, clientConn net.Conn) {
	m.mu.RLock()
	f, ok := m.forwards[id]
	m.mu.RUnlock()

	if !ok || !f.Running {
		clientConn.Close()
		return
	}

	// 连接目标
	targetConn, err := net.Dial("tcp", f.TargetAddr)
	if err != nil {
		clientConn.Close()
		return
	}

	// 双向转发
	go m.pipe(clientConn, targetConn, id, true)
	go m.pipe(targetConn, clientConn, id, false)
}

func (m *Manager) pipe(src, dst net.Conn, id string, toTarget bool) {
	defer src.Close()
	defer dst.Close()

	buf := make([]byte, 32*1024) // 32KB 缓冲
	for {
		n, err := src.Read(buf)
		if err != nil {
			if err != io.EOF {
				// 连接关闭
			}
			return
		}

		_, err = dst.Write(buf[:n])
		if err != nil {
			return
		}

		m.mu.Lock()
		if f, ok := m.forwards[id]; ok {
			if toTarget {
				f.BytesSent += int64(n)
			} else {
				f.BytesRecv += int64(n)
			}
		}
		m.mu.Unlock()
	}
}

// Stop 停止端口转发。
func (m *Manager) Stop(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if listener, ok := m.listeners[id]; ok {
		listener.Close()
		delete(m.listeners, id)
	}

	if f, ok := m.forwards[id]; ok {
		f.Running = false
	}

	return nil
}

// List 列出所有转发规则。
func (m *Manager) List() []*Forward {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*Forward
	for _, f := range m.forwards {
		result = append(result, f)
	}
	return result
}

// Delete 删除转发规则。
func (m *Manager) Delete(id string) error {
	m.mu.Lock()

	if listener, ok := m.listeners[id]; ok {
		listener.Close()
		delete(m.listeners, id)
	}
	if f, ok := m.forwards[id]; ok {
		f.Running = false
	}
	delete(m.forwards, id)
	m.mu.Unlock()

	return nil
}

func generateID() string {
	return "fwd-" + shared.GenID("")
}
