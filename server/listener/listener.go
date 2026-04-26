// Package listener 提供 C2 监听器管理。
// 借鉴 Sliver 的 Listener 管理 — 统一管理 HTTP、mTLS、DNS、Named Pipe 等多种传输方式。
//
// 面试要点：
// 1. 监听器是 C2 Server 接收 Agent 连接的入口
// 2. 每种传输方式有独立的监听器：
//    - HTTP: 监听 TCP 端口，处理 REST 请求
//    - mTLS: 监听 TCP 端口，进行双向 TLS 握手
//    - DNS: 不需要端口，拦截 DNS 查询
//    - Named Pipe: 不需要端口，创建 Windows Pipe
// 3. Sliver 设计：每个监听器有独立的 ID、名称、配置、状态
// 4. 多监听器支持：Server 同时监听多种传输方式
package listener

import (
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/aegis-c2/aegis/shared"
)

// TransportType 定义传输类型。
type TransportType string

const (
	TransportHTTP   TransportType = "http"
	TransportHTTPS  TransportType = "https"
	TransportMTLS   TransportType = "mtls"
	TransportDNS    TransportType = "dns"
	TransportNamedPipe TransportType = "named_pipe"
	TransportWireGuard TransportType = "wireguard"
)

// Listener 表示一个 C2 监听器。
type Listener struct {
	ID          string
	Name        string
	Type        TransportType
	Config      map[string]string // 传输特定配置
	Running     bool
	AgentCount  int
	CreatedAt   time.Time
	LastStarted *time.Time
	mu          sync.Mutex
	tcpListener net.Listener     // 底层 TCP 监听器
	httpServer  *http.Server     // HTTP 服务器（用于 HTTP/HTTPS）
}

// Manager 管理所有监听器。
type Manager struct {
	mu        sync.RWMutex
	listeners map[string]*Listener
}

// NewManager 创建监听器管理器。
func NewManager() *Manager {
	return &Manager{
		listeners: make(map[string]*Listener),
	}
}

// CreateHTTP 创建 HTTP 监听器。
func (m *Manager) CreateHTTP(name, bindAddr string, port int) (*Listener, error) {
	return m.create(name, TransportHTTP, map[string]string{
		"bind_addr": fmt.Sprintf("%s:%d", bindAddr, port),
		"port":      fmt.Sprintf("%d", port),
	})
}

// CreateHTTPS 创建 HTTPS 监听器。
func (m *Manager) CreateHTTPS(name, bindAddr string, port int, certPath, keyPath string) (*Listener, error) {
	return m.create(name, TransportHTTPS, map[string]string{
		"bind_addr": fmt.Sprintf("%s:%d", bindAddr, port),
		"port":      fmt.Sprintf("%d", port),
		"cert":      certPath,
		"key":       keyPath,
	})
}

// CreateMTLS 创建 mTLS 监听器。
func (m *Manager) CreateMTLS(name, bindAddr string, port int) (*Listener, error) {
	return m.create(name, TransportMTLS, map[string]string{
		"bind_addr": fmt.Sprintf("%s:%d", bindAddr, port),
		"port":      fmt.Sprintf("%d", port),
	})
}

// CreateDNS 创建 DNS 监听器。
func (m *Manager) CreateDNS(name, domain, nameserver string) (*Listener, error) {
	return m.create(name, TransportDNS, map[string]string{
		"domain":     domain,
		"nameserver": nameserver,
	})
}

// CreateNamedPipe 创建 Named Pipe 监听器。
func (m *Manager) CreateNamedPipe(name, pipeName string) (*Listener, error) {
	return m.create(name, TransportNamedPipe, map[string]string{
		"pipe_name": pipeName,
		"pipe_path": fmt.Sprintf(`\\.\pipe\%s`, pipeName),
	})
}

func (m *Manager) create(name string, transportType TransportType, config map[string]string) (*Listener, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := generateID()
	listener := &Listener{
		ID:        id,
		Name:      name,
		Type:      transportType,
		Config:    config,
		Running:   false,
		CreatedAt: time.Now(),
	}

	m.listeners[id] = listener
	return listener, nil
}

// isRunning 安全读取 Running 状态（带 l.mu 锁）。
func (l *Listener) isRunning() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.Running
}

// Start 启动监听器。
func (m *Manager) Start(id string, handler http.Handler) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	l, ok := m.listeners[id]
	if !ok {
		return fmt.Errorf("listener not found: %s", id)
	}
	if l.isRunning() {
		return fmt.Errorf("listener already running: %s", id)
	}

	switch l.Type {
	case TransportHTTP, TransportHTTPS:
		addr := l.Config["bind_addr"]
		if addr == "" {
			return fmt.Errorf("listener missing bind_addr")
		}
		if handler == nil {
			handler = http.DefaultServeMux
		}
		l.httpServer = &http.Server{
			Addr:         addr,
			Handler:      handler,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  120 * time.Second,
		}

		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("listen %s: %w", addr, err)
		}
		l.tcpListener = ln

		go func() {
			if l.Type == TransportHTTPS {
				certPath := l.Config["cert"]
				keyPath := l.Config["key"]
				if err := l.httpServer.ServeTLS(ln, certPath, keyPath); err != nil && err != http.ErrServerClosed {
					l.mu.Lock()
					l.Running = false
					l.mu.Unlock()
				}
			} else {
				if err := l.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
					l.mu.Lock()
					l.Running = false
					l.mu.Unlock()
				}
			}
		}()

	case TransportDNS, TransportNamedPipe, TransportWireGuard, TransportMTLS:
		// 这些传输方式需要额外的初始化（DNS 服务器、Named Pipe、WireGuard、mTLS）
		// 当前仅标记状态，实际监听需要对应传输层支持
	}

	l.mu.Lock()
	l.Running = true
	l.mu.Unlock()
	now := time.Now()
	l.LastStarted = &now
	return nil
}

// Stop 停止监听器。
func (m *Manager) Stop(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	l, ok := m.listeners[id]
	if !ok {
		return fmt.Errorf("listener not found: %s", id)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.httpServer != nil {
		l.httpServer.Close()
		l.httpServer = nil
	}
	if l.tcpListener != nil {
		l.tcpListener.Close()
		l.tcpListener = nil
	}

	l.Running = false
	return nil
}

// Get 获取监听器。
func (m *Manager) Get(id string) (*Listener, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	l, ok := m.listeners[id]
	if !ok {
		return nil, fmt.Errorf("listener not found: %s", id)
	}
	return l, nil
}

// List 列出所有监听器。
func (m *Manager) List() []*Listener {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*Listener
	for _, l := range m.listeners {
		result = append(result, l)
	}
	return result
}

// Delete 删除监听器（先停止再删除，防止资源泄漏）。
func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	l, ok := m.listeners[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("listener not found: %s", id)
	}
	// Stop under Manager lock to avoid race with RunningListeners
	if l.isRunning() {
		l.mu.Lock()
		if l.httpServer != nil {
			l.httpServer.Close()
			l.httpServer = nil
		}
		if l.tcpListener != nil {
			l.tcpListener.Close()
			l.tcpListener = nil
		}
		l.Running = false
		l.mu.Unlock()
	}
	delete(m.listeners, id)
	m.mu.Unlock()
	return nil
}

// RunningListeners 返回正在运行的监听器。
func (m *Manager) RunningListeners() []*Listener {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*Listener
	for _, l := range m.listeners {
		l.mu.Lock()
		running := l.Running
		l.mu.Unlock()
		if running {
			result = append(result, l)
		}
	}
	return result
}

// Count 返回监听器数量。
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.listeners)
}

func generateID() string {
	return shared.GenID("lstn")
}
