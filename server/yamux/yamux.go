// Package yamux 提供服务端 Yamux 多路复用支持。
// 在单个 WebSocket 连接上复用多个逻辑流，带并发控制和 MUX/1 前缀检测。
package yamux

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"
	"github.com/aegis-c2/aegis/shared/protocol"
)

const (
	yamuxMaxConcurrentSends   = 64
	yamuxMaxConcurrentStreams = 128
	yamuxPingInterval         = 0 // 服务端不需要主动 ping，由客户端驱动
)

// Session 管理单个 Agent 的 Yamux 会话。
type Session struct {
	yamuxSess *yamux.Session
	wsConn    *websocket.Conn
	agentID   string
	handleMsg func(env *protocol.Envelope) map[string]interface{}
	mu        sync.Mutex
	streams   map[uint32]bool
	streamSem chan struct{}
	closed    bool
}

// wsReadWriter 将 WebSocket 连接包装为 io.ReadWriteCloser。
type wsReadWriter struct {
	conn     *websocket.Conn
	overflow []byte // 缓冲上一轮 Read 未读完的剩余数据
}

func (w *wsReadWriter) Read(p []byte) (n int, err error) {
	// 优先返回上一轮剩余的 overflow 数据
	if len(w.overflow) > 0 {
		n = copy(p, w.overflow)
		w.overflow = w.overflow[n:]
		return n, nil
	}

	_, msg, err := w.conn.ReadMessage()
	if err != nil {
		return 0, err
	}
	if len(msg) > len(p) {
		// 消息超出缓冲区，截断并缓存剩余数据
		n = copy(p, msg[:len(p)])
		w.overflow = msg[len(p):]
		return n, nil
	}
	return copy(p, msg), nil
}

func (w *wsReadWriter) Write(p []byte) (n int, err error) {
	err = w.conn.WriteMessage(websocket.BinaryMessage, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *wsReadWriter) Close() error {
	return w.conn.Close()
}

// NewSession 在 WebSocket 连接上创建 Yamux 会话。
// handleMsg 是消息处理回调，通常传入 server.handleWSMessage。
func NewSession(wsConn *websocket.Conn, handleMsg func(env *protocol.Envelope) map[string]interface{}) (*Session, error) {
	wrw := &wsReadWriter{conn: wsConn}

	config := yamux.DefaultConfig()
	config.LogOutput = nil
	config.EnableKeepAlive = false // 服务端被动响应 ping

	sess, err := yamux.Server(wrw, config)
	if err != nil {
		return nil, fmt.Errorf("yamux: %w", err)
	}

	return &Session{
		yamuxSess: sess,
		wsConn:    wsConn,
		handleMsg: handleMsg,
		streams:   make(map[uint32]bool),
		streamSem: make(chan struct{}, yamuxMaxConcurrentStreams),
	}, nil
}

// SetAgentID 设置关联的 Agent ID。
func (s *Session) SetAgentID(id string) {
	s.agentID = id
}

// Serve 启动 Yamux 流监听循环。
// 应在 WebSocket handler 中作为 goroutine 运行。
func (s *Session) Serve() {
	defer s.Close()

	for {
		stream, err := s.yamuxSess.AcceptStream()
		if err != nil {
			if !s.yamuxSess.IsClosed() {
				log.Printf("[yamux] accept stream error: %v", err)
			}
			return
		}

		// 信号量限制并发流数（Sliver: mtlsYamuxMaxConcurrentStreams）
		select {
		case s.streamSem <- struct{}{}:
			// 流关闭时释放信号量
			go func() {
				defer stream.Close()
				defer func() {
					<-s.streamSem
					s.mu.Lock()
					delete(s.streams, stream.StreamID())
					s.mu.Unlock()
				}()

				s.handleStream(stream)
			}()
		default:
			// 超过并发限制，拒绝此流
			log.Printf("[yamux] max streams reached, rejecting stream %d", stream.StreamID())
			stream.Close()
		}
	}
}

// handleStream 处理单个 Yamux 流。
// 使用 io.ReadAll 处理 TCP 分片，确保接收完整 JSON 消息。
func (s *Session) handleStream(stream *yamux.Stream) {
	s.mu.Lock()
	s.streams[stream.StreamID()] = true
	s.mu.Unlock()

	// N-P1-14: Limit stream size to prevent memory exhaustion (10MB)
	const maxStreamSize = 10 * 1024 * 1024
	data, err := io.ReadAll(io.LimitReader(stream, maxStreamSize))
	if err != nil {
		return
	}
	if len(data) >= maxStreamSize {
		log.Printf("[yamux] stream %d exceeded max size (%d), dropping", stream.StreamID(), maxStreamSize)
		return
	}

	var env protocol.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return
	}

	if s.handleMsg == nil {
		return
	}

	resp := s.handleMsg(&env)
	if resp == nil {
		return
	}

	respBytes, _ := json.Marshal(resp)
	stream.Write(respBytes)
}

// NumStreams 返回当前活跃流数量。
func (s *Session) NumStreams() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.streams)
}

// Close 关闭 Yamux 会话。
func (s *Session) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()

	if s.yamuxSess != nil {
		s.yamuxSess.Close()
	}
	if s.wsConn != nil {
		s.wsConn.Close()
	}
}

// IsClosed 检查会话是否已关闭。
func (s *Session) IsClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed || s.yamuxSess.IsClosed()
}
