// Package transport 提供 Yamux 多路复用支持。
// 在单个 WebSocket/mTLS 连接上复用多个逻辑流（shell、文件传输、SOCKS 等）。
// 借鉴 Sliver: sendSem (64) + streamSem (128) + Ping + MUX/1 前缀协议。
package transport

import (
	"fmt"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"
)

const (
	yamuxMaxConcurrentSends  = 64  // 最大并发发送数（Sliver: mtlsYamuxMaxConcurrentSends）
	yamuxMaxConcurrentStreams = 128 // 最大并发流数（Sliver: mtlsYamuxMaxConcurrentStreams）
	yamuxPingInterval        = 2 * time.Minute // 心跳间隔
	yamuxPreface              = "MUX/1" // 多路复用前缀
)

// YamuxSession 管理底层连接上的 Yamux 多路复用。
type YamuxSession struct {
	conn      ioReadWriter // 底层连接（WebSocket/mTLS）
	yamuxSess *yamux.Session

	// 并发控制（Sliver 模式：信号量限制并发）
	sendSem  chan struct{} // 发送信号量
	streamSem chan struct{} // 流信号量

	mu       sync.Mutex
	closed   bool
	pongOnce sync.Once
}

// ioReadWriter 封装底层 IO 连接。
type ioReadWriter interface {
	Read(p []byte) (n int, err error)
	Write(p []byte) (n int, err error)
	Close() error
}

// wsConnWrapper 将 WebSocket 连接包装为 io.ReadWriteCloser。
type wsConnWrapper struct {
	conn     *websocket.Conn
	overflow []byte // 缓冲上一轮 Read 未读完的剩余数据
	mu       sync.Mutex
}

func (w *wsConnWrapper) Read(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

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

func (w *wsConnWrapper) Write(p []byte) (n int, err error) {
	err = w.conn.WriteMessage(websocket.BinaryMessage, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *wsConnWrapper) Close() error {
	return w.conn.Close()
}

// WritePreface 在连接上写入 "MUX/1" 前缀，告知服务端使用 Yamux 模式。
func WritePreface(conn ioReadWriter) error {
	_, err := conn.Write([]byte(yamuxPreface))
	return err
}

// ReadPreface 从连接读取并验证 "MUX/1" 前缀。
// 循环读取直到收到完整前缀（处理 TCP 分片）。
func ReadPreface(conn ioReadWriter) (bool, error) {
	buf := make([]byte, len(yamuxPreface))
	n := 0
	for n < len(buf) {
		rn, err := conn.Read(buf[n:])
		if err != nil {
			return false, err
		}
		n += rn
	}
	return string(buf) == yamuxPreface, nil
}

// NewClient 在已有连接上创建客户端 Yamux 会话。
// 调用方负责先发送 MUX/1 前缀。
func NewClient(conn ioReadWriter) (*YamuxSession, error) {
	config := yamux.DefaultConfig()
	config.LogOutput = nil
	config.EnableKeepAlive = true
	config.KeepAliveInterval = yamuxPingInterval

	sess, err := yamux.Client(conn, config)
	if err != nil {
		return nil, fmt.Errorf("yamux client: %w", err)
	}

	return &YamuxSession{
		conn:      conn,
		yamuxSess: sess,
		sendSem:   make(chan struct{}, yamuxMaxConcurrentSends),
		streamSem: make(chan struct{}, yamuxMaxConcurrentStreams),
	}, nil
}

// NewServer 在已有连接上创建服务端 Yamux 会话。
// 调用方负责先验证 MUX/1 前缀。
func NewServer(conn ioReadWriter) (*YamuxSession, error) {
	config := yamux.DefaultConfig()
	config.LogOutput = nil
	config.EnableKeepAlive = true
	config.KeepAliveInterval = yamuxPingInterval

	sess, err := yamux.Server(conn, config)
	if err != nil {
		return nil, fmt.Errorf("yamux server: %w", err)
	}

	return &YamuxSession{
		conn:      conn,
		yamuxSess: sess,
		sendSem:   make(chan struct{}, yamuxMaxConcurrentSends),
		streamSem: make(chan struct{}, yamuxMaxConcurrentStreams),
	}, nil
}

// OpenStream 打开一个新的逻辑流，受 sendSem 限制并发数。
// P1-13 fix: use select with timeout to prevent indefinite blocking under high concurrency.
func (s *YamuxSession) OpenStream() (*yamux.Stream, error) {
	// 获取发送信号量（Sliver: sendSem acquire）with timeout
	select {
	case s.sendSem <- struct{}{}:
		defer func() { <-s.sendSem }()
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("timed out waiting for yamux send slot")
	}

	stream, err := s.yamuxSess.OpenStream()
	if err != nil {
		return nil, err
	}
	return stream, nil
}

// OpenStreamNonBlocking 尝试打开流，不阻塞。
func (s *YamuxSession) OpenStreamNonBlocking() (*yamux.Stream, error) {
	select {
	case s.sendSem <- struct{}{}:
		defer func() { <-s.sendSem }()
		return s.yamuxSess.OpenStream()
	default:
		return nil, fmt.Errorf("max concurrent sends reached (%d)", yamuxMaxConcurrentSends)
	}
}

// AcceptStream 接受传入的逻辑流，受 streamSem 限制并发数。
// 返回的流在 Close 时自动释放信号量配额。
func (s *YamuxSession) AcceptStream() (*trackedStream, error) {
	stream, err := s.yamuxSess.AcceptStream()
	if err != nil {
		return nil, err
	}

	// 获取流信号量（Sliver: streamSem acquire）
	select {
	case s.streamSem <- struct{}{}:
		return &trackedStream{Stream: stream, release: func() { s.releaseStream() }}, nil
	default:
		stream.Close()
		return nil, fmt.Errorf("max concurrent streams reached (%d)", yamuxMaxConcurrentStreams)
	}
}

func (s *YamuxSession) releaseStream() {
	select {
	case <-s.streamSem:
	default:
	}
}

// trackedStream 包装 yamux.Stream，Close 时自动释放信号量。
type trackedStream struct {
	*yamux.Stream
	release func()
}

func (t *trackedStream) Close() error {
	if t.release != nil {
		t.release()
	}
	return t.Stream.Close()
}

// ActiveStreams 返回当前活跃流数量。
func (s *YamuxSession) ActiveStreams() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.yamuxSess.NumStreams()
}

// Close 关闭 Yamux 会话及底层连接。
func (s *YamuxSession) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	var err1, err2 error
	if s.yamuxSess != nil {
		err1 = s.yamuxSess.Close()
	}
	if s.conn != nil {
		err2 = s.conn.Close()
	}
	if err1 != nil {
		return err1
	}
	return err2
}

// IsClosed 检查会话是否已关闭。
func (s *YamuxSession) IsClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed || s.yamuxSess.IsClosed()
}

// Ping 发送 Yamux 心跳并等待响应。
func (s *YamuxSession) Ping() error {
	_, err := s.yamuxSess.Ping()
	return err
}
