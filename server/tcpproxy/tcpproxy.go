// Package tcpproxy 提供 TCP 代理转发。
// 借鉴 Sliver 的 tcpproxy — 纯 TCP 流量转发，与 SOCKS 互补。
//
// 面试要点：
// 1. TCP Proxy vs SOCKS Proxy：
//    - SOCKS: 通用代理，支持任意 TCP/UDP 目标
//    - TCP Proxy: 固定目标，一对一转发
// 2. 使用场景：
//    - 固定转发到某个内网服务
//    - 不需要客户端配置 SOCKS
//    - 性能更好（无 SOCKS 握手开销）
package tcpproxy

import (
	"fmt"
	"io"
	"net"
	"sync"
)

// Proxy 是一个 TCP 代理实例。
type Proxy struct {
	ID         string
	ListenAddr string
	TargetAddr string
	Running    bool
	BytesSent  int64
	BytesRecv  int64
	Connections int
	mu         sync.Mutex
	listener   net.Listener
}

// NewProxy 创建 TCP 代理。
func NewProxy(id, listenAddr, targetAddr string) *Proxy {
	return &Proxy{
		ID:         id,
		ListenAddr: listenAddr,
		TargetAddr: targetAddr,
	}
}

// Start 启动 TCP 代理。
func (p *Proxy) Start() error {
	listener, err := net.Listen("tcp", p.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	p.listener = listener
	p.Running = true

	go p.run()
	return nil
}

func (p *Proxy) run() {
	defer func() {
		p.mu.Lock()
		p.Running = false
		p.mu.Unlock()
	}()

	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return
		}

		p.mu.Lock()
		p.Connections++
		p.mu.Unlock()

		go p.handle(conn)
	}
}

func (p *Proxy) handle(clientConn net.Conn) {
	defer func() {
		clientConn.Close()
		p.mu.Lock()
		p.Connections--
		p.mu.Unlock()
	}()

	targetConn, err := net.Dial("tcp", p.TargetAddr)
	if err != nil {
		return
	}
	defer targetConn.Close()

	// 双向转发
	done := make(chan struct{}, 2)
	go p.pipe("client→target", clientConn, targetConn, done)
	go p.pipe("target→client", targetConn, clientConn, done)

	<-done
	<-done
}

func (p *Proxy) pipe(name string, src, dst net.Conn, done chan struct{}) {
	defer func() { done <- struct{}{} }()

	buf := make([]byte, 64*1024)
	for {
		n, err := src.Read(buf)
		if err != nil {
			if err != io.EOF {
				// 日志
			}
			return
		}

		_, writeErr := dst.Write(buf[:n])
		if writeErr != nil {
			return
		}

		p.mu.Lock()
		if name == "client→target" {
			p.BytesSent += int64(n)
		} else {
			p.BytesRecv += int64(n)
		}
		p.mu.Unlock()
	}
}

// Stop 停止 TCP 代理。
func (p *Proxy) Stop() error {
	if p.listener != nil {
		return p.listener.Close()
	}
	return nil
}

// Stats 返回代理统计信息。
func (p *Proxy) Stats() map[string]interface{} {
	p.mu.Lock()
	defer p.mu.Unlock()

	return map[string]interface{}{
		"id":          p.ID,
		"listen_addr": p.ListenAddr,
		"target_addr": p.TargetAddr,
		"running":     p.Running,
		"bytes_sent":  p.BytesSent,
		"bytes_recv":  p.BytesRecv,
		"connections": p.Connections,
	}
}
