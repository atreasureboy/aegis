//go:build !windows || !amd64

// Package transport 提供 Named Pipe 传输（非 Windows stub）。
package transport

import (
	"fmt"

	"github.com/aegis-c2/aegis/shared/protocol"
)

// NamedPipeTransportConfig 是 Named Pipe Transport 配置。
type NamedPipeTransportConfig struct {
	PipeName   string
	RemoteHost string
}

// NamedPipeTransport 实现了 Transporter 接口（stub）。
type NamedPipeTransport struct {
	config  *NamedPipeTransportConfig
	agentID string
}

func NewNamedPipeTransport(cfg *NamedPipeTransportConfig, agentID string) *NamedPipeTransport {
	return &NamedPipeTransport{config: cfg, agentID: agentID}
}

func (n *NamedPipeTransport) Register(env *protocol.Envelope) (*map[string]string, error) {
	return nil, fmt.Errorf("named pipe transport requires Windows")
}

func (n *NamedPipeTransport) Heartbeat(env *protocol.Envelope) (*map[string]string, error) {
	return nil, fmt.Errorf("named pipe transport requires Windows")
}

func (n *NamedPipeTransport) PollTask(env *protocol.Envelope) ([]byte, error) {
	return nil, fmt.Errorf("named pipe transport requires Windows")
}

func (n *NamedPipeTransport) SubmitResult(env *protocol.Envelope) (*map[string]string, error) {
	return nil, fmt.Errorf("named pipe transport requires Windows")
}
