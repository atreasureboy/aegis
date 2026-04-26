//go:build !windows || !amd64

// Package transport 提供 Named Pipe 传输支持（非 Windows 平台 stub）。
package transport

import (
	"fmt"
)

// NamedPipeServer 是 Named Pipe 服务器端。
type NamedPipeServer struct {
	config  *NamedPipeConfig
	running bool
	handle  uintptr
}

// NewNamedPipeServer 创建 Named Pipe 服务器。
func NewNamedPipeServer(pipeName string) *NamedPipeServer {
	return &NamedPipeServer{
		config: &NamedPipeConfig{
			PipeName:   pipeName,
			ServerPath: fmt.Sprintf(`\\.\pipe\%s`, pipeName),
		},
	}
}

// Start 启动 Named Pipe 监听。
func (s *NamedPipeServer) Start() error {
	return fmt.Errorf("named pipe server requires Windows")
}

// Stop 停止 Named Pipe 服务器。
func (s *NamedPipeServer) Stop() error {
	s.running = false
	return nil
}

// NamedPipeClient 是 Named Pipe 客户端。
type NamedPipeClient struct {
	config *NamedPipeConfig
	handle uintptr
}

// NewNamedPipeClient 创建 Named Pipe 客户端。
func NewNamedPipeClient(pipeName string, remoteHost string) *NamedPipeClient {
	path := fmt.Sprintf(`\\.\pipe\%s`, pipeName)
	if remoteHost != "" {
		path = fmt.Sprintf(`\\%s\pipe\%s`, remoteHost, pipeName)
	}
	return &NamedPipeClient{
		config: &NamedPipeConfig{
			PipeName:   pipeName,
			RemoteHost: remoteHost,
			ServerPath: path,
		},
	}
}

// Connect 连接到 Named Pipe 服务器。
func (c *NamedPipeClient) Connect() error {
	return fmt.Errorf("named pipe client requires Windows")
}

// Read 从 Named Pipe 读取数据。
func (c *NamedPipeClient) Read(buf []byte) (int, error) {
	return 0, fmt.Errorf("named pipe requires Windows")
}

// Write 向 Named Pipe 写入数据。
func (c *NamedPipeClient) Write(data []byte) (int, error) {
	return 0, fmt.Errorf("named pipe requires Windows")
}

// Close 关闭 Named Pipe 连接。
func (c *NamedPipeClient) Close() error {
	return nil
}
