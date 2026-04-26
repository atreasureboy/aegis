// Package transport 提供 Named Pipe 传输配置（平台无关）。
package transport

import "fmt"

// NamedPipeConfig 是 Named Pipe 传输配置。
type NamedPipeConfig struct {
	PipeName   string
	ServerPath string
	RemoteHost string
}

// NamedPipeServerPath 生成 Named Pipe 服务器路径。
func NamedPipeServerPath(pipeName string) string {
	return fmt.Sprintf(`\\.\pipe\%s`, pipeName)
}

// NamedPipeClientPath 生成 Named Pipe 客户端路径。
func NamedPipeClientPath(pipeName string, remoteHost string) string {
	if remoteHost != "" {
		return fmt.Sprintf(`\\%s\pipe\%s`, remoteHost, pipeName)
	}
	return fmt.Sprintf(`\\.\pipe\%s`, pipeName)
}
