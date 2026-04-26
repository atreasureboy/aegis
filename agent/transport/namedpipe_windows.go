//go:build windows && amd64

// Package transport 提供 Named Pipe 传输支持（Windows 实现）。
package transport

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procCreateNamedPipe    = kernel32.NewProc("CreateNamedPipeW")
	procConnectNamedPipe   = kernel32.NewProc("ConnectNamedPipe")
	procWaitNamedPipe      = kernel32.NewProc("WaitNamedPipeW")
	procSetNamedPipeState  = kernel32.NewProc("SetNamedPipeHandleState")
)

const (
	PIPE_ACCESS_DUPLEX       = 0x00000003
	PIPE_TYPE_MESSAGE        = 0x00000004
	PIPE_READMODE_MESSAGE    = 0x00000002
	PIPE_WAIT                = 0x00000000
	PIPE_UNLIMITED_INSTANCES = 255
	NMPWAIT_WAIT_FOREVER     = 0xFFFFFFFF
)

// NamedPipeServer 是 Named Pipe 服务器端。
type NamedPipeServer struct {
	config  *NamedPipeConfig
	running bool
	handle  windows.Handle
}

// NewNamedPipeServer 创建 Named Pipe 服务器。
func NewNamedPipeServer(pipeName string) *NamedPipeServer {
	return &NamedPipeServer{
		config: &NamedPipeConfig{
			PipeName:   pipeName,
			ServerPath: NamedPipeServerPath(pipeName),
		},
	}
}

// Start 启动 Named Pipe 监听。
func (s *NamedPipeServer) Start() error {
	pathPtr, _ := syscall.UTF16PtrFromString(s.config.ServerPath)

	// 构建安全描述符：仅允许 Administrators 和 SYSTEM 访问
	// SDDL: D:(A;;GA;;;SY)(A;;GA;;;BA) — SYSTEM 和 Administrators 完全控制
	securitySDDL := "D:(A;;GA;;;SY)(A;;GA;;;BA)"
	sd, err := windows.SecurityDescriptorFromString(securitySDDL)
	if err != nil {
		return fmt.Errorf("SecurityDescriptorFromString: %w", err)
	}
	sa := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
		InheritHandle:      1,
	}

	h, _, err := procCreateNamedPipe.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		PIPE_ACCESS_DUPLEX,
		PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT,
		PIPE_UNLIMITED_INSTANCES,
		4096,
		4096,
		0,
		uintptr(unsafe.Pointer(&sa)),
	)
	if h == uintptr(windows.InvalidHandle) {
		return fmt.Errorf("CreateNamedPipe: %w", err)
	}

	s.handle = windows.Handle(h)

	r, _, err := procConnectNamedPipe.Call(uintptr(s.handle), 0)
	if r == 0 {
		if err != windows.ERROR_PIPE_CONNECTED {
			return fmt.Errorf("ConnectNamedPipe: %w", err)
		}
	}

	s.running = true
	return nil
}

// Stop 停止 Named Pipe 服务器。
func (s *NamedPipeServer) Stop() error {
	s.running = false
	if s.handle != windows.InvalidHandle {
		return windows.CloseHandle(s.handle)
	}
	return nil
}

// Read 从 Named Pipe 读取数据。
func (s *NamedPipeServer) Read(buf []byte) (int, error) {
	if s.handle == windows.InvalidHandle {
		return 0, fmt.Errorf("pipe not connected")
	}
	var bytesRead uint32
	err := windows.ReadFile(s.handle, buf, &bytesRead, nil)
	if err != nil {
		return 0, err
	}
	return int(bytesRead), nil
}

// Write 向 Named Pipe 写入数据。
func (s *NamedPipeServer) Write(data []byte) (int, error) {
	if s.handle == windows.InvalidHandle {
		return 0, fmt.Errorf("pipe not connected")
	}
	var bytesWritten uint32
	err := windows.WriteFile(s.handle, data, &bytesWritten, nil)
	if err != nil {
		return 0, err
	}
	return int(bytesWritten), nil
}

// NamedPipeClient 是 Named Pipe 客户端。
type NamedPipeClient struct {
	config *NamedPipeConfig
	handle windows.Handle
}

// NewNamedPipeClient 创建 Named Pipe 客户端。
func NewNamedPipeClient(pipeName string, remoteHost string) *NamedPipeClient {
	return &NamedPipeClient{
		config: &NamedPipeConfig{
			PipeName:   pipeName,
			RemoteHost: remoteHost,
			ServerPath: NamedPipeClientPath(pipeName, remoteHost),
		},
	}
}

// Connect 连接到 Named Pipe 服务器。
func (c *NamedPipeClient) Connect() error {
	pathPtr, _ := syscall.UTF16PtrFromString(c.config.ServerPath)

	r, _, _ := procWaitNamedPipe.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		NMPWAIT_WAIT_FOREVER,
	)
	if r == 0 {
		return fmt.Errorf("WaitNamedPipe timeout: %s", c.config.ServerPath)
	}

	h, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0, nil,
		windows.OPEN_EXISTING,
		windows.SECURITY_SQOS_PRESENT|windows.SECURITY_ANONYMOUS,
		0,
	)
	if err != nil {
		return fmt.Errorf("CreateFile(%s): %w", c.config.ServerPath, err)
	}

	c.handle = h

	mode := uint32(PIPE_READMODE_MESSAGE)
	r, _, err = procSetNamedPipeState.Call(
		uintptr(c.handle),
		uintptr(unsafe.Pointer(&mode)),
		0, 0,
	)
	if r == 0 {
		windows.CloseHandle(c.handle)
		c.handle = windows.InvalidHandle
		return fmt.Errorf("SetNamedPipeHandleState: %w", err)
	}

	return nil
}

// Read 从 Named Pipe 读取数据。
func (c *NamedPipeClient) Read(buf []byte) (int, error) {
	if c.handle == windows.InvalidHandle {
		return 0, fmt.Errorf("pipe not connected")
	}
	var bytesRead uint32
	err := windows.ReadFile(c.handle, buf, &bytesRead, nil)
	return int(bytesRead), err
}

// Write 向 Named Pipe 写入数据。
func (c *NamedPipeClient) Write(data []byte) (int, error) {
	if c.handle == windows.InvalidHandle {
		return 0, fmt.Errorf("pipe not connected")
	}
	var bytesWritten uint32
	err := windows.WriteFile(c.handle, data, &bytesWritten, nil)
	return int(bytesWritten), err
}

// Close 关闭 Named Pipe 连接。
func (c *NamedPipeClient) Close() error {
	if c.handle != windows.InvalidHandle {
		err := windows.CloseHandle(c.handle)
		c.handle = 0
		return err
	}
	return nil
}

// Handle 返回底层句柄。
func (c *NamedPipeClient) Handle() windows.Handle {
	return c.handle
}

// SetDeadline 实现 net.Conn 接口。
func (c *NamedPipeClient) SetDeadline(t time.Time) error       { return nil }
func (c *NamedPipeClient) SetReadDeadline(t time.Time) error   { return nil }
func (c *NamedPipeClient) SetWriteDeadline(t time.Time) error  { return nil }
func (c *NamedPipeClient) LocalAddr() interface{}              { return pipeAddr{c.config.ServerPath} }
func (c *NamedPipeClient) RemoteAddr() interface{}             { return pipeAddr{c.config.ServerPath} }

type pipeAddr struct{ path string }
func (a pipeAddr) Network() string { return "pipe" }
func (a pipeAddr) String() string  { return a.path }
