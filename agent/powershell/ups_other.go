//go:build !windows || !amd64 || !cgo

package powershell

// UnmanagedPS 在非 Windows 平台上的空壳。
type UnmanagedPS struct{}

// NewUnmanagedPS 在非 Windows 平台上返回错误。
func NewUnmanagedPS() (*UnmanagedPS, error) {
	return nil, nil
}

// Execute 在非 Windows 平台上返回错误。
func (u *UnmanagedPS) Execute(script string) (string, error) {
	return "", nil
}

// Version 返回 0。
func (u *UnmanagedPS) Version() int {
	return 0
}

// Close 为空。
func (u *UnmanagedPS) Close() {}
