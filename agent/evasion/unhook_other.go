//go:build !windows || !amd64 || !cgo

package evasion

import "fmt"

// UnhookNTDLL 在非 Windows 平台返回错误。
func UnhookNTDLL() error {
	return fmt.Errorf("unhook only supported on Windows")
}

// CheckNTDLLHooks 在非 Windows 平台返回空列表。
func CheckNTDLLHooks() ([]string, error) {
	return nil, nil
}

// GetNTDLLTextInfo 在非 Windows 平台返回错误。
func GetNTDLLTextInfo() (uintptr, uint, error) {
	return 0, 0, fmt.Errorf("unhook only supported on Windows")
}
