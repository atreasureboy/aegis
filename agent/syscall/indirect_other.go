//go:build !windows || !amd64 || !cgo

package syscall

import "unsafe"

// ExecuteIndirect 在非 Windows 或非 CGO 平台上不可用。
func ExecuteIndirect(ssn uint32, args ...unsafe.Pointer) int {
	return -1
}
