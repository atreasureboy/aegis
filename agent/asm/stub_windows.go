//go:build windows && amd64 && !cgo

// Package stub 提供间接 syscall 的 Go 端 placeholder 实现。
// 当 CGO 不可用时，回退到标准 syscall.Syscall 接口。
package stub

import (
	"syscall"
)

// IndirectSyscall 执行间接系统调用。
// 非 CGO 模式下无法绕过 EDR hook，返回错误码。
func IndirectSyscall(syscallNum uint32, args ...uintptr) int64 {
	_ = syscallNum
	_ = args
	return -1
}

// SpoofRetAddr 修改调用栈上的返回地址。
// 非 CGO 模式下无法实现栈欺骗，返回错误码。
func SpoofRetAddr(targetAddr uintptr, fn uintptr, args ...uintptr) int64 {
	_ = targetAddr
	_ = fn
	_ = args
	return -1
}
