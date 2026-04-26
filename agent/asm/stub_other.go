//go:build !windows || !amd64

package stub

// IndirectSyscall 在非 Windows 平台返回 unsupported。
func IndirectSyscall(syscallNum uint32, args ...uintptr) int32 {
	return -1 // unsupported
}

// SpoofRetAddr 在非 Windows 平台返回 unsupported。
func SpoofRetAddr(targetAddr uintptr, fn uintptr, args ...uintptr) int32 {
	return -1 // unsupported
}
