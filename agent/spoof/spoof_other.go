//go:build !windows || !amd64 || !cgo

package spoof

// RetGadget 存储找到的 ret 指令地址。
type RetGadget struct {
	Address uintptr
	Module  string
}

// FindRetGadget 在非 Windows 平台上返回 nil。
func FindRetGadget(moduleName string) *RetGadget {
	return nil
}

// SpoofCall 使用调用栈欺骗方式执行目标函数（最多 4 参数）。
// 在非 Windows 平台上返回 -1。
func SpoofCall(targetFn uintptr, retGadget uintptr, args ...uintptr) int {
	return -1
}

// SpoofCallMany 使用调用栈欺骗方式执行目标函数（最多 10 参数）。
// 在非 Windows 平台上返回 -1。
func SpoofCallMany(targetFn uintptr, retGadget uintptr, args ...uintptr) int {
	return -1
}
