//go:build !windows || !amd64 || !cgo

package inject

// Inject 执行进程注入。
// 使用标准 Windows API 实现（面试时可以展示 syscall 层的间接调用版本）。
func Inject(cfg *InjectConfig) *InjectResult {
	// Windows 平台的完整实现需要 CGO 或 syscall 包
	// 这里提供框架结构
	return &InjectResult{
		Success: false,
		Message: "inject requires Windows platform with CGO enabled",
	}
}

// InjectShellcode 是注入的核心步骤说明。
// 实际实现（Windows, C/CGO）：
//
// 1. NtOpenProcess
//    - 打开目标进程，获取 HANDLE
//    - 需要 PROCESS_ALL_ACCESS 权限
//
// 2. NtAllocateVirtualMemory
//    - 在目标进程分配内存
//    - 初始保护: PAGE_READWRITE
//
// 3. NtWriteVirtualMemory
//    - 将 shellcode 写入分配的内存
//
// 4. NtProtectVirtualMemory
//    - 修改内存保护为 PAGE_EXECUTE_READ
//
// 5. NtCreateThreadEx
//    - 在目标进程创建远程线程
//    - 线程入口点指向 shellcode
//
// 面试时可以解释每个步骤对应的防御检测手段：
// - ETW 记录内存保护变更
// - AMSI 扫描写入的内存
// - Sysmon Event ID 8/10 记录进程创建和内存操作