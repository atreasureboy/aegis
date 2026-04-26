// Package syscall 提供 Windows 间接系统调用支持。
// 借鉴 Havoc 的 Syscalls 模块：从 ntdll.dll 解析 syscall 编号，通过间接调用绕过 EDR hook。
//
// 面试要点：
// 1. EDR 通常通过 hook Win32 API（如 ntdll.dll 中的 stub）来监控系统调用
// 2. 间接 syscall 直接通过 syscall 指令进入内核，绕过用户态 hook
// 3. 需要先解析 ntdll.dll 的导出表，获取每个 Nt* 函数的 syscall number
// 4. Go 的间接 syscall 比 C 更复杂，因为 Go 没有 inline asm（amd64 除外）
package syscall

// SyscallTable 存储从 ntdll.dll 解析出的 syscall 编号映射。
type SyscallTable struct {
	entries map[string]uint32
}

// NewSyscallTable 创建 syscall 表。
func NewSyscallTable() *SyscallTable {
	return &SyscallTable{
		entries: make(map[string]uint32),
	}
}

// Register 手动注册一个 syscall 编号（用于已知 fallback 场景）。
func (t *SyscallTable) Register(name string, num uint32) {
	t.entries[name] = num
}

// GetSyscall 获取指定函数的 syscall 编号。
func (t *SyscallTable) GetSyscall(name string) (uint32, bool) {
	num, ok := t.entries[name]
	return num, ok
}

// GetSyscallOrZero 获取 syscall 编号，找不到时返回 0。
func (t *SyscallTable) GetSyscallOrZero(name string) uint32 {
	num, _ := t.GetSyscall(name)
	return num
}

// Count 返回已注册的 syscall 数量。
func (t *SyscallTable) Count() int {
	return len(t.entries)
}

// KnownSyscalls 是 Windows 10/11 常见的 syscall 编号（仅供参考，不用于生产）。
// 注意：这些编号随 Windows 版本变化，实际应通过 ResolveNtdll 动态解析。
var KnownSyscalls = map[string]uint32{
	"NtAllocateVirtualMemory":  0x18,
	"NtFreeVirtualMemory":      0x1e,
	"NtProtectVirtualMemory":   0x50,
	"NtWriteVirtualMemory":     0x3a,
	"NtCreateThreadEx":         0xc1,
	"NtOpenProcess":            0x26,
	"NtReadVirtualMemory":      0x3f,
	"NtQuerySystemInformation": 0x36,
	"NtCreateFile":             0x55,
	"NtReadFile":               0x6,
	"NtWriteFile":              0x8,
}
