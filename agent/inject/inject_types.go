// Package inject 提供进程注入支持。
// 借鉴 Havoc 的 Inject 模块和 Sliver 的 process injection 实现。
package inject

// InjectMethod 指定进程注入的方法。
type InjectMethod int

const (
	MethodWindowsAPI    InjectMethod = iota // CreateRemoteThread
	MethodIndirectSyscall                   // 间接 Nt* syscall 绕过 EDR 钩子
	MethodThreadHijack                      // 劫持已有线程（无需创建远程线程）
	MethodFiberAPC                          // Fiber Injection + APC（本地线程转换）
	MethodAPCEarlyBird                      // APC Early Bird（挂起进程 + QueueUserAPC + ResumeThread）
)

// InjectConfig 是进程注入的配置。
type InjectConfig struct {
	PID        int          // 目标进程 PID
	Shellcode  []byte       // 要注入的 shellcode
	UseSyscall bool         // 是否使用间接 syscall (compatibility alias for MethodIndirectSyscall)
	Method     InjectMethod // 注入方法，优先级高于 UseSyscall
}

// SpawnConfig 是创建进程并注入的配置（sideload/migrate 使用）。
type SpawnConfig struct {
	ProcessName string   // 要创建的进程路径
	ProcessArgs []string // 进程参数
	PPID        int      // 伪造的父进程 PID（0 = 不伪造）
	Shellcode   []byte   // 要注入的 shellcode
	Kill        bool     // 执行完成后终止进程
	UseSyscall  bool     // 是否使用间接 syscall
}

// InjectResult 是注入结果。
type InjectResult struct {
	Success bool
	Message string
}
