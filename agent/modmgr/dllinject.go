// Package dllinject 提供 DLL 注入/旁加载。
// 参考 Havoc 的 LoadModule / SpawnDLL 和 Sliver 的 DLL sideload。
//
// 注入方式：
// 1. ReflectLoad — 反射式 DLL 加载（将 DLL 映射到目标进程内存并手动解析重定位/导入）
// 2. LoadLibrary — 经典 LoadLibrary 注入（写入 DLL 路径到目标进程，CreateRemoteThread 调用 LoadLibrary）
// 3. SpawnDLL — 创建挂起进程 + 反射加载 + 恢复线程
package modmgr

// DLLConfig 是 DLL 注入配置。
type DLLConfig struct {
	PID        uint32 // 目标进程 PID（LoadLibrary 模式）
	DLLPath    string // DLL 文件路径（LoadLibrary 模式，磁盘上存在）
	DLLData    []byte // DLL 原始字节（ReflectLoad 模式，内存中）
	EntryPoint string // DLL 导出函数名（"" = DllMain）
	Method     string // "loadlibrary" | "reflect" | "spawn"
	SpawnPath  string // 用于 spawn 模式的进程路径
	PPID       int    // 父进程欺骗 PID（0 = 不使用）
	Args       string // SpawnDLL 命令行参数
}

// DLLResult 是注入结果。
type DLLResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}
