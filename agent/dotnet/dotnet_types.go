package dotnet

// AssemblyConfig 是 .NET 程序集执行的配置。
type AssemblyConfig struct {
	AssemblyPath   string   // 程序集路径或字节数据
	ClassName      string   // 要调用的类名 (可选，默认入口点)
	MethodName     string   // 要调用的方法名 (可选，默认 Main)
	Args           []string // 命令行参数
	InProcess      bool     // 是否在进程中执行
	AMSI           bool     // 是否在执行前绕过 AMSI
	ETW            bool     // 是否在执行前绕过 ETW
}

// AssemblyResult 是 .NET 程序集执行的结果。
type AssemblyResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
	Duration string
}

// AMSIContext 描述 AMSI 上下文。
type AMSIContext struct {
	AmsiScanBufferAddr uintptr // AmsiScanBuffer 函数地址
	PatchBytes         []byte  // Patch bytes
	OriginalBytes      []byte  // 原始字节（用于恢复）
}

// ETWContext 描述 ETW 上下文。
type ETWContext struct {
	EtwEventWriteAddr uintptr
	PatchBytes        []byte
	OriginalBytes     []byte
}
