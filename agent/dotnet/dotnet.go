//go:build (!windows || !amd64) || (!cgo && windows && amd64)

package dotnet

import (
	"fmt"
	"os/exec"
	"time"
)

// ExecuteInProcess 在非 Windows 平台使用 dotnet CLI 执行程序集。
func ExecuteInProcess(config *AssemblyConfig) (*AssemblyResult, error) {
	startTime := time.Now()

	args := []string{"exec", config.AssemblyPath}
	args = append(args, config.Args...)

	cmd := exec.Command("dotnet", args...)
	output, err := cmd.CombinedOutput()
	duration := time.Since(startTime).String()

	if err != nil {
		exitCode := -1
		if cmd.ProcessState != nil {
			exitCode = cmd.ProcessState.ExitCode()
		}
		return &AssemblyResult{
			ExitCode: exitCode,
			Duration: duration,
		}, fmt.Errorf("dotnet exec: %w", err)
	}

	return &AssemblyResult{
		ExitCode: 0,
		Stdout:   string(output),
		Duration: duration,
	}, nil
}

// ExecuteOutProcess 创建新进程执行 .NET 程序集。
func ExecuteOutProcess(config *AssemblyConfig) (*AssemblyResult, error) {
	return ExecuteInProcess(config)
}

// BypassAMSI 在非 Windows 平台不适用。
func BypassAMSI() (*AMSIContext, error) {
	return nil, fmt.Errorf("AMSI bypass requires Windows")
}

// BypassETW 在非 Windows 平台不适用。
func BypassETW() (*ETWContext, error) {
	return nil, fmt.Errorf("ETW bypass requires Windows")
}

// RestoreAMSI 恢复 AMSI 原始状态。
func (ctx *AMSIContext) Restore() error {
	return fmt.Errorf("AMSI restore requires Windows")
}

// RestoreETW 恢复 ETW 原始状态。
func (ctx *ETWContext) Restore() error {
	return fmt.Errorf("ETW restore requires Windows")
}

// CommonDotNetTools 是常用的 .NET 工具列表（面试参考）。
var CommonDotNetTools = map[string]string{
	"Seatbelt":      "系统安全配置枚举",
	"Rubeus":        "Kerberos 操作（票据、黄金票等）",
	"Mimikatz":      "凭据提取（密码哈希、票据等）",
	"SharpHound":    "AD 信息收集（BloodHound 数据源）",
	"SharpDPAPI":    "DPAPI 解密",
	"SharpChromium": "Chromium 浏览器凭据提取",
	"SharpWeb":      "浏览器凭据提取（多浏览器）",
	"Watson":        "Windows 漏洞利用建议",
	"PowerView":     "AD 信息收集（PowerShell 版）",
}
