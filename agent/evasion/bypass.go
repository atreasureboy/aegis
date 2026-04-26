//go:build !windows || !amd64 || !cgo

// Package evasion 提供 EDR/AV 绕过技术。
// 借鉴 Sliver 的 AMSI/ETW bypass 和 Havoc 的 RefreshPE 技术。
//
// 面试要点：
// 1. AMSI (Antimalware Scan Interface) - Windows 反恶意软件扫描接口
//    - PowerShell、.NET、VBScript 等都会通过 AMSI 扫描脚本内容
//    - 绕过方式：patch amsi.dll 中的 AmsiScanBuffer 函数，使其始终返回 "clean"
//    - 防御视角：EDR 会监控 amsi.dll 的内存修改
//
// 2. ETW (Event Tracing for Windows) - Windows 事件追踪
//    - PowerShell 的 ScriptBlock 日志、.NET 活动都通过 ETW 上报
//    - 绕过方式：patch EtwEventWrite 函数使其无操作
//    - 防御视角：ETW 静默会被 Windows 安全日志检测到
//
// 3. RefreshPE (API Unhooking) - 恢复被 EDR hook 的 API
//    - EDR 通过 inline hook 监控关键 API (NtAllocateVirtualMemory 等)
//    - 思路：从磁盘重新加载 ntdll.dll，覆盖内存中被 hook 的版本
//    - 防御视角：EDR 会检测 ntdll.dll 的重新加载
//
// 4. PPID Spoofing - 伪造父进程 ID
//    - 新进程的父进程设为 explorer.exe 而非 cmd.exe，降低可疑性
//    - 使用 PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
//    - 防御视角：ETW 记录父子进程关系
package evasion

import (
	"encoding/hex"
	"fmt"
)

// AMSIBypass 描述 AMSI 绕过技术。
type AMSIBypass struct {
	Name        string
	Description string
	Technique   string
	// 完整实现需要 Windows API 调用
}

// AMSIBypassRegistry 修改注册表中的 AMSI 配置。
// 这是最简单的绕过方式，但也是最先被检测的。
func AMSIBypassRegistry() error {
	// 完整实现需要:
	// 1. 打开注册表键: HKLM\SOFTWARE\Microsoft\AMSI
	// 2. 修改 ProviderEnabled = 0
	// 3. 或使用 AMSI 的 KnownDlls bypass
	return fmt.Errorf("not implemented - requires Windows API")
}

// AMSIBypassMemoryPatch 通过内存 patch 绕过 AMSI。
// 这是 Cobalt Strike / Sliver 常用的方式。
func AMSIBypassMemoryPatch() error {
	// 完整实现需要:
	// 1. LoadLibrary("amsi.dll")
	// 2. GetProcAddress("AmsiScanBuffer")
	// 3. VirtualProtect 修改内存保护为 RW
	// 4. Patch 前几个字节为 "xor rax, rax; ret" (48 31 C0 C3)
	// 5. VirtualProtect 恢复为 RX
	//
	// 常见 patch bytes:
	// - AmsiScanBuffer: 48 31 C0 C3 (xor rax, rax; ret)
	// - 或 B8 57 00 07 80 C3 (mov eax, 0x80070057; ret - E_INVALIDARG)
	return fmt.Errorf("not implemented - requires Windows API + memory patching")
}

// ETWBypass 描述 ETW 绕过技术。
type ETWBypass struct {
	Name        string
	Description string
	Technique   string
}

// ETWBypassMemoryPatch patch EtwEventWrite 使其不记录事件。
func ETWBypassMemoryPatch() error {
	// 完整实现需要:
	// 1. GetProcAddress(ntdll.dll, "EtwEventWrite")
	// 2. VirtualProtect → 修改保护为 RW
	// 3. Patch 为 "xor rax, rax; ret"
	// 4. VirtualProtect → 恢复为 RX
	//
	// 或更隐蔽的方式：
	// - Patch EtwEventWrite 内部的 EtwWrite 调用点
	// - 修改 ETW provider 的回调函数
	return fmt.Errorf("not implemented - requires Windows API + memory patching")
}

// RefreshPE 从磁盘重新加载 ntdll.dll，清除 EDR 的 inline hooks。
// 借鉴 Havoc 的 RefreshPE 技术。
func RefreshPE() error {
	// 完整实现需要:
	// 1. 打开 ntdll.dll 的磁盘文件
	// 2. 解析 PE 头，找到 .text 节
	// 3. 获取内存中 ntdll.dll 的基址 (GetModuleHandle)
	// 4. 将磁盘中的 .text 节复制到内存中覆盖
	// 5. 修复重定位
	//
	// 关键：只覆盖 .text 节，不覆盖 .data/.rdata
	// 因为 EDR 可能在 .data 中设置了监控点
	return fmt.Errorf("not implemented - requires PE parsing + memory manipulation")
}

// PPIDSpoofConfig 是 PPID 欺骗的配置。
type PPIDSpoofConfig struct {
	ParentPID    uint32 // 父进程 PID
	InheritHandle bool  // 是否继承句柄
}

// CreateProcessSpoof 使用指定的父进程创建新进程。
func CreateProcessSpoof(cmdLine string, config PPIDSpoofConfig) error {
	// 完整实现需要:
	// 1. OpenProcess(parentPID) 获取父进程句柄
	// 2. InitializeProcThreadAttributeList
	// 3. UpdateProcThreadAttribute(
	//      PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
	//      &parentHandle)
	// 4. CreateProcess with EXTENDED_STARTUPINFO_PRESENT
	// 5. 新进程的父进程会是指定的 PID，而非当前进程
	return fmt.Errorf("not implemented - requires Windows API")
}

// BypassReport 生成绕过技术的状态报告。
func BypassReport() string {
	return fmt.Sprintf(`Evasion Techniques Status:
  AMSI Bypass:     [ ] Not applied (requires Windows + memory patch)
                     Technique: Patch AmsiScanBuffer → xor rax, rax; ret
  ETW Bypass:      [ ] Not applied (requires Windows + memory patch)
                     Technique: Patch EtwEventWrite → NOP
  RefreshPE:       [ ] Not applied (requires Windows + PE reload)
                     Technique: Reload ntdll.dll .text section from disk
  PPID Spoofing:   [ ] Available (stub implementation)
                     Technique: PROC_THREAD_ATTRIBUTE_PARENT_PROCESS

  Interview Notes:
  - AMSI: EDR monitors amsi.dll memory integrity via driver callback
  - ETW: Windows 10+ logs ETW provider state changes
  - RefreshPE: EDR detects via section object monitoring (NtCreateSection)
  - Hardware breakpoint bypass: non-patching alternative using debug registers`,
	)
}

// AMSISignatures 是常见的 AMSI 签名检测值。
// 用于面试中说明为什么需要绕过 AMSI。
var AMSISignatures = []string{
	"amsi.dll!AmsiScanBuffer - scans script content",
	"amsi.dll!AmsiScanString - scans individual strings",
	"amsi.dll!AmsiOpenSession - opens scanning session",
}

// ETWProviders 是 Windows 安全相关的 ETW Provider。
var ETWProviders = []string{
	"Microsoft-Windows-PowerShell (GUID: {A0C1853B-5C40-4B15-8766-3CF1C58F985A})",
	"Microsoft-Windows-DotNETRuntime (GUID: {E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4})",
	"Microsoft-Windows-Threat-Intelligence (GUID: {F4E1897C-BAAE-49EC-A289-9E5C6F1896F5})",
}

// PatchBytes 是常用的 patch bytes (面试参考)。
var PatchBytes = map[string]string{
	"AmsiScanBuffer_x64":      "B8 57 00 07 80 C3",              // mov eax, E_INVALIDARG; ret
	"AmsiScanBuffer_x64_v2":   "48 31 C0 C3",                    // xor rax, rax; ret (legacy, less reliable)
	"EtwEventWrite_x64":       "48 31 C0 C3",                     // xor rax, rax; ret
	"EtwEventWrite_NOP_x64":   "90 90 90 90 90 90 90 90 90 90",  // 10x NOP
	"AmsiScanBuffer_x86":      "B8 57 00 07 80 C2 14 00",         // mov eax, E_INVALIDARG; ret 14
}

// HexToBytes 将 hex 字符串转为字节数组。
func HexToBytes(hexStr string) ([]byte, error) {
	return hex.DecodeString(hexStr)
}
