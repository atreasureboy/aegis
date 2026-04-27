// Package memdump 提供进程内存转储。
// 使用 dbghelp.dll 转储 Windows 进程。
//
// 面试要点：
// 1. 进程转储用途：提取 LSASS 内存中的明文密码、浏览器凭据等
// 2. Windows API：dbghelp.dll dump function
// 3. Dump 类型：FullMemory (0x00000002), WithDataSegs (0x00000001)
// 4. 防御视角：EDR 监控 lsass.exe 的 OpenProcess，RunAsPPL 保护
package memdump

// CommonDumpTargets 是常见的转储目标进程。
var CommonDumpTargets = map[string]string{
	"lsass.exe":   "Windows 登录凭据 (NTLM hash, Kerberos tickets)",
	"chrome.exe":  "Chrome 浏览器凭据 (cookies, passwords)",
	"firefox.exe": "Firefox 浏览器凭据",
	"outlook.exe": "Outlook 邮件凭据",
	"winword.exe": "Word 文档可能包含敏感数据",
	"svchost.exe": "Windows 服务可能包含凭据",
	"conhost.exe": "控制台进程可能包含命令行历史",
}
