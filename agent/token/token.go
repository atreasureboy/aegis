//go:build !windows || !amd64

// Package token 提供 Windows Token 操作（非 Windows 平台 stub）。
package token

import "fmt"

// PrivilegeConfig 描述一个要启用的权限。
type PrivilegeConfig struct {
	Name    string
	Enabled bool
}

// EnablePrivilege 启用指定的 Token 权限。
func EnablePrivilege(privilege string) error {
	return fmt.Errorf("not implemented - requires Windows")
}

// ImpersonateConfig 是 Token 模拟的配置。
type ImpersonateConfig struct {
	PID      uint32
	ThreadID uint32
	Username string
}

// ImpersonateProcessToken 通过复制目标进程的 Token 来模拟用户。
func ImpersonateProcessToken(pid uint32) error {
	return fmt.Errorf("not implemented - requires Windows")
}

// ImpersonateUser 通过用户名查找并模拟指定用户。
func ImpersonateUser(username string) error {
	return fmt.Errorf("not implemented - requires Windows")
}

// RevToSelf 恢复为原始 Token。
func RevToSelf() error {
	return fmt.Errorf("not implemented - requires Windows")
}

// MakeToken 使用指定凭据创建新登录会话并模拟。
func MakeToken(domain, username, password string) error {
	return fmt.Errorf("not implemented - requires Windows")
}

// StealToken 复制目标进程的 Token 并永久模拟。
func StealToken(pid uint32) error {
	return fmt.Errorf("not implemented - requires Windows")
}

// TokenInfo 返回当前 Token 信息。
func TokenInfo() (string, error) {
	return "", fmt.Errorf("not implemented - requires Windows")
}

// CommonPrivileges 是常用的 Windows 权限列表。
var CommonPrivileges = map[string]string{
	"SeDebugPrivilege":            "允许调试/访问其他进程 - 进程注入需要",
	"SeImpersonatePrivilege":      "允许模拟其他用户 - PrintSpoofer 需要",
	"SeAssignPrimaryTokenPrivilege": "允许分配主 Token - JuicyPotato 需要",
	"SeTcbPrivilege":              "充当操作系统的一部分 - 极少分配",
	"SeLoadDriverPrivilege":       "允许加载/卸载驱动 - 驱动漏洞利用需要",
	"SeBackupPrivilege":           "允许备份文件 - 可绕过文件权限读取敏感文件",
	"SeRestorePrivilege":          "允许恢复文件 - 可覆盖系统文件",
	"SeTakeOwnershipPrivilege":    "允许获取对象所有权 - 可修改文件权限",
}

// IntegrityLevel 描述完整性级别。
var IntegrityLevel = map[string]string{
	"Untrusted":   "S-1-16-0 (最低权限)",
	"Low":         "S-1-16-4096 (IE 保护模式)",
	"Medium":      "S-1-16-8192 (普通用户进程)",
	"High":        "S-1-16-12288 (管理员权限)",
	"System":      "S-1-16-16384 (SYSTEM 权限)",
	"Protected":   "PPL (Protected Process Light)",
}
