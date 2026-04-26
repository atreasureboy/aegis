//go:build !windows

// Package ps 提供进程列表（非 Windows 平台 stub）。
package ps

import (
	"fmt"
	"strings"
)

// List 列出所有进程。
func List() ([]Process, error) {
	return listUnix()
}

func listUnix() ([]Process, error) {
	// Linux: 读取 /proc 目录
	// macOS: sysctl CTL_KERN KERN_PROC
	return nil, fmt.Errorf("process listing requires platform-specific implementation")
}

// Kill 终止进程。
func Kill(pid int) error {
	return syscall.Kill(pid, syscall.SIGKILL)
}

// GetProcessByName 按名称查找进程。
func GetProcessByName(name string) ([]Process, error) {
	all, err := List()
	if err != nil {
		return nil, err
	}
	var result []Process
	for _, p := range all {
		if strings.EqualFold(p.Name, name) {
			result = append(result, p)
		}
	}
	return result, nil
}

// GetProcessByPID 按 PID 获取进程信息。
func GetProcessByPID(pid int) (*Process, error) {
	all, err := List()
	if err != nil {
		return nil, err
	}
	for _, p := range all {
		if p.PID == pid {
			return &p, nil
		}
	}
	return nil, fmt.Errorf("process not found: %d", pid)
}

// FormatProcessList 格式化进程列表输出。
func FormatProcessList(processes []Process) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%-8s %-8s %-30s %-15s %-6s %s\n",
		"PID", "PPID", "Name", "Owner", "Arch", "Memory"))
	sb.WriteString(strings.Repeat("-", 100) + "\n")
	for _, p := range processes {
		memStr := formatBytes(p.Memory)
		sb.WriteString(fmt.Sprintf("%-8d %-8d %-30s %-15s %-6s %s\n",
			p.PID, p.PPID, truncate(p.Name, 30), p.Owner, p.Arch, memStr))
	}
	sb.WriteString(fmt.Sprintf("\nTotal: %d processes\n", len(processes)))
	return sb.String()
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen-3] + "..."
	}
	return s
}
