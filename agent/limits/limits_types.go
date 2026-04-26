// Package limits 提供 Agent 执行限制。
package limits

import (
	"fmt"
	"runtime"
	"strings"
	"time"
)

// Config 是 Agent 执行限制配置。
type Config struct {
	KillDate        time.Time // 自毁日期
	MaxConns        int       // 最大连接数
	AllowedUsers    []string  // 允许的用户
	AllowedHosts    []string  // 允许的主机
	AllowedDomains  []string  // 允许的域
	BlockedUsers    []string  // 阻止的用户（如安全分析人员）
	MinCPUs         int       // 最小 CPU 数（反沙箱）
	MinMemoryMB     int       // 最小内存 MB（反沙箱）
	AllowedLocales  []string  // 允许的系统语言
	AllowedTimezone string    // 允许的时区
}

// CheckHardware 检查硬件配置（反沙箱）。
func (c *Config) CheckHardware() error {
	cpus := runtime.NumCPU()
	if c.MinCPUs > 0 && cpus < c.MinCPUs {
		return fmt.Errorf("insufficient CPUs: %d (minimum: %d)", cpus, c.MinCPUs)
	}
	return nil
}

// CheckTimezone 检查时区（反沙箱）。
func (c *Config) CheckTimezone() error {
	if c.AllowedTimezone == "" {
		return nil
	}
	tz := time.Now().Location().String()
	if tz != c.AllowedTimezone {
		return fmt.Errorf("timezone mismatch: expected %s, got %s", c.AllowedTimezone, tz)
	}
	return nil
}

// Contains 字符串大小写无关查找。
func Contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}

// SandboxIndicators 是常见的沙箱指标。
var SandboxIndicators = map[string]string{
	"Processes": "vboxservice,vmtoolsd,sandboxie,dllhost.exe (multiple)",
	"Registry":  `HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit 0`,
	"Files":     `C:\windows\system32\drivers\VBoxMouse.sys`,
	"MAC":       "08:00:27 (VirtualBox), 00:0C:29 (VMware)",
	"Username":  "admin, test, user, sandbox, malware, cuckoo",
	"Memory":    "Less than 2GB RAM (most sandboxes)",
	"CPUs":      "Less than 2 cores (most sandboxes)",
}
