// Package repl 提供 gRPC REPL 交互终端。
package repl

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/aegis-c2/aegis/proto/aegispb"
)

// printTable 打印表格到 stdout。
func printTable(header []string, rows [][]string) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	w.Write([]byte(strings.Join(header, "\t") + "\n"))
	w.Write([]byte(strings.Repeat("─", 60) + "\n"))
	for _, row := range rows {
		w.Write([]byte(strings.Join(row, "\t") + "\n"))
	}
	w.Flush()
}

// PrintAgents 打印 Agent 列表。
func PrintAgents(agents []*aegispb.AgentInfo) {
	if len(agents) == 0 {
		fmt.Println("  no agents registered")
		return
	}
	printTable(
		[]string{"ID", "HOSTNAME", "OS", "ARCH", "USER", "IP", "STATE", "TRANSPORT", "LAST SEEN"},
		agentRows(agents),
	)
	fmt.Printf("\n  %d agent(s)\n", len(agents))
}

func agentRows(agents []*aegispb.AgentInfo) [][]string {
	rows := make([][]string, len(agents))
	for i, a := range agents {
		rows[i] = []string{
			trunc(a.ID, 8),
			a.Hostname,
			a.OS,
			a.Arch,
			a.Username,
			a.IP,
			a.State,
			a.Transport,
			ago(a.LastHeartbeat),
		}
	}
	return rows
}

// PrintAgent 打印单个 Agent 详情。
func PrintAgent(a *aegispb.AgentInfo) {
	fmt.Println("  ID:          " + a.ID)
	fmt.Println("  Hostname:    " + a.Hostname)
	fmt.Println("  OS:          " + a.OS)
	fmt.Println("  Arch:        " + a.Arch)
	fmt.Println("  User:        " + a.Username)
	fmt.Println("  PID:         " + fmt.Sprintf("%d", a.PID))
	fmt.Println("  IP:          " + a.IP)
	fmt.Println("  State:       " + a.State)
	fmt.Println("  Transport:   " + a.Transport)
	fmt.Println("  Profile:     " + a.ProfileName)
	fmt.Println("  First Seen:  " + ts(a.FirstSeen))
	fmt.Println("  Last Beat:   " + ts(a.LastHeartbeat))
	fmt.Println("  Fail Count:  " + fmt.Sprintf("%d", a.FailCount))
}

// PrintTasks 打印任务列表。
func PrintTasks(tasks []*aegispb.TaskInfo) {
	if len(tasks) == 0 {
		fmt.Println("  no tasks")
		return
	}
	printTable(
		[]string{"ID", "AGENT", "CMD", "ARGS", "STATUS", "PRIORITY", "CREATED", "RESULT"},
		taskRows(tasks),
	)
	fmt.Printf("\n  %d task(s)\n", len(tasks))
}

func taskRows(tasks []*aegispb.TaskInfo) [][]string {
	rows := make([][]string, len(tasks))
	for i, t := range tasks {
		rows[i] = []string{
			trunc(t.ID, 8),
			trunc(t.AgentID, 8),
			t.Command,
			trunc(t.Args, 15),
			t.Status,
			fmt.Sprintf("%d", t.Priority),
			ago(t.CreatedAt),
			trunc(t.Result, 20),
		}
	}
	return rows
}

// PrintTask 打印单个任务详情。
func PrintTask(t *aegispb.TaskInfo) {
	fmt.Println("  ID:         " + t.ID)
	fmt.Println("  Agent:      " + t.AgentID)
	fmt.Println("  Command:    " + t.Command)
	fmt.Println("  Args:       " + t.Args)
	fmt.Println("  Status:     " + t.Status)
	fmt.Println("  Priority:   " + fmt.Sprintf("%d", t.Priority))
	fmt.Println("  Created:    " + ts(t.CreatedAt))
	fmt.Println("  Result:     " + t.Result)
	fmt.Println("  Exit Code:  " + fmt.Sprintf("%d", t.ExitCode))
	fmt.Println("  Audit Tag:  " + t.AuditTag)
}

// PrintListeners 打印 Listener 列表。
func PrintListeners(listeners []*aegispb.ListenerInfo) {
	if len(listeners) == 0 {
		fmt.Println("  no listeners")
		return
	}
	printTable(
		[]string{"ID", "NAME", "PROTO", "HOST", "PORT", "RUNNING"},
		listenerRows(listeners),
	)
}

func listenerRows(listeners []*aegispb.ListenerInfo) [][]string {
	rows := make([][]string, len(listeners))
	for i, l := range listeners {
		rows[i] = []string{
			trunc(l.ID, 8),
			l.Name,
			l.Protocol,
			l.Host,
			fmt.Sprintf("%d", l.Port),
			fmt.Sprintf("%v", l.Running),
		}
	}
	return rows
}

// PrintOperators 打印操作员列表。
func PrintOperators(operators []*aegispb.OperatorInfo) {
	if len(operators) == 0 {
		fmt.Println("  no operators")
		return
	}
	printTable(
		[]string{"ID", "NAME", "ROLE", "CONNECTED", "IP", "LAST SEEN"},
		operatorRows(operators),
	)
}

func operatorRows(ops []*aegispb.OperatorInfo) [][]string {
	rows := make([][]string, len(ops))
	for i, o := range ops {
		rows[i] = []string{
			trunc(o.ID, 8),
			o.Name,
			o.Role,
			fmt.Sprintf("%v", o.Connected),
			o.IPAddress,
			ago(o.LastSeen),
		}
	}
	return rows
}

// PrintProfiles 打印 Profile 列表。
func PrintProfiles(profiles []*aegispb.ProfileInfo) {
	if len(profiles) == 0 {
		fmt.Println("  no profiles")
		return
	}
	printTable(
		[]string{"NAME", "SLEEP", "JITTER", "USER AGENT", "ACTIVE"},
		profileRows(profiles),
	)
}

func profileRows(profiles []*aegispb.ProfileInfo) [][]string {
	rows := make([][]string, len(profiles))
	for i, p := range profiles {
		active := ""
		if p.Active {
			active = "*"
		}
		rows[i] = []string{
			p.Name,
			fmt.Sprintf("%ds", p.SleepSec),
			fmt.Sprintf("%d%%", p.JitterPct),
			p.UserAgent,
			active,
		}
	}
	return rows
}

// PrintServerInfo 打印服务器信息。
func PrintServerInfo(info *aegispb.ServerInfo) {
	fmt.Println("  Version:       " + info.Version)
	fmt.Println("  Uptime:        " + uptime(info.Uptime))
	fmt.Println("  Agents:        " + fmt.Sprintf("%d", info.AgentCount))
	fmt.Println("  Operators:     " + fmt.Sprintf("%d", info.OperatorCount))
	fmt.Println("  Listeners:     " + fmt.Sprintf("%d", info.ListenerCount))
	fmt.Println("  Active Profile: " + info.ActiveProfile)
}

// PrintEvent 打印单条事件。
func PrintEvent(e *aegispb.EventInfo) {
	fmt.Printf("  [%s] %s (agent=%s task=%s)\n", e.Type, ts(e.Timestamp), e.AgentID, e.TaskID)
}

// trunc 截断字符串到最大长度。
func trunc(s string, max int) string {
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// ts 将 Unix 时间戳转为可读字符串。
func ts(unix int64) string {
	if unix == 0 {
		return "never"
	}
	return time.Unix(unix, 0).Format("15:04:05")
}

// ago 返回相对时间。
func ago(unix int64) string {
	if unix == 0 {
		return "never"
	}
	d := time.Since(time.Unix(unix, 0))
	if d < time.Minute {
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh ago", int(d.Hours()))
}

// uptime 将秒数转为可读字符串。
func uptime(seconds int64) string {
	d := time.Duration(seconds) * time.Second
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd%dh", int(d.Hours())/24, int(d.Hours())%24)
}
