package modules

import (
	"fmt"
	"strings"
	"time"

	"github.com/aegis-c2/aegis/agent/watcher"
)

// 全局 watcher 管理器。
var watchMgr = watcher.NewManager()

// WatcherModule 处理文件监控命令。
// Usage:
//
//	watch add <id> <path> [recursive] [interval_sec]
//	watch stop <id>
//	watch events <id>
//	watch list
func WatcherModule(args string) (string, string, int) {
	fields := strings.Fields(args)
	if len(fields) < 1 {
		return "usage: watch <add|stop|events|list> [args...]\n" +
			"  add <id> <path> [recursive] [interval_sec] — start watching a path\n" +
			"  stop <id>                                   — stop watching\n" +
			"  events <id>                                 — get pending events\n" +
			"  list                                        — list all watchers", "", 1
	}

	switch fields[0] {
	case "add":
		if len(fields) < 3 {
			return "", "usage: watch add <id> <path> [recursive] [interval_sec]", 1
		}
		id := fields[1]
		path := fields[2]
		recursive := false
		interval := 5 * time.Second

		if len(fields) > 3 {
			if fields[3] == "true" || fields[3] == "1" {
				recursive = true
			}
		}
		if len(fields) > 4 {
			var secs int
			if _, err := fmt.Sscanf(fields[4], "%d", &secs); err == nil && secs > 0 {
				interval = time.Duration(secs) * time.Second
			}
		}

		w, err := watchMgr.Add(id, path, recursive, interval)
		if err != nil {
			return "", err.Error(), 1
		}
		return fmt.Sprintf("watcher started: id=%s path=%s recursive=%v interval=%v",
			w.ID, w.Path, w.Recursive, w.Interval), "", 0

	case "stop":
		if len(fields) < 2 {
			return "", "usage: watch stop <id>", 1
		}
		if err := watchMgr.Stop(fields[1]); err != nil {
			return "", err.Error(), 1
		}
		return fmt.Sprintf("watcher stopped: %s", fields[1]), "", 0

	case "events":
		if len(fields) < 2 {
			return "", "usage: watch events <id>", 1
		}
		evts, err := watchMgr.Events(fields[1])
		if err != nil {
			return "", err.Error(), 1
		}
		if len(evts) == 0 {
			return "no pending events", "", 0
		}
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("%-8s %-60s %-10s %s\n", "CHANGE", "PATH", "SIZE", "MODTIME"))
		sb.WriteString(strings.Repeat("-", 100) + "\n")
		for _, e := range evts {
			sb.WriteString(fmt.Sprintf("%-8s %-60s %-10d %s\n",
				e.Change, e.Path, e.Size, e.ModTime.Format(time.RFC3339)))
		}
		return sb.String(), "", 0

	case "list":
		watches := watchMgr.List()
		if len(watches) == 0 {
			return "no active watchers", "", 0
		}
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("%-12s %-40s %-10s %s\n", "ID", "PATH", "RECURSIVE", "INTERVAL"))
		sb.WriteString(strings.Repeat("-", 80) + "\n")
		for _, w := range watches {
			sb.WriteString(fmt.Sprintf("%-12s %-40s %-10v %v\n",
				w.ID, w.Path, w.Recursive, w.Interval))
		}
		return sb.String(), "", 0

	default:
		return fmt.Sprintf("unknown subcommand: %s", fields[0]), "", 1
	}
}
