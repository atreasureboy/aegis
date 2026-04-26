// Package ps 提供进程列表。
package ps

// Process 表示一个进程。
type Process struct {
	PID         int     `json:"pid"`
	PPID        int     `json:"ppid"`
	Name        string  `json:"name"`
	Owner       string  `json:"owner"`
	Arch        string  `json:"arch"`
	SessionID   int     `json:"session_id"`
	Path        string  `json:"path"`
	CPU         float64 `json:"cpu"`
	Memory      int64   `json:"memory"` // bytes
	CommandLine string  `json:"cmdline"`
}
