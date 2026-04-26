package audit

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// Logger 负责记录所有操作的审计日志。
type Logger struct {
	file   *os.File
	mu     sync.Mutex
}

// New 创建审计日志器。
func New(logPath string) (*Logger, error) {
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &Logger{file: f}, nil
}

// Log 写入一条审计日志。
func (l *Logger) Log(event string, fields map[string]string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	var parts string
	for k, v := range fields {
		parts += fmt.Sprintf(" %s=%s", k, v)
	}
	entry := fmt.Sprintf("[%s] %s%s\n", timestamp, event, parts)

	if l.file != nil {
		if _, err := l.file.WriteString(entry); err != nil {
			// 文件写入失败时降级到 stderr
			log.Printf("[AUDIT ERROR] file write failed: %v", err)
		}
	}
	// Only log to file — avoid duplicating to stderr (AUDIT-1)
}

// LogOperator 写入一条带操作员上下文的审计日志。
func (l *Logger) LogOperator(operatorID, action, target, result string) {
	if l == nil {
		return
	}
	l.Log(action, map[string]string{
		"operator": operatorID,
		"target":   target,
		"result":   result,
	})
}

// Close 同步并关闭日志文件。
func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		l.file.Sync() // 确保缓冲区刷入磁盘
		l.file.Close()
		l.file = nil
	}
}

// Sync 强制将缓冲区刷入磁盘。
func (l *Logger) Sync() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		l.file.Sync()
	}
}
