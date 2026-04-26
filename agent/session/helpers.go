package session

import (
	"crypto/rand"
	"fmt"
	"os"
	"os/user"
	"runtime"

	"github.com/aegis-c2/aegis/shared"
)

func GenerateID() string {
	return shared.GenID("aegis")
}

// Hostname 返回主机名。
func Hostname() string {
	h, _ := os.Hostname()
	return h
}

// GOOS 返回操作系统。
func GOOS() string {
	return runtime.GOOS
}

// GOARCH 返回架构。
func GOARCH() string {
	return runtime.GOARCH
}

// Username 返回当前用户名。
func Username() string {
	u, err := user.Current()
	if err != nil {
		return "unknown"
	}
	return u.Username
}

// PID 返回当前进程 ID。
func PID() int {
	return os.Getpid()
}

// RandomBytes 生成随机字节切片（使用 crypto/rand 保证安全性）。
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("rand.Read: %w", err)
	}
	return b, nil
}
