//go:build !windows

package service

import (
	"fmt"
	"runtime"
	"strings"
)

// ServiceInfo represents a service on non-Windows (stub).
type ServiceInfo struct {
	Name        string
	DisplayName string
	Description string
	State       string
	StartType   string
	BinaryPath  string
	PID         uint32
}

// EnumServices is not available on non-Windows platforms.
func EnumServices() ([]ServiceInfo, error) {
	return nil, fmt.Errorf("service enumeration not supported on %s", runtime.GOOS)
}

// FormatServices formats service list for display.
func FormatServices(services []ServiceInfo) string {
	var sb strings.Builder
	sb.WriteString("service enumeration is only available on Windows\n")
	return sb.String()
}
