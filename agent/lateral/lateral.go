//go:build !windows

package lateral

import "fmt"

// WMIExec 在 Windows 之外的桩实现。
func WMIExec(target, username, password, command string) (uint32, error) {
	return 0, fmt.Errorf("WMIExec only available on Windows")
}

// WMIExecSimple 在 Windows 之外的桩实现。
func WMIExecSimple(target, command string) (uint32, error) {
	return 0, fmt.Errorf("WMIExecSimple only available on Windows")
}

// WMICheck 在 Windows 之外的桩实现。
func WMICheck(target, username, password string) error {
	return fmt.Errorf("WMICheck only available on Windows")
}

// RemoteCmd 在 Windows 之外的桩实现。
func RemoteCmd(target, username, password, command string) (string, error) {
	return "", fmt.Errorf("RemoteCmd only available on Windows")
}
