//go:build !windows || !amd64

package evasion

// CheckSandbox 在非 Windows 平台上返回不检测。
func CheckSandbox() (bool, []string) {
	return false, nil
}

// CheckVM 在非 Windows 平台上返回不检测。
func CheckVM() (bool, string) {
	return false, ""
}

// CheckParentProcess 在非 Windows 平台上返回不检测。
func CheckParentProcess() (bool, string) {
	return false, ""
}

// CheckSleepAcceleration 在非 Windows 平台上返回 false。
func CheckSleepAcceleration() bool {
	return false
}

// CheckUserInteraction 在非 Windows 平台上返回 true。
func CheckUserInteraction() bool {
	return true
}
