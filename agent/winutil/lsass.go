//go:build windows && amd64

package winutil

import "syscall"

// FindLSASSPID 查找 lsass.exe 的 PID。
func FindLSASSPID() (int, error) {
	snapshot, err := CreateToolhelp32Snapshot()
	if err != nil {
		return 0, err
	}
	defer CloseHandle(snapshot)

	var pe PROCESSENTRY32
	if err := Process32First(snapshot, &pe); err != nil {
		return 0, err
	}

	for {
		name := ExeFileName(&pe)
		if name == "lsass.exe" {
			return int(pe.Th32ProcessID), nil
		}
		if err := Process32Next(snapshot, &pe); err != nil {
			break
		}
	}
	return 0, nil
}

// ExeFileName 从 PROCESSENTRY32 提取进程名。
func ExeFileName(pe *PROCESSENTRY32) string {
	return syscall.UTF16ToString(pe.ExeFile[:])
}

// CloseHandle 关闭内核对象句柄。
func CloseHandle(h syscall.Handle) error {
	return syscall.CloseHandle(h)
}
