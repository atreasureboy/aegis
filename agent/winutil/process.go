//go:build windows && amd64

// Package winutil 提供共享的 Windows 进程枚举工具。
package winutil

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	modKernel32                   = syscall.NewLazyDLL("kernel32.dll")
	procCreateToolhelp32Snapshot  = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW           = modKernel32.NewProc("Process32FirstW")
	procProcess32NextW            = modKernel32.NewProc("Process32NextW")
)

const TH32CS_SNAPPROCESS = 0x00000002

// PROCESSENTRY32 是 CreateToolhelp32Snapshot 返回的进程快照结构。
type PROCESSENTRY32 struct {
	Size              uint32
	CntUsage          uint32
	Th32ProcessID     uint32
	DefaultHeapID     uintptr
	Th32ModuleID      uint32
	CntThreads        uint32
	Th32ParentProcessID uint32
	PriorityClassBase int32
	Flags             uint32
	ExeFile           [260]uint16
}

// CreateToolhelp32Snapshot 创建进程快照。
func CreateToolhelp32Snapshot() (syscall.Handle, error) {
	ret, _, err := procCreateToolhelp32Snapshot.Call(TH32CS_SNAPPROCESS, 0)
	if ret == ^uintptr(0) { /* INVALID_HANDLE_VALUE */
		return 0, err
	}
	return syscall.Handle(ret), nil
}

// Process32First 获取第一个进程。
func Process32First(snapshot syscall.Handle, pe *PROCESSENTRY32) error {
	pe.Size = uint32(unsafe.Sizeof(*pe))
	ret, _, err := procProcess32FirstW.Call(uintptr(snapshot), uintptr(unsafe.Pointer(pe)))
	if ret == 0 {
		return err
	}
	return nil
}

// Process32Next 获取下一个进程。
func Process32Next(snapshot syscall.Handle, pe *PROCESSENTRY32) error {
	ret, _, err := procProcess32NextW.Call(uintptr(snapshot), uintptr(unsafe.Pointer(pe)))
	if ret == 0 {
		return err
	}
	return nil
}

// FindProcessByName 按名称查找进程 PID（返回第一个匹配）。
func FindProcessByName(name string) (uint32, error) {
	snapshot, err := CreateToolhelp32Snapshot()
	if err != nil {
		return 0, err
	}
	defer syscall.CloseHandle(snapshot)

	var pe PROCESSENTRY32
	if err := Process32First(snapshot, &pe); err != nil {
		return 0, err
	}

	for {
		if syscall.UTF16ToString(pe.ExeFile[:]) == name {
			return pe.Th32ProcessID, nil
		}
		if err := Process32Next(snapshot, &pe); err != nil {
			break
		}
	}
	return 0, fmt.Errorf("process %q not found", name)
}

// GetParentPID 获取指定进程的父进程 ID。
func GetParentPID(pid uint32) (uint32, error) {
	snapshot, err := CreateToolhelp32Snapshot()
	if err != nil {
		return 0, err
	}
	defer syscall.CloseHandle(snapshot)

	var pe PROCESSENTRY32
	if err := Process32First(snapshot, &pe); err != nil {
		return 0, err
	}

	for {
		if pe.Th32ProcessID == pid {
			return pe.Th32ParentProcessID, nil
		}
		if err := Process32Next(snapshot, &pe); err != nil {
			break
		}
	}
	return 0, fmt.Errorf("process %d not found", pid)
}

// GetProcessName 获取指定 PID 的进程名。
func GetProcessName(pid uint32) (string, error) {
	snapshot, err := CreateToolhelp32Snapshot()
	if err != nil {
		return "", err
	}
	defer syscall.CloseHandle(snapshot)

	var pe PROCESSENTRY32
	if err := Process32First(snapshot, &pe); err != nil {
		return "", err
	}

	for {
		if pe.Th32ProcessID == pid {
			return syscall.UTF16ToString(pe.ExeFile[:]), nil
		}
		if err := Process32Next(snapshot, &pe); err != nil {
			break
		}
	}
	return "", fmt.Errorf("process %d not found", pid)
}
