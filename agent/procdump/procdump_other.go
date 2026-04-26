//go:build !windows

package procdump

import (
	"fmt"
	"os/exec"
)

// Dump 使用 /proc/PID/mem 或 gcore 转储 Linux 进程。
func Dump(pid int, outputPath string, fullMemory bool) error {
	// Try gcore first
	cmd := exec.Command("gcore", "-o", outputPath, "-p", fmt.Sprintf("%d", pid))
	if err := cmd.Run(); err == nil {
		return nil
	}
	return fmt.Errorf("Linux process dump requires gcore or /proc filesystem access")
}

// DumpLSASS 不适用 Linux。
func DumpLSASS(outputPath string) error {
	return fmt.Errorf("DumpLSASS is Windows-only")
}

// ReadMemory 在 Linux 上通过 /proc/PID/mem 读取。
func ReadMemory(pid uint32, addr uint64, size uint64) ([]byte, error) {
	return nil, fmt.Errorf("ReadMemory is Windows-only")
}

// WriteMemory 在 Linux 上通过 /proc/PID/mem 写入。
func WriteMemory(pid uint32, addr uint64, data []byte) error {
	return fmt.Errorf("WriteMemory is Windows-only")
}

// ScanMemory 在 Linux 上通过 /proc/PID/mem 扫描。
func ScanMemory(pid uint32, pattern []byte) ([]uint64, error) {
	return nil, fmt.Errorf("ScanMemory is Windows-only")
}

// QueryMemory 查询进程内存布局。
func QueryMemory(pid uint32) ([]PageResult, error) {
	return nil, fmt.Errorf("QueryMemory is Windows-only")
}

// PageResult 内存区域信息（跨平台兼容结构体）。
type PageResult struct {
	BaseAddress    uint64
	RegionSize     uint64
	AllocationProtect uint32
	Protect        uint32
	State          uint32
	Type           uint32
}
