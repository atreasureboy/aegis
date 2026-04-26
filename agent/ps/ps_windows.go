//go:build windows

package ps

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// List 返回所有进程列表。
func List() ([]Process, error) {
	return listWindows()
}

func listWindows() ([]Process, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = windows.Process32First(snapshot, &entry)
	if err != nil {
		return nil, fmt.Errorf("Process32First: %w", err)
	}

	var procs []Process
	for {
		proc := Process{
			PID:       int(entry.ProcessID),
			PPID:      int(entry.ParentProcessID),
			Name:      utf16ToString(entry.ExeFile[:]),
			SessionID: getSessionID(entry.ProcessID),
			Arch:      getArch(entry.ProcessID),
			Memory:    getProcessMemory(entry.ProcessID),
			CommandLine: "",
		}
		procs = append(procs, proc)

		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}

	return procs, nil
}

func utf16ToString(buf []uint16) string {
	for i, v := range buf {
		if v == 0 {
			return syscall.UTF16ToString(buf[:i])
		}
	}
	return syscall.UTF16ToString(buf)
}

func getSessionID(pid uint32) int {
	var sessionID uint32
	err := windows.ProcessIdToSessionId(pid, &sessionID)
	if err != nil {
		return -1
	}
	return int(sessionID)
}

func getArch(pid uint32) string {
	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "?"
	}
	defer windows.CloseHandle(hProcess)

	var isWow64 bool
	windows.IsWow64Process(hProcess, &isWow64)
	if isWow64 {
		return "x86"
	}
	return "x64"
}

func getProcessMemory(pid uint32) int64 {
	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(hProcess)

	type procMemCounters struct {
		CB                         uint32
		PageFaultCount             uint32
		PeakWorkingSetSize         uintptr
		WorkingSetSize             uintptr
		QuotaPeakPagedPoolUsage    uintptr
		QuotaPagedPoolUsage        uintptr
		QuotaPeakNonPagedPoolUsage uintptr
		QuotaNonPagedPoolUsage     uintptr
		PagefileUsage              uint32
		PeakPagefileUsage          uint32
		PrivateUsage               uint64
	}
	var pmc procMemCounters
	pmc.CB = uint32(unsafe.Sizeof(pmc))

	ret, _, _ := syscall.NewLazyDLL("psapi.dll").NewProc("GetProcessMemoryInfo").Call(
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&pmc)),
		uintptr(pmc.CB),
	)
	if ret == 0 {
		return 0
	}
	return int64(pmc.WorkingSetSize)
}

// Kill 终止进程。
func Kill(pid int) error {
	hProcess, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(hProcess)
	return windows.TerminateProcess(hProcess, 0)
}

// === PEB/TEB 相关 ===

// PEB represents the Process Environment Block.
type PEB struct {
	InheritedAddressSpace    byte
	ReadImageFileExecOptions byte
	BeingDebugged            byte
	Spare                    byte
	Mutant                   uintptr
	ImageBaseAddress         uintptr
	Ldr                      uintptr
	ProcessParameters        uintptr
}

// getCommandLine 获取进程的命令行。
func getCommandLine(pid uint32) string {
	hProcess, err := windows.OpenProcess(windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(hProcess)

	// Read PEB → RTL_USER_PROCESS_PARAMETERS → CommandLine
	var pbi processBasicInformation
	var retLen uint32
	err = windows.NtQueryInformationProcess(hProcess, 0, unsafe.Pointer(&pbi), uint32(unsafe.Sizeof(pbi)), &retLen)
	if err != nil {
		return ""
	}

	var peb PEB
	err = windows.ReadProcessMemory(hProcess, pbi.PebBaseAddress,
		(*byte)(unsafe.Pointer(&peb)), unsafe.Sizeof(peb), nil)
	if err != nil {
		return ""
	}

	// Read CommandLine from RTL_USER_PROCESS_PARAMETERS
	type rtlUserProcParams struct {
		_           [16]byte
		_           [16]byte
		ImagePath   windows.NTUnicodeString
		CommandLine windows.NTUnicodeString
	}
	var params rtlUserProcParams
	err = windows.ReadProcessMemory(hProcess, peb.ProcessParameters,
		(*byte)(unsafe.Pointer(&params)), unsafe.Sizeof(params), nil)
	if err != nil {
		return ""
	}

	buf := make([]uint16, paramsCommandLine(params.CommandLine))
	err = windows.ReadProcessMemory(hProcess, uintptr(unsafe.Pointer(params.CommandLine.Buffer)),
		(*byte)(unsafe.Pointer(&buf[0])), uintptr(paramsCommandLine(params.CommandLine)*2), nil)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(syscall.UTF16ToString(buf))
}

func paramsCommandLine(s windows.NTUnicodeString) int {
	return int(s.Length / 2)
}

// processBasicInformation 对应 PROCESS_BASIC_INFORMATION。
type processBasicInformation struct {
	ExitStatus                   int32
	PebBaseAddress               uintptr
	AffinityMask                 uintptr
	BasePriority                 int32
	UniqueProcessID              uintptr
	InheritedFromUniqueProcessID uintptr
}

// GetProcessCmdLine 获取指定 PID 的命令行。
func GetProcessCmdLine(pid int) string {
	return getCommandLine(uint32(pid))
}

// ReadPEB 读取进程的 PEB。
func ReadPEB(pid int) (*PEB, error) {
	hProcess, err := windows.OpenProcess(windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return nil, fmt.Errorf("OpenProcess: %w", err)
	}
	defer windows.CloseHandle(hProcess)

	var pbi processBasicInformation
	var retLen uint32
	err = windows.NtQueryInformationProcess(hProcess, 0, unsafe.Pointer(&pbi), uint32(unsafe.Sizeof(pbi)), &retLen)
	if err != nil {
		return nil, fmt.Errorf("NtQueryInformationProcess: %w", err)
	}

	var peb PEB
	err = windows.ReadProcessMemory(hProcess, pbi.PebBaseAddress,
		(*byte)(unsafe.Pointer(&peb)), unsafe.Sizeof(peb), nil)
	if err != nil {
		return nil, fmt.Errorf("ReadProcessMemory: %w", err)
	}

	return &peb, nil
}

// ReadMemoryAt 读取进程指定地址的内存。
func ReadMemoryAt(pid int, address uintptr, size uint32) ([]byte, error) {
	hProcess, err := windows.OpenProcess(windows.PROCESS_VM_READ, false, uint32(pid))
	if err != nil {
		return nil, fmt.Errorf("OpenProcess: %w", err)
	}
	defer windows.CloseHandle(hProcess)

	buf := make([]byte, size)
	err = windows.ReadProcessMemory(hProcess, address, &buf[0], uintptr(size), nil)
	if err != nil {
		return nil, fmt.Errorf("ReadProcessMemory: %w", err)
	}
	return buf, nil
}

// WriteMemoryAt 写入内存到进程指定地址。
func WriteMemoryAt(pid int, address uintptr, data []byte) error {
	hProcess, err := windows.OpenProcess(windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("OpenProcess: %w", err)
	}
	defer windows.CloseHandle(hProcess)

	err = windows.WriteProcessMemory(hProcess, address, &data[0], uintptr(len(data)), nil)
	if err != nil {
		return fmt.Errorf("WriteProcessMemory: %w", err)
	}
	return nil
}

// FindModule 在进程地址空间中查找模块。
func FindModule(pid int, moduleName string) (uintptr, error) {
	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, uint32(pid))
	if err != nil {
		return 0, fmt.Errorf("OpenProcess: %w", err)
	}
	defer windows.CloseHandle(hProcess)

	// 读取 PEB → LDR → InLoadOrderModuleList
	var pbi processBasicInformation
	var retLen uint32
	err = windows.NtQueryInformationProcess(hProcess, 0, unsafe.Pointer(&pbi), uint32(unsafe.Sizeof(pbi)), &retLen)
	if err != nil {
		return 0, fmt.Errorf("NtQueryInformationProcess: %w", err)
	}

	var peb PEB
	err = windows.ReadProcessMemory(hProcess, pbi.PebBaseAddress,
		(*byte)(unsafe.Pointer(&peb)), unsafe.Sizeof(peb), nil)
	if err != nil {
		return 0, fmt.Errorf("ReadProcessMemory(PEB): %w", err)
	}

	// LDR: PEB.Ldr 指向 PEB_LDR_DATA
	// PEB_LDR_DATA.InLoadOrderModuleList → LIST_ENTRY → LDR_DATA_TABLE_ENTRY
	type listEntry struct {
		Flink uintptr
		Blink uintptr
	}

	var ldr listEntry
	err = windows.ReadProcessMemory(hProcess, peb.Ldr,
		(*byte)(unsafe.Pointer(&ldr)), unsafe.Sizeof(ldr), nil)
	if err != nil {
		return 0, fmt.Errorf("ReadProcessMemory(LDR): %w", err)
	}

	// 遍历 InLoadOrderModuleList 链表
	// Windows x64 LDR_DATA_TABLE_ENTRY 正确布局：
	//   0x00: InLoadOrderLinks (LIST_ENTRY, 16 bytes)
	//   0x10: InMemoryOrderLinks (LIST_ENTRY)
	//   0x20: InInitializationOrderLinks (LIST_ENTRY)
	//   0x30: DllBase (PVOID)
	//   0x38: EntryPoint (PVOID)
	//   0x40: SizeOfImage (ULONG)
	//   0x44: Reserved2 (PVOID)
	//   0x48: HashLinks (LIST_ENTRY)
	//   0x58: FullDllName (UNICODE_STRING)
	//   0x68: BaseDllName (UNICODE_STRING)
	type ldrDataTableEntry struct {
		InLoadOrderLinks         listEntry
		InMemoryOrderLinks       listEntry
		InInitializationOrderLinks listEntry
		DllBase                  uintptr
		EntryPoint               uintptr
		SizeOfImage              uint32
		_                        uint32 // Reserved2
		_                        listEntry // HashLinks
		_                        [8]byte   // DllBaseOriginalHash (8)
		LoadCount                uint16
		_                        uint16 // OSMajorVersion
		_                        uint32 // Flags
		FullDllName              windows.NTUnicodeString
		BaseDllName              windows.NTUnicodeString
	}

	entryAddr := ldr.Flink
	for i := 0; i < 256; i++ { // 防止无限循环
		var entry ldrDataTableEntry
		err = windows.ReadProcessMemory(hProcess, entryAddr,
			(*byte)(unsafe.Pointer(&entry)), unsafe.Sizeof(entry), nil)
		if err != nil {
			break
		}

		// 读取模块名
		if entry.BaseDllName.Length > 0 {
			nameBuf := make([]uint16, entry.BaseDllName.Length/2)
			err = windows.ReadProcessMemory(hProcess, uintptr(unsafe.Pointer(entry.BaseDllName.Buffer)),
				(*byte)(unsafe.Pointer(&nameBuf[0])), uintptr(entry.BaseDllName.Length), nil)
			if err == nil {
				name := syscall.UTF16ToString(nameBuf)
				if strings.EqualFold(name, moduleName) {
					return entry.DllBase, nil
				}
			}
		}

		// 移动到下一个
		nextAddr := entry.InLoadOrderLinks.Flink
		if nextAddr == ldr.Flink {
			break
		}
		entryAddr = nextAddr
	}

	return 0, fmt.Errorf("module %s not found in PID %d", moduleName, pid)
}
