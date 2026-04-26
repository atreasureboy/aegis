//go:build windows && amd64

package syscall

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	imageDOSHeaderSig        = 0x5A4D // MZ
	imageNTHeaderSig         = 0x00004550
	imageDirEntryExport      = 0
)


// ptrFromUintptr converts a uintptr to unsafe.Pointer.
// Safe when the uintptr is a valid module handle.
//
//go:nosplit
func ptrFromUintptr(u uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&u))
}

// ResolveNtdll 从内存中已加载的 ntdll.dll 解析所有 Nt* 函数的 syscall 编号。
//
// 实现步骤：
// 1. LoadLibrary("ntdll.dll") 获取模块基址（已加载则 refcount++）
// 2. 手动解析 PE 导出表
// 3. 扫描每个 Nt* 函数的 stub，识别 "mov eax, SSN" 指令 (B8 xx xx xx xx)
// 4. 提取 4 字节立即数作为 syscall number
func (t *SyscallTable) ResolveNtdll() error {
	mod, err := windows.LoadLibraryEx("ntdll.dll", 0, windows.DONT_RESOLVE_DLL_REFERENCES)
	if err != nil {
		mod, err = windows.LoadLibrary("ntdll.dll")
		if err != nil {
			return fmt.Errorf("failed to load ntdll.dll: %w", err)
		}
	}

	base := ptrFromUintptr(uintptr(mod))

	// 1. 验证 DOS Header
	dosHeader := (*imageDosHeader)(base)
	if dosHeader.Signature != imageDOSHeaderSig {
		return fmt.Errorf("invalid DOS signature at ntdll.dll")
	}

	ntSig := binary.LittleEndian.Uint32(
		unsafe.Slice((*byte)(unsafe.Add(base, uintptr(dosHeader.Lfanew))), 4),
	)
	if ntSig != imageNTHeaderSig {
		return fmt.Errorf("invalid NT signature")
	}

	// 2. 定位导出目录
	// NT Headers 布局:
	//   +0: Signature (4 bytes)
	//   +4: IMAGE_FILE_HEADER (20 bytes)
	//   +24: IMAGE_OPTIONAL_HEADER64
	//     DataDirectory[0] = 导出目录，位于 OptionalHeader + 96
	dirBytes := unsafe.Slice((*byte)(unsafe.Add(base, uintptr(dosHeader.Lfanew)+120)), 8)

	exportRVA := binary.LittleEndian.Uint32(dirBytes[0:4])
	if exportRVA == 0 {
		return fmt.Errorf("ntdll.dll has no export directory")
	}

	exportDir := (*imageExportDirectory)(unsafe.Add(base, exportRVA))

	// 3. 遍历导出函数名
	names := unsafe.Slice(
		(*uint32)(unsafe.Add(base, exportDir.AddressOfNames)),
		exportDir.NumberOfNames,
	)
	ordinals := unsafe.Slice(
		(*uint16)(unsafe.Add(base, exportDir.AddressOfNameOrdinals)),
		exportDir.NumberOfNames,
	)
	functions := unsafe.Slice(
		(*uint32)(unsafe.Add(base, exportDir.AddressOfFunctions)),
		exportDir.NumberOfFunctions,
	)

	count := 0
	for i := uint32(0); i < exportDir.NumberOfNames; i++ {
		nameRVA := names[i]
		namePtr := (*byte)(unsafe.Add(base, nameRVA))
		nameBytes := unsafe.Slice(namePtr, 256)

		nameLen := 0
		for nameLen < len(nameBytes) && nameBytes[nameLen] != 0 {
			nameLen++
		}
		funcName := string(nameBytes[:nameLen])

		if !strings.HasPrefix(funcName, "Nt") {
			continue
		}

		ordinal := ordinals[i]
		funcRVA := functions[ordinal]
		funcAddr := unsafe.Add(base, funcRVA)
		funcBytes := unsafe.Slice((*byte)(funcAddr), 16)

		ssn := extractSSN(funcBytes)
		if ssn != 0 {
			t.entries[funcName] = ssn
			count++
		}
	}

	// 如果解析失败或数量过少，使用已知列表 fallback
	if count < 10 {
		for name, num := range KnownSyscalls {
			if _, ok := t.entries[name]; !ok {
				t.entries[name] = num
			}
		}
	}

	return nil
}

// extractSSN 从 ntdll.dll 函数 stub 中提取 syscall number。
//
// Windows 10/11 x64 的 Nt* stub 格式：
//
//	mov r10, rcx          ; 4C 8B D1
//	mov eax, <SSN>        ; B8 ?? ?? ?? ??  ← 提取这个
//	test byte ptr [...], 1 ; 可选
//	jne ...               ; 可选
//	syscall               ; 0F 05
//	ret                   ; C3
func extractSSN(buf []byte) uint32 {
	// N-P1-11: Verify "mov r10, rcx" (4C 8B D1) prefix before extracting SSN.
	// Windows 10/11 x64 Nt* stubs always start with this instruction.
	// This prevents false positives from random 0xB8 bytes in the stub.
	for i := 0; i < len(buf)-8; i++ {
		if i+3 <= len(buf)-8 && buf[i] == 0x4C && buf[i+1] == 0x8B && buf[i+2] == 0xD1 {
			// mov r10, rcx found, next instruction should be mov eax, imm32 (B8 xx xx xx xx)
			if i+4 < len(buf) && buf[i+3] == 0xB8 {
				return binary.LittleEndian.Uint32(buf[i+4 : i+8])
			}
		}
	}
	return 0
}

// PE 结构体定义

type imageDosHeader struct {
	Signature uint16
	_         [29]uint16
	Lfanew    int32
}

type imageExportDirectory struct {
	_                     [2]uint32
	_                     uint32
	_                     [2]uint16
	_                     [2]uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
}
