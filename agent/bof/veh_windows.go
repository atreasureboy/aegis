//go:build windows && amd64

package bof

/*
#include <windows.h>
#include <setjmp.h>

// bof_crash_info 记录 BOF 崩溃信息，供 Go 层上报服务器。
typedef struct {
    unsigned long exception_code;
    void*         exception_address;
    void*         rip;
} bof_crash_info;

static bof_crash_info g_crash_info = {0};
static PVOID          g_ve_handler  = NULL;
static jmp_buf        g_recovery;

// VEH 回调：BOF 崩溃时捕获异常，记录信息并跳转到恢复点。
static LONG WINAPI veh_bof_handler(PEXCEPTION_POINTERS ex) {
    g_crash_info.exception_code   = ex->ExceptionRecord->ExceptionCode;
    g_crash_info.exception_address = ex->ExceptionRecord->ExceptionAddress;
#if _WIN64
    g_crash_info.rip = (void*)ex->ContextRecord->Rip;
#else
    g_crash_info.rip = (void*)ex->ContextRecord->Eip;
#endif
    longjmp(g_recovery, 1);
    return EXCEPTION_CONTINUE_EXECUTION; // never reached
}

// veh_register 注册 VEH 处理器。
__declspec(dllexport) int veh_register(void) {
    g_ve_handler = AddVectoredExceptionHandler(1, veh_bof_handler);
    return (g_ve_handler != NULL) ? 0 : -1;
}

// veh_unregister 移除 VEH 处理器。
__declspec(dllexport) void veh_unregister(void) {
    if (g_ve_handler) {
        RemoveVectoredExceptionHandler(g_ve_handler);
        g_ve_handler = NULL;
    }
}

// bof_call_safe 在 VEH 保护下调用 BOF 入口。
__declspec(dllexport) int bof_call_safe(LPVOID entry, char* args, int args_len) {
    if (setjmp(g_recovery) != 0) {
        // VEH 已捕获崩溃，返回非零值通知调用者
        return -1;
    }
    // 正常调用路径
    void (*fn)(char*, int) = (void(*)(char*, int))entry;
    fn(args, args_len);
    return 0;
}

// veh_get_crash_info 返回最近一次崩溃信息。
__declspec(dllexport) bof_crash_info* veh_get_crash_info(void) {
    return &g_crash_info;
}

// veh_crash_code 返回异常代码。
__declspec(dllexport) unsigned long veh_crash_code(void) {
    return g_crash_info.exception_code;
}

// veh_crash_addr 返回异常地址。
__declspec(dllexport) void* veh_crash_addr(void) {
    return g_crash_info.exception_address;
}

// veh_crash_rip 返回 RIP。
__declspec(dllexport) void* veh_crash_rip(void) {
    return g_crash_info.rip;
}
*/
import "C"
import "unsafe"

// VEHCatch 存储 VEH 捕获的崩溃信息。
type VEHCatch struct {
	ExceptionCode    uint32
	ExceptionAddress uintptr
	RIP              uintptr
}

// vehRegister 注册 VEH 异常处理器。
func vehRegister() error {
	ret := C.veh_register()
	if ret != 0 {
		return ErrVEHRegister
	}
	return nil
}

// vehUnregister 移除 VEH 异常处理器。
func vehUnregister() {
	C.veh_unregister()
}

// vehGetCrashInfo 获取最近一次 BOF 崩溃信息。
func vehGetCrashInfo() VEHCatch {
	return VEHCatch{
		ExceptionCode:    uint32(C.veh_crash_code()),
		ExceptionAddress: uintptr(C.veh_crash_addr()),
		RIP:              uintptr(C.veh_crash_rip()),
	}
}

// bofCallSafe 在 VEH 保护下执行 BOF 入口。返回 true 表示崩溃被捕获。
func bofCallSafe(entry uintptr, args *byte, argsLen int) (crashed bool) {
	ret := C.bof_call_safe(
		C.LPVOID(ptrFromUintptr(entry)),
		(*C.char)(unsafe.Pointer(args)),
		C.int(argsLen),
	)
	return ret != 0
}
