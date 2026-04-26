//go:build windows && amd64 && cgo

package lateral

/*
#cgo LDFLAGS: -lole32 -loleaut32 -lwbemuuid

#include <windows.h>
#include <wbemcli.h>
#include <stdio.h>
#include <stdlib.h>

// WMIExec 通过 WMI 在远程机器上执行命令。
// 原理：COM + IWbemServices → Win32_Process.Create
// 比 PsExec 更隐蔽：不创建服务，只创建临时进程。
//
// 返回：创建的进程 PID，失败返回 0。
int wmi_exec(const wchar_t* target,
             const wchar_t* username,
             const wchar_t* password,
             const wchar_t* command,
             unsigned int* outPID) {
    HRESULT hr;
    IWbemLocator* pLocator = NULL;
    IWbemServices* pServices = NULL;

    // 1. 初始化 COM — 追踪是否由我们初始化
    int comInitialized = 0;
    hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        return -1;
    }
    if (hr != RPC_E_CHANGED_MODE) {
        comInitialized = 1;
    }

    hr = CoInitializeSecurity(NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE, NULL);
    // RPC_E_TOO_LATE is OK if already called
    if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
        if (comInitialized) CoUninitialize();
        return -2;
    }

    // 2. 创建 WbemLocator
    hr = CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
        &IID_IWbemLocator, (LPVOID*)&pLocator);
    if (FAILED(hr)) {
        if (comInitialized) CoUninitialize();
        return -3;
    }

    // 3. 构建连接字符串: \\TARGET\root\cimv2
    wchar_t serverName[512];
    swprintf(serverName, 512, L"\\\\%s\\root\\cimv2", target);

    // 4. 连接到远程 WMI
    BSTR bstrServer = SysAllocString(serverName);
    BSTR bstrUser = NULL;
    BSTR bstrPass = NULL;

    if (username && username[0]) {
        bstrUser = SysAllocString(username);
    }
    if (password && password[0]) {
        bstrPass = SysAllocString(password);
    }

    hr = pLocator->lpVtbl->ConnectServer(pLocator,
        bstrServer,
        bstrUser,    // username (NULL = current user)
        bstrPass,    // password
        NULL,        // locale
        0,           // flags
        NULL,        // authority
        NULL,        // context
        &pServices);

    if (bstrUser) SysFreeString(bstrUser);
    if (bstrPass) SysFreeString(bstrPass);
    SysFreeString(bstrServer);

    if (FAILED(hr)) {
        pLocator->lpVtbl->Release(pLocator);
        if (comInitialized) CoUninitialize();
        return -4;
    }

    pLocator->lpVtbl->Release(pLocator);

    // 5. 设置代理认证 (need IUnknown* cast)
    hr = CoSetProxyBlanket((IUnknown*)pServices,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE);
    if (FAILED(hr)) {
        pServices->lpVtbl->Release(pServices);
        if (comInitialized) CoUninitialize();
        return -5;
    }

    // 6. 获取 Win32_Process 类 (call GetObjectW via vtable index — MinGW header lacks it)
    BSTR bstrClass = SysAllocString(L"Win32_Process");
    BSTR bstrMethod = SysAllocString(L"Create");
    IWbemClassObject* pClass = NULL;
    IWbemClassObject* pInParams = NULL;
    IWbemClassObject* pOutParams = NULL;

    // IWbemServices::GetObjectW is at vtable index 16
    typedef HRESULT (WINAPI *GetObjectW_t)(IWbemServices*, BSTR, LONG, IWbemContext*, IWbemClassObject**, IWbemCallResult**);
    GetObjectW_t pGetObjectW = (GetObjectW_t)((void**)pServices->lpVtbl)[16];
    hr = pGetObjectW(pServices, bstrClass, 0, NULL, &pClass, NULL);
    SysFreeString(bstrClass);
    if (FAILED(hr)) {
        pServices->lpVtbl->Release(pServices);
        if (comInitialized) CoUninitialize();
        return -6;
    }

    // 7. 获取 Create 方法的输入参数定义
    hr = pClass->lpVtbl->GetMethod(pClass, bstrMethod, 0, &pInParams, NULL);
    SysFreeString(bstrMethod);
    pClass->lpVtbl->Release(pClass);
    if (FAILED(hr)) {
        pServices->lpVtbl->Release(pServices);
        if (comInitialized) CoUninitialize();
        return -7;
    }

    // 8. 创建输入参数实例并设置 CommandLine
    hr = pInParams->lpVtbl->SpawnInstance(pInParams, 0, &pOutParams);
    if (FAILED(hr)) {
        pInParams->lpVtbl->Release(pInParams);
        pServices->lpVtbl->Release(pServices);
        if (comInitialized) CoUninitialize();
        return -8;
    }

    // 设置 CommandLine 参数
    BSTR bstrCmdLine = SysAllocString(L"CommandLine");
    VARIANT varCommand;
    VariantInit(&varCommand);
    varCommand.vt = VT_BSTR;
    varCommand.bstrVal = SysAllocString(command);

    hr = pOutParams->lpVtbl->Put(pOutParams, bstrCmdLine, 0, &varCommand, 0);
    SysFreeString(bstrCmdLine);
    VariantClear(&varCommand);
    pInParams->lpVtbl->Release(pInParams);

    if (FAILED(hr)) {
        pOutParams->lpVtbl->Release(pOutParams);
        pServices->lpVtbl->Release(pServices);
        if (comInitialized) CoUninitialize();
        return -9;
    }

    // 9. 执行 Win32_Process.Create (ExecMethod via vtable index 23)
    BSTR bstrExecMethod = SysAllocString(L"Win32_Process");
    BSTR bstrCreateMethod = SysAllocString(L"Create");
    IWbemClassObject* pResult = NULL;

    typedef HRESULT (WINAPI *ExecMethod_t)(IWbemServices*, BSTR, BSTR, LONG, IWbemContext*, IWbemClassObject*, IWbemClassObject**, IWbemCallResult**);
    ExecMethod_t pExecMethod = (ExecMethod_t)((void**)pServices->lpVtbl)[23];
    hr = pExecMethod(pServices,
        bstrExecMethod,
        bstrCreateMethod,
        0, NULL,
        pOutParams,
        &pResult, NULL);

    SysFreeString(bstrExecMethod);
    SysFreeString(bstrCreateMethod);
    pOutParams->lpVtbl->Release(pOutParams);

    if (FAILED(hr)) {
        pServices->lpVtbl->Release(pServices);
        if (comInitialized) CoUninitialize();
        return -10;
    }

    // 10. 获取返回值（检查 WMI 调用是否成功，不作为 PID）
    VARIANT varReturnValue;
    VariantInit(&varReturnValue);
    BSTR bstrRet = SysAllocString(L"ReturnValue");
    hr = pResult->lpVtbl->Get(pResult, bstrRet, 0, &varReturnValue, NULL, 0);
    SysFreeString(bstrRet);

    // ReturnValue 非零表示 WMI 方法调用失败（如权限不足、路径无效等）
    if (SUCCEEDED(hr)) {
        unsigned int retCode = 0;
        if (varReturnValue.vt == VT_UINT) {
            retCode = varReturnValue.uintVal;
        } else if (varReturnValue.vt == VT_UI4) {
            retCode = varReturnValue.ulVal;
        } else if (varReturnValue.vt == VT_I4) {
            retCode = (unsigned int)varReturnValue.lVal;
        }
        if (retCode != 0) {
            // WMI Create 返回非零错误码，不是 PID
            VariantClear(&varReturnValue);
            pResult->lpVtbl->Release(pResult);
            pServices->lpVtbl->Release(pServices);
            if (comInitialized) CoUninitialize();
            return -10;
        }
    }
    VariantClear(&varReturnValue);

    // 获取 ProcessId（真正的 PID 来源）
    BSTR bstrPid = SysAllocString(L"ProcessId");
    VARIANT varPid;
    VariantInit(&varPid);
    hr = pResult->lpVtbl->Get(pResult, bstrPid, 0, &varPid, NULL, 0);
    SysFreeString(bstrPid);

    if (SUCCEEDED(hr)) {
        if (varPid.vt == VT_UI4) {
            *outPID = varPid.ulVal;
        } else if (varPid.vt == VT_I4) {
            *outPID = (unsigned int)varPid.lVal;
        }
        VariantClear(&varPid);
    }

    pResult->lpVtbl->Release(pResult);
    pServices->lpVtbl->Release(pServices);
    if (comInitialized) CoUninitialize();

    return 0;
}

*/
import "C"

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

// WMIExec 通过 WMI 在远程机器上执行命令。
//
// 参数：
//   - target:   目标机器名或 IP（如 "192.168.1.100"）
//   - username: 用户名（如 "DOMAIN\\Administrator"，空 = 当前用户）
//   - password: 密码（空 = 当前凭据）
//   - command:  要执行的命令
//
// 返回：创建的进程 PID。
//
// 与 PsExec 的区别：
//   - PsExec: 在目标上创建 PSEXESVC 服务（持久痕迹）
//   - WMI: 只创建临时进程，无服务注册
func WMIExec(target, username, password, command string) (uint32, error) {
	targetW, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return 0, fmt.Errorf("encode target: %w", err)
	}
	userW, err := syscall.UTF16PtrFromString(username)
	if err != nil {
		return 0, fmt.Errorf("encode username: %w", err)
	}
	passW, err := syscall.UTF16PtrFromString(password)
	if err != nil {
		return 0, fmt.Errorf("encode password: %w", err)
	}
	cmdW, err := syscall.UTF16PtrFromString(command)
	if err != nil {
		return 0, fmt.Errorf("encode command: %w", err)
	}

	var outPID C.uint

	// Handle empty username/password
	var userPtr, passPtr *C.wchar_t
	if username != "" {
		userPtr = (*C.wchar_t)(unsafe.Pointer(userW))
	}
	if password != "" {
		passPtr = (*C.wchar_t)(unsafe.Pointer(passW))
	}

	ret := C.wmi_exec(
		(*C.wchar_t)(unsafe.Pointer(targetW)),
		userPtr,
		passPtr,
		(*C.wchar_t)(unsafe.Pointer(cmdW)),
		&outPID,
	)

	if ret != 0 {
		return 0, fmt.Errorf("WMIExec failed: code=%d (%s)", int(ret), wmiErrorString(int(ret)))
	}

	return uint32(outPID), nil
}

func wmiErrorString(code int) string {
	switch code {
	case -1:
		return "CoInitializeEx failed"
	case -2:
		return "CoInitializeSecurity failed"
	case -3:
		return "CoCreateInstance IWbemLocator failed"
	case -4:
		return "ConnectServer failed (check credentials and target)"
	case -5:
		return "CoSetProxyBlanket failed"
	case -6:
		return "GetObject Win32_Process failed"
	case -7:
		return "GetMethod Create failed"
	case -8:
		return "SpawnInstance failed"
	case -9:
		return "Put CommandLine failed"
	case -10:
		return "ExecMethod Create failed"
	default:
		return fmt.Sprintf("unknown error code %d", code)
	}
}

// WMIExecSimple 简化版 WMI 远程执行（使用当前用户凭据）。
func WMIExecSimple(target, command string) (uint32, error) {
	return WMIExec(target, "", "", command)
}

// WMICheck 测试是否可以连接到目标机器的 WMI 服务。
func WMICheck(target, username, password string) error {
	_, err := WMIExec(target, username, password, "cmd.exe /C echo test")
	if err != nil && strings.Contains(err.Error(), "code=-4") {
		return fmt.Errorf("cannot connect to WMI on %s: authentication or network issue", target)
	}
	return err
}
