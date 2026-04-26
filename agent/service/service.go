//go:build !windows || !amd64

// Package service 提供 Windows 服务安装/管理（非 Windows 平台 stub）。
package service

import "fmt"

// Install 安装 Agent 为 Windows 服务。
func Install(config ServiceConfig) error {
	// 完整实现需要：
	// 1. OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS) → hSCM
	// 2. CreateService(hSCM,
	//      config.Name,
	//      config.DisplayName,
	//      SERVICE_ALL_ACCESS,
	//      SERVICE_WIN32_OWN_PROCESS,
	//      config.StartType,
	//      SERVICE_ERROR_NORMAL,
	//      config.BinaryPath,
	//      NULL, NULL, NULL, NULL, NULL) → hService
	// 3. ChangeServiceConfig2(hService, SERVICE_CONFIG_DESCRIPTION, &desc)
	// 4. StartService(hService, 0, NULL)
	// 5. CloseServiceHandle(hService)
	// 6. CloseServiceHandle(hSCM)

	// 面试重点解释：
	// - 服务名称应伪装为合法服务 (如 "WindowsUpdate", "Defender")
	// - 描述应与合法服务一致
	// - 二进制路径应在合法目录下 (如 C:\Windows\System32)
	return fmt.Errorf("service installation requires Windows API implementation")
}

// Uninstall 卸载服务。
func Uninstall(serviceName string) error {
	// 1. OpenSCManager → hSCM
	// 2. OpenService(hSCM, serviceName, SERVICE_ALL_ACCESS) → hService
	// 3. ControlService(hService, SERVICE_CONTROL_STOP, &status)
	// 4. DeleteService(hService)
	// 5. CloseServiceHandle(hService)
	// 6. CloseServiceHandle(hSCM)
	return fmt.Errorf("service removal requires Windows API implementation")
}

// Start 启动服务。
func Start(serviceName string) error {
	// StartService(hService, 0, NULL)
	return fmt.Errorf("service start requires Windows API implementation")
}

// Stop 停止服务。
func Stop(serviceName string) error {
	// ControlService(hService, SERVICE_CONTROL_STOP, &status)
	return fmt.Errorf("service stop requires Windows API implementation")
}

// Query 查询服务状态。
func Query(serviceName string) (string, error) {
	// QueryServiceStatus(hService, &status)
	// 返回服务状态 (running, stopped, paused, etc)
	return "", fmt.Errorf("service query requires Windows API implementation")
}

// ListServices 列出所有服务。
func ListServices() (string, error) {
	// EnumServicesStatus(hSCM, SERVICE_WIN32, SERVICE_STATE_ALL, ...)
	return "", fmt.Errorf("service listing requires Windows API implementation")
}

// CommonServiceNames 是常见的合法服务名称（用于伪装参考）。
var CommonServiceNames = []string{
	"wuauserv",      // Windows Update
	"WinDefend",     // Windows Defender
	"BITS",          // Background Intelligent Transfer
	"CryptSvc",      // Cryptographic Services
	"Dhcp",          // DHCP Client
	"Dnscache",      // DNS Client
	"LanmanServer",  // Server
	"LanmanWorkstation", // Workstation
	"TermService",   // Remote Desktop Services
}
