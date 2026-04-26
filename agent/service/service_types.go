// Package service 提供 Windows 服务安装/管理。
package service

// ServiceConfig 是 Windows 服务配置。
type ServiceConfig struct {
	Name        string // 服务名称 (如 "AegisUpdate")
	DisplayName string // 显示名称 (如 "Windows Update Helper")
	Description string // 服务描述
	BinaryPath  string // Agent 可执行文件路径
	StartType   uint32 // 启动类型 (AUTO_START, DEMAND_START)
}
