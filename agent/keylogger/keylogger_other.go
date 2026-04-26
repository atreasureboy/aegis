//go:build !windows

package keylogger

import "fmt"

// KeyState 非 Windows 平台 stub。
type KeyState struct{}

// NewKeylogger 创建键盘记录器（stub）。
func NewKeylogger() *KeyState {
	return &KeyState{}
}

// Start 启动键盘记录（stub）。
func (k *KeyState) Start() error {
	return fmt.Errorf("keylogger not supported on this platform")
}

// Stop 停止键盘记录（stub）。
func (k *KeyState) Stop() {}

// Dump 返回记录的按键（stub）。
func (k *KeyState) Dump() string {
	return ""
}

// Clear 清空记录（stub）。
func (k *KeyState) Clear() {}

// IsRunning 返回运行状态（stub）。
func (k *KeyState) IsRunning() bool {
	return false
}
