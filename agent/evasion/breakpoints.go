//go:build !windows || !amd64 || !cgo

// Package breakpoints 提供硬件断点引擎（非 Windows 平台 stub）。
package evasion

import (
	"fmt"
)

// Set 设置一个硬件断点（stub）。
func (e *Engine) Set(bp *HardwareBreakpoint) error {
	if bp.Index < 0 || bp.Index > 3 {
		return fmt.Errorf("invalid debug register index: %d (must be 0-3)", bp.Index)
	}
	e.breakpoints[bp.Index] = bp
	return nil
}

// Clear 清除指定索引的硬件断点。
func (e *Engine) Clear(index int) error {
	if index < 0 || index > 3 {
		return fmt.Errorf("invalid debug register index: %d (must be 0-3)", index)
	}
	e.breakpoints[index] = nil
	return nil
}

// ClearAll 清除所有硬件断点。
func (e *Engine) ClearAll() {
	for i := range e.breakpoints {
		e.breakpoints[i] = nil
	}
}

// Install 安装异常处理器（stub）。
func (e *Engine) Install() error {
	e.installed = true
	return nil
}

// Uninstall 移除异常处理器。
func (e *Engine) Uninstall() error {
	e.ClearAll()
	e.installed = false
	return nil
}

// AmsiBypass 使用硬件断点绕过 AMSI（stub）。
func AmsiBypass() error {
	engine := NewEngine()
	bp := &HardwareBreakpoint{
		Address: 0,
		Type:    BreakpointExec,
		Length:  Len1Byte,
		Index:   0,
		Handler: func() uintptr { return 0 },
	}
	_ = engine.Set(bp)
	_ = engine.Install()
	return fmt.Errorf("hardware breakpoint AMSI bypass requires Windows API implementation")
}

// ETWBypassHardwareBreakpoint 使用硬件断点绕过 ETW（stub）。
func ETWBypassHardwareBreakpoint() error {
	return fmt.Errorf("hardware breakpoint ETW bypass requires Windows API implementation")
}

// DR7Register 是 DR7 控制寄存器的位布局。
type DR7Register uint64
