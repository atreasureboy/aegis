// Package breakpoints 提供硬件断点引擎类型定义（平台无关）。
package evasion

// BreakpointType 定义断点类型。
type BreakpointType uint8

const (
	BreakpointExec      BreakpointType = 0 // 执行断点
	BreakpointWrite     BreakpointType = 1 // 写入断点
	BreakpointReadWrite BreakpointType = 3 // 读写断点
)

// BreakpointLen 定义断点长度。
type BreakpointLen uint8

const (
	Len1Byte BreakpointLen = 0
	Len2Byte BreakpointLen = 1
	Len4Byte BreakpointLen = 2
	Len8Byte BreakpointLen = 3
)

// HardwareBreakpoint 描述一个硬件断点。
type HardwareBreakpoint struct {
	Address  uintptr
	Type     BreakpointType
	Length   BreakpointLen
	Index    int
	Handler  func() uintptr
}

// Engine 是硬件断点引擎。
type Engine struct {
	breakpoints [4]*HardwareBreakpoint
	installed   bool
	vehHandle   uintptr
}

// NewEngine 创建硬件断点引擎。
func NewEngine() *Engine {
	return &Engine{}
}
