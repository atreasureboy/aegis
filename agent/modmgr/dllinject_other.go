//go:build !windows

package modmgr

import "fmt"

// LoadModule 非 Windows 桩。
func LoadModule(cfg *ModConfig) *ModResult {
	return &ModResult{Success: false, Message: "DLL injection only available on Windows"}
}
