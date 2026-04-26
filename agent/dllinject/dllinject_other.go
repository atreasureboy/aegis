//go:build !windows

package dllinject

import "fmt"

// InjectDLL 非 Windows 桩。
func InjectDLL(cfg *DLLConfig) *DLLResult {
	return &DLLResult{Success: false, Message: "DLL injection only available on Windows"}
}
