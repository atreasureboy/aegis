//go:build !windows || !amd64

package credentials

import "fmt"

// SAMDumpResult is the stub for non-Windows.
type SAMDumpResult struct {
	SAMPath    string `json:"sam_path"`
	SYSTEMPath string `json:"system_path"`
	Success    bool   `json:"success"`
	Error      string `json:"error,omitempty"`
}

// DumpSAM returns error on non-Windows platforms.
func DumpSAM() (*SAMDumpResult, error) {
	return nil, fmt.Errorf("SAM dump is only supported on Windows")
}
