//go:build (!windows || !amd64) || (!cgo && windows && amd64)

package bof

import "fmt"

// ExecuteBOF 加载并执行 BOF（非 Windows 平台 stub）。
func ExecuteBOF(data []byte, entryPoint string, args []byte, apis map[string]uint64) (stdout []byte, stderr []byte, err error) {
	return nil, nil, fmt.Errorf("BOF execution requires Windows amd64 platform")
}
