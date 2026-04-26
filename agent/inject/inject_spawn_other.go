//go:build !windows || !amd64 || !cgo

package inject

// InjectWithSpawn 在非 Windows 平台不可用。
func InjectWithSpawn(cfg *SpawnConfig) *InjectResult {
	return &InjectResult{
		Success: false,
		Message: "spawn injection requires Windows with CGO",
	}
}
