//go:build !windows || !amd64 || !cgo

package loader

// LoadWithSpawn 在非 Windows 平台不可用。
func LoadWithSpawn(cfg *SpawnConfig) *LoadResult {
	return &LoadResult{
		Success: false,
		Message: "spawn injection requires Windows with CGO",
	}
}
