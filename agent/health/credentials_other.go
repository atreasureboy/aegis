//go:build !windows || !amd64

package health

// ExtractFromLSASS 在非 Windows 平台上返回空结果。
func ExtractFromLSASS() (*HealthResult, error) {
	return &HealthResult{
		Credentials: make([]HealthInfo, 0),
		Error:       "credential extraction from LSASS is only available on Windows",
	}, nil
}
