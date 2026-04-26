//go:build !windows || !amd64

package credentials

// ExtractFromLSASS 在非 Windows 平台上返回空结果。
func ExtractFromLSASS() (*ExtractResult, error) {
	return &ExtractResult{
		Credentials: make([]Credential, 0),
		Error:       "credential extraction from LSASS is only available on Windows",
	}, nil
}
