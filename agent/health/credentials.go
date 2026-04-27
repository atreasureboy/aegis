// Package health 提供凭据提取能力。
// 支持从 LSASS 进程内存中提取 NTLM 哈希、Kerberos 票据等信息。
package health

// HealthInfo 是提取到的凭据。
type HealthInfo struct {
	Username    string `json:"username"`
	Domain      string `json:"domain"`
	NTLMHash    string `json:"ntlm_hash,omitempty"`
	LMHash      string `json:"lm_hash,omitempty"`
	Password    string `json:"password,omitempty"`    // WDigest 明文密码
	TicketData  string `json:"ticket_data,omitempty"` // Kerberos 票据
	SourceType  string `json:"source_type"`           // "msv", "wdigest", "kerberos", "tspkg"
}

// HealthResult 是凭据提取结果。
type HealthResult struct {
	Credentials []HealthInfo `json:"credentials"`
	Error       string       `json:"error,omitempty"`
}

// ExtractResult is an alias for HealthResult (backward compatibility).
type ExtractResult = HealthResult

// Credential is an alias for HealthInfo (backward compatibility).
type Credential = HealthInfo
