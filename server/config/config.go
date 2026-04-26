package config

import "os"

// ServerConfig 是服务端的全局配置。
type ServerConfig struct {
	ListenAddr         string               `yaml:"listen_addr"`
	CertFile           string               `yaml:"cert_file"`
	KeyFile            string               `yaml:"key_file"`
	HeartbeatInterval  int                  `yaml:"heartbeat_interval_sec"`
	MaxTasksPerMinute  int                  `yaml:"max_tasks_per_minute"`
	MaxConcurrentTasks int                  `yaml:"max_concurrent_tasks"`
	TaskTimeoutSec     int                  `yaml:"task_timeout_sec"`
	AcademicMode       bool                 `yaml:"academic_mode"`
	AllowedCommands    []string             `yaml:"allowed_commands"`
	BlockedCommands    []string             `yaml:"blocked_commands"`
	Whitelist          WhitelistConfig      `yaml:"whitelist"`
	CircuitBreaker     CircuitBreakerConfig `yaml:"circuit_breaker"`
	APIKey             string               `yaml:"api_key"` // operator API auth key
}

// WhitelistConfig 是 IP/域名白名单配置。
type WhitelistConfig struct {
	Enabled       bool     `yaml:"enabled"`
	AllowedIPs    []string `yaml:"allowed_ips"`
	AllowedDomains []string `yaml:"allowed_domains"`
}

// CircuitBreakerConfig 是熔断器配置。
type CircuitBreakerConfig struct {
	MaxHeartbeatFailures int  `yaml:"max_heartbeat_failures"`
	MaxTasksPerMinute    int  `yaml:"max_tasks_per_minute"`
	MaxConcurrentTasks   int  `yaml:"max_concurrent_tasks"`
	TaskTimeoutSec       int  `yaml:"task_timeout_sec"`
	AnomalyDetection     bool `yaml:"anomaly_detection"`
}

// DefaultServerConfig 返回默认的服务端配置。
func DefaultServerConfig() *ServerConfig {
	addr := ":8443"
	if a := os.Getenv("AEGIS_HTTP_ADDR"); a != "" {
		addr = a
	}
	return &ServerConfig{
		ListenAddr:        addr,
		HeartbeatInterval: 10,
		MaxTasksPerMinute: 10,
		MaxConcurrentTasks:   3,
		TaskTimeoutSec:       60,
		AcademicMode:         true,
		AllowedCommands: []string{
			"whoami", "hostname", "uname", "ps", "ls", "cat",
			"netstat", "ifconfig", "ipconfig", "pwd", "date",
			"echo", "info", "process",
		},
		BlockedCommands: []string{
			"rm", "shutdown", "reboot", "format", "del",
			"net user", "mimikatz", "powershell -enc",
		},
		Whitelist: WhitelistConfig{
			Enabled: false,
			AllowedIPs: []string{
				"127.0.0.0/8",
				"10.0.0.0/8",
				"172.16.0.0/12",
				"192.168.0.0/16",
			},
		},
		CircuitBreaker: CircuitBreakerConfig{
			MaxHeartbeatFailures: 5,
			MaxTasksPerMinute:    10,
			MaxConcurrentTasks:   3,
			TaskTimeoutSec:       60,
			AnomalyDetection:     true,
		},
	}
}
