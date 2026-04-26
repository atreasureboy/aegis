// Package config 提供 gRPC 客户端配置管理。
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ClientConfig 存储客户端连接配置。
type ClientConfig struct {
	ServerAddr   string `json:"server_addr"`
	CertPath     string `json:"cert_path"`
	KeyPath      string `json:"key_path"`
	CACertPath   string `json:"ca_cert_path"`
	OperatorName string `json:"operator_name"`
}

// DefaultConfig 返回默认配置。
func DefaultConfig() *ClientConfig {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.TempDir()
	}
	return &ClientConfig{
		ServerAddr: "127.0.0.1:8444",
		CertPath:   filepath.Join(home, ".aegis-client", "client.crt"),
		KeyPath:    filepath.Join(home, ".aegis-client", "client.key"),
		CACertPath: filepath.Join(home, ".aegis-client", "ca.crt"),
		OperatorName: "admin",
	}
}

// LoadConfig 从配置文件加载配置。
func LoadConfig(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var cfg ClientConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return &cfg, nil
}

// Save 将配置保存到文件。
func (c *ClientConfig) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
