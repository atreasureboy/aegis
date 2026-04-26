// Package transport 提供 WireGuard 传输支持。
package transport

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// randInt 返回 [min, max] 范围内的随机整数。
func randInt(min, max int) int {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		return min // fallback
	}
	return min + int(n.Int64())
}

// WireGuardConfig 是 WireGuard 配置。
type WireGuardConfig struct {
	ServerPrivateKey string // 服务端私钥（base64）
	ServerPublicKey  string // 服务端公钥（base64）
	ServerListenPort int    // 监听端口 (UDP)
	ServerIP         string // 服务端 WG IP (如 "10.0.0.1")
}

// WireGuardPeerConfig 是 Agent 端的 WireGuard 配置。
type WireGuardPeerConfig struct {
	PrivateKey    string // Agent 私钥
	PublicKey     string // Agent 公钥
	ServerPubKey  string // 服务端公钥（Peer PublicKey）
	ServerIP      string // 服务端 WG IP
	AgentIP       string // Agent WG IP (如 "10.0.0.2")
	Endpoint      string // 服务端地址 (IP:Port)
	AllowedIPs    string // 允许路由的 IP 范围
}

// GenerateKeys 使用 Curve25519 生成 WireGuard 密钥对。
// WireGuard 使用 32 字节随机数作为私钥，base64 编码。
func GenerateKeys() (privateKey, publicKey string, err error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return "", "", err
	}

	// WireGuard 私钥：需要清除最高位、设置次高位等
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	privateKey = base64.StdEncoding.EncodeToString(priv[:])
	publicKey, err = publicKeyFromPrivate(priv[:])
	if err != nil {
		return "", "", err
	}
	return privateKey, publicKey, nil
}

// publicKeyFromPrivate 从 Curve25519 私钥计算公钥（纯 Go 实现，无需外部 wg 命令）。
func publicKeyFromPrivate(priv []byte) (string, error) {
	var pub, privArr [32]byte
	copy(privArr[:], priv)
	curve25519.ScalarBaseMult(&pub, &privArr)
	return base64.StdEncoding.EncodeToString(pub[:]), nil
}

// GeneratePeer 为 Agent 生成 WireGuard 密钥对。
func GeneratePeer() (*WireGuardPeerConfig, error) {
	privKey, pubKey, err := GenerateKeys()
	if err != nil {
		return nil, err
	}

	return &WireGuardPeerConfig{
		PrivateKey: privKey,
		PublicKey:  pubKey,
		AllowedIPs: "0.0.0.0/0",
	}, nil
}

// GenerateServerConfig 生成服务端配置。
func GenerateServerConfig(listenPort int) (*WireGuardConfig, error) {
	privKey, pubKey, err := GenerateKeys()
	if err != nil {
		return nil, err
	}

	return &WireGuardConfig{
		ServerPrivateKey: privKey,
		ServerPublicKey:  pubKey,
		ServerListenPort: listenPort,
		ServerIP:         "10.0.0.1",
	}, nil
}

// ServerConfigFile 生成服务端 wg-quick 配置文件。
func (c *WireGuardConfig) ServerConfigFile(peers []WireGuardPeerConfig) string {
	config := "[Interface]\n"
	config += fmt.Sprintf("PrivateKey = %s\n", c.ServerPrivateKey)
	config += fmt.Sprintf("Address = %s/24\n", c.ServerIP)
	config += fmt.Sprintf("ListenPort = %d\n\n", c.ServerListenPort)

	for i, p := range peers {
		config += fmt.Sprintf("[Peer] # Agent %d\n", i+1)
		config += fmt.Sprintf("PublicKey = %s\n", p.PublicKey)
		config += fmt.Sprintf("AllowedIPs = %s/32\n\n", p.AgentIP)
	}

	return config
}

// AgentConfigFile 生成 Agent 端 wg-quick 配置文件。
func (p *WireGuardPeerConfig) AgentConfigFile() string {
	config := "[Interface]\n"
	config += fmt.Sprintf("PrivateKey = %s\n", p.PrivateKey)
	config += fmt.Sprintf("Address = %s/24\n", p.AgentIP)
	config += "DNS = 1.1.1.1\n"
	config += "\n[Peer]\n"
	config += fmt.Sprintf("PublicKey = %s\n", p.ServerPubKey)
	config += fmt.Sprintf("Endpoint = %s\n", p.Endpoint)
	config += fmt.Sprintf("AllowedIPs = %s\n", p.AllowedIPs)
	config += "PersistentKeepalive = 25\n"
	return config
}

// SetupTunnel 通过 wg-quick 建立 WireGuard 隧道。
// 返回隧道接口名称（用于后续清理）。
func (p *WireGuardPeerConfig) SetupTunnel(configContent string) (string, error) {
	if runtime.GOOS == "windows" {
		return p.setupWindows(configContent)
	}
	return p.setupUnix(configContent)
}

func (p *WireGuardPeerConfig) setupUnix(configContent string) (string, error) {
	// 检查 wg-quick 是否存在
	if _, err := exec.LookPath("wg-quick"); err != nil {
		return "", fmt.Errorf("wg-quick not found. Install: apt install wireguard-tools (Linux) or brew install wireguard-tools (MacOS)")
	}

	// 使用合法接口名：wg-quick 要求接口名只含字母数字和短线
	ifaceName := fmt.Sprintf("aegis-%d", randInt(1000, 9999))
	tmpDir, err := os.MkdirTemp("", "wg-aegis")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	tmpFile := filepath.Join(tmpDir, ifaceName+".conf")
	if err := os.WriteFile(tmpFile, []byte(configContent), 0600); err != nil {
		return "", fmt.Errorf("write config: %w", err)
	}

	// 使用 wg-quick up 建立隧道
	cmd := exec.Command("wg-quick", "up", tmpFile)
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("wg-quick up: %s\n%s", err, string(output))
	}

	return ifaceName, nil
}

func (p *WireGuardPeerConfig) setupWindows(configContent string) (string, error) {
	// Windows 使用 wg.exe 或注册表方式
	// 方式 1: 如果有 wg.exe（WireGuard for Windows）
	if _, err := exec.LookPath("wg"); err == nil {
		tmpFile, err := os.CreateTemp("", "wg-conf-*.conf")
		if err != nil {
			return "", fmt.Errorf("create temp config: %w", err)
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.WriteString(configContent); err != nil {
			return "", fmt.Errorf("write config: %w", err)
		}
		tmpFile.Close()

		cmd := exec.Command("wg-quick", "up", tmpFile.Name())
		if output, err := cmd.CombinedOutput(); err != nil {
			return "", fmt.Errorf("wg-quick up: %s\n%s", err, string(output))
		}
		return "wg0", nil
	}

	return "", fmt.Errorf("WireGuard for Windows not installed. Download from https://www.wireguard.com/install/")
}

// TeardownTunnel 关闭 WireGuard 隧道。
func TeardownTunnel(ifaceName string) error {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("wg-quick", "down", ifaceName)
		return cmd.Run()
	}
	cmd := exec.Command("wg-quick", "down", ifaceName)
	return cmd.Run()
}

// IsAvailable 检查 WireGuard 工具是否可用。
func IsAvailable() bool {
	if runtime.GOOS == "windows" {
		_, err := exec.LookPath("wg")
		return err == nil
	}
	_, err := exec.LookPath("wg-quick")
	return err == nil
}

func (p *WireGuardPeerConfig) ServerPublicKey() string {
	if p.ServerPubKey == "" {
		// 空值表示尚未配置服务端公钥
		return ""
	}
	return p.ServerPubKey
}

// SetServerPublicKey 设置服务端公钥（用于与 ServerConfig 合并后）。
func (p *WireGuardPeerConfig) SetServerPublicKey(key string) {
	p.ServerPubKey = key
}

// Validate 检查配置是否完整。
func (p *WireGuardPeerConfig) Validate() error {
	var missing []string
	if p.PrivateKey == "" {
		missing = append(missing, "PrivateKey")
	}
	if p.ServerPubKey == "" {
		missing = append(missing, "ServerPubKey")
	}
	if p.AgentIP == "" {
		missing = append(missing, "AgentIP")
	}
	if p.Endpoint == "" {
		missing = append(missing, "Endpoint")
	}
	if len(missing) > 0 {
		return fmt.Errorf("incomplete WireGuard config: missing %s", strings.Join(missing, ", "))
	}
	return nil
}
