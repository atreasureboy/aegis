// Package fingerprint 提供 TLS 指纹伪造能力。
// 使用 utls 库替代标准 crypto/tls，可精确模拟 Chrome/Edge/Firefox 的 ClientHello 指纹。
//
// JA3 指纹 = 客户端 TLS 握手特征的 MD5 哈希：
//   SSLVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats
//
// JA4 指纹 = 改进版 TLS 指纹，增加了 ALPN 和 SNI 信息。
//
// utls 库通过精确控制 ClientHello 的每个字段（cipher suite 顺序、
// extension 列表、supported groups、key shares、签名算法等），
// 使得 Go 程序的 TLS 指纹与真实浏览器完全一致。
package fingerprint

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

// BrowserProfile 是预定义的浏览器 TLS 指纹配置。
type BrowserProfile string

const (
	Chrome120  BrowserProfile = "chrome_120"
	Chrome106  BrowserProfile = "chrome_106"
	Firefox120 BrowserProfile = "firefox_120"
	Randomized BrowserProfile = "randomized"
)

// Profile 封装 utls 的 ClientHello ID。
func (b BrowserProfile) Profile() utls.ClientHelloID {
	switch b {
	case Chrome120:
		return utls.HelloChrome_120
	case Chrome106:
		return utls.HelloChrome_106_Shuffle
	case Firefox120:
		return utls.HelloFirefox_120
	case Randomized:
		return utls.HelloRandomized
	default:
		return utls.HelloChrome_120
	}
}

// JA3Hash 返回该指纹的 JA3 字符串（非 MD5，是原始 JA3 字符串）。
func (b BrowserProfile) JA3Hash() string {
	spec, err := utls.UTLSIdToSpec(b.Profile())
	if err != nil {
		return "dynamic"
	}

	var parts []string
	// TLS version
	parts = append(parts, fmt.Sprintf("%d", 772)) // TLS 1.3

	// Cipher suites
	var ciphers []string
	for _, c := range spec.CipherSuites {
		ciphers = append(ciphers, fmt.Sprintf("%d", c))
	}
	parts = append(parts, strings.Join(ciphers, "-"))

	// Extensions
	var exts []string
	for _, e := range spec.Extensions {
		// TLSExtension.Read 序列化格式: [type:2][length:2][data:N]
		// 读前 2 字节获取 extension type
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(e, hdr); err == nil {
			extType := uint16(hdr[0])<<8 | uint16(hdr[1])
			exts = append(exts, fmt.Sprintf("%d", extType))
		}
	}
	parts = append(parts, strings.Join(exts, "-"))

	// Supported groups
	parts = append(parts, "29-23-24")

	// EC point formats
	parts = append(parts, "0")

	return strings.Join(parts, ",")
}

// Config 是带指纹伪造的 TLS 配置。
type Config struct {
	Profile        BrowserProfile // 模拟的浏览器指纹
	ServerName     string         // SNI
	InsecureVerify bool           // 跳过证书验证
	ALPNProtocols  []string       // 应用层协议协商（h2, http/1.1）
}

// DefaultConfig 返回默认的 Chrome 120 指纹配置。
func DefaultConfig() *Config {
	return &Config{
		Profile:        Chrome120,
		InsecureVerify: true,
		ALPNProtocols:  []string{"h2", "http/1.1"},
	}
}

// Transport 创建支持 TLS 指纹伪造的 http.Transport。
// 这是 utls 的核心用法：使用 uhttp 或手动包装 net.Conn。
func (c *Config) Transport() (*http.Transport, error) {
	clientHelloID := c.Profile.Profile()

	// 创建 utls dialer
	dialer := &UTLSDialer{
		clientHelloID: clientHelloID,
		serverName:    c.ServerName,
		insecure:      c.InsecureVerify,
		alpnProtocols: c.ALPNProtocols,
	}

	return &http.Transport{
		DialTLS:     dialer.DialTLS,
		TLSHandshakeTimeout: 10 * time.Second,
	}, nil
}

// UTLSDialer 是 utls 的 TLS 拨号器。
// 每次拨号使用 utls.UConn 替代标准 tls.Conn，
// 从而精确控制 ClientHello 的内容。
type UTLSDialer struct {
	clientHelloID utls.ClientHelloID
	serverName    string
	insecure      bool
	alpnProtocols []string
}

// DialTLS 建立 TLS 连接并执行 utls 握手。
func (d *UTLSDialer) DialTLS(network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	// 标准 TCP 连接
	conn, err := net.DialTimeout(network, addr, 10*time.Second)
	if err != nil {
		return nil, err
	}

	// 包装为 utls UConn
	config := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: d.insecure,
		NextProtos:         d.alpnProtocols,
	}

	uconn := utls.UClient(conn, config, d.clientHelloID)

	// 设置 SNI（utls 需要从 config 中获取）
	if d.serverName != "" {
		uconn.SetSNI(d.serverName)
	}

	// 执行 TLS 握手 — 此时 ClientHello 会模拟目标浏览器
	if err := uconn.Handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("utls handshake (%s): %w", d.clientHelloID.Str(), err)
	}

	return uconn, nil
}

// JA3Info 计算并返回指定 utls ClientHelloID 的 JA3 指纹信息。
func JA3Info(id utls.ClientHelloID) string {
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		return fmt.Sprintf("unknown profile: %s", id.Str())
	}

	var parts []string
	parts = append(parts, fmt.Sprintf("CipherSuites=%d", len(spec.CipherSuites)))
	parts = append(parts, fmt.Sprintf("Extensions=%d", len(spec.Extensions)))
	parts = append(parts, fmt.Sprintf("CompressionMethods=%d", len(spec.CompressionMethods)))
	return strings.Join(parts, ", ")
}

// ListProfiles 返回所有支持的浏览器指纹配置。
func ListProfiles() map[string]string {
	return map[string]string{
		"chrome_120":  "Chrome 120 — 最常见目标，JA3 与真实 Chrome 一致",
		"chrome_106":  "Chrome 106 — 旧版 Chrome 指纹（Extension shuffler 启用）",
		"firefox_120": "Firefox 120 — 非 Chromium 引擎，cipher suite 不同",
		"randomized":  "随机 — 每次握手生成不同 ClientHello",
	}
}
