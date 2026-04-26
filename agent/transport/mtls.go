// Package mtls 提供 mTLS (Mutual TLS) 传输支持。
// 借鉴 Sliver 的 mTLS listener — 双向 TLS 认证，只有持有合法证书的 Agent 才能连接。
//
// 面试要点：
// 1. 普通 HTTPS 只验证服务器证书（单向认证）
// 2. mTLS 同时验证客户端和服务器证书（双向认证）
// 3. 每个 Agent 持有独立的客户端证书，被吊销后即无法连接
// 4. EDR 检测：mTLS 流量特征（TLS 握手指纹、证书链分析）
// 5. 防御优势：即使通信被截获，没有客户端证书也无法伪装为合法 Agent
package transport

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"io"
	"net"
	"time"
)

// CertPair 是一对证书（CA + 客户端/服务端）。
type CertPair struct {
	CertPEM  []byte
	KeyPEM   []byte
	CertDER  []byte
	KeyDER   []byte
}

// CACert 是 CA 证书（用于签发客户端/服务端证书）。
type CACert struct {
	Cert    *x509.Certificate
	CertPEM []byte
	Key     *rsa.PrivateKey
	KeyPEM  []byte
}

// GenerateCA 生成自签名 CA 证书。
// 用于签发所有 Agent 的客户端证书和服务端的服务器证书。
func GenerateCA() (*CACert, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate RSA key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate cert serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Aegis C2"},
			CommonName:   "Aegis CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return &CACert{
		Cert:    template,
		CertPEM: certPEM,
		Key:     key,
		KeyPEM:  keyPEM,
	}, nil
}

// GenerateClientCert 使用 CA 签发 Agent 客户端证书。
func (ca *CACert) GenerateClientCert(agentID string) (*CertPair, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate RSA key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate cert serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Aegis C2"},
			CommonName:   fmt.Sprintf("agent-%s", agentID),
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	return &CertPair{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
		CertDER: certDER,
		KeyDER:  x509.MarshalPKCS1PrivateKey(key),
	}, nil
}

// GenerateServerCert 使用 CA 签发服务端证书。
func (ca *CACert) GenerateServerCert(hostnames []string) (*CertPair, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate RSA key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate cert serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Aegis C2"},
			CommonName:   "Aegis Server",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    hostnames,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	return &CertPair{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
		CertDER: certDER,
		KeyDER:  x509.MarshalPKCS1PrivateKey(key),
	}, nil
}

// TLSConfig 是 mTLS 的 TLS 配置。
type TLSConfig struct {
	Port     int
	CACert   *CACert
	SrvCert  *CertPair
	CertPool *x509.CertPool
}

// NewServerTLSConfig 创建 mTLS 服务端的 tls.Config。
// 要求客户端提供有效证书（ClientAuth: RequireAndVerifyClientCert）。
func NewServerTLSConfig(ca *CACert, srvCert *CertPair) *tls.Config {
	certPool := x509.NewCertPool()
	certPool.AddCert(ca.Cert)

	srvTLS, err := tls.X509KeyPair(srvCert.CertPEM, srvCert.KeyPEM)
	if err != nil {
		return nil // Caller should handle nil return
	}

	return &tls.Config{
		Certificates: []tls.Certificate{srvTLS},
		ClientCAs:    certPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
}

// NewClientTLSConfig 创建 mTLS 客户端的 tls.Config。
// 携带客户端证书用于服务端验证。
func NewClientTLSConfig(ca *CACert, clientCert *CertPair) *tls.Config {
	certPool := x509.NewCertPool()
	certPool.AddCert(ca.Cert)

	clientTLS, err := tls.X509KeyPair(clientCert.CertPEM, clientCert.KeyPEM)
	if err != nil {
		return nil // Caller should handle nil return
	}

	return &tls.Config{
		RootCAs:      certPool,
		Certificates: []tls.Certificate{clientTLS},
		MinVersion:   tls.VersionTLS13,
		// InsecureSkipVerify: false — 验证服务端证书
	}
}

// MTLSConfig 是 mTLS Transport 配置。
type MTLSConfig struct {
	ServerAddr string     // host:port
	CACert     *CACert    // CA 证书
	ClientCert *CertPair  // 客户端证书
}

// MTLSChannel 管理 mTLS 连接和 Yamux 会话。
type MTLSChannel struct {
	cfg    *MTLSConfig
	conn   *tls.Conn
	yamux  *YamuxSession
}

// NewMTLSChannel 创建 mTLS 通道，完成 TLS 握手 + Yamux 会话建立。
func NewMTLSChannel(cfg *MTLSConfig) (*MTLSChannel, error) {
	// 1. Extract hostname for TLS ServerName
	host, _, err := net.SplitHostPort(cfg.ServerAddr)
	if err != nil {
		host = cfg.ServerAddr
	}

	tlsConf := NewClientTLSConfig(cfg.CACert, cfg.ClientCert)
	if tlsConf == nil {
		return nil, fmt.Errorf("mtls: NewClientTLSConfig returned nil (invalid certificate)")
	}
	tlsConf.ServerName = host

	conn, err := tls.Dial("tcp", cfg.ServerAddr, tlsConf)
	if err != nil {
		return nil, fmt.Errorf("mtls dial: %w", err)
	}

	// 2. 发送 MUX/1 前缀（Sliver 协议）
	wrapper := &tlsConnWrapper{conn: conn}
	if err := WritePreface(wrapper); err != nil {
		conn.Close()
		return nil, fmt.Errorf("mtls preface: %w", err)
	}

	// 3. 创建 Yamux 客户端会话
	yamux, err := NewClient(wrapper)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("mtls yamux: %w", err)
	}

	return &MTLSChannel{
		cfg:   cfg,
		conn:  conn,
		yamux: yamux,
	}, nil
}

// Send 通过 Yamux 流发送数据并读取完整响应。
func (m *MTLSChannel) Send(data []byte) ([]byte, error) {
	stream, err := m.yamux.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}
	defer stream.Close()

	if _, err := stream.Write(data); err != nil {
		return nil, err
	}

	// 流式读取直到 EOF（避免 64KB 固定缓冲区截断大消息）
	resp, err := io.ReadAll(stream)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Recv 接受传入的流并读取完整数据。
func (m *MTLSChannel) Recv() ([]byte, error) {
	stream, err := m.yamux.AcceptStream()
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	resp, err := io.ReadAll(stream)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Close 关闭 mTLS 连接。
func (m *MTLSChannel) Close() error {
	if m.yamux != nil {
		m.yamux.Close()
	}
	if m.conn != nil {
		m.conn.Close()
	}
	return nil
}

// YamuxSession 返回底层 Yamux 会话。
func (m *MTLSChannel) YamuxSession() *YamuxSession {
	return m.yamux
}

// tlsConnWrapper 将 TLS 连接包装为 io.ReadWriteCloser。
type tlsConnWrapper struct {
	conn *tls.Conn
}

func (w *tlsConnWrapper) Read(p []byte) (n int, err error) {
	return w.conn.Read(p)
}

func (w *tlsConnWrapper) Write(p []byte) (n int, err error) {
	return w.conn.Write(p)
}

func (w *tlsConnWrapper) Close() error {
	return w.conn.Close()
}

// ResolveServerAddr 解析服务器地址（支持 DNS 和 IP）。
func ResolveServerAddr(addr string) ([]net.IP, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	return net.LookupIP(host)
}
