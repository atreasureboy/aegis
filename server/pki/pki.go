// Package pki 管理操作员证书颁发机构（CA）和客户端证书签发。
package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// Manager 管理 CA 证书和操作员客户端证书。
type Manager struct {
	caCert     *x509.Certificate
	caKey      *rsa.PrivateKey
	caCertPEM  []byte
	caKeyPEM   []byte
}

// New 加载或首次生成自签名 CA。
func New(caCertPath, caKeyPath string) (*Manager, error) {
	m := &Manager{}

	// Try loading existing CA
	certPEM, err := os.ReadFile(caCertPath)
	if err == nil {
		keyPEM, err2 := os.ReadFile(caKeyPath)
		if err2 != nil {
			return nil, fmt.Errorf("load CA key: %w", err2)
		}
		return m.loadCA(certPEM, keyPEM)
	}

	// Generate new CA
	return m, m.generateCA(caCertPath, caKeyPath)
}

// GenerateBootstrap 首次启动时生成 CA + bootstrap 管理员证书。
// 返回 caCertPEM, caKeyPEM, adminCertPEM, adminKeyPEM, error。
func GenerateBootstrap(caCertPath, caKeyPath string) (caCert, caKey, adminCert, adminKey []byte, err error) {
	m := &Manager{}
	if err := m.generateCA(caCertPath, caKeyPath); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("generate CA: %w", err)
	}

	adminCert, adminKey, err = m.GenerateOperatorCert("admin", "admin")
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("generate admin cert: %w", err)
	}

	return m.caCertPEM, m.caKeyPEM, adminCert, adminKey, nil
}

// generateCA 生成自签名根 CA。
func (m *Manager) generateCA(certPath, keyPath string) error {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate CA serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Aegis C2 CA",
			Organization: []string{"Aegis"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create CA cert: %w", err)
	}

	m.caCert, _ = x509.ParseCertificate(certDER)
	m.caKey = key
	m.caCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	m.caKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	if err := os.WriteFile(certPath, m.caCertPEM, 0600); err != nil {
		return fmt.Errorf("write CA cert: %w", err)
	}
	if err := os.WriteFile(keyPath, m.caKeyPEM, 0600); err != nil {
		return fmt.Errorf("write CA key: %w", err)
	}

	return nil
}

// loadCA 从 PEM 数据加载现有 CA。
func (m *Manager) loadCA(certPEM, keyPEM []byte) (*Manager, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("decode CA cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("decode CA key PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}

	m.caCert = cert
	m.caKey = key
	m.caCertPEM = certPEM
	m.caKeyPEM = keyPEM
	return m, nil
}

// GenerateOperatorCert 为操作员生成客户端证书。
// CommonName=name, OU=role, ExtKeyUsage=ClientAuth。
func (m *Manager) GenerateOperatorCert(name, role string) (certPEM, keyPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate operator key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         name,
			OrganizationalUnit: []string{role},
			Organization:       []string{"Aegis"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0), // 1 year
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, m.caCert, &key.PublicKey, m.caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create operator cert: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM, nil
}

// VerifyOperatorCert 验证操作员证书是否由我们的 CA 签发。
// 返回 operator name (CN), role (OU), error。
func (m *Manager) VerifyOperatorCert(cert *x509.Certificate) (name, role string, err error) {
	opts := x509.VerifyOptions{
		Roots:         m.CACertPool(),
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Intermediates: x509.NewCertPool(),
	}

	if _, err := cert.Verify(opts); err != nil {
		return "", "", fmt.Errorf("verify cert: %w", err)
	}

	return cert.Subject.CommonName, firstOU(cert), nil
}

// CACertPool 返回 CA cert pool 用于 gRPC ClientAuth。
func (m *Manager) CACertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(m.caCert)
	return pool
}

// CACertPEM 返回 CA 证书 PEM。
func (m *Manager) CACertPEM() []byte {
	return m.caCertPEM
}

// CACert 返回 CA 证书对象（用于签发子证书）。
func (m *Manager) CACert() *x509.Certificate {
	return m.caCert
}

// CAKeyPEM 返回 CA 私钥 PEM。
func (m *Manager) CAKeyPEM() []byte {
	return m.caKeyPEM
}

// CAKey 返回 CA 私钥对象（用于签名子证书）。
func (m *Manager) CAKey() *rsa.PrivateKey {
	return m.caKey
}

func firstOU(cert *x509.Certificate) string {
	if len(cert.Subject.OrganizationalUnit) > 0 {
		return cert.Subject.OrganizationalUnit[0]
	}
	return ""
}
