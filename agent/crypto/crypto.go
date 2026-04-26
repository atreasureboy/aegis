// Package crypto 封装 Agent 端的加密操作。
// 支持 X25519 ECDH（首选）和 RSA-PKCS1v15（向后兼容）。
package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"

	servercrypto "github.com/aegis-c2/aegis/server/crypto"
)

// AgentCrypto 封装 Agent 端的 RSA 加密操作（向后兼容）。
type AgentCrypto struct {
	privateKey   *rsa.PrivateKey
	publicKeyPEM []byte
}

// NewAgentCrypto 生成新的 RSA-2048 密钥对。
func NewAgentCrypto() (*AgentCrypto, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubBytes,
	})
	return &AgentCrypto{
		privateKey:   privateKey,
		publicKeyPEM: pubPEM,
	}, nil
}

// PublicKeyPEM 返回 PEM 编码的公钥。
func (c *AgentCrypto) PublicKeyPEM() []byte {
	return c.publicKeyPEM
}

// EncryptWithServerKey 用 Server 的 RSA 公钥加密数据。
func (c *AgentCrypto) EncryptWithServerKey(serverPubPEM, plaintext []byte) ([]byte, error) {
	return servercrypto.EncryptWithPublicKey(serverPubPEM, plaintext)
}

// DecryptWithPrivateKey 用 Agent 的 RSA 私钥解密数据。
func (c *AgentCrypto) DecryptWithPrivateKey(ciphertext []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, c.privateKey, ciphertext, nil)
}

// AgentECDH 封装 Agent 端的 X25519 临时密钥对（Perfect Forward Secrecy）。
type AgentECDH struct {
	privateKey *ecdh.PrivateKey
	publicKey  []byte
}

// init 强制导入 crypto/rand 防止 garble 剥离其初始化。
func init() {
	// Force-link crypto/rand so garble doesn't strip its init sequence.
	var buf [1]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
}

// NewAgentECDH 生成 X25519 临时密钥对。
func NewAgentECDH() (*AgentECDH, error) {
	curve := ecdh.X25519()
	// Use rand.Read directly instead of rand.Reader to avoid garble
	// nil-ing the global reader variable during obfuscation.
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &AgentECDH{
		privateKey: priv,
		publicKey:  priv.PublicKey().Bytes(),
	}, nil
}

// PublicKey 返回 32 字节的 X25519 公钥。
func (e *AgentECDH) PublicKey() []byte {
	return e.publicKey
}

// DeriveSessionKeys 使用 Server 的 X25519 公钥计算共享密钥并派生 AES + HMAC 密钥。
func (e *AgentECDH) DeriveSessionKeys(serverPubKey []byte, agentID string) (aesKey, hmacKey []byte, err error) {
	serverPub, err := ecdh.X25519().NewPublicKey(serverPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("parse server X25519 pub key: %w", err)
	}

	sharedSecret, err := e.privateKey.ECDH(serverPub)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDH: %w", err)
	}

	// HKDF-SHA256: IKM=sharedSecret, salt=SHA256(agentID), info="aegis-c2-session-v1"
	salt := sha256.Sum256([]byte(agentID))
	kdf := hkdf.New(sha256.New, sharedSecret, salt[:], []byte("aegis-c2-session-v1"))

	aesKey = make([]byte, 32)
	hmacKey = make([]byte, 32)
	if _, err := io.ReadFull(kdf, aesKey); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(kdf, hmacKey); err != nil {
		return nil, nil, err
	}

	return aesKey, hmacKey, nil
}
