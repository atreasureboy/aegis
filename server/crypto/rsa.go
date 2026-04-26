// Package crypto 封装 Server 端的加密操作。
// 支持 X25519 ECDH（首选）和 RSA-PKCS1v15（向后兼容）。
package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"

	sharedecdh "github.com/aegis-c2/aegis/shared/ecdh"
)

// RSAKeyPair 封装了 RSA 密钥对操作（向后兼容）。
type RSAKeyPair struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// GenerateKeyPair 生成 RSA-2048 密钥对。
func GenerateKeyPair() (*RSAKeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &RSAKeyPair{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
	}, nil
}

// PublicKeyPEM 返回 PEM 编码的公钥。
func (k *RSAKeyPair) PublicKeyPEM() []byte {
	pubBytes, _ := x509.MarshalPKIXPublicKey(k.publicKey)
	block := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubBytes,
	}
	return pem.EncodeToMemory(block)
}

// PrivateKeyPEM 返回 PEM 编码的私钥。
func (k *RSAKeyPair) PrivateKeyPEM() []byte {
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(k.privateKey),
	}
	return pem.EncodeToMemory(block)
}

// Decrypt 用 RSA-OAEP 私钥解密数据（替代 PKCS1v15 防 Bleichenbacher 攻击）。
func (k *RSAKeyPair) Decrypt(ciphertext []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, k.privateKey, ciphertext, nil)
}

// Encrypt 用 RSA-OAEP 公钥加密数据（替代 PKCS1v15 防 Bleichenbacher 攻击）。
func (k *RSAKeyPair) Encrypt(plaintext []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, k.publicKey, plaintext, nil)
}

// LoadPublicKeyPEM 从 PEM 数据加载 RSA 公钥。
func LoadPublicKeyPEM(pemData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return rsaPub, nil
}

// LoadRSAKeyFromPEM 从 PEM 数据加载 RSA 私钥并返回完整的密钥对。
func LoadRSAKeyFromPEM(pemData []byte) (*RSAKeyPair, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 as fallback
		pkcs8Key, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parse PKCS1: %v; parse PKCS8: %v", err, err2)
		}
		var ok bool
		privKey, ok = pkcs8Key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("PKCS8 key is not RSA")
		}
	}
	return &RSAKeyPair{
		privateKey: privKey,
		publicKey:  &privKey.PublicKey,
	}, nil
}

// EncryptWithPublicKey 用 PEM 编码的 RSA 公钥加密数据。
func EncryptWithPublicKey(pemData, plaintext []byte) ([]byte, error) {
	pub, err := LoadPublicKeyPEM(pemData)
	if err != nil {
		return nil, err
	}
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, plaintext, nil)
}

// ECDHKeyPair 是 Server 端的 X25519 长期密钥对。
// 直接使用 shared/ecdh.ServerKeyPair，避免重复定义。
type ECDHKeyPair = sharedecdh.ServerKeyPair

// GenerateECDHKeyPair 生成 X25519 密钥对。
func GenerateECDHKeyPair() (*ECDHKeyPair, error) {
	return sharedecdh.GenerateServerKeyPair()
}

// LoadECDHKeyPairFromHex 从 hex 编码的私钥加载密钥对。
func LoadECDHKeyPairFromHex(hexPriv string) (*ECDHKeyPair, error) {
	return sharedecdh.LoadServerKeyPairFromHex(hexPriv)
}

// DeriveSessionKeys 使用 Agent 的 X25519 公钥计算共享密钥并派生 AES + HMAC 密钥。
func DeriveSessionKeys(k *ECDHKeyPair, agentPubKey []byte, agentID string) (aesKey, hmacKey []byte, err error) {
	secret, err := sharedecdh.SharedSecret(k.PrivateKey, agentPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDH: %w", err)
	}

	keys, err := sharedecdh.DeriveKeys(secret, agentID, "aegis-c2-session-v1")
	if err != nil {
		return nil, nil, err
	}
	return keys.AESKey, keys.HMACKey, nil
}

// NewHKDF 是 hkdf.New 的便捷包装，供外部包使用。
func NewHKDF(hash func() hash.Hash, secret, salt, info []byte) io.Reader {
	return hkdf.New(hash, secret, salt, info)
}
