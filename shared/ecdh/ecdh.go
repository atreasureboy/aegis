// Package ecdh 实现 X25519 ECDH 密钥交换 + HKDF-SHA256 派生。
// 替代 RSA-PKCS1v15：提供 Perfect Forward Secrecy，确定性 nonce。
package ecdh

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// ServerKeyPair 是 Server 端的 X25519 长期密钥对。
// 长期持有，嵌入所有生成的 Agent 二进制。
type ServerKeyPair struct {
	PublicKey  []byte // 32 字节
	PrivateKey *ecdh.PrivateKey
}

// GenerateServerKeyPair 生成 Server 的 X25519 密钥对。
func GenerateServerKeyPair() (*ServerKeyPair, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ServerKeyPair{
		PublicKey:  priv.PublicKey().Bytes(),
		PrivateKey: priv,
	}, nil
}

// PublicKeyHex 返回 hex 编码的公钥（用于嵌入 Agent）。
func (k *ServerKeyPair) PublicKeyHex() string {
	return hex.EncodeToString(k.PublicKey)
}

// LoadServerKeyPairFromHex 从 hex 字符串加载 Server 私钥。
func LoadServerKeyPairFromHex(hexPriv string) (*ServerKeyPair, error) {
	data, err := hex.DecodeString(hexPriv)
	if err != nil {
		return nil, err
	}
	if len(data) != 32 {
		return nil, fmt.Errorf("invalid private key length: %d (expected 32)", len(data))
	}
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(data)
	if err != nil {
		return nil, err
	}
	return &ServerKeyPair{
		PublicKey:  priv.PublicKey().Bytes(),
		PrivateKey: priv,
	}, nil
}

// AgentKeyPair 是 Agent 端的 X25519 临时密钥对。
// 每次注册生成新对，用完即弃（PFS）。
type AgentKeyPair struct {
	PublicKey  []byte // 32 字节
	PrivateKey *ecdh.PrivateKey
}

// GenerateAgentKeyPair 生成 Agent 的临时 X25519 密钥对。
func GenerateAgentKeyPair() (*AgentKeyPair, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &AgentKeyPair{
		PublicKey:  priv.PublicKey().Bytes(),
		PrivateKey: priv,
	}, nil
}

// SharedSecret 计算 X25519 共享密钥。
// N-P0-4: Validates agentPubKey before ECDH — rejects all-zero and small-order points.
func SharedSecret(agentPriv *ecdh.PrivateKey, serverPub []byte) ([32]byte, error) {
	// N-P0-4: Reject all-zero public key
	zeroKey := make([]byte, 32)
	if len(serverPub) != 32 || bytes.Equal(serverPub, zeroKey) {
		return [32]byte{}, fmt.Errorf("invalid X25519 public key: all-zero or wrong length")
	}

	// N-P0-4: Reject known small-order points on Curve25519.
	// These points produce predictable shared secrets and must be rejected.
	// The 8 small-order points are well-known constants (see RFC 7748, Section 5).
	smallOrderPoints := [][32]byte{
		{0}, // all-zero (already checked above, kept for completeness)
		{1}, // point at infinity representation
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
		{0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
		{0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57},
		{0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00},
		{0xa0, 0x63, 0x6a, 0x43, 0x5c, 0xaf, 0x73, 0xdb, 0x4e, 0x2f, 0x4e, 0xaa, 0x63, 0x7c, 0xe0, 0xa4, 0xfb, 0xbb, 0xa3, 0x3b, 0xa7, 0xe3, 0x71, 0x79, 0x27, 0xdd, 0xb1, 0x22, 0x2f, 0x60, 0xee, 0x28},
		{0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0xd7},
	}
	for _, sp := range smallOrderPoints {
		if bytes.Equal(serverPub, sp[:]) {
			return [32]byte{}, fmt.Errorf("invalid X25519 public key: small-order point")
		}
	}

	serverPubKey, err := ecdh.X25519().NewPublicKey(serverPub)
	if err != nil {
		return [32]byte{}, err
	}
	secret, err := agentPriv.ECDH(serverPubKey)
	if err != nil {
		return [32]byte{}, err
	}
	return [32]byte(secret), nil
}

// DerivedKeys 是从共享密钥派生的会话密钥。
type DerivedKeys struct {
	AESKey  []byte // AES-256 密钥（32 字节）
	HMACKey []byte // HMAC-SHA256 密钥（32 字节）
}

// DeriveKeys 使用 HKDF-SHA256 从共享密钥派生 AES + HMAC 密钥。
// info 参数用于域分离（如 "aegis-c2-session-v1"）。
func DeriveKeys(sharedSecret [32]byte, agentID string, info string) (DerivedKeys, error) {
	salt := sha256.Sum256([]byte(agentID))
	hkdfReader := hkdf.New(sha256.New, sharedSecret[:], salt[:], []byte(info))

	aesKey := make([]byte, 32)
	hmacKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, aesKey); err != nil {
		return DerivedKeys{}, fmt.Errorf("derive AES key: %w", err)
	}
	if _, err := io.ReadFull(hkdfReader, hmacKey); err != nil {
		return DerivedKeys{}, fmt.Errorf("derive HMAC key: %w", err)
	}

	return DerivedKeys{AESKey: aesKey, HMACKey: hmacKey}, nil
}

// DeterministicNonce 从序列号 + 随机前缀派生 12-byte nonce（AES-GCM 标准大小）。
// 结构: [randPrefix:4][seqNum:8]
// 随机前缀防止 Agent 重启后 seqNum 归零导致 nonce 重用。
// 在注册时，Agent 的 ECDH 密钥对是新的，所以随机前缀也是新的，
// 确保即使 seqNum 归零也不会与之前会话产生 nonce 冲突。
func DeterministicNonce(seqNum uint64, randPrefix []byte) []byte {
	nonce := make([]byte, 12)
	// 取随机前缀的前 4 字节
	for i := 0; i < 4 && i < len(randPrefix); i++ {
		nonce[i] = randPrefix[i]
	}
	// seqNum 占据后 8 字节
	nonce[4] = byte(seqNum >> 56)
	nonce[5] = byte(seqNum >> 48)
	nonce[6] = byte(seqNum >> 40)
	nonce[7] = byte(seqNum >> 32)
	nonce[8] = byte(seqNum >> 24)
	nonce[9] = byte(seqNum >> 16)
	nonce[10] = byte(seqNum >> 8)
	nonce[11] = byte(seqNum)
	return nonce
}
