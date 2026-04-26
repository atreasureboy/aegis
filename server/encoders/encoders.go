// Package encoders 提供 Shellcode 编码/加密。
// 借鉴 Sliver 的 encoders (server/encoders/) — 对 Payload 进行 XOR/Base64/AES 编码，绕过静态检测。
//
// 面试要点：
// 1. 为什么需要编码：杀软会扫描已知 shellcode 特征码（如 msfvenom 生成的字节序列）
// 2. XOR 编码：最简单的编码方式，每个字节 XOR 一个密钥
//    - 优势：解码速度快，体积小
//    - 劣势：XOR 密钥可能被暴力破解
// 3. AES 加密：强加密，需要密钥解密
//    - 优势：无法被静态分析
//    - 劣势：需要 AES 解密代码（增加 stub 大小）
// 4. 编码 ≠ 加密：
//    - 编码是可逆的数据变换（如 Base64）
//    - 加密需要密钥（如 AES）
// 5. Stager 中包含解码器（decoder stub）
package encoders

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// Encoder 是编码器的接口。
type Encoder interface {
	Name() string
	Encode(data []byte) ([]byte, error)
	Decode(data []byte) ([]byte, error)
}

// XOREncoder 使用 XOR 编码。
type XOREncoder struct {
	Key byte
}

// Name 返回编码器名称。
func (e *XOREncoder) Name() string { return "xor" }

// Encode XOR 编码数据（每次调用生成随机密钥）。
func (e *XOREncoder) Encode(data []byte) ([]byte, error) {
	// 生成随机单字节密钥（避开 0x00）
	keyByte := make([]byte, 1)
	if _, err := io.ReadFull(rand.Reader, keyByte); err != nil {
		return nil, err
	}
	if keyByte[0] == 0 {
		keyByte[0] = 0xAB
	}
	key := keyByte[0]
	e.Key = key // 保存供参考

	encoded := make([]byte, len(data)+1)
	encoded[0] = key // 密钥放在第一个字节
	for i, b := range data {
		encoded[i+1] = b ^ key
	}
	return encoded, nil
}

// Decode XOR 解码数据。
func (e *XOREncoder) Decode(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("data too short")
	}
	key := data[0]
	decoded := make([]byte, len(data)-1)
	for i, b := range data[1:] {
		decoded[i] = b ^ key
	}
	return decoded, nil
}

// Base64Encoder 使用 Base64 编码。
type Base64Encoder struct{}

func (e *Base64Encoder) Name() string { return "base64" }

func (e *Base64Encoder) Encode(data []byte) ([]byte, error) {
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(encoded, data)
	return encoded, nil
}

func (e *Base64Encoder) Decode(data []byte) ([]byte, error) {
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	n, err := base64.StdEncoding.Decode(decoded, data)
	if err != nil {
		return nil, err
	}
	return decoded[:n], nil
}

// AESEncoder 使用 AES-256-GCM 加密。
type AESEncoder struct {
	Key []byte // 32 bytes
}

func (e *AESEncoder) Name() string { return "aes256" }

func (e *AESEncoder) Encode(plaintext []byte) ([]byte, error) {
	if len(e.Key) != 32 {
		return nil, fmt.Errorf("AES key must be 32 bytes")
	}

	block, err := aes.NewCipher(e.Key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// nonce + ciphertext
	return aesGCM.Seal(nonce, nonce, plaintext, nil), nil
}

func (e *AESEncoder) Decode(ciphertext []byte) ([]byte, error) {
	if len(e.Key) != 32 {
		return nil, fmt.Errorf("AES key must be 32 bytes")
	}

	block, err := aes.NewCipher(e.Key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return aesGCM.Open(nil, nonce, ciphertext, nil)
}

var aes256Key []byte

func init() {
	aes256Key = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, aes256Key); err != nil {
		panic("failed to generate AES key: " + err.Error())
	}
}

// Registry 是所有编码器的注册表。
var Registry = map[string]func() Encoder{
	"xor": func() Encoder { return &XOREncoder{Key: 0xAB} },
	"base64": func() Encoder { return &Base64Encoder{} },
	"aes256": func() Encoder { return &AESEncoder{Key: aes256Key} },
}

// Encode 使用指定编码器编码数据。
func Encode(data []byte, encoderName string) ([]byte, error) {
	factory, ok := Registry[encoderName]
	if !ok {
		return nil, fmt.Errorf("unknown encoder: %s", encoderName)
	}
	enc := factory()
	return enc.Encode(data)
}

// Decode 使用指定编码器解码数据。
func Decode(data []byte, encoderName string) ([]byte, error) {
	factory, ok := Registry[encoderName]
	if !ok {
		return nil, fmt.Errorf("unknown encoder: %s", encoderName)
	}
	enc := factory()
	return enc.Decode(data)
}
