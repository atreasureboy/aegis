// Package encoder 提供流量编码器，用于 C2 通信的 payload 变换。
// 借鉴 Sliver implant/sliver/encoders/traffic/ 的可插拔编码器设计。
package encoder

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"
)

// Encoder 是流量编码器的通用接口。
type Encoder interface {
	Name() string
	Encode([]byte) []byte
	Decode([]byte) ([]byte, error)
}

// NopEncoder 不做任何变换（用于测试或明文模式）。
type NopEncoder struct{}

func (NopEncoder) Name() string                 { return "nop" }
func (NopEncoder) Encode(data []byte) []byte    { return data }
func (NopEncoder) Decode(data []byte) ([]byte, error) { return data, nil }

// Base64Encoder 使用标准 base64 编码。
type Base64Encoder struct{}

func (Base64Encoder) Name() string                { return "base64" }
func (Base64Encoder) Encode(data []byte) []byte   { return []byte(base64.StdEncoding.EncodeToString(data)) }
func (Base64Encoder) Decode(data []byte) ([]byte, error) { return base64.StdEncoding.DecodeString(string(data)) }

// Base64URLEncoder 使用 URL-safe base64 编码（无填充）。
type Base64URLEncoder struct{}

func (Base64URLEncoder) Name() string                { return "base64-url" }
func (Base64URLEncoder) Encode(data []byte) []byte   { return []byte(base64.RawURLEncoding.EncodeToString(data)) }
func (Base64URLEncoder) Decode(data []byte) ([]byte, error) { return base64.RawURLEncoding.DecodeString(string(data)) }

// Base58Encoder 使用 base58 编码（比特币字母表，去除易混淆字符 0OIl）。
// Go stdlib 没有 base58，这里手动实现。
type Base58Encoder struct{}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Encode(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	leadingZeros := 0
	for _, b := range data {
		if b != 0 {
			break
		}
		leadingZeros++
	}
	// 使用大数处理，避免 uint64 溢出（8 字节全 0xFF 会超出 uint64 范围）
	digits := []byte(base58Alphabet)

	// 将 data 转为大数
	var n big.Int
	n.SetBytes(data)

	// 反复除以 58 取余
	var result []byte
	zero := big.NewInt(0)
	base := big.NewInt(58)
	mod := new(big.Int)
	for n.Cmp(zero) > 0 {
		n.DivMod(&n, base, mod)
		result = append([]byte{digits[mod.Int64()]}, result...)
	}
	for i := 0; i < leadingZeros; i++ {
		result = append([]byte{'1'}, result...)
	}
	return string(result)
}

func base58Decode(s string) []byte {
	if len(s) == 0 {
		return nil
	}
	leadingZeros := 0
	for _, c := range s {
		if c != '1' {
			break
		}
		leadingZeros++
	}
	// 使用 math/big 避免 uint64 溢出
	var n big.Int
	n.SetInt64(0)
	base := big.NewInt(58)
	digits := base58Alphabet
	for _, c := range s {
		idx := -1
		for i, a := range digits {
			if a == c {
				idx = i
				break
			}
		}
		if idx < 0 {
			return nil
		}
		n.Mul(&n, base)
		n.Add(&n, big.NewInt(int64(idx)))
	}
	result := n.Bytes()
	result = append(make([]byte, leadingZeros), result...)
	return result
}

func (Base58Encoder) Name() string                { return "base58" }
func (Base58Encoder) Encode(data []byte) []byte   { return []byte(base58Encode(data)) }
func (Base58Encoder) Decode(data []byte) ([]byte, error) { return base58Decode(string(data)), nil }

// HexEncoder 使用十六进制编码。
type HexEncoder struct{}

func (HexEncoder) Name() string                { return "hex" }
func (HexEncoder) Encode(data []byte) []byte   { return []byte(hex.EncodeToString(data)) }
func (HexEncoder) Decode(data []byte) ([]byte, error) { return hex.DecodeString(string(data)) }

// encoderCache holds singleton instances to avoid recreating on every call.
var (
	base64Encoder     = Base64Encoder{}
	base64URLEncoder  = Base64URLEncoder{}
	base58Encoder     = Base58Encoder{}
	hexEncoder        = HexEncoder{}
	nopEncoder        = NopEncoder{}
	encoderCacheMu    sync.Mutex
	encoderCache      = map[string]Encoder{
		"base64":     base64Encoder,
		"base64-url": base64URLEncoder,
		"base58":     base58Encoder,
		"hex":        hexEncoder,
		"nop":        nopEncoder,
		"none":       nopEncoder,
	}
)

// GetEncoder 根据名称获取编码器。
func GetEncoder(name string) (Encoder, error) {
	encoderCacheMu.Lock()
	defer encoderCacheMu.Unlock()

	if enc, ok := encoderCache[name]; ok {
		return enc, nil
	}
	return nil, fmt.Errorf("unknown encoder: %s", name)
}
