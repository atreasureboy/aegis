package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"sync"
)

// gcmCache caches GCM instances per key to avoid repeated aes.NewCipher + cipher.NewGCM.
var (
	gcmCache   = make(map[string]cipher.AEAD)
	gcmCacheMu sync.RWMutex
)

func getGCM(key []byte) (cipher.AEAD, error) {
	keyStr := string(key)
	gcmCacheMu.RLock()
	if gcm, ok := gcmCache[keyStr]; ok {
		gcmCacheMu.RUnlock()
		return gcm, nil
	}
	gcmCacheMu.RUnlock()

	gcmCacheMu.Lock()
	defer gcmCacheMu.Unlock()
	// Double-check after acquiring write lock
	if gcm, ok := gcmCache[keyStr]; ok {
		return gcm, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	gcmCache[keyStr] = gcm
	return gcm, nil
}

// GenerateKey 生成随机 32-byte AES 密钥。
func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	return key, err
}

// EncryptAESGCM 用 AES-256-GCM 加密数据。
// 返回 (密文, nonce) 分开的值，便于序列化传输。
func EncryptAESGCM(key, data []byte) ([]byte, []byte, error) {
	gcm, err := getGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return gcm.Seal(nil, nonce, data, nil), nonce, nil
}

// DecryptAESGCM 用 AES-256-GCM 解密数据。
func DecryptAESGCM(key, nonce, ciphertext []byte) ([]byte, error) {
	gcm, err := getGCM(key)
	if err != nil {
		return nil, err
	}
	if gcm.NonceSize() != len(nonce) {
		return nil, fmt.Errorf("nonce size mismatch: expected %d, got %d", gcm.NonceSize(), len(nonce))
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}
