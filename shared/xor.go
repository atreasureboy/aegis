package shared

// XORBytes 对字节流进行循环 XOR 加密/解密。
// 如果 key 为空，直接返回原始 data。
func XORBytes(data, key []byte) []byte {
	if len(key) == 0 {
		return data
	}
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result
}

// XORBytesInPlace 原地 XOR，避免额外分配（高性能场景使用）。
func XORBytesInPlace(data, key []byte) {
	if len(key) == 0 {
		return
	}
	for i := range data {
		data[i] ^= key[i%len(key)]
	}
}
