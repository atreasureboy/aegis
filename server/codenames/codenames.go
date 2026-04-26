// Package codenames 提供 Agent 代号生成。
// 借鉴 Sliver 的 codenames (server/codenames/) — 为每个 Agent 生成独特的代号。
//
// 面试要点：
// 1. 代号用于在 C2 中快速识别 Agent（比 UUID 更易读）
// 2. Sliver 使用形容词+名词组合（如 "happy-penguin"）
// 3. Havoc 使用随机字符串
// 4. 好处：
//    - 操作员记忆友好
//    - 终端显示美观
//    - 日志中易于区分
package codenames

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

var adjectives = []string{
	"silent", "hidden", "stealth", "ghost", "phantom",
	"shadow", "dark", "night", "black", "white",
	"rapid", "swift", "quick", "fast", "slow",
	"bright", "fierce", "bold", "calm", "cool",
	"lucky", "happy", "wild", "free", "deep",
	"alpha", "bravo", "delta", "echo", "foxtrot",
	"golf", "hotel", "india", "juliet", "kilo",
	"omega", "sigma", "theta", "zulu", "nova",
}

var nouns = []string{
	"penguin", "falcon", "eagle", "hawk", "wolf",
	"tiger", "lion", "bear", "snake", "fox",
	"dragon", "phoenix", "raven", "shark", "whale",
	"viper", "cobra", "panther", "jaguar", "lynx",
	"specter", "wraith", "spirit",
	"storm", "blaze", "spark", "flame", "ember",
	"mirror", "pulse", "wave",
	"cipher", "vector", "nexus", "vertex", "pixel",
}

// Generate 生成一个独特的 Agent 代号。
func Generate() string {
	adjIdx, err := rand.Int(rand.Reader, big.NewInt(int64(len(adjectives))))
	if err != nil {
		// 降级为固定索引（crypto/rand 极少失败）
		adjIdx = big.NewInt(0)
	}
	nounIdx, err := rand.Int(rand.Reader, big.NewInt(int64(len(nouns))))
	if err != nil {
		nounIdx = big.NewInt(0)
	}
	adj := adjectives[adjIdx.Int64()]
	noun := nouns[nounIdx.Int64()]
	return fmt.Sprintf("%s-%s", adj, noun)
}

// GenerateUnique 生成不重复的代号。
func GenerateUnique(existing map[string]bool) string {
	for i := 0; i < 1000; i++ {
		name := Generate()
		if !existing[name] {
			return name
		}
	}
	// 如果所有组合都用了，添加随机后缀
	randSuffix, err := rand.Int(rand.Reader, big.NewInt(10000))
	suffix := int64(0)
	if err == nil {
		suffix = randSuffix.Int64()
	}
	return fmt.Sprintf("%s-%d", Generate(), suffix)
}

// List 返回所有可能的组合数量。
func List() int {
	return len(adjectives) * len(nouns)
}

// GenerateBatch 批量生成代号。
func GenerateBatch(n int) []string {
	names := make([]string, n)
	for i := 0; i < n; i++ {
		names[i] = Generate()
	}
	return names
}
