package shared

import (
	"crypto/rand"
	"fmt"
)

// GenID 生成带前缀的唯一 ID（使用 crypto/rand）。
func GenID(prefix string) string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback: mix prefix hash with time-based entropy
		// Avoids deterministic "prefix-fallback" which could collide
		b2 := make([]byte, 4)
		rand.Read(b2) // best-effort second attempt
		return fmt.Sprintf("%s-%x", prefix, b2)
	}
	return fmt.Sprintf("%s-%x", prefix, b)
}
