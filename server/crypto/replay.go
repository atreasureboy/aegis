package crypto

import (
	"encoding/binary"
	"sync"
	"time"
)

// ReplayWindow 是 RFC 4303 IPsec ESP 风格的反重放滑动窗口。
// 用 64-bit bitmap 替代 map[nonce]time，O(1) 时间复杂度，
// 固定 8 字节内存 per-agent，无 GC 压力。
type ReplayWindow struct {
	mu         sync.Mutex // protects window and largestSeq
	window     uint64     // 64-bit bitmap
	largestSeq uint64     // 最大已接收序列号
	size       uint64     // 窗口大小（默认 64）
}

// NewReplayWindow 创建指定大小的滑动窗口。
func NewReplayWindow(size uint) *ReplayWindow {
	sz := uint64(size)
	if sz == 0 || sz > 64 {
		sz = 64
	}
	return &ReplayWindow{size: sz}
}

// Check 检查并记录序列号。返回 false 表示是重放（已存在）。
// 实现 RFC 4303 Section 3.4.3 Anti-Replay 算法：
//   1. 如果 seq <= largestSeq - windowSize: 超出窗口，拒绝
//   2. 如果 bit 已设置: 重放，拒绝
//   3. 如果 seq > largestSeq: 窗口右移，更新 largestSeq
//   4. 设置对应 bit
func (rw *ReplayWindow) Check(seq uint64) bool {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	// seq == 0: 初始值，总是拒绝（防止零序列号攻击）
	if seq == 0 {
		return false
	}

	// 情况 1: 超出窗口左边界
	if rw.largestSeq >= rw.size && seq <= rw.largestSeq-rw.size {
		return false // 超出窗口，视为重放
	}

	// 情况 2: 在窗口内，检查 bit
	if seq <= rw.largestSeq {
		bitIndex := rw.largestSeq - seq
		if bitIndex < 64 {
			if (rw.window & (1 << bitIndex)) != 0 {
				return false // bit 已设置，重放
			}
			// 标记 bit
			rw.window |= (1 << bitIndex)
			return true // 新序列号，接受
		}
		return false // 不应该到这里（情况 1 已覆盖）
	}

	// 情况 3: seq > largestSeq，窗口右移
	bitIndex := seq - rw.largestSeq
	if bitIndex >= 64 {
		// 新 seq 超出当前窗口 64 位以上，直接清空 bitmap
		rw.window = 1 // 新位置设为 1
	} else {
		// 窗口右移：左移 bitIndex 位，新位置设为 1
		rw.window = (rw.window << bitIndex) | 1
	}
	rw.largestSeq = seq
	return true
}

// SeqNumNonce 从 12-byte nonce 提取 64-bit 序列号。
// Agent 端使用 DeterministicNonce(seqNum, randPrefix) 编码：
// 前 4 字节是随机前缀，后 8 字节大端编码的 seqNum。
func SeqNumNonce(nonce []byte) uint64 {
	if len(nonce) < 12 {
		return 0
	}
	// 后 8 字节是 seqNum
	return binary.BigEndian.Uint64(nonce[4:12])
}

// NonceCache 是向后兼容的包装器。
// 内部使用 ReplayWindow 而非 map，
// 但保留原有的 API 签名。
type NonceCache struct {
	windows map[string]*ReplayWindow // agentID -> ReplayWindow
	mu      sync.RWMutex
	window  time.Duration // 保留用于 TTL（但 ReplayWindow 自身不需要清理）
}

// NewNonceCache 创建 Nonce 缓存。
func NewNonceCache(window time.Duration) *NonceCache {
	return &NonceCache{
		windows: make(map[string]*ReplayWindow),
		window:  window,
	}
}

// Check 检查 Nonce 是否已存在。
// 使用序列号滑动窗口，O(1) 时间，固定 8 字节内存。
func (nc *NonceCache) Check(nonce []byte) bool {
	seq := SeqNumNonce(nonce)
	if seq == 0 {
		// 向后兼容：如果 nonce 不是序列号格式（随机 nonce），
		// 使用全局的 ReplayWindow（key = ""）
		return nc.checkWithKey("", seq)
	}
	// 对于序列号格式的 nonce，需要 agentID 来隔离
	// 这里的 nonce 不携带 agentID，使用全局窗口
	return nc.checkWithKey("", seq)
}

func (nc *NonceCache) checkWithKey(key string, seq uint64) bool {
	nc.mu.RLock()
	rw, ok := nc.windows[key]
	nc.mu.RUnlock()

	if !ok {
		nc.mu.Lock()
		if rw, ok = nc.windows[key]; !ok {
			rw = NewReplayWindow(64)
			nc.windows[key] = rw
		}
		nc.mu.Unlock()
	}

	return !rw.Check(seq) // ReplayWindow.Check 返回 true=新, false=重放
}

// AgentNonceCache 是 per-agent 的 ReplayWindow 管理器。
// 每个 Agent 独立的 64-bit 滑动窗口，O(1) 检查，8 字节内存。
type AgentNonceCache struct {
	windows map[string]*ReplayWindow
	mu      sync.RWMutex
}

// NewAgentNonceCache 创建 per-agent 的 Nonce 缓存。
func NewAgentNonceCache(_ time.Duration) *AgentNonceCache {
	return &AgentNonceCache{
		windows: make(map[string]*ReplayWindow),
	}
}

// Check 检查指定 Agent 的 Nonce 是否已存在。
func (anc *AgentNonceCache) Check(agentID string, nonce []byte) bool {
	seq := SeqNumNonce(nonce)

	anc.mu.RLock()
	rw, ok := anc.windows[agentID]
	anc.mu.RUnlock()

	if !ok {
		anc.mu.Lock()
		if rw, ok = anc.windows[agentID]; !ok {
			rw = NewReplayWindow(64)
			anc.windows[agentID] = rw
		}
		anc.mu.Unlock()
	}

	return !rw.Check(seq)
}

// Remove 移除指定 Agent 的窗口（Agent 下线时调用）。
func (anc *AgentNonceCache) Remove(agentID string) {
	anc.mu.Lock()
	defer anc.mu.Unlock()
	delete(anc.windows, agentID)
}

// Count 返回当前缓存的 Agent 数量。
func (anc *AgentNonceCache) Count() int {
	anc.mu.RLock()
	defer anc.mu.RUnlock()
	return len(anc.windows)
}

// TimestampValidator 验证时间戳是否在可接受范围内。
type TimestampValidator struct {
	maxDrift time.Duration
}

func NewTimestampValidator(maxDrift time.Duration) *TimestampValidator {
	return &TimestampValidator{maxDrift: maxDrift}
}

// Validate 检查时间戳是否在当前时间的允许偏差范围内。
func (v *TimestampValidator) Validate(tsMillis int64) bool {
	now := time.Now().UnixMilli()
	diff := now - tsMillis
	if diff < 0 {
		diff = -diff
	}
	return time.Duration(diff)*time.Millisecond <= v.maxDrift
}
