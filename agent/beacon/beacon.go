// Package beacon 提供 Beacon 模式支持。
// 借鉴 Cobalt Strike / Sliver 的 Beacon 机制。
//
// 面试要点：
// 1. Beacon vs Session 的区别：
//    - Session (交互式): Agent 持续运行，实时接收命令，适合渗透测试
//    - Beacon (周期性): Agent 定期上线检查任务，其余时间不活跃，更隐蔽
// 2. Beacon 模式的优势：
//    - 网络流量更稀疏，降低被检测概率
//    - Agent 进程不活跃时不会消耗 CPU
//    - 适合长期潜伏（weeks/months）
// 3. Beacon 的配置：
//    - Check-in interval: 上线间隔 (60s, 300s, 3600s 等)
//    - Jitter: 抖动百分比 (如 25% = 间隔在 75%-125% 之间随机)
//    - Max tasks per check-in: 每次上线最多获取的任务数
package beacon

import (
	"crypto/rand"
	"math"
	"time"
)

// Config 是 Beacon 模式的配置。
type Config struct {
	Mode              Mode          // Session 或 Beacon
	CheckinInterval   time.Duration // Beacon 模式下的上线间隔
	Jitter            float64       // 抖动比例 (0.0 - 1.0)
	MaxTasksPerCheck  int           // 每次上线最多获取任务数
	KillDate          time.Time     // 自毁日期
	WorkingHours      WorkingHours  // 工作时间段
}

// Mode 定义 Agent 运行模式。
type Mode int

const (
	ModeSession Mode = iota // 交互式 Session（默认）
	ModeBeacon              // 周期性 Beacon
)

// WorkingHours 定义允许上线的时间段。
type WorkingHours struct {
	StartHour int // 开始小时 (0-23)
	StartMin  int // 开始分钟 (0-59)
	EndHour   int // 结束小时 (0-23)
	EndMin    int // 结束分钟 (0-59)
}

// NewSessionConfig 创建默认的 Session 模式配置。
func NewSessionConfig() *Config {
	return &Config{
		Mode:            ModeSession,
		CheckinInterval: 60 * time.Second,
		Jitter:          0.1,
		MaxTasksPerCheck: 10,
	}
}

// NewBeaconConfig 创建 Beacon 模式配置。
func NewBeaconConfig(interval time.Duration, jitter float64) *Config {
	return &Config{
		Mode:            ModeBeacon,
		CheckinInterval: interval,
		Jitter:          jitter,
		MaxTasksPerCheck: 5,
	}
}

// NextCheckin 计算下一次上线的时间。
// 借鉴 Cobalt Strike 的 jitter 计算：
// sleep_time * (1 - jitter/2) 到 sleep_time * (1 + jitter/2)
func (c *Config) NextCheckin() time.Duration {
	base := c.CheckinInterval
	if c.Jitter > 0 {
		// Cobalt Strike jitter: sleep * (1-jitter) ~ sleep * (1+jitter)
		minFactor := 1.0 - c.Jitter
		maxFactor := 1.0 + c.Jitter
		factor := minFactor + randFloat64()*(maxFactor-minFactor)
		return time.Duration(float64(base) * factor)
	}
	return base
}

// randFloat64 returns a cryptographically secure random float in [0,1).
func randFloat64() float64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0.5 // fallback
	}
	return float64(uint64(b[0])<<56|uint64(b[1])<<48|uint64(b[2])<<40|uint64(b[3])<<32|
		uint64(b[4])<<24|uint64(b[5])<<16|uint64(b[6])<<8|uint64(b[7])) / float64(math.MaxUint64+1)
}

// IsKillDate 检查是否超过自毁日期。
func (c *Config) IsKillDate() bool {
	if c.KillDate.IsZero() {
		return false
	}
	return time.Now().After(c.KillDate)
}

// InWorkingHours 检查当前是否在工作时间段内。
// 支持跨午夜场景（如 22:00 - 06:00 夜班）。
func (c *Config) InWorkingHours() bool {
	wh := c.WorkingHours
	if wh.StartHour == 0 && wh.StartMin == 0 && wh.EndHour == 0 && wh.EndMin == 0 {
		return true // 未配置
	}

	now := time.Now()
	currentMin := now.Hour()*60 + now.Minute()
	startMin := wh.StartHour*60 + wh.StartMin
	endMin := wh.EndHour*60 + wh.EndMin

	if startMin <= endMin {
		// 正常区间：如 09:00-18:00
		return currentMin >= startMin && currentMin <= endMin
	}
	// 跨午夜：如 22:00-06:00 → [1320, 1440) ∪ [0, 360]
	return currentMin >= startMin || currentMin <= endMin
}

// WaitUntilWorkingHours 等待到下一个工作时间段。
func (c *Config) WaitUntilWorkingHours() {
	if c.InWorkingHours() {
		return
	}

	wh := c.WorkingHours
	now := time.Now()
	currentMin := now.Hour()*60 + now.Minute()
	startMin := wh.StartHour*60 + wh.StartMin

	var waitMin int
	if currentMin < startMin {
		waitMin = startMin - currentMin
	} else {
		waitMin = (24*60 - currentMin) + startMin
	}

	time.Sleep(time.Duration(waitMin) * time.Minute)
}

// SelfDestruct 模拟自毁行为。
// 完整实现：擦除内存中的敏感数据、删除文件、退出进程。
func (c *Config) SelfDestruct() {
	// 1. 清除所有密钥材料
	// 2. 清除内存中的任务结果
	// 3. 可选：删除自身可执行文件
	// 4. 退出进程
}
