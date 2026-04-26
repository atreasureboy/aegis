// Package canary 提供 DNS Canary 检测。
// 借鉴 Sliver 的 DNS Canary — 检测 Agent 是否被分析/逆向。
//
// 面试要点：
// 1. DNS Canary 原理：
//    - 在 Payload 中嵌入一个唯一域名（如 <unique_id>.canary.evil.com）
//    - 正常 Agent 不会解析此域名
//    - 如果安全分析人员在沙箱/虚拟机中运行 Payload，DNS 查询会被记录
//    - Server 监控 DNS 服务器的查询日志，发现查询即说明被分析
// 2. 工作流程：
//    - Payload 生成时创建唯一 canary 域名
//    - Server 注册 canary 到 DNS 服务器
//    - 当 canary 域名被查询时，Server 收到通知
//    - Server 标记对应 Payload 为"已暴露"
// 3. 触发场景：
//    - 安全产品自动 DNS 解析所有字符串
//    - 分析人员手动查询域名以追踪 C2
//    - 沙箱环境中的自动网络行为分析
// 4. 防御视角：
//    - 安全人员应先检查 Payload 中的 DNS 请求
//    - 使用本地 DNS 服务器或阻断 DNS 查询
//    - 不要直接执行未分析的陌生二进制
package canary

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Canary 是一个 DNS 金丝雀标记。
type Canary struct {
	ID        string    // 唯一标识
	Domain    string    // Canary 域名
	PayloadID string    // 关联的 Payload ID
	CreatedAt time.Time
	Triggered bool      // 是否已被查询
	TriggerAt *time.Time // 触发时间
	SourceIP  string    // 查询来源 IP
}

// CanaryDetector 检测 DNS Canary 触发。
type CanaryDetector struct {
	mu      sync.RWMutex
	canaries map[string]*Canary
	domain   string // 基础域名 (如 "canary.evil.com")
}

// NewCanaryDetector 创建 Canary 检测器。
func NewCanaryDetector(baseDomain string) *CanaryDetector {
	return &CanaryDetector{
		canaries: make(map[string]*Canary),
		domain:   baseDomain,
	}
}

// Generate 为指定 Payload 生成唯一 Canary。
func (d *CanaryDetector) Generate(payloadID string) (*Canary, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generate random: %w", err)
	}

	id := hex.EncodeToString(b)
	domain := fmt.Sprintf("%s.%s", id, d.domain)

	canary := &Canary{
		ID:        id,
		Domain:    domain,
		PayloadID: payloadID,
		CreatedAt: time.Now(),
	}

	d.canaries[id] = canary
	return canary, nil
}

// CheckDNSQuery 检查是否有 DNS 查询到达 Canary 域名。
// 这个方法由 DNS 服务器日志分析器调用。
func (d *CanaryDetector) CheckDNSQuery(queriedDomain, sourceIP string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	for id, canary := range d.canaries {
		if queriedDomain == canary.Domain ||
		   len(queriedDomain) > len(canary.ID) && queriedDomain[:len(canary.ID)] == canary.ID {
			canary.Triggered = true
			now := time.Now()
			canary.TriggerAt = &now
			canary.SourceIP = sourceIP

			// 从活跃列表中移除（已触发）
			delete(d.canaries, id)
			break
		}
	}
}

// List 列出所有 Canary 状态。
func (d *CanaryDetector) List() []*Canary {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var result []*Canary
	for _, c := range d.canaries {
		result = append(result, c)
	}
	return result
}

// Get 获取指定 Canary。
func (d *CanaryDetector) Get(id string) (*Canary, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	c, ok := d.canaries[id]
	if !ok {
		return nil, fmt.Errorf("canary not found: %s", id)
	}
	return c, nil
}

// Report 生成 Canary 状态报告。
func (d *CanaryDetector) Report() string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	active := 0
	triggered := 0
	for _, c := range d.canaries {
		if c.Triggered {
			triggered++
		} else {
			active++
		}
	}

	return fmt.Sprintf("DNS Canary Report:\n"+
		"  Active:     %d\n"+
		"  Triggered:  %d\n"+
		"  Total:      %d\n",
		active, triggered, active+triggered)
}
