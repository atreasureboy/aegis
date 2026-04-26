// Package profile 提供 Server 端的 Profile 验证。
// 验证传入的 Agent 请求是否符合当前激活的 C2 Profile 定义的特征。
// 不符合 Profile 的请求可能是安全分析人员的探测或重放攻击。
package profile

import (
	"net/http"
	"strings"
	"sync"
)

// Validator 验证 HTTP 请求是否符合 C2 Profile 定义的特征。
type Validator struct {
	mu      sync.RWMutex
	profile *C2Profile
}

// NewValidator 创建一个新的 Profile 验证器。
func NewValidator(p *C2Profile) *Validator {
	return &Validator{profile: p}
}

// UpdateProfile 更新验证器使用的 Profile（用于热加载场景）。
func (v *Validator) UpdateProfile(p *C2Profile) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.profile = p
}

// ValidationResult 包含验证结果。
type ValidationResult struct {
	Valid  bool
	Reason string // 如果不合法，说明原因
	Score  int    // 匹配得分（0-100）
}

// Validate 检查 HTTP 请求是否符合 Profile 定义的特征。
// 返回验证结果，不合法时不立即拒绝（避免暴露检测能力）。
func (v *Validator) Validate(r *http.Request) ValidationResult {
	v.mu.RLock()
	p := v.profile
	v.mu.RUnlock()

	if p == nil {
		return ValidationResult{Valid: true, Score: 50, Reason: "no profile loaded"}
	}

	score := 0
	maxScore := 0
	var failures []string

	httpCfg := p.HTTP

	// 1. 检查 User-Agent
	maxScore += 25
	if httpCfg.UserAgent != "" {
		ua := r.Header.Get("User-Agent")
		if ua != "" {
			if ua == httpCfg.UserAgent {
				score += 25
			} else if strings.Contains(ua, "Mozilla") || strings.Contains(ua, "Chrome") {
				// 至少是浏览器 UA，部分匹配
				score += 10
			} else {
				failures = append(failures, "suspicious user-agent")
			}
		}
	} else {
		score += 25 // no UA requirement
	}

	// 2. 检查自定义 Header
	maxScore += 25
	if len(httpCfg.Headers) > 0 {
		allMatch := true
		for key, expectedVal := range httpCfg.Headers {
			actualVal := r.Header.Get(key)
			if actualVal == "" {
				allMatch = false
				break
			}
			if !strings.EqualFold(actualVal, expectedVal) {
				allMatch = false
				break
			}
		}
		if allMatch {
			score += 25
		} else {
			failures = append(failures, "custom headers mismatch")
		}
	} else {
		score += 25 // no custom header requirement
	}

	// 3. 检查 Cookie
	maxScore += 20
	if httpCfg.CookieName != "" {
		cookie, err := r.Cookie(httpCfg.CookieName)
		if err == nil && cookie.Value != "" {
			score += 20
		} else {
			failures = append(failures, "missing expected cookie: "+httpCfg.CookieName)
		}
	} else {
		score += 20 // no cookie requirement
	}

	// 4. 检查请求方法
	maxScore += 15
	if httpCfg.Method != "" {
		if strings.EqualFold(r.Method, httpCfg.Method) {
			score += 15
		} else {
			failures = append(failures, "http method mismatch")
		}
	} else {
		score += 15 // no method requirement
	}

	// 5. 检查路径（仅对非 API 路径进行检查）
	// Agent 的 /register /heartbeat /poll /result 是固定端点，
	// Profile path 仅影响 /api/v1/analytics 等代理路由路径
	maxScore += 15
	if httpCfg.Path != "" {
		// 核心 API 端点不参与路径验证 — 它们是固定路由，不受 profile path 约束
		isCoreAPI := r.URL.Path == "/register" ||
			r.URL.Path == "/heartbeat" ||
			r.URL.Path == "/poll" ||
			r.URL.Path == "/result"
		if isCoreAPI {
			score += 15 // 核心端点自动通过路径检查
		} else if r.URL.Path == httpCfg.Path {
			score += 15
		} else {
			failures = append(failures, "path mismatch")
		}
	} else {
		score += 15 // no path requirement
	}

	// 计算百分比
	pct := 0
	if maxScore > 0 {
		pct = (score * 100) / maxScore
	}

	return ValidationResult{
		Valid:  pct >= 85,
		Reason: strings.Join(failures, "; "),
		Score:  pct,
	}
}

// IsHoneyCheck 返回是否需要返回蜂蜜响应（低分但不拒绝）。
// 用于记录潜在的探测行为。
func (r ValidationResult) IsHoneyCheck() bool {
	return r.Score >= 30 && r.Score < 85
}
