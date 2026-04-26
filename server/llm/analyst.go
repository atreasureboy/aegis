// Package llm 提供 LLM 智能体集成，用于自动化后渗透分析。
// 服务端通过 OpenAI-compatible API 接入大模型，Agent 上报环境信息后，
// 智能体自动分析并推荐/生成最优攻击策略。
//
// 架构：
// 1. Agent 首次上线 → 发送环境指纹（OS/进程/补丁/网络）
// 2. LLM 智能体分析环境 → 生成 post-exploitation 计划
// 3. 操作者收到推荐 → 确认执行或自行决策
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Config 是 LLM 智能体的配置。
type Config struct {
	APIKey     string        // OpenAI-compatible API key
	BaseURL    string        // API 基础 URL（默认 https://api.openai.com/v1）
	Model      string        // 模型名称（默认 gpt-4o）
	Timeout    time.Duration // 请求超时
	MaxTokens  int           // 最大 token 数
	Temperature float64      // 创造性参数 (0-1)
}

// DefaultConfig 返回默认 LLM 配置。
func DefaultConfig() *Config {
	return &Config{
		BaseURL:    "https://api.openai.com/v1",
		Model:      "gpt-4o",
		Timeout:    30 * time.Second,
		MaxTokens:  2048,
		Temperature: 0.3, // 低创造性，偏好确定性回答
	}
}

// EnvFingerprint 是 Agent 上报的环境指纹。
type EnvFingerprint struct {
	AgentID    string   `json:"agent_id"`
	Hostname   string   `json:"hostname"`
	OS         string   `json:"os"`
	Arch       string   `json:"arch"`
	Username   string   `json:"username"`
	PID        int      `json:"pid"`
	Processes  []string `json:"processes,omitempty"`
	IPs        []string `json:"ips,omitempty"`
	Patches    []string `json:"patches,omitempty"`
	Antivirus  []string `json:"antivirus,omitempty"`
	Domain     string   `json:"domain,omitempty"`
	Locale     string   `json:"locale,omitempty"`
}

// AnalysisResult 是 LLM 智能体的分析结果。
type AnalysisResult struct {
	AgentID          string   `json:"agent_id"`
	RiskLevel        string   `json:"risk_level"`         // low/medium/high
	Environment      string   `json:"environment"`        // 环境描述
	AntivirusDetected []string `json:"av_detected,omitempty"`
	Recommendations  []string `json:"recommendations"`    // 推荐操作
	SuggestedTasks   []TaskSuggestion `json:"suggested_tasks"`
	Summary          string   `json:"summary"`
}

// TaskSuggestion 是 LLM 推荐的具体任务。
type TaskSuggestion struct {
	Command     string `json:"command"`      // 命令类型
	Args        string `json:"args"`         // 参数
	Priority    int    `json:"priority"`     // 1-5
	Reason      string `json:"reason"`       // 推荐理由
	RiskLevel   string `json:"risk_level"`   // 操作风险
}

// cachedEntry 是带 TTL 的缓存条目。
type cachedEntry struct {
	result    *AnalysisResult
	expiresAt time.Time
}

// Analyst 是 LLM 智能体分析器。
type Analyst struct {
	cfg    *Config
	client *http.Client
	mu     sync.Mutex
	cache  map[string]*cachedEntry // 缓存分析结果，带 TTL
	ttl    time.Duration           // 缓存过期时间
}

// NewAnalyst 创建 LLM 智能体分析器。
func NewAnalyst(cfg *Config) *Analyst {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	// SEC-5: 内部 URL 验证 — 防止 SSRF 即使外部 handler 验证被绕过
	if err := validateLLMURL(cfg.BaseURL); err != nil {
		// 配置了非法 URL，降级为无 LLM 模式（而非静默接受）
		cfg = nil
	}
	a := &Analyst{
		cfg: cfg,
		client: &http.Client{
			Timeout: cfg.Timeout,
		},
		cache: make(map[string]*cachedEntry),
		ttl:   30 * time.Minute, // 缓存 30 分钟过期
	}
	if cfg == nil {
		a.client = nil // nil client signals LLM unavailable
	}
	return a
}

// validateLLMURL 验证 LLM BaseURL 是否合法（HTTPS + 白名单域名 + 非内网 IP）。
func validateLLMURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("only https scheme allowed")
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() {
			return fmt.Errorf("LLM base_url must not point to private addresses")
		}
	}
	if host == "" {
		return fmt.Errorf("empty host")
	}
	return nil
}

// Analyze 发送环境指纹到 LLM，获取后渗透分析结果。
func (a *Analyst) Analyze(ctx context.Context, fp *EnvFingerprint) (*AnalysisResult, error) {
	if a.client == nil || a.cfg == nil {
		return nil, fmt.Errorf("LLM analyst not configured (invalid or missing base_url)")
	}
	a.mu.Lock()
	if entry, ok := a.cache[fp.AgentID]; ok && time.Now().Before(entry.expiresAt) {
		result := entry.result
		a.mu.Unlock()
		return result, nil
	}
	// 过期或无缓存，删除旧条目
	delete(a.cache, fp.AgentID)
	a.mu.Unlock()

	prompt := buildAnalysisPrompt(fp)

	reqBody := map[string]interface{}{
		"model": a.cfg.Model,
		"messages": []map[string]string{
			{
				"role":    "system",
				"content": systemPrompt,
			},
			{
				"role":    "user",
				"content": prompt,
			},
		},
		"max_tokens":  a.cfg.MaxTokens,
		"temperature": a.cfg.Temperature,
		"response_format": map[string]string{
			"type": "json_object",
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", a.cfg.BaseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.cfg.APIKey)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(respBody))
	}

	// 解析 LLM 响应
	var apiResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("parse API response: %w", err)
	}

	if len(apiResp.Choices) == 0 {
		return nil, fmt.Errorf("empty LLM response")
	}

	var result AnalysisResult
	if err := json.Unmarshal([]byte(apiResp.Choices[0].Message.Content), &result); err != nil {
		return nil, fmt.Errorf("parse LLM analysis: %w", err)
	}

	result.AgentID = fp.AgentID

	// 缓存结果（带 TTL）
	a.mu.Lock()
	a.cache[fp.AgentID] = &cachedEntry{
		result:    &result,
		expiresAt: time.Now().Add(a.ttl),
	}
	a.mu.Unlock()

	return &result, nil
}

// GetCached 获取缓存的分析结果（未过期时）。
func (a *Analyst) GetCached(agentID string) (*AnalysisResult, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	entry, ok := a.cache[agentID]
	if !ok || time.Now().After(entry.expiresAt) {
		delete(a.cache, agentID)
		return nil, false
	}
	return entry.result, true
}

// ClearCache 清除分析缓存。
func (a *Analyst) ClearCache() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cache = make(map[string]*cachedEntry)
}

const systemPrompt = `You are a C2 operation assistant. Your role is to analyze compromised host environments and recommend post-exploitation actions.

Respond ONLY with valid JSON in this exact schema:
{
  "risk_level": "low|medium|high",
  "environment": "brief description of the target environment",
  "av_detected": ["list of detected antivirus/EDR products"],
  "recommendations": ["list of strategic recommendations"],
  "suggested_tasks": [
    {"command": "task_type", "args": "parameters", "priority": 1-5, "reason": "why", "risk_level": "low|medium|high"}
  ],
  "summary": "executive summary"
}

Valid command types: shell, info, ls, cat, pwd, hostname, whoami, ps, upload, download, migrate, persist, elevate, enum_network, enum_domain, enum_creds, screenshot, keylog.

Be concise. Prioritize stealth over speed. Recommend lateral movement only after local enumeration is complete.`

func buildAnalysisPrompt(fp *EnvFingerprint) string {
	// N-P1-13: Sanitize user-controlled fields to prevent prompt injection.
	return fmt.Sprintf(`Analyze this compromised host:
AgentID: %s
Hostname: %s
OS: %s/%s
Username: %s (PID %d)
Processes: %v
IPs: %v
Patches: %v
Antivirus: %v
Domain: %s
Locale: %s`,
		sanitize(fp.AgentID), sanitize(fp.Hostname), sanitize(fp.OS), sanitize(fp.Arch),
		sanitize(fp.Username), fp.PID,
		sanitizeSlice(fp.Processes), sanitizeSlice(fp.IPs),
		sanitizeSlice(fp.Patches), sanitizeSlice(fp.Antivirus),
		sanitize(fp.Domain), sanitize(fp.Locale))
}

// sanitize removes characters that could be used for prompt injection.
func sanitize(s string) string {
	// Strip control characters and common injection markers
	s = strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, s)
	// Truncate to prevent oversized inputs
	if len(s) > 256 {
		s = s[:256]
	}
	return s
}

func sanitizeSlice(items []string) string {
	cleaned := make([]string, len(items))
	for i, item := range items {
		cleaned[i] = sanitize(item)
	}
	return fmt.Sprintf("%v", cleaned)
}
