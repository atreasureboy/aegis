// Package webhook 提供外部通知集成。
// 借鉴 Havoc 的 webhook 系统 — 将 C2 事件推送到 Discord/Slack 等外部服务。
//
// 面试要点：
// 1. Webhook 是事件驱动的 HTTP POST 通知
// 2. 应用场景：
//    - Agent 上线 → 发送通知到 Discord 频道
//    - 任务完成 → 发送结果摘要到 Slack
//    - 熔断器触发 → 紧急告警
// 3. Havoc 实现：teamserver/pkg/webhook/discord.go
// 4. 安全考虑：Webhook URL 包含认证令牌，需要加密存储
package webhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Provider 定义通知提供商。
type Provider string

const (
	Discord Provider = "discord"
	Slack   Provider = "slack"
	Webex   Provider = "webex"
	Custom  Provider = "custom"
)

// Config 是 Webhook 的配置。
type Config struct {
	Provider    Provider
	URL         string            // Webhook URL
	Events      []string          // 感兴趣的事件类型
	Username    string            // 显示用户名
	AvatarURL   string            // 头像 URL
	Headers     map[string]string // 自定义请求头
	Timeout     time.Duration
}

// Notifier 是 Webhook 通知器。
type Notifier struct {
	config *Config
	client *http.Client
}

// NewNotifier 创建 Webhook 通知器。
func NewNotifier(config *Config) *Notifier {
	return &Notifier{
		config: config,
		client: &http.Client{Timeout: config.Timeout},
	}
}

// allowedWebhookDomains 是允许发送 Webhook 的外部服务域名。
var allowedWebhookDomains = map[string]bool{
	"discord.com":       true,
	"discordapp.com":    true,
	"hooks.slack.com":   true,
	"slack.com":         true,
	"api.ciscospark.com": true,
	"webexapis.com":     true,
}

// validateWebhookURL 验证 Webhook URL 是否为合法的外部服务地址（防 SSRF）。
func validateWebhookURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("only https scheme allowed for webhooks")
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("empty host in webhook URL")
	}

	// DNS rebinding 防护：在发送时再次解析 IP 并验证
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() {
			return fmt.Errorf("webhook URL must not be a raw IP address")
		}
	}

	// 域名白名单：仅允许已知的外部 Webhook 服务
	allowed := false
	for domain := range allowedWebhookDomains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("webhook domain %q not in allowed list", host)
	}

	return nil
}

// Send 发送一条通知。
func (n *Notifier) Send(title, content string) error {
	if !n.isSubscribedToEvent(title) {
		return nil
	}

	if err := validateWebhookURL(n.config.URL); err != nil {
		return fmt.Errorf("webhook URL validation failed: %w", err)
	}

	// DNS rebinding 防护：解析实际 IP 并确认不是内部地址
	u, _ := url.Parse(n.config.URL)
	if addrs, err := net.LookupHost(u.Hostname()); err == nil {
		for _, addr := range addrs {
			if ip := net.ParseIP(addr); ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified()) {
				return fmt.Errorf("webhook DNS rebinding detected: %s resolved to %s", u.Hostname(), addr)
			}
		}
	}

	var payload interface{}
	switch n.config.Provider {
	case Discord:
		payload = n.discordPayload(title, content)
	case Slack:
		payload = n.slackPayload(title, content)
	case Webex:
		payload = n.webexPayload(title, content)
	case Custom:
		payload = map[string]string{
			"title":   title,
			"content": content,
			"time":    time.Now().Format(time.RFC3339),
		}
	default:
		payload = n.discordPayload(title, content)
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}

	req, err := http.NewRequest("POST", n.config.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create webhook request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range n.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned error: %d", resp.StatusCode)
	}

	return nil
}

// discordPayload 构建 Discord Webhook 消息。
func (n *Notifier) discordPayload(title, content string) map[string]interface{} {
	return map[string]interface{}{
		"username":  n.config.Username,
		"avatar_url": n.config.AvatarURL,
		"embeds": []map[string]interface{}{
			{
				"title":       title,
				"description": content,
				"color":       colorForEvent(title),
				"timestamp":   time.Now().Format(time.RFC3339),
				"footer": map[string]interface{}{
					"text": "Aegis C2",
				},
			},
		},
	}
}

// slackPayload 构建 Slack Webhook 消息。
func (n *Notifier) slackPayload(title, content string) map[string]interface{} {
	return map[string]interface{}{
		"text": fmt.Sprintf("*%s*\n%s", title, content),
		"username": n.config.Username,
		"icon_url": n.config.AvatarURL,
	}
}

// webexPayload 构建 Webex Teams 消息。
func (n *Notifier) webexPayload(title, content string) map[string]interface{} {
	return map[string]interface{}{
		"markdown": fmt.Sprintf("**%s**\n\n%s", title, content),
	}
}

// isSubscribedToEvent 检查是否订阅了此事件。
func (n *Notifier) isSubscribedToEvent(eventType string) bool {
	if len(n.config.Events) == 0 {
		return true // 无过滤，订阅所有事件
	}
	for _, e := range n.config.Events {
		if strings.EqualFold(e, eventType) {
			return true
		}
	}
	return false
}

// colorForEvent 根据事件类型返回颜色。
func colorForEvent(eventType string) int {
	switch {
	case strings.Contains(eventType, "online"):
		return 0x00FF00 // 绿色
	case strings.Contains(eventType, "offline"):
		return 0xFF0000 // 红色
	case strings.Contains(eventType, "completed"):
		return 0x0000FF // 蓝色
	case strings.Contains(eventType, "failed"):
		return 0xFF0000 // 红色
	case strings.Contains(eventType, "circuit"):
		return 0xFF6600 // 橙色
	default:
		return 0x888888 // 灰色
	}
}
