// Package profile 提供 C2 Profile 管理。
// 借鉴 Sliver 的 C2 配置和 Havoc 的 Profile 系统 — 定义 C2 通信的流量特征。
//
// 面试要点：
// 1. C2 Profile 定义了 C2 流量的外观（HTTP 头、URI 路径、编码方式等）
// 2. 目的：让 C2 流量看起来像正常流量（如 Google Analytics、CDN 请求）
// 3. Malleable C2 (Cobalt Strike 概念)：
//    - 可配置 User-Agent、HTTP 头、Cookie 名称
//    - 可配置 URI 路径和请求方法
//    - 支持数据编码变换（Base64/NetBIOS/参数名变换）
// 4. 防御视角：
//    - 检测异常的 HTTP 头（如异常大的 Cookie）
//    - 检测固定的 User-Agent 模式
//    - JA3/JA4 TLS 指纹检测
package profile

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"time"
)

// C2Profile 定义 C2 通信的流量特征。
type C2Profile struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	HTTP        HTTPConfig   `json:"http"`
	DNS         DNSConfig    `json:"dns"`
	MTLS        MTLSConfig   `json:"mtls"`
}

// HTTPConfig 定义 HTTP C2 的流量特征。
type HTTPConfig struct {
	Method     string            `json:"method"`       // GET/POST
	Path       string            `json:"path"`         // 请求路径
	UserAgent  string            `json:"user_agent"`   // User-Agent 头
	Headers    map[string]string `json:"headers"`      // 自定义请求头
	CookieName string            `json:"cookie_name"`  // Cookie 中的字段名
	ParamName  string            `json:"param_name"`   // URL 参数名
	DataTransform string         `json:"data_transform"` // 数据编码方式
	MaxBodySize  int              `json:"max_body_size"`  // 最大响应体大小

	// ProbabilisticHeaders: 每请求随机注入 1-N 个额外头。
	// key=头名称, value=可选值列表（随机选一个）。
	ProbabilisticHeaders map[string][]string `json:"probabilistic_headers,omitempty"`
}

// DNSConfig 定义 DNS C2 的配置。
type DNSConfig struct {
	Domain     string `json:"domain"`
	Nameserver string `json:"nameserver"`
	RecordType string `json:"record_type"` // A or TXT
}

// MTLSConfig 定义 mTLS C2 的配置。
type MTLSConfig struct {
	BindAddress string `json:"bind_address"`
	Port        int    `json:"port"`
}

// DefaultProfile 返回默认的 C2 Profile（模仿正常 HTTP 流量）。
func DefaultProfile() *C2Profile {
	return &C2Profile{
		Name:        "default",
		Description: "Default HTTP C2 profile",
		HTTP: HTTPConfig{
			Method:     "POST",
			Path:       "/api/v1/analytics",
			UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			Headers:    map[string]string{"Accept": "application/json", "Content-Type": "application/json"},
			CookieName: "session_id",
			ParamName:  "data",
			DataTransform: "base64",
			MaxBodySize:  1048576,
		},
	}
}

// GoogleAnalyticsProfile 模仿 Google Analytics 流量。
// 这是 Cobalt Strike 和 Sliver 都支持的经典 Profile 模板。
func GoogleAnalyticsProfile() *C2Profile {
	return &C2Profile{
		Name:        "google_analytics",
		Description: "Mimics Google Analytics traffic pattern",
		HTTP: HTTPConfig{
			Method:    "GET",
			Path:      "/collect",
			UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			Headers: map[string]string{
				"Accept":          "*/*",
				"Accept-Language": "en-US,en;q=0.9",
				"Referer":         "https://www.google.com/",
			},
			CookieName:    "_ga",
			ParamName:     "v",
			DataTransform: "base64-url",
			MaxBodySize:   512000,
		},
	}
}

// CDNProfile 模仿 CDN 资源请求。
func CDNProfile() *C2Profile {
	return &C2Profile{
		Name:        "cdn_static",
		Description: "Mimics CDN static asset requests",
		HTTP: HTTPConfig{
			Method:    "GET",
			Path:      "/static/js/bundle.min.js",
			UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			Headers: map[string]string{
				"Accept":          "application/javascript",
				"Accept-Encoding": "gzip, deflate, br",
				"Cache-Control":   "no-cache",
			},
			CookieName:    "cf_clearance",
			ParamName:     "v",
			DataTransform: "base64",
			MaxBodySize:   2097152,
		},
	}
}

// LoadProfile 从 JSON 文件加载 C2 Profile。
func LoadProfile(path string) (*C2Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read profile: %w", err)
	}

	var profile C2Profile
	if err := json.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("parse profile: %w", err)
	}
	return &profile, nil
}

// SaveProfile 将 C2 Profile 保存为 JSON 文件。
func (p *C2Profile) SaveProfile(path string) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal profile: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// ApplyToHeaders 将 Profile 中的 HTTP 头应用到请求头映射中。
func (p *C2Profile) ApplyToHeaders(headers map[string]string) {
	for k, v := range p.HTTP.Headers {
		headers[k] = v
	}
	headers["User-Agent"] = p.HTTP.UserAgent
}

// RandomizeHeaders 从 ProbabilisticHeaders 中随机选 0-N 个注入到 headers。
// 每个请求调用一次，产生不同的头组合。
func (p *C2Profile) RandomizeHeaders(headers map[string]string) {
	if len(p.HTTP.ProbabilisticHeaders) == 0 {
		return
	}

	pool := p.HTTP.ProbabilisticHeaders
	count := rand.Intn(len(pool) + 1)
	if count == 0 {
		return
	}

	// Fisher-Yates shuffle 后取前 count 个，确保真正的随机选择
	keys := make([]string, 0, len(pool))
	for k := range pool {
		keys = append(keys, k)
	}
	for i := len(keys) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		keys[i], keys[j] = keys[j], keys[i]
	}

	for _, k := range keys[:count] {
		values := pool[k]
		if len(values) > 0 {
			headers[k] = values[rand.Intn(len(values))]
		}
	}
}

// BuiltInProfiles 返回所有内置 Profile。
var BuiltInProfiles = map[string]func() *C2Profile{
	"default":           DefaultProfile,
	"google_analytics":  GoogleAnalyticsProfile,
	"cdn_static":        CDNProfile,
}

// Manager 管理多个 C2 Profile。
type Manager struct {
	mu        sync.RWMutex
	profiles  map[string]*C2Profile
	active    string // 当前激活的 profile
	watchers  map[string]*fileWatcher // 文件路径 → 监控器
	done      chan struct{}
}

// fileWatcher 监控文件变更。
type fileWatcher struct {
	path     string
	name     string
	modTime  time.Time
	interval time.Duration
}

// NewManager 创建一个新的 Profile 管理器。
func NewManager() *Manager {
	m := &Manager{
		profiles: make(map[string]*C2Profile),
		active:   "default",
	}
	// 加载所有内置 Profile
	for name, fn := range BuiltInProfiles {
		m.profiles[name] = fn()
	}
	return m
}

// Register 注册一个自定义 Profile。
func (m *Manager) Register(name string, p *C2Profile) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.profiles[name] = p
}

// Get 获取指定名称的 Profile。
func (m *Manager) Get(name string) (*C2Profile, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.profiles[name]
	return p, ok
}

// Active 返回当前激活的 Profile。
func (m *Manager) Active() *C2Profile {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.profiles[m.active]
	if !ok || p == nil {
		return DefaultProfile()
	}
	return p
}

// SetActive 设置当前激活的 Profile。
func (m *Manager) SetActive(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.profiles[name]; ok {
		m.active = name
		return true
	}
	return false
}

// List 返回所有已注册的 Profile 名称。
func (m *Manager) List() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	names := make([]string, 0, len(m.profiles))
	for name := range m.profiles {
		names = append(names, name)
	}
	return names
}

// LoadFromFile 从文件加载 Profile 并注册。
func (m *Manager) LoadFromFile(name, path string) error {
	p, err := LoadProfile(path)
	if err != nil {
		return err
	}
	m.Register(name, p)
	return nil
}

// WatchAndReload 启动 Profile 文件监控，检测到变更时自动热加载。
func (m *Manager) WatchAndReload(interval time.Duration) {
	if m.done == nil {
		m.done = make(chan struct{})
	}
	m.mu.Lock()
	if m.watchers == nil {
		m.watchers = make(map[string]*fileWatcher)
	}
	m.mu.Unlock()

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-m.done:
				return
			case <-ticker.C:
				m.checkAndReload()
			}
		}
	}()
}

// AddWatch 添加一个需要监控的 Profile 文件。
func (m *Manager) AddWatch(name, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat profile file: %w", err)
	}

	// 先加载
	if err := m.LoadFromFile(name, path); err != nil {
		return err
	}

	m.mu.Lock()
	m.watchers[name] = &fileWatcher{
		path:     path,
		name:     name,
		modTime:  info.ModTime(),
		interval: 10 * time.Second,
	}
	m.mu.Unlock()

	return nil
}

// checkAndReload 检查所有监控的文件是否有变更。
func (m *Manager) checkAndReload() {
	m.mu.RLock()
	watchers := make([]*fileWatcher, 0, len(m.watchers))
	for _, w := range m.watchers {
		watchers = append(watchers, w)
	}
	m.mu.RUnlock()

	for _, w := range watchers {
		info, err := os.Stat(w.path)
		if err != nil {
			continue
		}
		if info.ModTime().After(w.modTime) {
			// 文件变更，热加载
			p, err := LoadProfile(w.path)
			if err != nil {
				continue
			}
			m.mu.Lock()
			m.profiles[w.name] = p
			w.modTime = info.ModTime()
			m.mu.Unlock()
		}
	}
}

// StopWatching 停止文件监控。
func (m *Manager) StopWatching() {
	if m.done != nil {
		close(m.done)
	}
}
