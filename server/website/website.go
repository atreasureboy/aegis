// Package website 提供 HTTP 网站托管服务。
// 借鉴 Sliver 的 website (server/website/) — 托管 Payload、Stage、钓鱼页面等。
//
// 面试要点：
// 1. 用途：
//    - 托管 Staged Payload（Stage 0 从网站下载 Stage 1）
//    - 托管钓鱼页面（模仿公司登录页面）
//    - 托管合法内容掩盖 C2 服务器
// 2. Sliver 实现：server/website/ — 支持路径前缀、内容类型、自动响应
// 3. 安全考虑：
//    - 托管内容应看起来合法
//    - 支持自定义 404 页面（返回正常页面而非错误）
// 4. 与 C2 Profile 集成：
//    - 网站响应风格与 C2 流量一致
package website

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/aegis-c2/aegis/shared"
)

// Website 是一个 HTTP 内容托管站点。
type Website struct {
	ID          string
	Name        string
	Host        string // 监听的域名/IP
	Port        int
	Paths       map[string]*WebPath // 路径 → 内容
	Running     bool
	mu          sync.RWMutex
	server      *http.Server // 用于优雅关闭
}

// WebPath 是一个路径及其内容。
type WebPath struct {
	Path        string
	ContentType string // MIME 类型
	Data        []byte // 响应内容
	StatusCode  int    // HTTP 状态码
}

// Manager 管理所有网站托管。
type Manager struct {
	websites map[string]*Website
	mu       sync.RWMutex
}

// NewManager 创建网站管理器。
func NewManager() *Manager {
	return &Manager{
		websites: make(map[string]*Website),
	}
}

// Create 创建一个网站。
func (m *Manager) Create(name, host string, port int) *Website {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := generateID()
	ws := &Website{
		ID:     id,
		Name:   name,
		Host:   host,
		Port:   port,
		Paths:  make(map[string]*WebPath),
	}

	m.websites[id] = ws
	return ws
}

// AddPath 添加一个路径及其内容。
func (w *Website) AddPath(path, contentType string, data []byte, statusCode int) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.Paths[path] = &WebPath{
		Path:        path,
		ContentType: contentType,
		Data:        data,
		StatusCode:  statusCode,
	}
}

// RemovePath 移除一个路径。
func (w *Website) RemovePath(path string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.Paths, path)
}

// AddPayloadPath 添加 Stage Payload 路径。
func (w *Website) AddPayloadPath(name string, payload []byte) {
	w.AddPath("/"+name, "application/octet-stream", payload, http.StatusOK)
}

// AddHTMLPath 添加 HTML 页面路径（钓鱼页面）。
func (w *Website) AddHTMLPath(name string, html string) {
	w.AddPath("/"+name, "text/html; charset=utf-8", []byte(html), http.StatusOK)
}

// AddJSPath 添加 JavaScript 路径（模仿 CDN 脚本）。
func (w *Website) AddJSPath(name string, js string) {
	w.AddPath("/static/js/"+name, "application/javascript; charset=utf-8", []byte(js), http.StatusOK)
}

// Start 启动网站服务。
func (w *Website) Start() error {
	w.mu.Lock()
	if w.Running {
		w.mu.Unlock()
		return fmt.Errorf("website already running")
	}

	mux := http.NewServeMux()

	for path, content := range w.Paths {
		p := path
		c := content
		mux.HandleFunc(p, func(rw http.ResponseWriter, r *http.Request) {
			rw.Header().Set("Content-Type", c.ContentType)
			rw.WriteHeader(c.StatusCode)
			rw.Write(c.Data)
		})
	}

	// 404 处理 — 返回正常页面，不暴露 C2
	mux.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
		w.mu.RLock()
		defer w.mu.RUnlock()

		for path, content := range w.Paths {
			if strings.HasPrefix(r.URL.Path, path) {
				rw.Header().Set("Content-Type", content.ContentType)
				rw.WriteHeader(content.StatusCode)
				rw.Write(content.Data)
				return
			}
		}

		// 默认 404
		rw.WriteHeader(http.StatusNotFound)
		rw.Write([]byte("404 Not Found"))
	})

	w.server = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", w.Host, w.Port),
		Handler: mux,
	}
	w.Running = true
	w.mu.Unlock()

	go func() {
		if err := w.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[website] server error: %v", err)
			w.mu.Lock()
			w.Running = false
			w.mu.Unlock()
		}
	}()

	return nil
}

// Stop 停止网站。
func (w *Website) Stop() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.Running = false
	if w.server != nil {
		return w.server.Close()
	}
	return nil
}

// List 列出所有网站。
func (m *Manager) List() []*Website {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*Website
	for _, ws := range m.websites {
		result = append(result, ws)
	}
	return result
}

// Get 获取网站。
func (m *Manager) Get(id string) (*Website, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ws, ok := m.websites[id]
	if !ok {
		return nil, fmt.Errorf("website not found: %s", id)
	}
	return ws, nil
}

// Delete 删除网站。
func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.websites[id]; !ok {
		return fmt.Errorf("website not found: %s", id)
	}
	delete(m.websites, id)
	return nil
}

func generateID() string {
	return shared.GenID("web")
}
