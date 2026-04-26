// Package stage 提供 Stage2 注册表，管理分离式交付的二阶段荷载信息。
package stage

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
)

// Entry 存储单个 Stage2 的注册信息。
type Entry struct {
	ID          string // "s2-xxxx"
	ExternalURL string // 外部下载地址（CDN/文件服务器）
	AESKeyHex   string // AES-GCM 密钥 hex
}

// Registry 是 Stage2 的内存注册表。
// Stage1 运行时从此注册表获取 stage2 的下载 URL + AES 密钥。
type Registry struct {
	mu      sync.RWMutex
	entries map[string]*Entry
}

// NewRegistry 创建空的 Stage2 注册表。
func NewRegistry() *Registry {
	return &Registry{
		entries: make(map[string]*Entry),
	}
}

// Register 注册一个新的 Stage2，返回生成的 Entry。
func (r *Registry) Register(externalURL, aesKeyHex string) (*Entry, error) {
	if externalURL == "" {
		return nil, fmt.Errorf("external URL is required")
	}
	if aesKeyHex == "" {
		return nil, fmt.Errorf("AES key is required")
	}

	id := genStageID()
	entry := &Entry{
		ID:          id,
		ExternalURL: externalURL,
		AESKeyHex:   aesKeyHex,
	}

	r.mu.Lock()
	r.entries[id] = entry
	r.mu.Unlock()

	return entry, nil
}

// Get 按 ID 查询 Stage2 信息。
func (r *Registry) Get(id string) (*Entry, bool) {
	r.mu.RLock()
	e, ok := r.entries[id]
	r.mu.RUnlock()
	return e, ok
}

// List 返回所有已注册的 Stage2。
func (r *Registry) List() []*Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Entry, 0, len(r.entries))
	for _, e := range r.entries {
		out = append(out, e)
	}
	return out
}

// Delete 移除指定 Stage2。
func (r *Registry) Delete(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.entries[id]; !ok {
		return false
	}
	delete(r.entries, id)
	return true
}

// GetLatest 返回最近注册的一个 Stage2（供默认 stage1 使用）。
// 如果没有任何注册则返回 nil。
func (r *Registry) GetLatest() *Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.entries) == 0 {
		return nil
	}
	var latest *Entry
	for _, e := range r.entries {
		if latest == nil || e.ID > latest.ID {
			latest = e
		}
	}
	return latest
}

// genStageID 生成 "s2-xxxx" 格式的 ID。
func genStageID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return "s2-" + hex.EncodeToString(b)
}
