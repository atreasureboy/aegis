// Package loot 提供捕获数据的持久化存储。
// 借鉴 Sliver 的 Loot 系统 — 存储从目标系统收集的凭证、文件、截图等敏感数据。
//
// 面试要点：
// 1. Loot 是 C2 框架中收集数据的集中存储区
// 2. 数据类型：密码哈希、票据、文件、截图、系统信息等
// 3. 存储方案：JSON 文件存储（简化版），生产环境应使用 SQLite
// 4. 安全考虑：Loot 数据应加密存储，访问需认证
package loot

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/aegis-c2/aegis/shared"
)

// LootType 定义 Loot 数据类型。
type LootType string

const (
	TypeCredential  LootType = "credential"
	TypeFile        LootType = "file"
	TypeScreenshot  LootType = "screenshot"
	TypeSystemInfo  LootType = "system_info"
	TypeProcessList LootType = "process_list"
	TypeNetworkInfo LootType = "network_info"
	TypeCustom      LootType = "custom"
)

// Loot 表示一条捕获的数据。
type Loot struct {
	ID        string    `json:"id"`
	AgentID   string    `json:"agent_id"`
	Type      LootType  `json:"type"`
	Name      string    `json:"name"`
	Filename  string    `json:"filename"`
	Data      []byte    `json:"data,omitempty"`
	DataPath  string    `json:"data_path,omitempty"` // 大数据存储路径
	Metadata  string    `json:"metadata"`            // JSON 格式的元数据
	CreatedAt time.Time `json:"created_at"`
	Host      string    `json:"host"`
	Username  string    `json:"username"`
}

// Credential 是凭证类型的 Loot 元数据。
type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Hash     string `json:"hash"`
	Domain   string `json:"domain"`
	Realm    string `json:"realm"`
}

// Store 是 Loot 存储后端。
type Store struct {
	mu   sync.RWMutex
	dir  string
	loot map[string]*Loot // id → Loot
}

// NewStore 创建 Loot 存储。
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create loot dir: %w", err)
	}

	store := &Store{
		dir:  dir,
		loot: make(map[string]*Loot),
	}

	// 加载已有数据
	if err := store.loadAll(); err != nil {
		return nil, fmt.Errorf("load loot: %w", err)
	}

	return store, nil
}

// Add 添加一条 Loot 记录。
func (s *Store) Add(loot *Loot) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 如果有大数据，写入文件
	if len(loot.Data) > 1048576 { // > 1MB
		path := filepath.Join(s.dir, loot.ID)
		if err := os.WriteFile(path, loot.Data, 0600); err != nil {
			return fmt.Errorf("write loot file: %w", err)
		}
		loot.DataPath = path
		loot.Data = nil // 不在内存中保留
	}

	s.loot[loot.ID] = loot
	return s.saveIndex()
}

// Get 按 ID 获取 Loot。
func (s *Store) Get(id string) (*Loot, error) {
	s.mu.RLock()
	loot, ok := s.loot[id]
	if !ok {
		s.mu.RUnlock()
		return nil, fmt.Errorf("loot not found: %s", id)
	}

	// Copy pointer-safe fields to return a snapshot
	result := &Loot{
		ID:        loot.ID,
		AgentID:   loot.AgentID,
		Type:      loot.Type,
		Name:      loot.Name,
		Filename:  loot.Filename,
		DataPath:  loot.DataPath,
		Metadata:  loot.Metadata,
		CreatedAt: loot.CreatedAt,
		Host:      loot.Host,
		Username:  loot.Username,
	}
	if loot.Data != nil {
		result.Data = make([]byte, len(loot.Data))
		copy(result.Data, loot.Data)
	}
	s.mu.RUnlock()

	// 如果数据在文件中，在锁外加载
	if result.DataPath != "" && len(result.Data) == 0 {
		data, err := os.ReadFile(result.DataPath)
		if err != nil {
			return nil, fmt.Errorf("read loot file: %w", err)
		}
		result.Data = data
	}

	return result, nil
}

// List 列出所有 Loot（可按类型过滤）。
func (s *Store) List(lootType *LootType, agentID string) []*Loot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*Loot
	for _, loot := range s.loot {
		if lootType != nil && loot.Type != *lootType {
			continue
		}
		if agentID != "" && loot.AgentID != agentID {
			continue
		}
		result = append(result, loot)
	}
	return result
}

// Delete 删除 Loot 记录及其数据文件。
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	loot, ok := s.loot[id]
	if !ok {
		return fmt.Errorf("loot not found: %s", id)
	}

	if loot.DataPath != "" {
		os.Remove(loot.DataPath)
	}

	delete(s.loot, id)
	return s.saveIndex()
}

// AddCredential 添加一条凭证 Loot。
func (s *Store) AddCredential(agentID, host, username, password, hash, domain string) error {
	cred := &Credential{
		Username: username,
		Password: password,
		Hash:     hash,
		Domain:   domain,
	}

	metadata, _ := json.Marshal(cred)
	id := generateID()

	return s.Add(&Loot{
		ID:        id,
		AgentID:   agentID,
		Type:      TypeCredential,
		Name:      fmt.Sprintf("Credential: %s@%s", username, host),
		Metadata:  string(metadata),
		CreatedAt: time.Now(),
		Host:      host,
	})
}

// AddFile 添加一个文件 Loot。
func (s *Store) AddFile(agentID, host, filename string, data []byte) error {
	id := generateID()

	return s.Add(&Loot{
		ID:        id,
		AgentID:   agentID,
		Type:      TypeFile,
		Name:      filename,
		Data:      data,
		CreatedAt: time.Now(),
		Host:      host,
	})
}

func (s *Store) loadAll() error {
	indexPath := filepath.Join(s.dir, "index.json")
	if _, err := os.Stat(indexPath); os.IsNotExist(err) {
		return nil // 无已有数据
	}

	data, err := os.ReadFile(indexPath)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &s.loot)
}

func (s *Store) saveIndex() error {
	indexPath := filepath.Join(s.dir, "index.json")
	data, err := json.MarshalIndent(s.loot, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(indexPath, data, 0600)
}

// generateID 生成唯一 ID（使用 crypto/rand）。
func generateID() string {
	return shared.GenID("loot")
}
