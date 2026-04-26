// Package watcher 提供文件系统监控（类似 Sliver 的 filewatch）。
// 使用跨平台轮询策略（而非 OS 特定 API），避免 CGO 依赖且跨平台一致。
//
// 面试要点：
// 1. 轮询策略：定期快照文件状态（mtime+size），对比变化
// 2. 优点：无需 CGO、跨平台一致、实现简单
// 3. 缺点：延迟取决于轮询间隔、对大量文件目录性能较差
// 4. 生产级替代方案：ReadDirectoryChangesW (Windows), inotify (Linux), FSEvents (macOS)
package watcher

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// WatchEvent 描述一次文件系统变更。
type WatchEvent struct {
	Path    string    `json:"path"`
	Change  string    `json:"change"` // created, modified, deleted
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
}

// Watch 表示一个活跃的监控目标。
type Watch struct {
	ID       string
	Path     string
	Recursive bool
	Interval time.Duration
	stop     chan struct{}
	stopped  bool
}

// Manager 管理所有文件监控任务。
type Manager struct {
	mu       sync.Mutex
	watches  map[string]*Watch
	snapshots map[string]map[string]fileStat // watchID -> path -> stat
	events   map[string][]WatchEvent        // watchID -> pending events
}

type fileStat struct {
	Size    int64
	ModTime time.Time
	Exists  bool
}

// NewManager 创建新的文件监控管理器。
func NewManager() *Manager {
	return &Manager{
		watches:   make(map[string]*Watch),
		snapshots: make(map[string]map[string]fileStat),
		events:    make(map[string][]WatchEvent),
	}
}

// Add 添加新的监控目标。
func (m *Manager) Add(id, path string, recursive bool, interval time.Duration) (*Watch, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.watches[id]; exists {
		return nil, fmt.Errorf("watch %s already exists", id)
	}

	// 验证路径存在
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("invalid path: %v", err)
	}
	if _, err := os.Stat(absPath); err != nil {
		return nil, fmt.Errorf("path not accessible: %v", err)
	}

	w := &Watch{
		ID:        id,
		Path:      absPath,
		Recursive: recursive,
		Interval:  interval,
		stop:      make(chan struct{}),
	}
	m.watches[id] = w
	m.snapshots[id] = make(map[string]fileStat)
	m.events[id] = nil

	// 记录初始快照
	m.snapshot(id, absPath, recursive)

	go m.monitorLoop(w)
	return w, nil
}

// Stop 停止指定监控。
func (m *Manager) Stop(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	w, ok := m.watches[id]
	if !ok {
		return fmt.Errorf("watch %s not found", id)
	}
	if !w.stopped {
		close(w.stop)
		w.stopped = true
	}
	return nil
}

// Events 返回指定监控的待处理事件。
func (m *Manager) Events(id string) ([]WatchEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	evts, ok := m.events[id]
	if !ok {
		return nil, fmt.Errorf("watch %s not found", id)
	}
	m.events[id] = nil // 清空
	return evts, nil
}

// List 返回所有活跃监控。
func (m *Manager) List() []*Watch {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make([]*Watch, 0, len(m.watches))
	for _, w := range m.watches {
		result = append(result, w)
	}
	return result
}

func (m *Manager) monitorLoop(w *Watch) {
	ticker := time.NewTicker(w.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-w.stop:
			return
		case <-ticker.C:
			m.mu.Lock()
			if w.stopped {
				m.mu.Unlock()
				return
			}
			m.checkChanges(w)
			m.mu.Unlock()
		}
	}
}

func (m *Manager) snapshot(watchID, root string, recursive bool) map[string]fileStat {
	statMap := make(map[string]fileStat)
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !recursive && path != root {
			if dir, _ := filepath.Split(path); filepath.Clean(dir) != filepath.Clean(root) {
				return filepath.SkipDir
			}
		}
		statMap[path] = fileStat{
			Size:    info.Size(),
			ModTime: info.ModTime(),
			Exists:  true,
		}
		return nil
	})
	return statMap
}

func (m *Manager) checkChanges(w *Watch) {
	current := m.snapshot(w.ID, w.Path, w.Recursive)
	prev := m.snapshots[w.ID]

	// 检测创建和修改
	for path, curStat := range current {
		oldStat, exists := prev[path]
		if !exists {
			m.events[w.ID] = append(m.events[w.ID], WatchEvent{
				Path:    path,
				Change:  "created",
				Size:    curStat.Size,
				ModTime: curStat.ModTime,
			})
		} else if curStat.ModTime != oldStat.ModTime || curStat.Size != oldStat.Size {
			m.events[w.ID] = append(m.events[w.ID], WatchEvent{
				Path:    path,
				Change:  "modified",
				Size:    curStat.Size,
				ModTime: curStat.ModTime,
			})
		}
	}

	// 检测删除
	for path, oldStat := range prev {
		if _, exists := current[path]; !exists && oldStat.Exists {
			m.events[w.ID] = append(m.events[w.ID], WatchEvent{
				Path:    path,
				Change:  "deleted",
				Size:    oldStat.Size,
				ModTime: oldStat.ModTime,
			})
		}
	}

	m.snapshots[w.ID] = current
}
