package types

import (
	"container/heap"
	"sync"
)

// AgentRegistry 管理所有已注册 Agent 的内存存储。
// 生产环境可替换为 DB，但 MVP 阶段用内存足够了。
type AgentRegistry struct {
	agents map[string]*Agent
	mu     sync.RWMutex
}

func NewAgentRegistry() *AgentRegistry {
	return &AgentRegistry{
		agents: make(map[string]*Agent),
	}
}

func (r *AgentRegistry) Register(a *Agent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.agents[a.ID] = a
}

func (r *AgentRegistry) Get(id string) (*Agent, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.agents[id]
	return a, ok
}

func (r *AgentRegistry) List() []*Agent {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]*Agent, 0, len(r.agents))
	for _, a := range r.agents {
		result = append(result, a)
	}
	return result
}

func (r *AgentRegistry) Remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.agents, id)
}

// --- TaskHeap: container/heap implementation for priority-based Task ordering ---

// TaskHeap 实现 container/heap.Interface，按 Priority 降序排列。
type TaskHeap []*Task

func (h TaskHeap) Len() int           { return len(h) }
func (h TaskHeap) Less(i, j int) bool { return h[i].Priority > h[j].Priority }
func (h TaskHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *TaskHeap) Push(x interface{}) {
	*h = append(*h, x.(*Task))
}

func (h *TaskHeap) Pop() interface{} {
	old := *h
	n := len(old)
	t := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	return t
}

// taskIndex 记录每个 task ID 在堆中的位置，用于快速查找。
// 但 Go 的 container/heap 不支持任意位置删除，
// 所以 Pop(agentID) 仍需 O(n) 查找 + O(n) remove。
// 主要优化在 Push: O(n log n) → O(log n)。

// TaskQueue 是一个按 Agent 分组的优先级任务队列。
// 每个 Agent 独立维护一个 TaskHeap，Pop 从该 Agent 的堆中取最高优先级任务。
type TaskQueue struct {
	heaps map[string]*TaskHeap // agentID → 该 Agent 的优先队列
	mu    sync.Mutex
}

func NewTaskQueue() *TaskQueue {
	return &TaskQueue{
		heaps: make(map[string]*TaskHeap),
	}
}

func (q *TaskQueue) Push(t *Task) {
	q.mu.Lock()
	defer q.mu.Unlock()

	h, ok := q.heaps[t.AgentID]
	if !ok {
		h = &TaskHeap{}
		heap.Init(h)
		q.heaps[t.AgentID] = h
	}
	heap.Push(h, t)
}

func (q *TaskQueue) Pop(agentID string) *Task {
	q.mu.Lock()
	defer q.mu.Unlock()

	h, ok := q.heaps[agentID]
	if !ok || h.Len() == 0 {
		return nil
	}

	// 从堆顶取出优先级最高的任务
	t := heap.Pop(h).(*Task)

	// 如果该 Agent 的堆已空，删除对应条目
	if h.Len() == 0 {
		delete(q.heaps, agentID)
	}
	return t
}

func (q *TaskQueue) sortByPriority() {
	// 不再需要，heap 自动维护顺序
}

// ForEach 遍历所有 Agent 队列中的任务。
func (q *TaskQueue) ForEach(fn func(*Task)) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, h := range q.heaps {
		for _, t := range *h {
			fn(t)
		}
	}
}
