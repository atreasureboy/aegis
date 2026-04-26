package types

import (
	"fmt"
	"sync"
	"time"
)

// AgentState 定义了 Agent 的生命周期状态。
type AgentState string

const (
	StateOffline  AgentState = "offline"
	StateOnline   AgentState = "online"
	StateSuspect  AgentState = "suspect"    // 异常行为，即将熔断
	StateFused    AgentState = "fused"      // 已熔断，拒绝通信
)

// ValidTransitions 定义了允许的状态转换。
// 借鉴 Sliver 的状态机模型：只有明确定义的转换才是合法的。
var ValidTransitions = map[AgentState][]AgentState{
	StateOffline: {StateOnline},
	StateOnline:  {StateSuspect, StateOffline},
	StateSuspect: {StateOnline, StateFused, StateOffline},
	StateFused:   {StateOffline}, // 只能通过手动重置恢复
}

// IsValidTransition 检查状态转换是否合法。
func IsValidTransition(from, to AgentState) bool {
	allowed, ok := ValidTransitions[from]
	if !ok {
		return false
	}
	for _, s := range allowed {
		if s == to {
			return true
		}
	}
	return false
}

// Agent 表示一个已注册的 Agent 实例。
type Agent struct {
	ID            string     `json:"id"`
	Hostname      string     `json:"hostname"`
	OS            string     `json:"os"`
	Arch          string     `json:"arch"`
	Username      string     `json:"username"`
	PID           int        `json:"pid"`
	IP            string     `json:"ip"`
	State         AgentState `json:"state"`
	FirstSeen     time.Time  `json:"first_seen"`
	LastHeartbeat time.Time  `json:"last_heartbeat"`
	HeartbeatSeq  uint64     `json:"heartbeat_seq"`
	AESKey        []byte     `json:"-"`
	HMACKey       []byte     `json:"-"`
	RSAPublicKey  []byte     `json:"-"`
	FailCount     int        `json:"fail_count"`
	ProfileName   string     `json:"profile_name"`   // Agent 使用的 C2 Profile
	TransportType string     `json:"transport_type"` // http/websocket/grpc
	mu            sync.RWMutex
}

// TransitionState 尝试转换到目标状态，返回错误如果转换不合法。
func (a *Agent) TransitionState(to AgentState) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !IsValidTransition(a.State, to) {
		return fmt.Errorf("invalid state transition: %s → %s", a.State, to)
	}
	a.State = to
	return nil
}

// UpdateHeartbeat 更新心跳，重置失败计数和状态恢复。
func (a *Agent) UpdateHeartbeat() {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	a.LastHeartbeat = now
	a.FailCount = 0
	if a.State == StateSuspect {
		a.State = StateOnline
	}
}

// UpdateHeartbeatWithSeq 更新心跳并检查序列号连续性。
// 返回 (isOutOfOrder, error)，序列号乱序可能意味着重放攻击或 Agent 状态异常。
func (a *Agent) UpdateHeartbeatWithSeq(seq uint64) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// 序列号回退：拒绝更新（可能是重放攻击或 Agent 重启）
	if seq <= a.HeartbeatSeq && a.HeartbeatSeq > 0 {
		return true, fmt.Errorf("stale heartbeat seq: got %d, expected >%d", seq, a.HeartbeatSeq)
	}
	a.HeartbeatSeq = seq
	a.LastHeartbeat = time.Now()
	a.FailCount = 0
	if a.State == StateSuspect {
		a.State = StateOnline
	}
	return false, nil
}

// IncrFail 增加失败计数，超过阈值自动转换状态。
func (a *Agent) IncrFail() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.FailCount++

	// 自动状态转换
	if a.FailCount >= 3 && a.State == StateOnline {
		a.State = StateSuspect
	}
	return a.FailCount
}

// GetFailCount 返回失败计数。
func (a *Agent) GetFailCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.FailCount
}

// GetState 返回当前状态。
func (a *Agent) GetState() AgentState {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.State
}

// SetState 尝试通过状态机转换设置状态，失败时静默忽略非法转换。
func (a *Agent) SetState(s AgentState) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if IsValidTransition(a.State, s) {
		a.State = s
	}
}

// ForceState 强制设置状态，绕过状态机验证（仅限操作员手动干预）。
func (a *Agent) ForceState(s AgentState) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.State = s
}

// IsAlive 返回 Agent 是否处于活跃状态。
func (a *Agent) IsAlive() bool {
	s := a.GetState()
	return s == StateOnline || s == StateSuspect
}

// TimeSinceLastHeartbeat 返回距上次心跳的时间。
func (a *Agent) TimeSinceLastHeartbeat() time.Duration {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return time.Since(a.LastHeartbeat)
}

// SetAESKey 安全设置 AES 密钥（带写锁）。
func (a *Agent) SetAESKey(key []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.AESKey = make([]byte, len(key))
	copy(a.AESKey, key)
}

// GetAESKey 安全读取 AES 密钥（带读锁）。
func (a *Agent) GetAESKey() []byte {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.AESKey == nil {
		return nil
	}
	k := make([]byte, len(a.AESKey))
	copy(k, a.AESKey)
	return k
}

// SetHMACKey 安全设置 HMAC 密钥（带写锁）。
func (a *Agent) SetHMACKey(key []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.HMACKey = make([]byte, len(key))
	copy(a.HMACKey, key)
}

// GetHMACKey 安全读取 HMAC 密钥（带读锁）。
func (a *Agent) GetHMACKey() []byte {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.HMACKey == nil {
		return nil
	}
	k := make([]byte, len(a.HMACKey))
	copy(k, a.HMACKey)
	return k
}

// Reset 将 Agent 重置为离线状态（操作员手动操作）。
func (a *Agent) Reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.State = StateOffline
	a.FailCount = 0
}

// Task 表示一个待执行或已执行的任务。
type Task struct {
	ID        string    `json:"id"`
	AgentID   string    `json:"agent_id"`
	Command   string    `json:"command"`
	Args      string    `json:"args"`
	Timeout   int       `json:"timeout"`
	Priority  int       `json:"priority"`
	AuditTag  string    `json:"audit_tag"`
	Status    string    `json:"status"`     // pending | dispatched | completed | failed | fused
	CreatedAt time.Time `json:"created_at"`
	SentAt    time.Time `json:"sent_at"`
	Result    *Result   `json:"result,omitempty"`
	RetryCount int      `json:"retry_count"` // 重试次数
}

// ShouldRetry 判断任务是否应该重试（失败且未超过重试上限）。
func (t *Task) ShouldRetry(maxRetries int) bool {
	return t.Status == TaskFailed && t.RetryCount < maxRetries
}

// Retry 增加重试计数并重置状态。
func (t *Task) Retry() {
	t.RetryCount++
	t.Status = TaskPending
	t.SentAt = time.Time{}
}

// Result 是任务执行结果。
type Result struct {
	Status   string        `json:"status"`
	Stdout   []byte        `json:"stdout"`
	Stderr   []byte        `json:"stderr"`
	ExitCode int           `json:"exit_code"`
	Duration time.Duration `json:"duration"`
}

// TaskStatus 常量。
const (
	TaskPending    = "pending"
	TaskDispatched = "dispatched"
	TaskCompleted  = "completed"
	TaskFailed     = "failed"
	TaskFused      = "fused"
)
