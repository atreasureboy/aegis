// Package event 提供发布-订阅事件系统。
// 借鉴 Sliver 的 events.go — Agent 上线/离线、任务提交/完成等操作符事件广播。
//
// 面试要点：
// 1. 事件系统是 C2 框架的"神经系统" — 所有组件通过事件通信
// 2. Pub-Sub 模式：Publisher 发布事件，Subscriber 接收感兴趣的事件
// 3. 应用场景：
//    - GUI 客户端实时更新 Agent 列表
//    - 多操作符之间的状态同步
//    - Webhook 通知触发
//    - 审计日志记录
// 4. Sliver 实现：sliver/server/core/events.go — EventBroker 结构体
package event

import (
	"encoding/json"
	"log"
	"sync"
	"time"
)

// Type 定义事件类型。
type Type string

const (
	AgentOnline        Type = "agent_online"
	AgentOffline       Type = "agent_offline"
	AgentHeartbeat     Type = "agent_heartbeat"
	TaskSubmitted      Type = "task_submitted"
	TaskCompleted      Type = "task_completed"
	TaskFailed         Type = "task_failed"
	OperatorJoin       Type = "operator_join"
	OperatorLeave      Type = "operator_leave"
	LootAdded          Type = "loot_added"
	CanaryTriggered    Type = "canary_triggered"
	CircuitBreakerTrip Type = "circuit_breaker_trip"
)

// Event 是一个结构化事件。
type Event struct {
	ID        string                 `json:"id"`
	Type      Type                   `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	AgentID   string                 `json:"agent_id,omitempty"`
	TaskID    string                 `json:"task_id,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Source    string                 `json:"source"` // 事件来源
}

// Broker 是事件总线。
type Broker struct {
	mu          sync.RWMutex
	subscribers map[Type]map[string]chan *Event // type → subscriberID → channel
	history     []*Event                        // 最近 N 条事件
	maxHistory  int
	dropped     int // 丢弃事件计数
}

// NewBroker 创建事件总线。
func NewBroker(maxHistory int) *Broker {
	return &Broker{
		subscribers: make(map[Type]map[string]chan *Event),
		history:     make([]*Event, 0, maxHistory),
		maxHistory:  maxHistory,
	}
}

// Subscribe 订阅指定类型的事件。
func (b *Broker) Subscribe(eventType Type, subscriberID string) (<-chan *Event, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, ok := b.subscribers[eventType]; !ok {
		b.subscribers[eventType] = make(map[string]chan *Event)
	}

	ch := make(chan *Event, 64)
	b.subscribers[eventType][subscriberID] = ch
	return ch, nil
}

// Unsubscribe 取消订阅。
func (b *Broker) Unsubscribe(eventType Type, subscriberID string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if subs, ok := b.subscribers[eventType]; ok {
		if ch, exists := subs[subscriberID]; exists {
			close(ch)
			delete(subs, subscriberID)
		}
	}
}

// UnsubscribeAll 取消某订阅者的所有订阅。
func (b *Broker) UnsubscribeAll(subscriberID string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, subs := range b.subscribers {
		if ch, ok := subs[subscriberID]; ok {
			close(ch)
			delete(subs, subscriberID)
		}
	}
}

// SubscribeAll 订阅所有类型的事件（通过通配符）。
func (b *Broker) SubscribeAll(subscriberID string) (<-chan *Event, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := make(chan *Event, 256)
	if _, ok := b.subscribers["*"]; !ok {
		b.subscribers["*"] = make(map[string]chan *Event)
	}
	b.subscribers["*"][subscriberID] = ch
	return ch, nil
}

// Publish 发布一个事件。
func (b *Broker) Publish(event *Event) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// 记录到历史
	if len(b.history) >= b.maxHistory {
		// Compact the backing array instead of slicing (prevents memory leak)
		copy(b.history, b.history[1:])
		b.history = b.history[:len(b.history)-1]
	}
	b.history = append(b.history, event)

	// 广播给订阅者 (Type 匹配 + 通配符订阅)
	if subs, ok := b.subscribers[event.Type]; ok {
		for _, ch := range subs {
			select {
			case ch <- event:
			default:
				b.dropped++
				log.Printf("[event] dropped event %s (type=%s subscriber channel full, total_dropped=%d)",
					event.ID, event.Type, b.dropped)
			}
		}
	}
	// 广播给通配符订阅者
	if wildcard, ok := b.subscribers["*"]; ok {
		for _, ch := range wildcard {
			select {
			case ch <- event:
			default:
				b.dropped++
				log.Printf("[event] dropped event %s (wildcard subscriber channel full, total_dropped=%d)",
					event.ID, b.dropped)
			}
		}
	}
}

// PublishJSON 从 JSON 字符串发布事件。
func (b *Broker) PublishJSON(jsonStr string) error {
	var event Event
	if err := json.Unmarshal([]byte(jsonStr), &event); err != nil {
		return err
	}
	event.Timestamp = time.Now()
	b.Publish(&event)
	return nil
}

// History 获取最近的事件。
func (b *Broker) History(n int) []*Event {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if n > len(b.history) {
		n = len(b.history)
	}
	result := make([]*Event, n)
	copy(result, b.history[len(b.history)-n:])
	return result
}

// AgentOnlineEvent 快捷创建 Agent 上线事件。
func AgentOnlineEvent(agentID, hostname, os, arch string) *Event {
	return &Event{
		Type:      AgentOnline,
		Timestamp: time.Now(),
		AgentID:   agentID,
		Source:    "agent",
		Data: map[string]interface{}{
			"hostname": hostname,
			"os":       os,
			"arch":     arch,
		},
	}
}

// TaskCompletedEvent 快捷创建任务完成事件。
func TaskCompletedEvent(agentID, taskID string, exitCode int) *Event {
	return &Event{
		Type:      TaskCompleted,
		Timestamp: time.Now(),
		AgentID:   agentID,
		TaskID:    taskID,
		Source:    "agent",
		Data: map[string]interface{}{
			"exit_code": exitCode,
		},
	}
}
