package dispatcher

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/aegis-c2/aegis/server/db"
	"github.com/aegis-c2/aegis/server/event"
	"github.com/aegis-c2/aegis/shared"
	"github.com/aegis-c2/aegis/shared/protocol"
	"github.com/aegis-c2/aegis/shared/types"
)

// Dispatcher 负责任务的排队、派发和结果回收。
// 借鉴 Havoc 的简洁 dispatch 模型 + Sliver 的任务优先级。
type Dispatcher struct {
	queue       *types.TaskQueue
	results     map[string]*types.Result // taskID -> Result
	resultTime  map[string]time.Time     // taskID -> stored time (for cleanup)
	mu          sync.RWMutex
	database    *db.DB
	eventBroker *event.Broker

	// Async result persistence
	resultCh   chan *dbWriteTask
	resultDone chan struct{}

	// Result cleanup goroutine lifecycle
	cleanerStop  chan struct{} // closed to signal cleaner to stop
	cleanerDone  chan struct{} // closed when cleaner has exited

	// Result TTL
	resultTTL time.Duration
}

type dbWriteTask struct {
	taskID   string
	stdout   []byte
	stderr   []byte
	exitCode int
}

func NewDispatcher(database *db.DB, eventBroker *event.Broker) *Dispatcher {
	d := &Dispatcher{
		queue:       types.NewTaskQueue(),
		results:     make(map[string]*types.Result),
		resultTime:  make(map[string]time.Time),
		database:    database,
		eventBroker: eventBroker,
		resultTTL:   30 * time.Minute,
	}

	// Start async result writer
	d.resultCh = make(chan *dbWriteTask, 256)
	d.resultDone = make(chan struct{})
	d.cleanerStop = make(chan struct{})
	d.cleanerDone = make(chan struct{})
	go d.resultWriter()

	// Start periodic result cleanup
	go d.resultCleaner()

	// Restore pending tasks from DB (survives server restart)
	if d.database != nil {
		pending, err := d.database.GetAllPendingTasks()
		if err != nil {
			log.Printf("[WARN] failed to restore pending tasks from db: %v", err)
		} else {
			for _, t := range pending {
				task := &types.Task{
					ID: t.ID, AgentID: t.AgentID, Command: t.Command, Args: t.Args,
					Timeout: 0, Priority: t.Priority, AuditTag: "",
					Status: t.State, CreatedAt: t.CreatedAt,
				}
				d.queue.Push(task)
			}
			if len(pending) > 0 {
				log.Printf("[dispatcher] restored %d pending tasks from DB", len(pending))
			}
		}
	}

	return d
}

// Submit 提交一个任务到队列。
func (d *Dispatcher) Submit(agentID, command, args string, timeout, priority int, auditTag string) *types.Task {
	d.mu.Lock()
	task := &types.Task{
		ID:        shared.GenID("task"),
		AgentID:   agentID,
		Command:   command,
		Args:      args,
		Timeout:   timeout,
		Priority:  priority,
		AuditTag:  auditTag,
		Status:    types.TaskPending,
		CreatedAt: time.Now(),
	}
	d.queue.Push(task)

	// 持久化到数据库
	if d.database != nil {
		if err := d.database.CreateTask(&db.Task{
			ID: task.ID, AgentID: task.AgentID, Command: task.Command,
			Args: task.Args, State: string(task.Status), Priority: task.Priority,
		}); err != nil {
			log.Printf("[WARN] failed to persist task to db: %v", err)
		}
	}
	d.mu.Unlock()

	// 发布事件（释放锁后执行，防止 eventBroker 锁排序死锁）
	if d.eventBroker != nil {
		d.eventBroker.Publish(&event.Event{
			Type:    event.TaskSubmitted,
			AgentID: agentID,
			TaskID:  task.ID,
			Source:  "dispatcher",
			Data: map[string]interface{}{
				"command": command,
				"args":    args,
			},
		})
	}

	return task
}

// NextTask 为指定 Agent 取出下一个待执行任务。
func (d *Dispatcher) NextTask(agentID string) *types.Task {
	d.mu.Lock()
	t := d.queue.Pop(agentID)
	if t != nil {
		t.Status = types.TaskDispatched
		t.SentAt = time.Now()
		// 同步 DB 状态
		if d.database != nil {
			if err := d.database.UpdateTaskState(t.ID, types.TaskDispatched); err != nil {
				log.Printf("[WARN] failed to update task state in db: %v", err)
			}
		}
	}
	d.mu.Unlock()
	return t
}

// SubmitResult 接收 Agent 回传的任务结果。
func (d *Dispatcher) SubmitResult(result *protocol.ResultPayload) {
	d.mu.Lock()
	d.results[result.TaskID] = &types.Result{
		Status:   result.Status,
		Stdout:   result.Stdout,
		Stderr:   result.Stderr,
		ExitCode: result.ExitCode,
		Duration: result.Duration,
	}
	d.resultTime[result.TaskID] = time.Now()

	// F-P1-3: Determine event type and DB write task while holding the lock,
	// but publish and enqueue AFTER releasing the lock to prevent deadlocks
	// with eventBroker (consistent with Submit's unlock-then-publish pattern).
	var evt *event.Event
	var dbTask *dbWriteTask
	if d.database != nil {
		dbTask = &dbWriteTask{
			taskID:   result.TaskID,
			stdout:   result.Stdout,
			stderr:   result.Stderr,
			exitCode: result.ExitCode,
		}
	}
	if d.eventBroker != nil {
		eType := event.TaskCompleted
		if result.ExitCode != 0 {
			eType = event.TaskFailed
		}
		evt = &event.Event{
			Type:    eType,
			AgentID: result.AgentID,
			TaskID:  result.TaskID,
			Source:  "dispatcher",
			Data: map[string]interface{}{
				"status":    result.Status,
				"exit_code": result.ExitCode,
			},
		}
	}
	d.mu.Unlock()

	// Enqueue DB write (outside lock) -- non-blocking with retry
	if d.database != nil && dbTask != nil {
		select {
		case d.resultCh <- dbTask:
		default:
			// Channel full: retry once with short delay before giving up
			go func(t *dbWriteTask) {
				select {
				case d.resultCh <- t:
				case <-time.After(5 * time.Second):
					log.Printf("[WARN] result channel full after 5s, DB persistence skipped for task %s", t.taskID)
				}
			}(dbTask)
		}
	}

	// Publish event (outside lock)
	if d.eventBroker != nil && evt != nil {
		d.eventBroker.Publish(evt)
	}
}

// GetResult 查询任务结果。
func (d *Dispatcher) GetResult(taskID string) (*types.Result, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	r, ok := d.results[taskID]
	return r, ok
}

// PendingCount 返回指定 Agent 的待执行任务数。
func (d *Dispatcher) PendingCount(agentID string) int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	count := 0
	d.queue.ForEach(func(t *types.Task) {
		if t.AgentID == agentID && t.Status == types.TaskPending {
			count++
		}
	})
	return count
}

// resultWriter 后台 goroutine，异步持久化任务结果。
func (d *Dispatcher) resultWriter() {
	defer close(d.resultDone)
	for task := range d.resultCh {
		if d.database != nil {
			if err := d.database.UpdateTaskResult(task.taskID, string(task.stdout), string(task.stderr), task.exitCode); err != nil {
				log.Printf("[WARN] failed to persist result: %v", err)
			}
		}
	}
}

// resultCleaner 定期清理过期结果。
// F-P1-4: Stop via cleanerStop channel when server shuts down.
func (d *Dispatcher) resultCleaner() {
	defer close(d.cleanerDone)
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-d.cleanerStop:
			return
		case <-ticker.C:
			d.mu.Lock()
			now := time.Now()
			for taskID, storedAt := range d.resultTime {
				if now.Sub(storedAt) > d.resultTTL {
					delete(d.results, taskID)
					delete(d.resultTime, taskID)
				}
			}
			d.mu.Unlock()
		}
	}
}

// Stop gracefully shuts down background goroutines (resultWriter + resultCleaner).
// F-P1-4: Call this during server shutdown to prevent goroutine leaks.
func (d *Dispatcher) Stop() {
	close(d.resultCh)
	close(d.cleanerStop)
	<-d.resultDone   // wait for writer to finish
	<-d.cleanerDone // wait for cleaner to finish
}

// ListTasks 返回队列中的所有任务（不含已出队 dispatched 的任务）。
// 已出队但未完成的任务不会被包含，需通过 SubmitResult 后的结果查询。
func (d *Dispatcher) ListTasks() []*types.Task {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var tasks []*types.Task
	d.queue.ForEach(func(t *types.Task) {
		tasks = append(tasks, t)
	})
	return tasks
}

// GetTask 查询指定任务的当前状态。
func (d *Dispatcher) GetTask(taskID string) *types.Task {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var found *types.Task
	d.queue.ForEach(func(t *types.Task) {
		if t.ID == taskID {
			found = t
		}
	})
	if found != nil {
		return found
	}
	// 也从结果中查找
	if _, ok := d.results[taskID]; ok {
		return &types.Task{
			ID:     taskID,
			Status: types.TaskCompleted,
		}
	}
	return nil
}

// WaitForTask 阻塞等待指定任务完成，直到超时。
func (d *Dispatcher) WaitForTask(taskID string, timeout time.Duration) (*types.Result, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if result, ok := d.GetResult(taskID); ok {
			return result, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return nil, fmt.Errorf("task %s timed out", taskID)
}
