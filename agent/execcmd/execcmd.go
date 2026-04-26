// Package execcmd provides command execution with child process tracking.
// Reference: Sliver's execute_children.go — tracks all spawned processes
// so they can be managed/terminated as a group.
package execcmd

import (
	"bytes"
	"fmt"
	"os/exec"
	"sync"
	"time"
)

// Child tracks an executed process and its children.
type Child struct {
	ID       string
	Cmd      *exec.Cmd
	Started  time.Time
	PID      int
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Done     bool
}

var (
	children   = make(map[string]*Child)
	childrenMu sync.Mutex
	nextID     int
)

// Execute runs a command and tracks it as a child process.
// Returns a unique ID for later management.
func Execute(name string, cmd *exec.Cmd) (string, error) {
	childrenMu.Lock()
	id := fmt.Sprintf("child_%d", nextID)
	nextID++
	childrenMu.Unlock()

	child := &Child{
		ID:      id,
		Cmd:     cmd,
		Started: time.Now(),
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("start %s: %w", name, err)
	}

	child.PID = cmd.Process.Pid

	childrenMu.Lock()
	children[id] = child
	childrenMu.Unlock()

	// Wait in background
	go func() {
		err := cmd.Wait()
		childrenMu.Lock()
		child.Done = true
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				child.ExitCode = exitErr.ExitCode()
			} else {
				child.ExitCode = 1
			}
		}
		childrenMu.Unlock()
	}()

	return id, nil
}

// ExecuteSync runs a command synchronously and returns output.
func ExecuteSync(cmd *exec.Cmd) (stdout, stderr string, exitCode int, err error) {
	var stdoutBuf, stderrBuf bytes.Buffer

	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err = cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	return stdoutBuf.String(), stderrBuf.String(), exitCode, err
}

// Kill terminates a child process by ID.
func Kill(id string) error {
	childrenMu.Lock()
	child, ok := children[id]
	childrenMu.Unlock()

	if !ok {
		return fmt.Errorf("child %s not found", id)
	}

	if child.Done {
		return fmt.Errorf("child %s already exited", id)
	}

	if child.Cmd.Process == nil {
		return fmt.Errorf("child %s has no process", id)
	}

	// Send SIGKILL on Unix, TerminateProcess on Windows
	if err := child.Cmd.Process.Kill(); err != nil {
		return fmt.Errorf("kill child %s (PID %d): %w", id, child.PID, err)
	}

	childrenMu.Lock()
	child.Done = true
	childrenMu.Unlock()
	return nil
}

// KillAll terminates all active child processes.
func KillAll() int {
	childrenMu.Lock()
	defer childrenMu.Unlock()

	count := 0
	for _, child := range children {
		if child.Done {
			continue
		}
		if child.Cmd.Process != nil {
			if err := child.Cmd.Process.Kill(); err == nil {
				count++
				child.Done = true
			}
		}
		childrenMu.Unlock()
		childrenMu.Lock()
	}
	return count
}

// List returns all tracked child processes.
func List() []*Child {
	childrenMu.Lock()
	defer childrenMu.Unlock()

	result := make([]*Child, 0, len(children))
	for _, c := range children {
		result = append(result, c)
	}
	return result
}

// Get returns a child by ID.
func Get(id string) (*Child, bool) {
	childrenMu.Lock()
	defer childrenMu.Unlock()
	c, ok := children[id]
	return c, ok
}

// Cleanup removes completed children older than the given duration.
func Cleanup(maxAge time.Duration) int {
	childrenMu.Lock()
	defer childrenMu.Unlock()

	count := 0
	now := time.Now()
	for id, c := range children {
		if c.Done && now.Sub(c.Started) > maxAge {
			delete(children, id)
			count++
		}
	}
	return count
}
