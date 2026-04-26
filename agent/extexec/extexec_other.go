//go:build !windows

package extexec

import "fmt"

// Extension is not available on non-Windows platforms.
type Extension struct {
	ID string
}

// Load is not available on non-Windows platforms.
func Load(data []byte, id string) (*Extension, error) {
	return nil, fmt.Errorf("extension loading not supported on this platform")
}

// Call is not available on non-Windows platforms.
func (e *Extension) Call(export string, arguments []byte, onFinish func([]byte)) error {
	return fmt.Errorf("extension calls not supported on this platform")
}

// Unload is not available on non-Windows platforms.
func (e *Extension) Unload() error {
	return fmt.Errorf("extension unloading not supported on this platform")
}
