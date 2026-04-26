//go:build !windows

package persist

import "fmt"

type PersistMethod string

const (
	MethodRegistry PersistMethod = "registry"
	MethodService  PersistMethod = "service"
	MethodSchTasks PersistMethod = "schtasks"
)

type PersistConfig struct {
	Name        string
	DisplayName string
	BinaryPath  string
	Description string
}

func (c *PersistConfig) Install(method PersistMethod) error {
	return fmt.Errorf("persistence not supported on this platform")
}

func (c *PersistConfig) Remove(method PersistMethod) error {
	return fmt.Errorf("persistence not supported on this platform")
}
