//go:build !windows

package priv

import "fmt"

func GetSystem() error {
	return fmt.Errorf("getsystem is only available on Windows")
}

func RunAs(domain, username, password, command string) error {
	return fmt.Errorf("runas is only available on Windows")
}
