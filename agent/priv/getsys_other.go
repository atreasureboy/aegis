//go:build !windows

package priv

import "fmt"

func GetSys() error {
	return fmt.Errorf("getsys is only available on Windows")
}

func RunAs(domain, username, password, command string) error {
	return fmt.Errorf("runas is only available on Windows")
}
