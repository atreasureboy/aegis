//go:build !windows

package weaponize

import "fmt"

type Config struct {
	PNGPath      string
	XORKey       []byte
	InjectTarget string
	InjectMethod string
}

func DefaultConfig() *Config {
	return &Config{
		PNGPath:      `C:\ProgramData\Microsoft OneDrive\setup\Cache\SplashScreen.png`,
		XORKey:       []byte{0x3A, 0xF1, 0x8C, 0x22, 0x77, 0xE4},
		InjectTarget: "explorer.exe",
		InjectMethod: "thread_hijack",
	}
}

func Run(cfg *Config) error {
	return fmt.Errorf("weaponize only supported on Windows")
}
