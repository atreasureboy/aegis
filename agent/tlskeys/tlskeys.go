// Package tlskeys provides TLS session key logging for Wireshark decryption.
// Reference: Sliver's tlskeys.go — writes NSS Key Log Format to file
// so Wireshark can decrypt captured TLS traffic.
package tlskeys

import (
	"crypto/tls"
	"fmt"
	"os"
	"sync"
)

// KeyLogWriter writes TLS session keys to a file in NSS Key Log Format.
// Format: LABEL <client_random> <secret>
var (
	keyLogFile   *os.File
	keyLogMu     sync.Mutex
	keyLogEnabled bool
)

// Enable starts TLS key logging to the specified file.
// Keys are written in NSS Key Log Format compatible with Wireshark.
// Set SSLKEYLOGFILE environment variable or call this directly.
func Enable(path string) error {
	keyLogMu.Lock()
	defer keyLogMu.Unlock()

	if keyLogFile != nil {
		keyLogFile.Close()
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("open key log file: %w", err)
	}

	keyLogFile = f
	keyLogEnabled = true
	return nil
}

// Disable stops TLS key logging.
func Disable() {
	keyLogMu.Lock()
	defer keyLogMu.Unlock()

	if keyLogFile != nil {
		keyLogFile.Close()
		keyLogFile = nil
	}
	keyLogEnabled = false
}

// IsEnabled returns whether key logging is active.
func IsEnabled() bool {
	keyLogMu.Lock()
	defer keyLogMu.Unlock()
	return keyLogEnabled
}

// KeyLogWriter returns a tls.KeyLogWriter function for use in tls.Config.
// Usage: cfg.KeyLogWriter = tlskeys.KeyLogWriter()
func KeyLogWriter() func([]byte) error {
	return func(keyLogLine []byte) error {
		keyLogMu.Lock()
		defer keyLogMu.Unlock()

		if keyLogFile == nil {
			return nil // silently ignore if not enabled
		}

		_, err := keyLogFile.Write(keyLogLine)
		if err != nil {
			return err
		}
		_, err = keyLogFile.Write([]byte("\n"))
		return err
	}
}

// WrapConfig adds key logging to a tls.Config if enabled.
func WrapConfig(cfg *tls.Config) {
	if !IsEnabled() {
		return
	}
	keyLogMu.Lock()
	f := keyLogFile
	keyLogMu.Unlock()
	if f != nil {
		cfg.KeyLogWriter = f
	}
}

// AutoEnable checks SSLKEYLOGFILE env var and enables if set.
func AutoEnable() {
	path := os.Getenv("SSLKEYLOGFILE")
	if path != "" {
		Enable(path)
	}
}
