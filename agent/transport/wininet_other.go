//go:build !windows || !amd64

package transport

import "net/http"

// newWininetTransport is not available on non-Windows platforms.
func newWininetTransport(userAgent string) http.RoundTripper {
	return nil
}
