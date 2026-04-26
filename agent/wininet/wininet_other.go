//go:build !windows

// Package wininet stub for non-Windows platforms.
package wininet

import (
	"fmt"
	"net/http"
)

// Client stub for non-Windows.
type Client struct{}

// NewClient is not available on non-Windows.
func NewClient(userAgent string) (*Client, error) {
	return nil, fmt.Errorf("wininet transport only available on Windows")
}

// RoundTrip is not implemented.
func (c *Client) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("wininet transport only available on Windows")
}

// Close is a no-op.
func (c *Client) Close() {}
