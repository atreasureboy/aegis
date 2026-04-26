// Package grpc 提供 gRPC + mTLS 客户端。
package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	_ "github.com/aegis-c2/aegis/server/grpc/jsoncodec"
	"github.com/aegis-c2/aegis/proto/aegispb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// Client 封装 gRPC 连接和服务端点。
type Client struct {
	conn  *grpc.ClientConn
	aegispb.OperatorServiceClient
}

// New 创建 gRPC + mTLS 客户端。
func New(addr, certPath, keyPath, caCertPath string) (*Client, error) {
	// Load client certificate
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}

	// Load CA certificate for server verification
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("invalid CA certificate")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	}

	creds := credentials.NewTLS(tlsConfig)

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(
			grpc.CallContentSubtype("json"),
			grpc.MaxCallRecvMsgSize(64*1024*1024), // 64MB for stage2 payloads
		),
	}

	conn, err := grpc.Dial(addr, opts...)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	return &Client{
		conn:                  conn,
		OperatorServiceClient: aegispb.NewOperatorServiceClient(conn),
	}, nil
}

// NewInsecure 创建不安全的 gRPC 客户端（仅用于开发调试）。
func NewInsecure(addr string) (*Client, error) {
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.CallContentSubtype("json"),
			grpc.MaxCallRecvMsgSize(64*1024*1024), // 64MB for stage2 payloads
		),
	}

	conn, err := grpc.Dial(addr, opts...)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	return &Client{
		conn:                  conn,
		OperatorServiceClient: aegispb.NewOperatorServiceClient(conn),
	}, nil
}

// Close 关闭连接。
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Context 返回默认上下文。
func (c *Client) Context() context.Context {
	return context.Background()
}
