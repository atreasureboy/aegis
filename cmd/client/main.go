// Aegis C2 gRPC 操作员客户端。
//
// 用法：
//
//	mTLS 模式: aegis-client --cert client.crt --key client.key --ca ca.crt --server 127.0.0.1:8444
//	调试模式:  aegis-client --insecure --server 127.0.0.1:8444
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/aegis-c2/aegis/client/grpc"
	"github.com/aegis-c2/aegis/client/repl"
)

func main() {
	serverAddr := flag.String("server", "127.0.0.1:8444", "gRPC server address")
	certPath := flag.String("cert", "", "Client TLS certificate path")
	keyPath := flag.String("key", "", "Client TLS private key path")
	caPath := flag.String("ca", "", "CA certificate path")
	insecure := flag.Bool("insecure", false, "Skip TLS verification (dev only)")
	name := flag.String("name", "admin", "Operator name")
	flag.Parse()

	// 优先使用环境变量
	if addr := os.Getenv("AEGIS_SERVER"); addr != "" {
		*serverAddr = addr
	}
	if cert := os.Getenv("AEGIS_CERT"); cert != "" {
		*certPath = cert
	}
	if key := os.Getenv("AEGIS_KEY"); key != "" {
		*keyPath = key
	}
	if ca := os.Getenv("AEGIS_CA"); ca != "" {
		*caPath = ca
	}

	var client *grpc.Client
	var err error

	if *insecure {
		fmt.Println("[WARN] running in insecure mode — no mTLS")
		client, err = grpc.NewInsecure(*serverAddr)
	} else {
		if *certPath == "" || *keyPath == "" || *caPath == "" {
			fmt.Println("Usage:")
			fmt.Println("  aegis-client --cert client.crt --key client.key --ca ca.crt --server 127.0.0.1:8444")
			fmt.Println("  or")
			fmt.Println("  aegis-client --insecure --server 127.0.0.1:8444")
			fmt.Println()
			fmt.Println("Environment variables: AEGIS_SERVER, AEGIS_CERT, AEGIS_KEY, AEGIS_CA")
			os.Exit(1)
		}
		client, err = grpc.New(*serverAddr, *certPath, *keyPath, *caPath)
	}
	if err != nil {
		log.Fatalf("[CLIENT] failed to connect: %v", err)
	}
	defer client.Close()

	fmt.Printf("[CLIENT] connected to %s as %s\n", *serverAddr, *name)

	// Start event stream
	eventStream := repl.NewEventStream(client.OperatorServiceClient, 256)
	eventStream.Start()
	defer eventStream.Stop()

	// Start REPL
	r := repl.New(client.OperatorServiceClient, eventStream.Channel(), *name)
	r.Run()
}
