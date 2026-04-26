package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/aegis-c2/aegis/server/config"
	"github.com/aegis-c2/aegis/server/core"
	grpcsrv "github.com/aegis-c2/aegis/server/grpc"
	httpsrv "github.com/aegis-c2/aegis/server/http"
	"github.com/aegis-c2/aegis/server/pki"
)

func main() {
	cfg := config.DefaultServerConfig()

	log.Println("[SERVER] initializing Aegis C2 server...")
	log.Printf("[SERVER] academic_mode: %v", cfg.AcademicMode)
	log.Printf("[SERVER] IP whitelist: %v", cfg.Whitelist.Enabled)
	log.Println("[SERVER] circuit breaker: enabled")

	// Initialize core service layer (transport-agnostic)
	coreSvc, err := core.New(cfg)
	if err != nil {
		log.Fatalf("[SERVER] failed to initialize core service: %v", err)
	}

	// Initialize PKI for gRPC operator auth
	pkiDir := filepath.Join("pki")
	os.MkdirAll(pkiDir, 0755)
	caCertPath := filepath.Join(pkiDir, "ca.crt")
	caKeyPath := filepath.Join(pkiDir, "ca.key")

	pkiMgr, err := pki.New(caCertPath, caKeyPath)
	if err != nil {
		log.Fatalf("[SERVER] failed to initialize PKI: %v", err)
	}
	log.Println("[SERVER] PKI initialized (CA: " + caCertPath + ")")

	// Start gRPC server (operator-facing, mTLS)
	grpcListenAddr := ":8444"
	if addr := os.Getenv("AEGIS_GRPC_ADDR"); addr != "" {
		grpcListenAddr = addr
	}

	grpcErrCh := make(chan error, 1)
	grpcSrv := grpcsrv.New(coreSvc, pkiMgr, coreSvc.Audit)

	// Start HTTP server (agent-facing)
	srv, err := httpsrv.NewWithCore(cfg, coreSvc)
	if err != nil {
		log.Fatalf("[SERVER] failed to initialize HTTP server: %v", err)
	}

	// Wire builder + profile manager + listener manager + stage store into gRPC for generate command
	grpcSrv.WithBuilder(srv.PayloadBuilder(), srv.ProfileManager(), srv.ListenerManager(), srv.ServerURL())
	grpcSrv.WithStageStore(srv.StageStore())

	go func() {
		if err := grpcSrv.Start(grpcListenAddr); err != nil {
			grpcErrCh <- err
		}
	}()
	log.Printf("[SERVER] gRPC operator service starting on %s", grpcListenAddr)

	if err := srv.Start(); err != nil {
		// Start 现在是非阻塞的，错误通过日志输出
		log.Printf("[SERVER] HTTP server starting: %v", err)
	}

	// Graceful shutdown on SIGINT/SIGTERM (Windows: also accept on stdin close)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Block forever so main() doesn't exit
	// On Windows, background processes may not receive signals properly,
	// so we also use a done channel that can be triggered programmatically.
	done := make(chan struct{})

	select {
	case sig := <-sigCh:
		log.Printf("[SERVER] received signal %v, shutting down...", sig)
	case <-done:
		log.Println("[SERVER] shutting down (done channel)...")
	case err := <-grpcErrCh:
		log.Printf("[SERVER] gRPC server error: %v, shutting down...", err)
	}

	// Shutdown HTTP server
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.GracefulShutdown(ctx); err != nil {
		log.Printf("[SERVER] HTTP shutdown error: %v", err)
	}

	// Graceful stop gRPC server (drain in-flight RPCs)
	if gs := grpcSrv.GRPCServer(); gs != nil {
		go gs.GracefulStop()
	}

	// Sync audit log to disk
	if coreSvc.Audit != nil {
		coreSvc.Audit.Sync()
		coreSvc.Audit.Close()
	}

	log.Println("[SERVER] shutdown complete")
}
