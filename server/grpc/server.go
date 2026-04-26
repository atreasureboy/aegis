// Package grpcsrv 实现 Operator 面向的 gRPC 服务器。
package grpcsrv

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/aegis-c2/aegis/proto/aegispb"
	"github.com/aegis-c2/aegis/server/audit"
	"github.com/aegis-c2/aegis/server/builder"
	"github.com/aegis-c2/aegis/server/core"
	"github.com/aegis-c2/aegis/server/listener"
	"github.com/aegis-c2/aegis/server/pki"
	"github.com/aegis-c2/aegis/server/profile"
	_ "github.com/aegis-c2/aegis/server/grpc/jsoncodec"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

var serverStartTime = time.Now()

// Server 实现 OperatorServiceServer。
type Server struct {
	aegispb.UnimplementedOperatorServiceServer
	core      *core.Service
	pki       *pki.Manager
	audit     *audit.Logger
	builder   *builder.Builder
	profileMgr *profile.Manager
	listenerMgr *listener.Manager
	serverURL  string // HTTP server URL for generate defaults
	stageStore map[string][]byte // staged payload store
	gs        *grpc.Server // stored for graceful shutdown
}

// New 创建 gRPC 服务器。
func New(coreSvc *core.Service, pkiMgr *pki.Manager, auditLog *audit.Logger) *Server {
	return &Server{
		core:  coreSvc,
		pki:   pkiMgr,
		audit: auditLog,
	}
}

// WithBuilder 设置 builder 和 profile manager（用于 generate 命令）。
func (s *Server) WithBuilder(b *builder.Builder, pmgr *profile.Manager, lmgr *listener.Manager, url string) *Server {
	s.builder = b
	s.profileMgr = pmgr
	s.listenerMgr = lmgr
	s.serverURL = url
	return s
}

// WithStageStore 设置 staged payload 存储（用于 stager→stage2 delivery）。
func (s *Server) WithStageStore(store map[string][]byte) *Server {
	s.stageStore = store
	return s
}

// GRPCServer 返回底层 gRPC 服务器（用于优雅关闭）。
func (s *Server) GRPCServer() *grpc.Server {
	return s.gs
}

// Start 启动 gRPC 服务器（带 mTLS）。
func (s *Server) Start(addr string) error {
	caPool := s.pki.CACertPool()

	tlsConfig := &tls.Config{
		ClientCAs:  caPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS13,
	}

	// Generate CA-signed server cert via PKI
	cert, err := s.generateServerCertPKI()
	if err != nil {
		return fmt.Errorf("generate server cert: %w", err)
	}
	tlsConfig.Certificates = []tls.Certificate{cert}

	creds := credentials.NewTLS(tlsConfig)

	opts := []grpc.ServerOption{
		grpc.Creds(creds),
		grpc.UnaryInterceptor(s.unaryAuthInterceptor),
		grpc.StreamInterceptor(s.streamAuthInterceptor),
	}

	gs := grpc.NewServer(opts...)
	s.gs = gs
	aegispb.RegisterOperatorServiceServer(gs, s)

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}

	log.Printf("[GRPC] operator service listening on %s", addr)
	return gs.Serve(lis)
}

// === RPC 实现 ===

func (s *Server) ListAgents(ctx context.Context, req *aegispb.ListAgentsRequest) (*aegispb.ListAgentsResponse, error) {
	opID, _ := operatorIDFromContext(ctx)
	s.audit.LogOperator(opID, "LIST_AGENTS", "", "")

	agents := s.core.ListAgents()
	resp := &aegispb.ListAgentsResponse{
		Agents: make([]*aegispb.AgentInfo, 0, len(agents)),
	}
	for _, a := range agents {
		resp.Agents = append(resp.Agents, toProtoAgent(a))
	}
	return resp, nil
}

func (s *Server) GetAgent(ctx context.Context, req *aegispb.GetAgentRequest) (*aegispb.GetAgentResponse, error) {
	opID, _ := operatorIDFromContext(ctx)
	s.audit.LogOperator(opID, "GET_AGENT", req.ID, "")

	a, ok := s.core.GetAgent(req.ID)
	if !ok {
		return nil, status.Error(codes.NotFound, "agent not found")
	}
	return &aegispb.GetAgentResponse{Agent: toProtoAgent(a)}, nil
}

// requireRole 检查操作员角色，不匹配时返回 gRPC error。
func (s *Server) requireRole(ctx context.Context, requiredRoles ...string) error {
	opCtx, ok := operatorFromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "no operator context")
	}
	for _, role := range requiredRoles {
		if opCtx.Role == role {
			return nil
		}
	}
	return status.Errorf(codes.PermissionDenied, "role %q required, got %q", requiredRoles, opCtx.Role)
}

func (s *Server) KillAgent(ctx context.Context, req *aegispb.KillAgentRequest) (*aegispb.KillAgentResponse, error) {
	opID, _ := operatorIDFromContext(ctx)
	if err := s.requireRole(ctx, "admin", "operator"); err != nil {
		s.audit.LogOperator(opID, "KILL_AGENT", req.ID, "denied: insufficient role")
		return nil, err
	}
	s.audit.LogOperator(opID, "KILL_AGENT", req.ID, "")

	task := s.core.CreateTask(req.ID, "kill", "", 5, 30, "grpc:"+opID)
	return &aegispb.KillAgentResponse{Success: task != nil}, nil
}

func (s *Server) CreateTask(ctx context.Context, req *aegispb.CreateTaskRequest) (*aegispb.CreateTaskResponse, error) {
	opID, _ := operatorIDFromContext(ctx)
	if err := s.requireRole(ctx, "admin", "operator"); err != nil {
		s.audit.LogOperator(opID, "CREATE_TASK", req.AgentID, "denied: insufficient role")
		return nil, err
	}
	s.audit.LogOperator(opID, "CREATE_TASK", req.AgentID, fmt.Sprintf("cmd=%s", req.Command))

	task := s.core.CreateTask(req.AgentID, req.Command, req.Args, int(req.Priority), int(req.Timeout), "grpc:"+opID)
	if task == nil {
		return nil, status.Error(codes.Internal, "failed to create task")
	}
	return &aegispb.CreateTaskResponse{Task: toProtoTask(task)}, nil
}

func (s *Server) GetTask(ctx context.Context, req *aegispb.GetTaskRequest) (*aegispb.GetTaskResponse, error) {
	opID, _ := operatorIDFromContext(ctx)
	s.audit.LogOperator(opID, "GET_TASK", req.ID, "")

	t, ok := s.core.GetTask(req.ID)
	if !ok {
		return nil, status.Error(codes.NotFound, "task not found")
	}
	return &aegispb.GetTaskResponse{Task: toProtoTask(t)}, nil
}

func (s *Server) ListTasks(ctx context.Context, req *aegispb.ListTasksRequest) (*aegispb.ListTasksResponse, error) {
	opID, _ := operatorIDFromContext(ctx)
	s.audit.LogOperator(opID, "LIST_TASKS", req.AgentID, "")

	tasks := s.core.ListTasks(req.AgentID)
	resp := &aegispb.ListTasksResponse{
		Tasks: make([]*aegispb.TaskInfo, 0, len(tasks)),
	}
	for _, t := range tasks {
		resp.Tasks = append(resp.Tasks, toProtoTask(t))
	}
	return resp, nil
}

func (s *Server) GeneratePayload(ctx context.Context, req *aegispb.GeneratePayloadRequest) (*aegispb.GeneratePayloadResponse, error) {
	opID, _ := operatorIDFromContext(ctx)
	if err := s.requireRole(ctx, "admin"); err != nil {
		s.audit.LogOperator(opID, "GENERATE_PAYLOAD", "", fmt.Sprintf("denied: insufficient role, os=%s arch=%s format=%s",
			req.Config.OS, req.Config.Arch, req.Config.Format))
		return nil, err
	}

	if s.builder == nil {
		return nil, status.Error(codes.Unavailable, "payload builder not available")
	}

	cfg := req.Config

	// Build server URL from lhost:lport
	serverURL := cfg.LHost
	if serverURL == "" {
		// Fallback: use the server's HTTP URL
		serverURL = s.serverURL
	}
	if cfg.LPort > 0 {
		serverURL = fmt.Sprintf("http://%s:%d", serverURL, cfg.LPort)
	} else if serverURL != "" && !containsPort(serverURL) {
		serverURL = fmt.Sprintf("%s:8443", serverURL)
	}

	buildCfg := &builder.BuildConfig{
		Name:              fmt.Sprintf("aegis-%d", time.Now().UnixNano()),
		GOOS:              cfg.OS,
		GOARCH:            cfg.Arch,
		Format:            builder.OutputFormat(cfg.Format),
		ServerURL:         serverURL,
		HeartbeatInterval: int(cfg.Sleep),
		HeartbeatJitter:   int(cfg.Jitter),
		UserAgent:         "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
		ProcessName:       "svchost",
		SleepMaskEnabled:  cfg.SleepMask,
		SyscallEnabled:    cfg.IndirectSyscalls,
		KillDate:          cfg.KillDate,
		AMSIEnabled:       !cfg.AMSI,
		ETWEnabled:        !cfg.ETW,
		StackSpoof:        cfg.StackSpoof,
		TLSFingerprint:    cfg.TLSFingerprint,
		StageType:         cfg.Stage,
		UseGarble:         cfg.Garble,
		CGOEnabled:        cfg.IndirectSyscalls || cfg.StackSpoof,
	}

	// Apply profile if specified
	if cfg.Profile != "" && s.profileMgr != nil {
		if p, ok := s.profileMgr.Get(cfg.Profile); ok {
			buildCfg.ProfileName = cfg.Profile
			buildCfg.ProfileMethod = p.HTTP.Method
			buildCfg.ProfilePath = p.HTTP.Path
			buildCfg.ProfileHeaders = p.HTTP.Headers
			buildCfg.ProfileCookie = p.HTTP.CookieName
			buildCfg.ProfileParam = p.HTTP.ParamName
			buildCfg.ProfileTransform = p.HTTP.DataTransform
		}
	} else if s.profileMgr != nil {
		p := s.profileMgr.Active()
		buildCfg.ProfileMethod = p.HTTP.Method
		buildCfg.ProfilePath = p.HTTP.Path
		buildCfg.ProfileHeaders = p.HTTP.Headers
		buildCfg.ProfileCookie = p.HTTP.CookieName
		buildCfg.ProfileParam = p.HTTP.ParamName
		buildCfg.ProfileTransform = p.HTTP.DataTransform
	}

	// Staged delivery: build stage1 or stage2 independently
	var outputPath string
	var resultData []byte
	var err error

	switch cfg.Stage {
	case "stage1":
		outputPath, err = s.builder.BuildStage1(buildCfg)
		if err != nil {
			s.audit.LogOperator(opID, "GENERATE_PAYLOAD", "", fmt.Sprintf("stage1 build failed: %s", err))
			return nil, status.Errorf(codes.Internal, "stage1 build failed: %v", err)
		}
		resultData, err = os.ReadFile(outputPath)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to read stage1: %v", err)
		}
		s.audit.LogOperator(opID, "GENERATE_PAYLOAD", "", fmt.Sprintf("STAGE1: path=%s size=%d", outputPath, len(resultData)))

	case "stage2":
		outputPath, err = s.builder.BuildStage2(buildCfg)
		if err != nil {
			s.audit.LogOperator(opID, "GENERATE_PAYLOAD", "", fmt.Sprintf("stage2 build failed: %s", err))
			return nil, status.Errorf(codes.Internal, "stage2 build failed: %v", err)
		}
		resultData, err = os.ReadFile(outputPath)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to read stage2: %v", err)
		}
		s.audit.LogOperator(opID, "GENERATE_PAYLOAD", "", fmt.Sprintf("STAGE2: path=%s size=%d", outputPath, len(resultData)))

	default:
		// Stageless: normal build
		outputPath, err = s.builder.Build(buildCfg)
		if err != nil {
			s.audit.LogOperator(opID, "GENERATE_PAYLOAD", "", fmt.Sprintf("failed: %s", err))
			return nil, status.Errorf(codes.Internal, "build failed: %v", err)
		}

		resultData, err = os.ReadFile(outputPath)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to read payload: %v", err)
		}

		s.audit.LogOperator(opID, "GENERATE_PAYLOAD", "", fmt.Sprintf("os=%s arch=%s format=%s size=%d",
			cfg.OS, cfg.Arch, cfg.Format, len(resultData)))
	}

	return &aegispb.GeneratePayloadResponse{
		Result: &aegispb.BuildResult{
			Path:   outputPath,
			Size:   int64(len(resultData)),
			SHA256: fmt.Sprintf("%x", sha256Sum(resultData)),
			Binary: resultData,
		},
	}, nil
}

func containsPort(s string) bool {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return true
		}
		if s[i] == '/' {
			return false
		}
	}
	return false
}

func sha256Sum(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

func (s *Server) SubscribeEvents(req *aegispb.SubscribeEventsRequest, stream aegispb.OperatorService_SubscribeEventsServer) error {
	opID, _ := operatorIDFromContext(stream.Context())
	s.audit.LogOperator(opID, "SUBSCRIBE_EVENTS", "", "")

	// Register operator as connected
	s.core.OperatorMgr.Connect(opID, peerIP(stream.Context()))
	defer s.core.OperatorMgr.Disconnect(opID)

	// Subscribe to all events
	subID := "grpc-" + opID
	ch, err := s.core.EventBroker.SubscribeAll(subID)
	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}
	defer s.core.EventBroker.UnsubscribeAll(subID)

	// Phase 1: Replay history
	history := s.core.History(50)
	for _, e := range history {
		if err := stream.Send(toProtoEvent(e)); err != nil {
			return err
		}
	}

	// Phase 2: Live events
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case e, ok := <-ch:
			if !ok {
				return nil
			}
			if err := stream.Send(toProtoEvent(e)); err != nil {
				return err
			}
		}
	}
}

func (s *Server) StartListener(ctx context.Context, req *aegispb.StartListenerRequest) (*aegispb.StartListenerResponse, error) {
	opID, _ := operatorIDFromContext(ctx)
	if err := s.requireRole(ctx, "admin"); err != nil {
		s.audit.LogOperator(opID, "START_LISTENER", req.Name, "denied: insufficient role")
		return nil, err
	}
	s.audit.LogOperator(opID, "START_LISTENER", req.Name, fmt.Sprintf("proto=%s port=%d", req.Protocol, req.Port))

	var l *listener.Listener
	var err error
	switch req.Protocol {
	case "http":
		l, err = s.core.ListenerMgr.CreateHTTP(req.Name, req.Host, int(req.Port))
	case "https":
		l, err = s.core.ListenerMgr.CreateHTTPS(req.Name, req.Host, int(req.Port), "", "")
	case "mtls":
		l, err = s.core.ListenerMgr.CreateMTLS(req.Name, req.Host, int(req.Port))
	case "dns":
		l, err = s.core.ListenerMgr.CreateDNS(req.Name, req.Host, "")
	case "named_pipe":
		l, err = s.core.ListenerMgr.CreateNamedPipe(req.Name, req.Host)
	default:
		return nil, status.Error(codes.InvalidArgument, "unsupported protocol: "+req.Protocol)
	}
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	s.core.ListenerMgr.Start(l.ID, nil)
	return &aegispb.StartListenerResponse{Listener: toProtoListener(l)}, nil
}

func (s *Server) StopListener(ctx context.Context, req *aegispb.StopListenerRequest) (*aegispb.StopListenerResponse, error) {
	opID, _ := operatorIDFromContext(ctx)
	if err := s.requireRole(ctx, "admin"); err != nil {
		s.audit.LogOperator(opID, "STOP_LISTENER", req.ID, "denied: insufficient role")
		return nil, err
	}
	s.audit.LogOperator(opID, "STOP_LISTENER", req.ID, "")

	if err := s.core.StopListener(req.ID); err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	return &aegispb.StopListenerResponse{Success: true}, nil
}

func (s *Server) ListListeners(ctx context.Context, req *aegispb.ListListenersRequest) (*aegispb.ListListenersResponse, error) {
	opID, _ := operatorIDFromContext(ctx)
	s.audit.LogOperator(opID, "LIST_LISTENERS", "", "")

	listeners := s.core.ListListeners()
	resp := &aegispb.ListListenersResponse{
		Listeners: make([]*aegispb.ListenerInfo, 0, len(listeners)),
	}
	for _, l := range listeners {
		resp.Listeners = append(resp.Listeners, toProtoListener(l))
	}
	return resp, nil
}

func (s *Server) ListOperators(ctx context.Context, req *aegispb.ListOperatorsRequest) (*aegispb.ListOperatorsResponse, error) {
	opID, _ := operatorIDFromContext(ctx)
	s.audit.LogOperator(opID, "LIST_OPERATORS", "", "")

	operators := s.core.ListOperators()
	resp := &aegispb.ListOperatorsResponse{
		Operators: make([]*aegispb.OperatorInfo, 0, len(operators)),
	}
	for _, o := range operators {
		resp.Operators = append(resp.Operators, toProtoOperator(o))
	}
	return resp, nil
}

func (s *Server) RegisterOperator(ctx context.Context, req *aegispb.RegisterOperatorRequest) (*aegispb.RegisterOperatorResponse, error) {
	opID, _ := operatorIDFromContext(ctx)
	s.audit.LogOperator(opID, "REGISTER_OPERATOR", req.Name, fmt.Sprintf("role=%s", req.Role))

	// Only admin can register operators
	opCtx, ok := operatorFromContext(ctx)
	if !ok || opCtx.Role != "admin" {
		return nil, status.Error(codes.PermissionDenied, "admin role required")
	}

	op, err := s.core.RegisterOperator(req.Name, req.Role)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	// Generate mTLS certificate for the new operator
	certPEM, keyPEM, err := s.pki.GenerateOperatorCert(req.Name, req.Role)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &aegispb.RegisterOperatorResponse{
		Operator:  toProtoOperator(op),
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		CACertPEM: s.pki.CACertPEM(),
	}, nil
}

func (s *Server) ListLoot(ctx context.Context, req *aegispb.ListLootRequest) (*aegispb.ListLootResponse, error) {
	opID, _ := operatorIDFromContext(ctx)
	s.audit.LogOperator(opID, "LIST_LOOT", req.AgentID, "")

	return &aegispb.ListLootResponse{}, nil
}

func (s *Server) GetServerInfo(ctx context.Context, req *aegispb.GetServerInfoRequest) (*aegispb.GetServerInfoResponse, error) {
	opID, _ := operatorIDFromContext(ctx)
	s.audit.LogOperator(opID, "GET_SERVER_INFO", "", "")

	agents := s.core.ListAgents()
	listeners := s.core.ListListeners()
	operators := s.core.ListOperators()

	return &aegispb.GetServerInfoResponse{
		Info: &aegispb.ServerInfo{
			Version:       "0.1.0",
			Uptime:        int64(time.Since(serverStartTime).Seconds()),
			AgentCount:    int32(len(agents)),
			OperatorCount: int32(len(operators)),
			ListenerCount: int32(len(listeners)),
			ActiveProfile: s.core.ActiveProfile(),
		},
	}, nil
}

func (s *Server) ListProfiles(ctx context.Context, req *aegispb.ListProfilesRequest) (*aegispb.ListProfilesResponse, error) {
	opID, _ := operatorIDFromContext(ctx)
	s.audit.LogOperator(opID, "LIST_PROFILES", "", "")

	names := s.core.ListProfiles()
	resp := &aegispb.ListProfilesResponse{
		Profiles: make([]*aegispb.ProfileInfo, 0, len(names)),
	}
	for _, name := range names {
		resp.Profiles = append(resp.Profiles, &aegispb.ProfileInfo{Name: name})
	}
	return resp, nil
}

func (s *Server) SetActiveProfile(ctx context.Context, req *aegispb.SetActiveProfileRequest) (*aegispb.SetActiveProfileResponse, error) {
	opID, _ := operatorIDFromContext(ctx)
	if err := s.requireRole(ctx, "admin"); err != nil {
		s.audit.LogOperator(opID, "SET_ACTIVE_PROFILE", req.Name, "denied: insufficient role")
		return nil, err
	}
	s.audit.LogOperator(opID, "SET_ACTIVE_PROFILE", req.Name, "")

	if err := s.core.SetActiveProfile(req.Name); err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	return &aegispb.SetActiveProfileResponse{Success: true}, nil
}

func (s *Server) Weaponize(ctx context.Context, req *aegispb.WeaponizeRequest) (*aegispb.WeaponizeResponse, error) {
	opID, _ := operatorIDFromContext(ctx)
	if err := s.requireRole(ctx, "admin"); err != nil {
		s.audit.LogOperator(opID, "WEAPONIZE", req.Chain, "denied: insufficient role")
		return nil, err
	}
	s.audit.LogOperator(opID, "WEAPONIZE", req.Chain, req.InputPath)

	return nil, status.Error(codes.Unimplemented, "weaponize not yet exposed via gRPC")
}

func (s *Server) RegisterStage2(ctx context.Context, req *aegispb.RegisterStage2Request) (*aegispb.RegisterStage2Response, error) {
	opID, _ := operatorIDFromContext(ctx)
	if err := s.requireRole(ctx, "admin"); err != nil {
		s.audit.LogOperator(opID, "REGISTER_STAGE2", req.ExternalURL, "denied: insufficient role")
		return nil, err
	}
	s.audit.LogOperator(opID, "REGISTER_STAGE2", "", fmt.Sprintf("url=%s", req.ExternalURL))

	if s.core == nil || s.core.StageRegistry == nil {
		return nil, status.Error(codes.Unavailable, "stage registry not available")
	}

	entry, err := s.core.StageRegistry.Register(req.ExternalURL, req.AESKeyHex)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "register stage2: %v", err)
	}

	return &aegispb.RegisterStage2Response{
		Stage2: &aegispb.Stage2Registration{
			ID:          entry.ID,
			ExternalURL: entry.ExternalURL,
			AESKeyHex:   entry.AESKeyHex,
		},
	}, nil
}

// === 拦截器 ===

type operatorCtxKey struct{}

// OperatorContext 存储从 mTLS 证书提取的操作员信息。
type OperatorContext struct {
	ID   string
	Role string
	IP   string
}

func (s *Server) unaryAuthInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	opCtx, err := s.extractOperator(ctx)
	if err != nil {
		return nil, err
	}
	return handler(context.WithValue(ctx, operatorCtxKey{}, opCtx), req)
}

func (s *Server) streamAuthInterceptor(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	opCtx, err := s.extractOperator(stream.Context())
	if err != nil {
		return err
	}
	wrapped := &wrappedStream{ServerStream: stream, ctx: context.WithValue(stream.Context(), operatorCtxKey{}, opCtx)}
	return handler(srv, wrapped)
}

type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedStream) Context() context.Context {
	return w.ctx
}

func (s *Server) extractOperator(ctx context.Context) (*OperatorContext, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no peer info")
	}

	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no TLS info")
	}

	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return nil, status.Error(codes.Unauthenticated, "no client certificate")
	}

	cert := tlsInfo.State.VerifiedChains[0][0]
	name, role, err := s.pki.VerifyOperatorCert(cert)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid operator certificate")
	}

	return &OperatorContext{
		ID:   name,
		Role: role,
		IP:   p.Addr.String(),
	}, nil
}

// operatorIDFromContext 从 context 提取操作员 ID。
func operatorIDFromContext(ctx context.Context) (string, bool) {
	if op, ok := ctx.Value(operatorCtxKey{}).(*OperatorContext); ok {
		return op.ID, true
	}
	return "", false
}

// operatorFromContext 从 context 提取完整 OperatorContext。
func operatorFromContext(ctx context.Context) (*OperatorContext, bool) {
	op, ok := ctx.Value(operatorCtxKey{}).(*OperatorContext)
	return op, ok
}

// peerIP 从 context 提取 IP 地址。
func peerIP(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok {
		return p.Addr.String()
	}
	return ""
}

// generateServerCertPKI 使用 PKI CA 签发 gRPC 服务器证书。
func (s *Server) generateServerCertPKI() (tls.Certificate, error) {
	dir := filepath.Join("certs")
	os.MkdirAll(dir, 0755)
	certPath := filepath.Join(dir, "grpc-server.crt")
	keyPath := filepath.Join(dir, "grpc-server.key")

	// Check if already exists
	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		return cert, nil
	}

	// Generate server key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate RSA key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "aegis-grpc-server",
			Organization: []string{"Aegis C2"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	// Sign with PKI CA instead of self-signing
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, s.pki.CACert(), &priv.PublicKey, s.pki.CAKey())
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create cert file: %w", err)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return tls.Certificate{}, fmt.Errorf("encode cert: %w", err)
	}

	keyOut, err := os.Create(keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create key file: %w", err)
	}
	defer keyOut.Close()
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return tls.Certificate{}, fmt.Errorf("encode key: %w", err)
	}

	log.Printf("[GRPC] generated CA-signed server cert at %s", certPath)
	return tls.LoadX509KeyPair(certPath, keyPath)
}
