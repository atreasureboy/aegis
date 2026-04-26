// OperatorService gRPC 服务定义。
package aegispb

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const operatorServiceName = "aegis.OperatorService"

// OperatorServiceClient Operator 端 gRPC 客户端。
type OperatorServiceClient interface {
	ListAgents(ctx context.Context, req *ListAgentsRequest, opts ...grpc.CallOption) (*ListAgentsResponse, error)
	GetAgent(ctx context.Context, req *GetAgentRequest, opts ...grpc.CallOption) (*GetAgentResponse, error)
	KillAgent(ctx context.Context, req *KillAgentRequest, opts ...grpc.CallOption) (*KillAgentResponse, error)

	CreateTask(ctx context.Context, req *CreateTaskRequest, opts ...grpc.CallOption) (*CreateTaskResponse, error)
	GetTask(ctx context.Context, req *GetTaskRequest, opts ...grpc.CallOption) (*GetTaskResponse, error)
	ListTasks(ctx context.Context, req *ListTasksRequest, opts ...grpc.CallOption) (*ListTasksResponse, error)

	GeneratePayload(ctx context.Context, req *GeneratePayloadRequest, opts ...grpc.CallOption) (*GeneratePayloadResponse, error)

	SubscribeEvents(ctx context.Context, req *SubscribeEventsRequest, opts ...grpc.CallOption) (OperatorService_SubscribeEventsClient, error)

	StartListener(ctx context.Context, req *StartListenerRequest, opts ...grpc.CallOption) (*StartListenerResponse, error)
	StopListener(ctx context.Context, req *StopListenerRequest, opts ...grpc.CallOption) (*StopListenerResponse, error)
	ListListeners(ctx context.Context, req *ListListenersRequest, opts ...grpc.CallOption) (*ListListenersResponse, error)

	ListOperators(ctx context.Context, req *ListOperatorsRequest, opts ...grpc.CallOption) (*ListOperatorsResponse, error)
	RegisterOperator(ctx context.Context, req *RegisterOperatorRequest, opts ...grpc.CallOption) (*RegisterOperatorResponse, error)

	ListLoot(ctx context.Context, req *ListLootRequest, opts ...grpc.CallOption) (*ListLootResponse, error)
	GetServerInfo(ctx context.Context, req *GetServerInfoRequest, opts ...grpc.CallOption) (*GetServerInfoResponse, error)
	ListProfiles(ctx context.Context, req *ListProfilesRequest, opts ...grpc.CallOption) (*ListProfilesResponse, error)
	SetActiveProfile(ctx context.Context, req *SetActiveProfileRequest, opts ...grpc.CallOption) (*SetActiveProfileResponse, error)
	Weaponize(ctx context.Context, req *WeaponizeRequest, opts ...grpc.CallOption) (*WeaponizeResponse, error)
	RegisterStage2(ctx context.Context, req *RegisterStage2Request, opts ...grpc.CallOption) (*RegisterStage2Response, error)
}

// operatorServiceClient 实现。
type operatorServiceClient struct {
	cc *grpc.ClientConn
}

// NewOperatorServiceClient 创建 Operator 端 gRPC 客户端。
func NewOperatorServiceClient(cc *grpc.ClientConn) OperatorServiceClient {
	return &operatorServiceClient{cc: cc}
}

func (c *operatorServiceClient) ListAgents(ctx context.Context, req *ListAgentsRequest, opts ...grpc.CallOption) (*ListAgentsResponse, error) {
	var resp ListAgentsResponse
	err := c.cc.Invoke(ctx, "/"+operatorServiceName+"/ListAgents", req, &resp, opts...)
	return &resp, err
}

func (c *operatorServiceClient) GetAgent(ctx context.Context, req *GetAgentRequest, opts ...grpc.CallOption) (*GetAgentResponse, error) {
	var resp GetAgentResponse
	err := c.cc.Invoke(ctx, "/"+operatorServiceName+"/GetAgent", req, &resp, opts...)
	return &resp, err
}

func (c *operatorServiceClient) KillAgent(ctx context.Context, req *KillAgentRequest, opts ...grpc.CallOption) (*KillAgentResponse, error) {
	var resp KillAgentResponse
	err := c.cc.Invoke(ctx, "/"+operatorServiceName+"/KillAgent", req, &resp, opts...)
	return &resp, err
}

func (c *operatorServiceClient) CreateTask(ctx context.Context, req *CreateTaskRequest, opts ...grpc.CallOption) (*CreateTaskResponse, error) {
	var resp CreateTaskResponse
	err := c.cc.Invoke(ctx, "/"+operatorServiceName+"/CreateTask", req, &resp, opts...)
	return &resp, err
}

func (c *operatorServiceClient) GetTask(ctx context.Context, req *GetTaskRequest, opts ...grpc.CallOption) (*GetTaskResponse, error) {
	var resp GetTaskResponse
	err := c.cc.Invoke(ctx, "/"+operatorServiceName+"/GetTask", req, &resp, opts...)
	return &resp, err
}

func (c *operatorServiceClient) ListTasks(ctx context.Context, req *ListTasksRequest, opts ...grpc.CallOption) (*ListTasksResponse, error) {
	var resp ListTasksResponse
	err := c.cc.Invoke(ctx, "/"+operatorServiceName+"/ListTasks", req, &resp, opts...)
	return &resp, err
}

func (c *operatorServiceClient) GeneratePayload(ctx context.Context, req *GeneratePayloadRequest, opts ...grpc.CallOption) (*GeneratePayloadResponse, error) {
	var resp GeneratePayloadResponse
	err := c.cc.Invoke(ctx, "/"+operatorServiceName+"/GeneratePayload", req, &resp, opts...)
	return &resp, err
}

func (c *operatorServiceClient) SubscribeEvents(ctx context.Context, req *SubscribeEventsRequest, opts ...grpc.CallOption) (OperatorService_SubscribeEventsClient, error) {
	stream, err := c.cc.NewStream(ctx, &_operatorServiceDesc.Streams[0], "/"+operatorServiceName+"/SubscribeEvents", opts...)
	if err != nil {
		return nil, err
	}
	x := &operatorServiceSubscribeEventsClient{stream}
	if err := x.SendMsg(req); err != nil {
		return nil, err
	}
	if err := x.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

func (c *operatorServiceClient) StartListener(ctx context.Context, req *StartListenerRequest, opts ...grpc.CallOption) (*StartListenerResponse, error) {
	var resp StartListenerResponse
	err := c.cc.Invoke(ctx, "/"+operatorServiceName+"/StartListener", req, &resp, opts...)
	return &resp, err
}

func (c *operatorServiceClient) StopListener(ctx context.Context, req *StopListenerRequest, opts ...grpc.CallOption) (*StopListenerResponse, error) {
	var resp StopListenerResponse
	err := c.cc.Invoke(ctx, "/"+operatorServiceName+"/StopListener", req, &resp, opts...)
	return &resp, err
}

func (c *operatorServiceClient) ListListeners(ctx context.Context, req *ListListenersRequest, opts ...grpc.CallOption) (*ListListenersResponse, error) {
	var resp ListListenersResponse
	err := c.cc.Invoke(ctx, "/"+operatorServiceName+"/ListListeners", req, &resp, opts...)
	return &resp, err
}

func (c *operatorServiceClient) ListOperators(ctx context.Context, req *ListOperatorsRequest, opts ...grpc.CallOption) (*ListOperatorsResponse, error) {
	var resp ListOperatorsResponse
	err := c.cc.Invoke(ctx, "/"+operatorServiceName+"/ListOperators", req, &resp, opts...)
	return &resp, err
}

func (c *operatorServiceClient) RegisterOperator(ctx context.Context, req *RegisterOperatorRequest, opts ...grpc.CallOption) (*RegisterOperatorResponse, error) {
	var resp RegisterOperatorResponse
	err := c.cc.Invoke(ctx, "/"+operatorServiceName+"/RegisterOperator", req, &resp, opts...)
	return &resp, err
}

func (c *operatorServiceClient) ListLoot(ctx context.Context, req *ListLootRequest, opts ...grpc.CallOption) (*ListLootResponse, error) {
	var resp ListLootResponse
	err := c.cc.Invoke(ctx, "/"+operatorServiceName+"/ListLoot", req, &resp, opts...)
	return &resp, err
}

func (c *operatorServiceClient) GetServerInfo(ctx context.Context, req *GetServerInfoRequest, opts ...grpc.CallOption) (*GetServerInfoResponse, error) {
	var resp GetServerInfoResponse
	err := c.cc.Invoke(ctx, "/"+operatorServiceName+"/GetServerInfo", req, &resp, opts...)
	return &resp, err
}

func (c *operatorServiceClient) ListProfiles(ctx context.Context, req *ListProfilesRequest, opts ...grpc.CallOption) (*ListProfilesResponse, error) {
	var resp ListProfilesResponse
	err := c.cc.Invoke(ctx, "/"+operatorServiceName+"/ListProfiles", req, &resp, opts...)
	return &resp, err
}

func (c *operatorServiceClient) SetActiveProfile(ctx context.Context, req *SetActiveProfileRequest, opts ...grpc.CallOption) (*SetActiveProfileResponse, error) {
	var resp SetActiveProfileResponse
	err := c.cc.Invoke(ctx, "/"+operatorServiceName+"/SetActiveProfile", req, &resp, opts...)
	return &resp, err
}

func (c *operatorServiceClient) Weaponize(ctx context.Context, req *WeaponizeRequest, opts ...grpc.CallOption) (*WeaponizeResponse, error) {
	var resp WeaponizeResponse
	err := c.cc.Invoke(ctx, "/"+operatorServiceName+"/Weaponize", req, &resp, opts...)
	return &resp, err
}

func (c *operatorServiceClient) RegisterStage2(ctx context.Context, req *RegisterStage2Request, opts ...grpc.CallOption) (*RegisterStage2Response, error) {
	var resp RegisterStage2Response
	err := c.cc.Invoke(ctx, "/"+operatorServiceName+"/RegisterStage2", req, &resp, opts...)
	return &resp, err
}

// === Streaming Client ===

// OperatorService_SubscribeEventsClient 事件流客户端。
type OperatorService_SubscribeEventsClient interface {
	Recv() (*EventInfo, error)
	grpc.ClientStream
}

type operatorServiceSubscribeEventsClient struct {
	grpc.ClientStream
}

func (x *operatorServiceSubscribeEventsClient) Recv() (*EventInfo, error) {
	m := new(EventInfo)
	if err := x.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// === Server ===

// UnimplementedOperatorServiceServer 未实现的服务基类。
type UnimplementedOperatorServiceServer struct{}

var errUnimplemented = status.Error(codes.Unimplemented, "not implemented")

func (UnimplementedOperatorServiceServer) ListAgents(ctx context.Context, req *ListAgentsRequest) (*ListAgentsResponse, error) {
	return nil, errUnimplemented
}
func (UnimplementedOperatorServiceServer) GetAgent(ctx context.Context, req *GetAgentRequest) (*GetAgentResponse, error) {
	return nil, errUnimplemented
}
func (UnimplementedOperatorServiceServer) KillAgent(ctx context.Context, req *KillAgentRequest) (*KillAgentResponse, error) {
	return nil, errUnimplemented
}
func (UnimplementedOperatorServiceServer) CreateTask(ctx context.Context, req *CreateTaskRequest) (*CreateTaskResponse, error) {
	return nil, errUnimplemented
}
func (UnimplementedOperatorServiceServer) GetTask(ctx context.Context, req *GetTaskRequest) (*GetTaskResponse, error) {
	return nil, errUnimplemented
}
func (UnimplementedOperatorServiceServer) ListTasks(ctx context.Context, req *ListTasksRequest) (*ListTasksResponse, error) {
	return nil, errUnimplemented
}
func (UnimplementedOperatorServiceServer) GeneratePayload(ctx context.Context, req *GeneratePayloadRequest) (*GeneratePayloadResponse, error) {
	return nil, errUnimplemented
}
func (UnimplementedOperatorServiceServer) SubscribeEvents(req *SubscribeEventsRequest, stream OperatorService_SubscribeEventsServer) error {
	return errUnimplemented
}
func (UnimplementedOperatorServiceServer) StartListener(ctx context.Context, req *StartListenerRequest) (*StartListenerResponse, error) {
	return nil, errUnimplemented
}
func (UnimplementedOperatorServiceServer) StopListener(ctx context.Context, req *StopListenerRequest) (*StopListenerResponse, error) {
	return nil, errUnimplemented
}
func (UnimplementedOperatorServiceServer) ListListeners(ctx context.Context, req *ListListenersRequest) (*ListListenersResponse, error) {
	return nil, errUnimplemented
}
func (UnimplementedOperatorServiceServer) ListOperators(ctx context.Context, req *ListOperatorsRequest) (*ListOperatorsResponse, error) {
	return nil, errUnimplemented
}
func (UnimplementedOperatorServiceServer) RegisterOperator(ctx context.Context, req *RegisterOperatorRequest) (*RegisterOperatorResponse, error) {
	return nil, errUnimplemented
}
func (UnimplementedOperatorServiceServer) ListLoot(ctx context.Context, req *ListLootRequest) (*ListLootResponse, error) {
	return nil, errUnimplemented
}
func (UnimplementedOperatorServiceServer) GetServerInfo(ctx context.Context, req *GetServerInfoRequest) (*GetServerInfoResponse, error) {
	return nil, errUnimplemented
}
func (UnimplementedOperatorServiceServer) ListProfiles(ctx context.Context, req *ListProfilesRequest) (*ListProfilesResponse, error) {
	return nil, errUnimplemented
}
func (UnimplementedOperatorServiceServer) SetActiveProfile(ctx context.Context, req *SetActiveProfileRequest) (*SetActiveProfileResponse, error) {
	return nil, errUnimplemented
}
func (UnimplementedOperatorServiceServer) Weaponize(ctx context.Context, req *WeaponizeRequest) (*WeaponizeResponse, error) {
	return nil, errUnimplemented
}
func (UnimplementedOperatorServiceServer) RegisterStage2(ctx context.Context, req *RegisterStage2Request) (*RegisterStage2Response, error) {
	return nil, errUnimplemented
}

// OperatorServiceServer Operator 服务接口。
type OperatorServiceServer interface {
	ListAgents(context.Context, *ListAgentsRequest) (*ListAgentsResponse, error)
	GetAgent(context.Context, *GetAgentRequest) (*GetAgentResponse, error)
	KillAgent(context.Context, *KillAgentRequest) (*KillAgentResponse, error)
	CreateTask(context.Context, *CreateTaskRequest) (*CreateTaskResponse, error)
	GetTask(context.Context, *GetTaskRequest) (*GetTaskResponse, error)
	ListTasks(context.Context, *ListTasksRequest) (*ListTasksResponse, error)
	GeneratePayload(context.Context, *GeneratePayloadRequest) (*GeneratePayloadResponse, error)
	SubscribeEvents(*SubscribeEventsRequest, OperatorService_SubscribeEventsServer) error
	StartListener(context.Context, *StartListenerRequest) (*StartListenerResponse, error)
	StopListener(context.Context, *StopListenerRequest) (*StopListenerResponse, error)
	ListListeners(context.Context, *ListListenersRequest) (*ListListenersResponse, error)
	ListOperators(context.Context, *ListOperatorsRequest) (*ListOperatorsResponse, error)
	RegisterOperator(context.Context, *RegisterOperatorRequest) (*RegisterOperatorResponse, error)
	ListLoot(context.Context, *ListLootRequest) (*ListLootResponse, error)
	GetServerInfo(context.Context, *GetServerInfoRequest) (*GetServerInfoResponse, error)
	ListProfiles(context.Context, *ListProfilesRequest) (*ListProfilesResponse, error)
	SetActiveProfile(context.Context, *SetActiveProfileRequest) (*SetActiveProfileResponse, error)
	Weaponize(context.Context, *WeaponizeRequest) (*WeaponizeResponse, error)
	RegisterStage2(context.Context, *RegisterStage2Request) (*RegisterStage2Response, error)
}

// OperatorService_SubscribeEventsServer 事件流服务器端。
type OperatorService_SubscribeEventsServer interface {
	Send(*EventInfo) error
	grpc.ServerStream
}

type operatorServiceSubscribeEventsServer struct {
	grpc.ServerStream
}

func (x *operatorServiceSubscribeEventsServer) Send(m *EventInfo) error {
	return x.ServerStream.SendMsg(m)
}

// RegisterOperatorServiceServer 注册 OperatorServiceServer 到 gRPC 服务器。
func RegisterOperatorServiceServer(s *grpc.Server, srv OperatorServiceServer) {
	s.RegisterService(&_operatorServiceDesc, srv)
}

var _operatorServiceDesc = grpc.ServiceDesc{
	ServiceName: operatorServiceName,
	HandlerType: (*OperatorServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "ListAgents", Handler: _operatorService_ListAgents_Handler},
		{MethodName: "GetAgent", Handler: _operatorService_GetAgent_Handler},
		{MethodName: "KillAgent", Handler: _operatorService_KillAgent_Handler},
		{MethodName: "CreateTask", Handler: _operatorService_CreateTask_Handler},
		{MethodName: "GetTask", Handler: _operatorService_GetTask_Handler},
		{MethodName: "ListTasks", Handler: _operatorService_ListTasks_Handler},
		{MethodName: "GeneratePayload", Handler: _operatorService_GeneratePayload_Handler},
		{MethodName: "StartListener", Handler: _operatorService_StartListener_Handler},
		{MethodName: "StopListener", Handler: _operatorService_StopListener_Handler},
		{MethodName: "ListListeners", Handler: _operatorService_ListListeners_Handler},
		{MethodName: "ListOperators", Handler: _operatorService_ListOperators_Handler},
		{MethodName: "RegisterOperator", Handler: _operatorService_RegisterOperator_Handler},
		{MethodName: "ListLoot", Handler: _operatorService_ListLoot_Handler},
		{MethodName: "GetServerInfo", Handler: _operatorService_GetServerInfo_Handler},
		{MethodName: "ListProfiles", Handler: _operatorService_ListProfiles_Handler},
		{MethodName: "SetActiveProfile", Handler: _operatorService_SetActiveProfile_Handler},
		{MethodName: "Weaponize", Handler: _operatorService_Weaponize_Handler},
		{MethodName: "RegisterStage2", Handler: _operatorService_RegisterStage2_Handler},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "SubscribeEvents",
			Handler:       _operatorService_SubscribeEvents_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "aegis.proto",
}

// === Unary Handlers ===

func _operatorService_ListAgents_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListAgentsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OperatorServiceServer).ListAgents(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + operatorServiceName + "/ListAgents"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OperatorServiceServer).ListAgents(ctx, req.(*ListAgentsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _operatorService_GetAgent_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetAgentRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OperatorServiceServer).GetAgent(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + operatorServiceName + "/GetAgent"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OperatorServiceServer).GetAgent(ctx, req.(*GetAgentRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _operatorService_KillAgent_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(KillAgentRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OperatorServiceServer).KillAgent(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + operatorServiceName + "/KillAgent"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OperatorServiceServer).KillAgent(ctx, req.(*KillAgentRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _operatorService_CreateTask_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateTaskRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OperatorServiceServer).CreateTask(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + operatorServiceName + "/CreateTask"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OperatorServiceServer).CreateTask(ctx, req.(*CreateTaskRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _operatorService_GetTask_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetTaskRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OperatorServiceServer).GetTask(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + operatorServiceName + "/GetTask"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OperatorServiceServer).GetTask(ctx, req.(*GetTaskRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _operatorService_ListTasks_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListTasksRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OperatorServiceServer).ListTasks(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + operatorServiceName + "/ListTasks"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OperatorServiceServer).ListTasks(ctx, req.(*ListTasksRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _operatorService_GeneratePayload_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GeneratePayloadRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OperatorServiceServer).GeneratePayload(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + operatorServiceName + "/GeneratePayload"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OperatorServiceServer).GeneratePayload(ctx, req.(*GeneratePayloadRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _operatorService_StartListener_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(StartListenerRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OperatorServiceServer).StartListener(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + operatorServiceName + "/StartListener"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OperatorServiceServer).StartListener(ctx, req.(*StartListenerRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _operatorService_StopListener_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(StopListenerRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OperatorServiceServer).StopListener(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + operatorServiceName + "/StopListener"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OperatorServiceServer).StopListener(ctx, req.(*StopListenerRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _operatorService_ListListeners_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListListenersRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OperatorServiceServer).ListListeners(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + operatorServiceName + "/ListListeners"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OperatorServiceServer).ListListeners(ctx, req.(*ListListenersRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _operatorService_ListOperators_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListOperatorsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OperatorServiceServer).ListOperators(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + operatorServiceName + "/ListOperators"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OperatorServiceServer).ListOperators(ctx, req.(*ListOperatorsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _operatorService_RegisterOperator_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RegisterOperatorRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OperatorServiceServer).RegisterOperator(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + operatorServiceName + "/RegisterOperator"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OperatorServiceServer).RegisterOperator(ctx, req.(*RegisterOperatorRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _operatorService_ListLoot_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListLootRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OperatorServiceServer).ListLoot(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + operatorServiceName + "/ListLoot"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OperatorServiceServer).ListLoot(ctx, req.(*ListLootRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _operatorService_GetServerInfo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetServerInfoRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OperatorServiceServer).GetServerInfo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + operatorServiceName + "/GetServerInfo"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OperatorServiceServer).GetServerInfo(ctx, req.(*GetServerInfoRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _operatorService_ListProfiles_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListProfilesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OperatorServiceServer).ListProfiles(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + operatorServiceName + "/ListProfiles"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OperatorServiceServer).ListProfiles(ctx, req.(*ListProfilesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _operatorService_SetActiveProfile_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SetActiveProfileRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OperatorServiceServer).SetActiveProfile(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + operatorServiceName + "/SetActiveProfile"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OperatorServiceServer).SetActiveProfile(ctx, req.(*SetActiveProfileRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _operatorService_Weaponize_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(WeaponizeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OperatorServiceServer).Weaponize(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + operatorServiceName + "/Weaponize"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OperatorServiceServer).Weaponize(ctx, req.(*WeaponizeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _operatorService_RegisterStage2_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RegisterStage2Request)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OperatorServiceServer).RegisterStage2(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + operatorServiceName + "/RegisterStage2"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OperatorServiceServer).RegisterStage2(ctx, req.(*RegisterStage2Request))
	}
	return interceptor(ctx, in, info, handler)
}

// === Stream Handler ===

func _operatorService_SubscribeEvents_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(SubscribeEventsRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(OperatorServiceServer).SubscribeEvents(m, &operatorServiceSubscribeEventsServer{stream})
}

// Code returns the gRPC status code from an error.
func Code(err error) codes.Code {
	if err == nil {
		return codes.OK
	}
	if s, ok := status.FromError(err); ok {
		return s.Code()
	}
	return codes.Unknown
}

// Errorf creates an error with a gRPC status code.
func Errorf(code codes.Code, format string, args ...interface{}) error {
	return status.Errorf(code, format, args...)
}
