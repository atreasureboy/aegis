# Aegis C2 Framework - 架构设计文档

> 学术面试用途的 C2 框架，借鉴 Sliver 和 Havoc 的设计优点，内置严格安全审查与熔断机制。

## 1. 设计目标

- **教学展示价值**：每个模块职责清晰，面试能讲清楚"为什么这么设计"
- **模块化**：传输层、加密层、任务调度层完全解耦
- **安全优先**：内置白名单、操作限制、自动熔断、审计日志
- **轻量**：最小化实现，不追求功能广度

## 2. 整体架构

```
┌─────────────────────────────────────────────────────────┐
│                        Client (CLI)                     │
│  ┌───────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  命令解析  │  │  任务提交     │  │  结果展示/日志    │  │
│  └─────┬─────┘  └──────┬───────┘  └──────────────────┘  │
│        └───────────────┼────────────────────────────────┘
│                        │ REST API / WebSocket
┌────────────────────────┼─────────────────────────────────┐
│                        │  Server                         │
│  ┌─────────────────────┼───────────────────────────────┐ │
│  │               HTTP 监听器                            │ │
│  │  ┌─────────────────┼───────────────────────────────┐│ │
│  │  │           安全审查层 (Gateway)                   ││ │
│  │  │  ┌──────────────┼──────────┐  ┌───────────────┐ ││ │
│  │  │  │ IP 白名单    │ 操作权限  │  │  熔断控制器    │ ││ │
│  │  │  └──────────────┴──────────┘  └───────────────┘ ││ │
│  │  └─────────────────┼───────────────────────────────┘│ │
│  │                    │                                 │ │
│  │  ┌─────────────────┼───────────────────────────────┐│ │
│  │  │           任务调度层                              ││ │
│  │  │  ┌──────────────┐  ┌──────────┐  ┌───────────┐  ││ │
│  │  │  │ Agent 管理器  │  │ 任务队列  │  │ 心跳管理   │  ││ │
│  │  │  └──────────────┘  └──────────┘  └───────────┘  ││ │
│  │  └─────────────────┼───────────────────────────────┘│ │
│  │                    │                                 │ │
│  │  ┌─────────────────┼───────────────────────────────┐│ │
│  │  │           加密层 (借鉴 Sliver)                    ││ │
│  │  │  Per-Agent AES-GCM + Nonce 重放防护              ││ │
│  │  └─────────────────────────────────────────────────┘│ │
│  └───────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                         │ HTTPS / WS
┌─────────────────────────────────────────────────────────────┐
│                        Agent                                │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │  注册/心跳    │  │  任务执行器   │  │  加密传输层        │  │
│  │  (循环)       │  │  (Shell/Info) │  │  (AES-GCM)       │  │
│  └──────────────┘  └──────────────┘  └───────────────────┘  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  安全限制: 不执行危险操作, 仅支持学术演示命令           │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## 3. 三端职责

### 3.1 Server（服务端）
- 接收 Agent 注册和心跳
- 管理 Agent 生命周期（在线/离线/超时）
- 任务队列管理（排队 → 派发 → 结果回收）
- 安全审查（白名单、权限、熔断）
- REST API 供 Client 调用

**借鉴来源**：
- 监听器模型 ← Sliver `server/c2/http.go` 的 HTTP Handler 结构
- 任务派发 ← Havoc `teamserver/cmd/server/dispatch.go` 的简洁流程
- Agent 管理 ← Sliver `server/core/` 的会话管理

### 3.2 Agent（植入体）
- 向 Server 注册（携带身份信息）
- 定时心跳保活
- 拉取任务并执行
- 加密回传结果
- 自动重连机制

**借鉴来源**：
- 心跳循环模型 ← Sliver `implant/sliver/transports/` 的传输抽象
- 任务执行器 ← Havoc 的 Demon 命令执行流程
- 每 Binary 独立密钥 ← Sliver 的动态编译密钥设计

### 3.3 Client（客户端）
- CLI 交互界面
- 通过 REST API 与 Server 通信
- 展示 Agent 列表、任务结果
- 下发任务命令

**借鉴来源**：
- CLI 交互模式 ← Sliver `client/console/` 的命令解析

## 4. 通信协议设计

### 4.1 消息格式（借鉴 Sliver 的 envelope 设计）

```protobuf
// 所有消息统一为 Envelope 结构
message Envelope {
    int64   timestamp    = 1;  // Unix 毫秒时间戳
    string  agent_id     = 2;  // Agent 唯一标识
    string  message_type = 3;  // register | heartbeat | task | result | ack
    bytes   payload      = 4;  // AES-GCM 加密后的载荷
    bytes   nonce        = 5;  // 24-byte random nonce
}
```

### 4.2 传输协议

```
Agent → Server:  POST /register   (首次注册)
Agent → Server:  POST /heartbeat  (心跳保活)
Agent → Server:  POST /poll       (拉取任务)
Agent → Server:  POST /result     (回传结果)

Client → Server: GET  /api/agents        (Agent 列表)
Client → Server: POST /api/tasks         (下发任务)
Client → Server: GET  /api/tasks/:id     (查询任务结果)
```

**为什么选 HTTP + REST**：
- 借鉴 Havoc 的简洁性，不用像 Sliver 那样引入 gRPC/Yamux
- REST API 面试时容易解释，且可以加 Web UI
- 足够支撑演示需求

## 5. 加密方案（借鉴 Sliver）

### 5.1 密钥体系

```
Server 启动时：
  1. 生成 RSA-2048 主密钥对 (pub/master.key, priv/master.key)
  2. Agent 编译时嵌入 Server 公钥

Agent 注册时：
  1. Agent 生成临时 AES-256 密钥
  2. 用 Server RSA 公钥加密 AES 密钥，随注册请求发送
  3. Server 解密后建立该 Agent 的加密会话

后续通信：
  所有消息使用 AES-256-GCM 加密，每次使用随机 Nonce
```

### 5.2 重放防护

```
每条消息携带 timestamp + nonce
Server 维护 nonce 缓存 (最近 5 分钟)
拒绝 timestamp 偏差 > 30s 或 nonce 重复的消息
```

## 6. 安全熔断系统（核心卖点）

### 6.1 IP 白名单
```yaml
security:
  whitelist:
    enabled: true
    allowed_ips: ["127.0.0.0/8", "10.0.0.0/8", "192.168.0.0/16"]
    allowed_domains: ["localhost", "*.local"]
```

### 6.2 操作权限控制
```yaml
security:
  allowed_commands:
    - "whoami"
    - "hostname"
    - "uname -a"
    - "ps aux"
    - "ls -la"
    - "cat /etc/hosts"
    - "netstat -an"
  blocked_commands: ["rm", "shutdown", "format", "net user", "mimikatz"]
  academic_mode: true  # 开启后仅允许白名单命令
```

### 6.3 自动熔断规则
```yaml
security:
  circuit_breaker:
    max_heartbeat_failures: 5      # 连续 5 次心跳失败 → 标记离线
    max_tasks_per_minute: 10       # 每分钟最多 10 个任务 → 限速
    max_concurrent_tasks: 3        # 同时最多 3 个任务
    task_timeout: 60s              # 任务超时自动取消
    anomaly_detection: true        # 异常行为检测
```

### 6.4 审计日志
```
所有操作写入审计日志：
[2026-04-20 10:15:30] AGENT_REGISTER  agent_id=xxx  ip=192.168.1.100
[2026-04-20 10:15:31] TASK_DISPATCH   agent_id=xxx  task=shell:whoami  operator=admin
[2026-04-20 10:15:32] TASK_RESULT     agent_id=xxx  task_id=yyy  status=success
[2026-04-20 10:15:35] CIRCUIT_BREAK   agent_id=xxx  reason=too_many_failures
```

## 7. 目录结构

```
aegis/
├── cmd/
│   ├── server/         # Server 入口
│   ├── agent/          # Agent 入口
│   └── client/         # Client 入口
├── server/
│   ├── http/           # HTTP 监听器
│   ├── gateway/        # 安全审查层 (IP 白名单、权限、熔断)
│   ├── dispatcher/     # 任务调度
│   ├── agent/          # Agent 管理 (注册、心跳、生命周期)
│   ├── crypto/         # 加密工具
│   ├── audit/          # 审计日志
│   └── config/         # 配置管理
├── agent/
│   ├── transport/      # 传输层 (HTTP 客户端)
│   ├── crypto/         # 加密工具
│   ├── executor/       # 任务执行器
│   └── config/         # Agent 配置 (嵌入公钥)
├── client/
│   ├── cmd/            # CLI 命令
│   └── api/            # REST API 客户端
├── shared/
│   ├── protocol/       # 消息定义 (Envelope, Task, Result)
│   └── types/          # 公共类型
├── config/
│   └── server.yaml     # 服务端配置
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

## 8. 面试讲解要点

1. **为什么全 Go**：Sliver 证明了 Go 的可行性，跨平台编译、并发模型天然适合 C2
2. **为什么 HTTP 而非 gRPC**：Havoc 的简洁设计思路，降低面试解释成本，HTTP 本身足够
3. **加密为什么用 AES-GCM**：认证加密，同时提供保密性和完整性，Sliver 也采用此方案
4. **安全熔断设计**：这是和 Sliver/Havoc 的本质区别，强调"学术用途"的边界意识
5. **模块化设计**：传输层、加密层、调度层解耦，展示工程化思维
