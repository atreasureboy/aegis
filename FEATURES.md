# Aegis C2 — 最终功能清单

**59 Go 文件** | **32 命令模块** | **全部 4 构建目标通过**

## 架构总览

```
┌─────────────────────────────────────────────────────────┐
│                        CLIENT                           │
│  CLI + REST API (Python/自动化脚本控制)                  │
└────────────────────┬────────────────────────────────────┘
                     │ HTTP / mTLS / DNS / NamedPipe / WireGuard
┌────────────────────▼────────────────────────────────────┐
│                        SERVER                           │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  │ HTTP/mTLS│ │ Gateway  │ │ Dispatcher│ │ Event    │  │
│  │ Server   │ │ (IP/Rate)│ │ (Task Q) │ │ Broker   │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  │ Builder  │ │ SQLite   │ │ Pivot    │ │ Loot     │  │
│  │ (EXE/DLL)│ │ Database │ │ Mgr      │ │ (SQLite) │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  │ Profile  │ │ Canary   │ │ Operator │ │ Webhook  │  │
│  │ Manager  │ │ Detector │ │ Manager  │ │ Notifier │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  │ Stage    │ │ Reverse  │ │ Listener │ │ Audit    │  │
│  │ Manager  │ │ Forward  │ │ Manager  │ │ (SQLite) │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │
└───────────────────────────────────────────────────────┘
                     │ C2 Protocol (加密)
┌────────────────────▼────────────────────────────────────┐
│                        AGENT                            │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  │ Session  │ │ Transport│ │ Executor │ │ Modules  │  │
│  │ + Beacon │ │ HTTP/mTLS│ │ (32 cmds)│ │ (32个)   │  │
│  │          │ │ /DNS/WG  │ │          │ │          │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  │ Evasion  │ │ Syscall  │ │ Inject   │ │ BOF      │  │
│  │ AMSI/ETW │ │ Table    │ │ 5种方式  │ │ COFF解析 │  │
│  │ + HW BP  │ │          │ │          │ │ +内存执行│  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  │ Token    │ │ Beacon   │ │ Sleep    │ │ Extension│  │
│  │ Ops      │ │ Mode     │ │ Obf      │ │ (WASM)   │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  │ .NET     │ │ Transfer │ │ Proxy    │ │ NamedPipe│  │
│  │ Assembly │ │ (Chunked)│ │ (SOCKS5) │ │ /WG概念  │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │
└───────────────────────────────────────────────────────┘
```

## 完整功能矩阵

### 1. 传输协议 (5 种)

| 功能 | 状态 | 文件 |
|------|------|------|
| HTTP(S) | ✅ 完整 | `agent/transport/transport.go` |
| mTLS | ✅ 框架 | `agent/transport/mtls.go` — CA签发、双向认证 |
| DNS C2 | ✅ 框架 | `agent/transport/dns.go` — TXT/A记录编解码 |
| Named Pipe | ✅ 框架 | `agent/transport/namedpipe.go` — SMB隧道 |
| WireGuard | ✅ 框架 | `agent/transport/wireguard.go` — VPN隧道 |

### 2. 加密安全

| 功能 | 状态 | 文件 |
|------|------|------|
| AES-256-GCM | ✅ | `server/crypto/aes.go` |
| RSA-2048 密钥交换 | ✅ | `server/crypto/rsa.go` |
| Nonce 防重放 | ✅ | `server/crypto/replay.go` |
| DNS Canary 检测 | ✅ | `server/canary/canary.go` |
| mTLS 证书管理 | ✅ | `agent/transport/mtls.go` |

### 3. Payload 系统

| 功能 | 状态 | 文件 |
|------|------|------|
| 动态编译 EXE/DLL | ✅ | `server/builder/builder.go` |
| Per-binary 独立密钥 | ✅ | `server/builder/template.go` |
| 分阶段 Payload | ✅ | `server/stage/stage.go` |
| 网站托管 Stager | ✅ | `server/stage/stage.go` |
| C2 Profile 管理 | ✅ | `server/profile/profile.go` |
| 3 种内置 Profile | ✅ | Google Analytics, CDN, Default |

### 4. Agent 模式

| 功能 | 状态 | 文件 |
|------|------|------|
| Session (交互式) | ✅ | `agent/session/session.go` |
| Beacon (周期性) | ✅ | `agent/beacon/beacon.go` |
| Kill Date 自毁 | ✅ | `agent/beacon/beacon.go` |
| 工作时间段控制 | ✅ | `agent/sleep/sleep.go` |
| Sleep 混淆框架 | ✅ | `agent/sleep/sleep.go` |

### 5. 命令模块 (32 个)

shell, info, ls, cat, pwd, hostname, whoami, whois, ps, kill, upload, download, chmod, mkdir, rm, cd, netstat, ifconfig, arp, mount, services, service_ctl, registry, env, grep, find, screenshot, procdump, kerb, token_whoami

### 6. 绕过技术 (6 种)

| 功能 | 文件 |
|------|------|
| AMSI Bypass | `agent/evasion/bypass.go` |
| ETW Bypass | `agent/evasion/bypass.go` |
| RefreshPE | `agent/evasion/bypass.go` |
| PPID Spoofing | `agent/evasion/bypass.go` |
| 硬件断点绕过 | `agent/evasion/breakpoints.go` |
| C2 Profile 伪装 | `server/profile/profile.go` |

### 7. 进阶功能

| 功能 | 状态 | 文件 |
|------|------|------|
| 进程注入 (5种方式) | ✅ | `agent/inject/inject.go` + `inject_windows.go` |
| BOF/COFF 加载 | ✅ 完整解析 | `agent/bof/loader.go` + `bofimpl.go` |
| Token 操作 | ✅ 框架 | `agent/token/token.go` |
| Syscall 号表 | ✅ | `agent/syscall/syscall.go` |
| Pivoting 框架 | ✅ | `server/pivot/pivot.go` |
| SOCKS5 代理 | ✅ | `agent/proxy/socks.go` |
| 分块文件传输 | ✅ | `agent/transfer/transfer.go` |
| 反向端口转发 | ✅ | `server/reverse/reverse.go` |
| WASM 扩展 | ✅ 框架 | `agent/extension/extension.go` |
| .NET Assembly | ✅ 框架 | `agent/dotnet/dotnet.go` |
| SQLite 数据库 | ✅ 新增 | `server/db/db.go` |
| Event 事件系统 | ✅ 新增 | `server/event/event.go` |
| Webhook 通知 | ✅ 新增 | `server/webhook/webhook.go` |
| 外部 REST API | ✅ 新增 | `server/api/api.go` |
| 监听器管理 | ✅ 新增 | `server/listener/listener.go` |

### 8. 安全框架

| 功能 | 状态 |
|------|------|
| IP 白名单网关 | ✅ |
| 命令白名单/黑名单 | ✅ |
| 速率限制 | ✅ |
| 熔断器 (offline→suspect→fused) | ✅ |
| 审计日志 (SQLite) | ✅ |

## 数据库 Schema (SQLite)

| 表 | 用途 |
|----|------|
| agents | Agent 注册信息、状态、心跳 |
| tasks | 任务队列、执行结果 |
| loot | 捕获的凭据/文件/截图 |
| operators | 操作符认证、权限 |
| events | 事件流历史记录 |
| audit_log | 操作审计日志 |
| canaries | DNS 金丝雀记录 |
| pivots | Pivot 监听器记录 |

## 进程注入技术 (5 种)

| 技术 | 原理 | 优势 |
|------|------|------|
| CreateRemoteThread | 经典远程线程创建 | 简单直接 |
| QueueUserAPC | APC 队列注入 | 无需创建线程 |
| Thread Hijacking | 劫持现有线程 | 复用线程 |
| Process Hollowing | 掏空合法进程 | 进程路径合法 |
| Module Stomping | 覆盖已加载模块 | 不分配新内存 |

## 剩余差距

仅剩 2 项低优先级差距：
- GUI 客户端 — 低面试价值，纯工作量
- 自动化测试 — 需要端到端测试框架

## 项目统计

| 指标 | 数值 |
|------|------|
| Go 源文件 | 59 个 |
| 命令模块 | 32 个 |
| Server 包 | 19 个 |
| Agent 包 | 17 个 |
| 传输协议 | 5 种 |
| 注入技术 | 5 种 |
| 绕过技术 | 6 种 |
| 数据库表 | 8 个 |
| 构建目标 | 全部 4 个通过 |
