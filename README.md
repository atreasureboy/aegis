# Aegis

> A full-featured Command & Control framework, built for security research and authorized red team operations.

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/Rust-nightly-dea584?logo=rust&logoColor=white" alt="Rust">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-blue" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
</p>

---

## Architecture

```
                                      ╔══════════════════════════════════════════════════════════╗
                                      ║                    AEGIS ECOSYSTEM                        ║
                                      ╚══════════════════════════════════════════════════════════╝

┌──────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                  CONTROL PLANE (Operator Side)                                       │
│                                                                                                      │
│   ┌──────────────┐     gRPC mTLS      ┌──────────────────────────────────────────────────┐           │
│   │              │ ◄────────────────► │                                                  │           │
│   │   Client     │                    │                  TEAMSERVER                       │           │
│   │  (CLI/REPL)  │                    │                                                   │           │
│   │              │                    │  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │           │
│   └──────────────┘                    │  │ Agent    │  │ Task     │  │ Operator     │   │           │
│                                       │  │ Manager  │  │ Dispatch │  │ Registry     │   │           │
│                                       │  └────┬─────┘  └────┬─────┘  └──────┬───────┘   │           │
│                                       │       │              │              │           │           │
│                                       │  ┌────┴──────────────┴──────────────┴───────┐   │           │
│                                       │  │              SQLite Database               │   │           │
│                                       │  │  agents │ tasks │ loot │ events │ audit   │   │           │
│                                       │  └────────────────────────────────────────────┘   │           │
│                                       │                                                   │           │
│                                       │  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │           │
│                                       │  │ Builder  │  │ Profile  │  │ Stage        │   │           │
│                                       │  │ Engine   │  │ Manager  │  │ Store        │   │           │
│                                       │  └──────────┘  └──────────┘  └──────────────┘   │           │
│                                       │                                                   │           │
│                                       │  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │           │
│                                       │  │ Canary   │  │ Webhook  │  │ LLM Analyst  │   │           │
│                                       │  │ DNS      │  │ Engine   │  │ Module       │   │           │
│                                       │  └──────────┘  └──────────┘  └──────────────┘   │           │
│                                       └──────────────────────────┬───────────────────────┘           │
└──────────────────────────────────────────────────────────────────┼───────────────────────────────────┘
                                                                   │
                    ╔══════════════════════════════════════════════╧═══════════════════════════════════╗
                    ║                        TRANSPORT LAYER (C2 Channels)                             ║
                    ╚══════════════════════════════════════════════╤═══════════════════════════════════╝
                                                                   │
              ┌──────────────────┬──────────────────┬───────────────┴──────┬──────────────────┐
              │                  │                  │                      │                  │
         ┌────▼─────┐      ┌────▼─────┐      ┌──────▼──────┐       ┌──────▼──────┐    ┌──────▼──────┐
         │ HTTP/S   │      │   mTLS   │      │ WebSocket   │       │  DNS C2     │    │ Named Pipe  │
         │ Profile  │      │ Pinning  │      │ + Yamux MUX │       │ Raw UDP     │    │ SMB Pivot   │
         │ Camou-   │      │ ECDH     │      │ Domain      │       │ Session     │    │ Chain       │
         │ flage    │      │ Handshake│      │ Fronting    │       │ Protocol    │    │             │
         └────┬─────┘      └────┬─────┘      └──────┬──────┘       └──────┬──────┘    └──────┬──────┘
              │                 │                   │                     │                  │
              └─────────────────┴───────────────────┴─────────────────────┴──────────────────┘
                                                   │
╔══════════════════════════════════════════════════╧══════════════════════════════════════════════════╗
║                              PAYLOAD LAYER (Implant Side)                                          ║
║                                                                                                    ║
║   ┌────────────────────────────────────────────────────────────────────────────────────────────┐   ║
║   │                                    AGENT RUNTIME                                           │   ║
║   │                                                                                            │   ║
║   │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────────────┐  │   ║
║   │  │ Transport  │  │  Session   │  │  Executor  │  │   Sleep    │  │    Evasion         │  │   ║
║   │  │  Drivers   │──►│  Manager  │──►│  Engine    │  │  Obfus-    │  │    Suite           │  │   ║
║   │  │  (5 proto) │  │  + Heart-  │  │  + Task    │  │  cation    │  │                    │  │   ║
║   │  │            │  │  beat      │  │  Queue     │  │  (Ekko/    │  │  AMSI/ETW Bypass   │  │   ║
║   │  └────────────┘  └────────────┘  └────────────┘  │   Foliage) │  │  Indirect Syscall  │  │   ║
║   │                                                    └────────────┘  │  HW Breakpoints    │  │   ║
║   │                                                                    │  Sandbox Detect    │  │   ║
║   │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐  │  PPID Spoofing     │  │   ║
║   │  │  Inject    │  │    BOF     │  │   .NET     │  │  Credential│  │  RefreshPE         │  │   ║
║   │  │  Engine    │  │  Loader    │  │  Loader    │  │  Extractor │  │  Stack Spoofing    │  │   ║
║   │  │            │  │            │  │            │  │            │  │  API Hashing       │  │   ║
║   │  │ APC/Fiber/ │  │ COFF Parse │  │ CLR Host   │  │ DPAPI/     │  └────────────────────┘  │   ║
║   │  │ Stomp+     │  │ In-Memory  │  │ In-Memory  │  │ Browser/   │                          │   ║
║   │  │ Hijack/    │  │ Exec       │  │ Exec       │  │ CredMgr    │  ┌────────────────────┐  │   ║
║   │  │ PoolParty  │  └────────────┘  └────────────┘  └────────────┘  │   Persistence      │  │   ║
║   │  └────────────┘                                                   │   Module           │  │   ║
║   │                                                                   │                    │  │   ║
║   │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐  │ Scheduled Task     │  │   ║
║   │  │  Network   │  │   File     │  │  Process   │  │   Screen   │  │ WMI Event          │  │   ║
║   │  │  Enum      │  │ Transfer   │  │  Enum      │  │  Capture   │  │ Registry Run       │  │   ║
║   │  │  AD/SMB    │  │ + Compress │  │ + Kill     │  │ + Keylog   │  │ Service Install    │  │   ║
║   │  └────────────┘  └────────────┘  └────────────┘  └────────────┘  └────────────────────┘  │   ║
║   │                                                                                            │   ║
║   │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐                          │   ║
║   │  │  SOCKS5    │  │   Port     │  │   Pivot    │  │  Token     │                          │   ║
║   │  │  Proxy     │  │ Forward    │  │ Chain      │  │  Ops       │                          │   ║
║   │  └────────────┘  └────────────┘  └────────────┘  └────────────┘                          │   ║
║   └────────────────────────────────────────────────────────────────────────────────────────────┘   ║
║                                                                                                    ║
║   ┌────────────────────────────────────────────────────────────────────────────────────────────┐   ║
║   │                                  DELIVERY CHAIN                                             │   ║
║   │                                                                                            │   ║
║   │   Staged Mode:                                                                             │   ║
║   │   ┌──────────┐    HTTPS      ┌──────────┐    AES-GCM     ┌──────────┐                      │   ║
║   │   │  Stager  │ ───────────►  │  Stage2  │ ◄───────────── │  Stage   │                      │   ║
║   │   │  (Go/    │               │  (Full   │   Decrypt      │  Store    │                      │   ║
║   │   │   Rust)  │               │  Agent)  │               │  (Server) │                      │   ║
║   │   └──────────┘               └──────────┘               └──────────┘                      │   ║
║   │                                                                                            │   ║
║   │   Stageless Mode:                                                                          │   ║
║   │   ┌──────────────────────────────────────────────────────────────────┐                     │   ║
║   │   │  Single Binary (EXE / DLL / Shellcode / Service)                 │                     │   ║
║   │   └──────────────────────────────────────────────────────────────────┘                     │   ║
║   │                                                                                            │   ║
║   │   Conversion:                                                                              │   ║
║   │   PE ──[Donut]──► Shellcode     PE ──[sRDI]──► Reflective Shellcode   PE ──[LNK]──► Link  │   ║
║   └────────────────────────────────────────────────────────────────────────────────────────────┘   ║
╚════════════════════════════════════════════════════════════════════════════════════════════════════╝
```

---

## Overview

Aegis is a modern C2 framework written primarily in Go, with Rust support for high-evasion payloads.
It implements a **three-tier architecture**: operator CLI connects to a central teamserver via gRPC mTLS,
the teamserver manages agents over multiple transport channels (HTTP/S, mTLS, WebSocket, DNS, Named Pipe),
and agents execute tasks with advanced evasion capabilities.

### Design Philosophy

| Principle | Implementation |
|-----------|---------------|
| **Defense in Depth** | AES-256-GCM + ECDH + HMAC + Anti-replay + mTLS |
| **Modularity** | Transport / Crypto / Scheduler fully decoupled |
| **Pluggable Agents** | Go implant (production) + Rust stager (high-evasion), coexist |
| **OPSEC-First** | Malleable profiles, JA3 spoofing, garble obfuscation, import renaming |
| **Teaching Value** | Clean code, clear boundaries, commented architecture |

---

## Security Architecture

### Encryption Chain

```
┌──────────────────────────────────────────────────────────────────┐
│                    Per-Agent Encryption Layer                     │
│                                                                  │
│  Agent                        Server                             │
│  ┌──────────┐                 ┌──────────┐                       │
│  │ X25519   │ ◄── ECDH ─────► │ X25519   │                       │
│  │ KeyPair  │     Exchange    │ KeyPair  │                       │
│  └────┬─────┘                 └────┬─────┘                       │
│       │                            │                             │
│       ▼ HKDF-SHA256                ▼ HKDF-SHA256                 │
│  ┌──────────┐                 ┌──────────┐                       │
│  │ AES-256  │ ◄── GCM ──────► │ AES-256  │                       │
│  │ Session  │     Envelope    │ Session  │                       │
│  └────┬─────┘                 └────┬─────┘                       │
│       │                            │                             │
│       ▼ HMAC-SHA256                ▼ HMAC Verify                 │
│  ┌──────────┐                 ┌──────────┐                       │
│  │ Envelope │ ◄── Integrity ─► │ Envelope │                       │
│  │ + Nonce  │     Check       │ + Nonce  │                       │
│  └──────────┘                 └──────────┘                       │
│                                                                  │
│  Anti-Replay: Sliding Window (RFC 4303) + TTL Cache              │
└──────────────────────────────────────────────────────────────────┘
```

### Circuit Breaker

```
┌──────────┐   heartbeat     ┌──────────┐   anomaly      ┌──────────┐
│  ONLINE  │ ◄─────────────► │ SUSPECT  │ ◄─────────────► │  FUSED   │
│  (green) │   fail × 5      │ (yellow) │   detection    │  (red)   │
└──────────┘                 └──────────┘                 └──────────┘
      │                           │                            │
      │    auto-recover           │   manual reset              │   quarantine
      └───────────────────────────┴─────────────────────────────┘
```

---

## Features

### Transport Protocols (5)

| Protocol | Use Case | Features |
|----------|----------|----------|
| **HTTP/S** | Primary C2 | Malleable profiles, custom headers, URI paths, encoding |
| **mTLS** | High-security | Mutual TLS, certificate pinning, ECDH handshake |
| **WebSocket** | CDN/Domain Fronting | WSS + Yamux multiplexing, domain fronting support |
| **DNS C2** | Covert channel | Raw DNS tunneling, session protocol, canary tokens |
| **Named Pipe** | Intra-pivot | SMB-based, for lateral movement pivoting |

### Evasion Suite

| Technique | Method | Detail |
|-----------|--------|--------|
| **AMSI Bypass** | Hardware breakpoint | DR0-DR3 + VEH, registry-based, CLR in-memory |
| **ETW Bypass** | Hardware breakpoint | EtwEventWrite HWBP, CLR patch |
| **Indirect Syscalls** | Hell's Gate style | ntdll.dll PE parsing, SSN extraction, asm engine |
| **Sleep Obfuscation** | Ekko / Foliage | Memory encryption during sleep, stack spoofing |
| **Hardware Breakpoints** | DR0-DR3 engine | Full VEH handler, multi-breakpoint support |
| **API Hashing** | DJB2 + Jenkins | String obfuscation in binary |
| **PPID Spoofing** | Explorer.exe | Masquerade parent process |
| **RefreshPE** | Anti-unhook | Restore ntdll.dll original bytes |
| **Sandbox Detection** | 7 detection methods | CPU, RAM, disk, domain, uptime, processes, artifacts |
| **Stack Spoofing** | Call stack camouflage | Fake return addresses, synchronized sleep |

### Process Injection (5 Methods)

| Method | OPSEC Profile |
|--------|---------------|
| **APC Early Bird** | Low visibility, fiber-based variant |
| **Thread Hijacking** | Standard, reliable |
| **Process Hollowing** | Classic, replace target process |
| **Module Stomping + Thread Hijack** | High OPSEC: no RWX, no new thread,合法 DLL .text |
| **PoolParty (NtCreateSection)** | Highest OPSEC: MEM_MAPPED, thread pool hijack |

### Payload System

- **Dynamic Compilation**: Server-side Go build with per-binary AES-256 keys
- **Output Formats**: EXE, DLL (shared lib), Shellcode (PIE + donut), Service
- **Staged Delivery**: Small stager downloads encrypted stage2 from server
- **Rust Stager**: no_std, ~50-80KB, PEB Walk + ROR13 hash, no Go runtime
- **Shellcode Conversion**: PE → Donut → Position-independent shellcode
- **sRDI**: PE → Reflective DLL Injection shellcode
- **LNK Generation**: Native MS-SHLLINK format for delivery
- **Steganography**: PNG IDAT payload embedding
- **Code Signing**: osslsigncode integration with timestamp support

### Credential Collection

| Source | Method |
|--------|--------|
| **LSASS (BOF)** | On-demand COFF module, not compiled into agent |
| **DPAPI** | Master Key extraction from %APPDATA% |
| **Browser** | Chrome/Edge SQLite + DPAPI decryption |
| **Credential Manager** | CredEnumerateW / CredReadW |
| **Registry** | HKLM\SECURITY\Policy\Secrets (SYSTEM required) |
| **SAM** | Registry hive extraction |

### Operations

- **Multi-Operator**: Role-based access (Admin / Operator / Observer)
- **SOCKS5 Proxy**: Agent-side port forwarding and reverse tunneling
- **File Transfer**: Upload/download with gzip compression
- **Interactive Shell**: PTY streaming
- **Job System**: Background task management
- **BOF/COF Loader**: Full COFF parser, Havoc compatibility, VEH symbol resolution
- **.NET CLR Hosting**: In-memory assembly execution with AMSI/ETW bypass
- **WMI Remote Execution**: Lateral movement via WMI
- **SSH Lateral Movement**: Native SSH client for remote command execution
- **Privilege Escalation**: GetSystem via injection, token manipulation
- **Canary Tokens**: DNS tripwire detection
- **Webhook Notifications**: Discord, Slack, Webex
- **LLM Analyst**: AI-powered behavioral analysis module
- **SQLite Database**: Full persistence (8 tables: agents, tasks, loot, operators, events, audit, canaries, pivots)

### Agent Commands (32+)

| Category | Commands |
|----------|----------|
| **System** | `info`, `whoami`, `hostname`, `pwd`, `env`, `uuid` |
| **Shell** | `shell`, `execute-assembly` |
| **File** | `ls`, `cat`, `upload`, `download`, `mkdir`, `rm`, `mv`, `cp`, `chtimes` |
| **Process** | `ps`, `kill`, `migrate`, `procdump`, `memread`, `memwrite`, `memdump` |
| **Network** | `netstat`, `ifconfig`, `arp`, `whois`, `services` |
| **Recon** | `priv_check`, `limits`, `screenshot`, `keylogger` |
| **Identity** | `token_whoami`, `token_impersonate`, `maketoken`, `revert` |
| **Persistence** | `persist add/remove/list`, `schtasks`, `wmi_event` |
| **Lateral** | `ssh`, `wmi`, `psexec` |
| **Proxy** | `socks`, `portfwd`, `rportfwd` |
| **Config** | `sleep`, `killdate`, `reconfig`, `die` |
| **Injection** | `inject`, `sideload`, `bof`, `execute-dotnet` |
| **PowerShell** | `powershell` (unmanaged CLR) |

---

## Project Structure

```
aegis/
│
├── cmd/
│   ├── agent/              # Agent entry point (session/beacon mode)
│   ├── client/             # Operator CLI (gRPC mTLS REPL)
│   └── server/             # Teamserver entry point
│
├── agent/                  # ═══ IMPLANT RUNTIME ═══
│   ├── asm/                # Assembly stubs (indirect syscall, spoofcall)
│   ├── autonomy/           # Autonomous operation mode
│   ├── beacon/             # Beacon heartbeat scheduler
│   ├── bof/                # BOF/COFF loader (parser, VEH, execution)
│   ├── config/             # Embedded build configuration
│   ├── crypto/             # Agent-side ECDH + AES-GCM
│   ├── dotnet/             # .NET CLR hosting (in-memory assembly exec)
│   ├── evasion/            # AMSI/ETW bypass, HWBP, sandbox detection, RefreshPE
│   ├── execcmd/            # Command execution dispatcher
│   ├── executor/           # Task execution engine
│   ├── extexec/            # External process execution
│   ├── fingerprint/        # Machine fingerprinting
│   ├── forwarder/          # Port forwarding engine
│   ├── health/             # Credential collection (DPAPI, browser, SAM, registry)
│   ├── input/              # Keylogger (SetWindowsHookEx)
│   ├── job/                # Background job management
│   ├── lateral/            # Lateral movement (SSH, WMI, remote cmd)
│   ├── limits/             # Resource limit enforcement
│   ├── loader/             # Process injection (5 methods, all Windows CGO)
│   ├── memdump/            # Process memory dump (MiniDumpWriteDump)
│   ├── modmgr/             # DLL injection manager
│   ├── modules/            # Command modules (shell, file, process, network, persist)
│   ├── mountenum/          # Mount point enumeration
│   ├── netenum/            # AD/network enumeration
│   ├── persist/            # Persistence (scheduled task, WMI event, registry, service)
│   ├── pivot/              # Pivot chain management
│   ├── powershell/         # Unmanaged PowerShell (CLR hosting)
│   ├── priv/               # Privilege escalation (GetSystem, token ops)
│   ├── proxy/              # SOCKS5 proxy
│   ├── ps/                 # Process enumeration
│   ├── registry/           # Registry operations
│   ├── screen/             # Screenshot capture
│   ├── service/            # Windows service management
│   ├── session/            # Session management + profile integration
│   ├── shell/              # Interactive shell (PTY)
│   ├── sleep/              # Sleep obfuscation (Ekko, Foliage, stack spoofing, C masks)
│   ├── spoof/              # PPID + call stack spoofing
│   ├── syscall/            # Indirect syscall engine
│   ├── tlskeys/            # TLS key logging
│   ├── token/              # Token manipulation (impersonate, make token)
│   ├── transfer/           # File transfer (chunked, compressed)
│   ├── transport/          # Transport drivers (HTTP, mTLS, WS, DNS, Pipe, WireGuard)
│   ├── uuid/               # Agent identity
│   ├── watcher/            # File system watcher
│   ├── weaponize/          # Loader stub for weaponized delivery
│   └── winutil/            # Windows utilities (LSASS, process helpers)
│
├── server/                 # ═══ TEAMSERVER ═══
│   ├── agent/              # Agent lifecycle manager
│   ├── audit/              # Audit log
│   ├── builder/            # Dynamic payload compilation (Go + Rust templates)
│   │   └── rust_stager/    # Rust no_std stager project
│   │       ├── Cargo.toml
│   │       └── src/        # main.rs, peb.rs, hash.rs, winhttp.rs,
│   │                       # crypto.rs, ntdll.rs, exec.rs
│   ├── canary/             # DNS canary token server
│   ├── codenames/          # Agent codename generator
│   ├── config/             # Server configuration
│   ├── core/               # Service layer orchestration
│   ├── crypto/             # AES-GCM, RSA, replay protection
│   ├── db/                 # SQLite database layer (WAL mode)
│   ├── dispatcher/         # Task dispatching + result collection
│   ├── encoders/           # Payload encoders
│   ├── event/              # Event system (pub/sub)
│   ├── gateway/            # HTTP gateway (agent-facing C2)
│   ├── grpc/               # gRPC server (operator-facing)
│   ├── http/               # Agent auth middleware
│   ├── listener/           # Listener management
│   ├── llm/                # LLM analyst module
│   ├── loot/               # Loot storage
│   ├── operator/           # Multi-operator management
│   ├── pivot/              # Pivot listener infrastructure
│   ├── pki/                # PKI (CA cert/key for gRPC mTLS)
│   ├── profile/            # Malleable C2 profile manager + validator
│   ├── stage/              # Stage2 payload store
│   ├── tcpproxy/           # TCP proxy
│   ├── weaponize/          # PE→shellcode (pe2shc, sRDI, LNK, stego)
│   ├── webhook/            # Webhook notifications (Discord/Slack/Webex)
│   ├── website/            # Website-hosted payload delivery
│   └── yamux/              # Yamux multiplexing
│
├── shared/                 # ═══ SHARED LIBRARIES ═══
│   ├── compress/           # Gzip compression
│   ├── ecdh/               # X25519 ECDH key exchange
│   ├── encoder/            # Base64/Base58/Hex encoders
│   ├── hash/               # DJB2/Jenkins API hashing
│   ├── id.go               # Shared ID generation
│   ├── protocol/           # Communication protocol definitions
│   ├── stego.go            # PNG steganography
│   ├── tlv/                # TLV encoding
│   ├── types/              # Shared type definitions
│   └── xor.go              # XOR utilities
│
├── proto/                  # gRPC message & service definitions
├── config/                 # Server configuration (server.yaml)
├── build/                  # Build output directory
└── Makefile                # Build automation
```

---

## Quick Start

### Prerequisites

| Dependency | Version | Required |
|------------|---------|----------|
| **Go** | >= 1.25 | Yes |
| **Rust** | nightly (optional) | For Rust stager |
| **GCC / MinGW-w64** | Any | For CGO (Windows evasion) |
| **NASM** | Any (optional) | For sRDI ReflectiveLoader |
| **donut** | Any (optional) | For PE→shellcode conversion |
| **osslsigncode** | Any (optional) | For PE code signing |
| **garble** | >= 0.16 (optional) | For Go obfuscation |

### Install Dependencies

```bash
# Go toolchain
go install mvdan.cc/garble@latest

# donut (optional, for shellcode conversion)
git clone https://github.com/TheWover/donut.git
cd donut && make

# osslsigncode (optional, for code signing)
# macOS:
brew install osslsigncode
# Ubuntu:
apt install osslsigncode
# Windows (choco):
choco install osslsigncode
```

### Build

```bash
git clone https://github.com/atreasureboy/aegis.git
cd aegis

# Build everything
make all

# Or build individually
make server       # → build/aegis-server
make client       # → build/aegis-client
make agent-linux  # → build/aegis-agent-linux
make agent-windows  # → build/aegis-agent.exe (CGO, full evasion)

# Agent variants
make agent-windows-nocgo  # No CGO (smaller, stub evasion only)
make agent-http          # HTTP transport only
make agent-mtls          # mTLS transport only
make agent-full          # All transports + evasion
```

### Server Configuration

Edit `config/server.yaml`:

```yaml
http:
  listen: ":8443"              # Agent-facing C2 listener
  host: "0.0.0.0"

grpc:
  listen: ":8444"              # Operator-facing gRPC listener

heartbeat:
  interval: 10                 # Default heartbeat interval (seconds)
  jitter: 3                    # Jitter range (seconds)

security:
  academic_mode: true          # Restrict to allowed commands only
  max_rate_per_minute: 10      # Task rate limit
  max_concurrent_tasks: 3      # Concurrent task limit
  task_timeout: 60             # Task timeout (seconds)
  max_heartbeat_failures: 5    # Circuit breaker threshold

allowed_commands:              # Command whitelist (academic mode)
  - whoami
  - hostname
  - ps
  - ls
  - cat
  - netstat
  - ifconfig
  - pwd
  - echo
  - info
  - process

blocked_commands:              # Command blacklist (always enforced)
  - rm
  - shutdown
  - reboot
  - format
  - del
  - "net user"
  - mimikatz
  - "powershell -enc"

circuit_breaker:
  enabled: true
  anomaly_detection: true      # Enable anomaly-based triggering
```

Environment variable overrides:

```bash
export AEGIS_GRPC_ADDR="0.0.0.0:8444"   # Override gRPC listener
export AEGIS_HTTP_ADDR="0.0.0.0:8443"   # Override HTTP listener
```

### Run

```bash
# 1. Start the C2 server (PKI auto-generated on first run)
./build/aegis-server

# 2. In another terminal, start the operator CLI
# Production (mTLS):
./build/aegis-client \
  --cert client.crt \
  --key client.key \
  --ca ca.crt \
  --server 127.0.0.1:8444

# Development (insecure):
./build/aegis-client --insecure --server 127.0.0.1:8444
```

Environment variable alternatives:

```bash
export AEGIS_SERVER="127.0.0.1:8444"
export AEGIS_CERT="client.crt"
export AEGIS_KEY="client.key"
export AEGIS_CA="ca.crt"
./build/aegis-client
```

### Generate Payload

```
aegis> generate --os windows --format exe --name myagent
```

This triggers server-side Go compilation with:
- Unique AES-256-GCM key per binary
- ECDH key pair for forward secrecy
- garble obfuscation (if installed)
- Import path renaming

### Advanced Payload Options

```
# Staged delivery (small stager + encrypted stage2)
aegis> generate --os windows --stage stager --name staged-agent

# Shellcode output (PIE + donut conversion)
aegis> generate --os windows --format shellcode --name shellcode-pie

# DLL output (for sideloading)
aegis> generate --os windows --format shared --name payload

# Rust stager (high evasion, no Go runtime)
# Requires: rustup target add x86_64-pc-windows-gnu
# The builder automatically compiles the Rust stager when --engine rust is used
```

### Basic Usage

```
aegis> agents                        # List all connected agents
aegis> info <agent-id>               # Show agent details
aegis> task <agent-id> whoami        # Execute a command
aegis> task <agent-id> shell ipconfig
aegis> task <agent-id> ps            # List processes
aegis> task <agent-id> netstat       # Network connections
aegis> task <agent-id> priv_check    # Check privileges
aegis> task <agent-id> screenshot    # Capture screen
aegis> task <agent-id> bof <file.o>  # Execute BOF
aegis> task <agent-id> inject <pid>  # Process injection
aegis> task <agent-id> sleep 30 10   # Set sleep 30s ±10s jitter
aegis> task <agent-id> socks start   # Start SOCKS5 proxy
aegis> interact <agent-id>           # Interactive shell session
aegis> loot list                     # List collected loot
aegis> events                        # View event stream
```

---

## C2 Profiles

Aegis supports malleable C2 profiles for traffic camouflage:

```yaml
name: "default"
method: "POST"
path: "/api/v1/update"
headers:
  Content-Type: "application/octet-stream"
  User-Agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
cookie: "session"
param: "data"
transform: "base64"  # base64 | hex | raw
```

Profiles control how agent traffic appears on the wire — HTTP method, URI path, headers,
cookie names, parameter names, and data encoding. Multiple profiles can be loaded and
switched at runtime.

---

## Comparison

| Feature | Sliver | Havoc | Aegis |
|---------|--------|-------|-------|
| Language | Go | C | Go + Rust |
| Dynamic Payloads | Yes | No | Yes |
| Per-binary Keys | Yes | N/A | Yes |
| DNS C2 | No | No | Yes |
| WireGuard | No | Yes | Yes |
| Named Pipe | Yes | No | Yes |
| AMSI Bypass | Yes | Yes | Yes (3 methods) |
| ETW Bypass | No | Yes | Yes (2 methods) |
| Sleep Obfuscation | No | Yes (Ekko) | Yes (Ekko + Foliage) |
| Process Injection | Yes | Yes | Yes (5 methods) |
| BOF Loader | Yes | Yes | Yes |
| Privilege Escalation | Limited | Limited | Yes (GetSystem + tokens) |
| .NET Execution | No | No | Yes (CLR hosting) |
| Hardware Breakpoints | No | No | Yes (DR0-DR3 + VEH) |
| C2 Profiles | Yes | Yes | Yes |
| Multi-Transport | Yes | No | Yes (5 protocols) |
| Circuit Breaker | No | No | Yes |
| Event System | Yes | No | Yes |
| LLM Analysis | No | No | Yes |
| Open Source | Yes | Yes | Yes |

---

## Disclaimer

This project is for **educational and authorized security research purposes only**.
Unauthorized use against systems you do not have explicit permission to test is illegal.
The authors do not endorse or condone malicious use.

---

## License

MIT

---

## Acknowledgments

- [Sliver](https://github.com/BishopFox/sliver) — Modular C2 architecture inspiration
- [Havoc](https://github.com/HavocFramework/Havoc) — Evasion techniques and BOF loading
- [Mythic](https://github.com/its-a-feature/Mythic) — Agent tasking paradigm, multi-language agent architecture
- [Cobalt Strike](https://www.cobaltstrike.com/) — C2 design philosophy, malleable profiles
