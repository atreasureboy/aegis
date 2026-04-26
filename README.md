# Aegis C2 Framework

> A next-generation Command & Control framework inspired by Sliver and Havoc, built for academic research and security demonstration.

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-blue" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
</p>

## Disclaimer

This project is for **educational and authorized security research purposes only**. Unauthorized use against systems you do not have explicit permission to test is illegal. The authors do not endorse or condone malicious use.

## Architecture

```
┌─────────────┐      HTTPS/mTLS/DNS/WireGuard      ┌─────────────┐
│   Client    │ ──────────────────────────────────► │   Server    │
│  (CLI)      │ ◄────────────────────────────────── │  (REST API) │
└─────────────┘                                     └──────┬──────┘
                                                           │
                                         ┌─────────────────┼─────────────────┐
                                         ▼                 ▼                 ▼
                                   ┌──────────┐    ┌──────────┐    ┌──────────┐
                                   │  Agent   │    │  Agent   │    │  Agent   │
                                   │ Windows  │    │  Linux   │    │ Windows  │
                                   │ (Session)│    │ (Beacon) │    │ (Beacon) │
                                   └──────────┘    └──────────┘    └──────────┘
```

## Features

### Transport

| Protocol | Description |
|----------|-------------|
| HTTP/S | Malleable profiles, custom headers, URI paths, encoding |
| mTLS | Mutual TLS with certificate pinning |
| DNS C2 | DNS tunneling for covert communication |
| WebSocket | WSS transport with Yamux multiplexing |
| Named Pipe | SMB-based intra-pivot communication |
| WireGuard | Encrypted tunnel transport |

### Cryptography

- **AES-256-GCM** encryption with per-binary unique keys
- **RSA-2048** key exchange (dev mode fallback)
- **X25519 ECDH** + HKDF-SHA256 for perfect forward secrecy
- Nonce replay protection (sliding window + TTL cache)
- HMAC-SHA256 envelope integrity verification

### Evasion (Windows)

| Technique | Implementation |
|-----------|---------------|
| AMSI Bypass | Hardware breakpoint (DR0-DR3 + VEH), registry-based, CLR in-memory patch |
| ETW Bypass | Hardware breakpoint on EtwEventWrite, CLR in-memory patch |
| Indirect Syscalls | ntdll.dll PE parsing, SSN extraction, assembly syscall engine |
| Sleep Obfuscation | Memory encryption during beacon sleep |
| Hardware Breakpoints | Full DR0-DR3 debug register engine with VEH |
| API Hashing | DJB2 + Jenkins hash for string obfuscation |

### Injection & Execution

- **Process Injection** — CreateRemoteThread, QueueUserAPC, Thread Hijacking, Process Hollowing, Module Stomping
- **BOF/COF Loader** — Full COFF parser, Havoc-style BOF compatibility, in-memory execution
- **Process Migration** — Migrate into another process space
- **.NET CLR Hosting** — In-memory assembly execution with automatic AMSI/ETW bypass
- **Privilege Escalation** — JuicyPotato, PrintSpoofer, GodPotato, UAC Bypass

### Operations

- **Multi-Operator** — Role-based access (Admin / Operator / Observer)
- **SOCKS5 Proxy** — Agent-side port forwarding and reverse tunneling
- **File Transfer** — Upload/download with compression
- **Canary Tokens** — DNS tripwire detection for unauthorized access
- **Webhook Notifications** — Discord, Slack, Webex integration
- **Dynamic Payload Builder** — Server-side Go compilation with obfuscation (garble)
- **SQLite Database** — Full persistence for agents, tasks, loot, events, audit log

### Cross-Platform Commands

| Category | Commands |
|----------|----------|
| Shell | `shell` — Execute arbitrary commands |
| File | `ls`, `cat`, `upload`, `download`, `mkdir`, `rm` |
| System | `info`, `hostname`, `whoami`, `pwd`, `env`, `ps` |
| Network | `netstat`, `ifconfig`, `arp`, `whois` |
| Process | `kill`, `procdump` |
| Search | `grep`, `find` |
| Recon | `services`, `service_ctl`, `mount` |
| Identity | `token_whoami`, `uuid`, `priv_check`, `limits` |

## Quick Start

### Build from Source

```bash
git clone https://github.com/atreasureboy/aegis.git
cd aegis

# Build Server
go build -o build/server ./cmd/server/

# Build Client
go build -o build/client ./cmd/client/

# Build Windows Agent (no CGO required)
GOOS=windows GOARCH=amd64 go build -o build/agent.exe ./cmd/agent/

# Build Linux Agent
GOOS=linux GOARCH=amd64 go build -o build/agent_linux ./cmd/agent/
```

### Run

```bash
# 1. Start the C2 Server
./build/server

# 2. In another terminal, start the Client
./build/client

# 3. On the target machine, run the Agent
./build/agent.exe  # Windows
./build/agent_linux  # Linux
```

### Generate Payload (from client CLI)

```
> generate --os windows --format exe --name myagent
```

This triggers server-side Go compilation with a unique AES-256 key per binary.

### Use the Agent

```
aegis> agents              # List all agents
aegis> info <agent-id>     # Agent details
aegis> task <agent-id> whoami          # Execute command
aegis> task <agent-id> shell ipconfig  # Shell command
aegis> task <agent-id> ps              # List processes
aegis> task <agent-id> netstat         # Network connections
aegis> task <agent-id> priv_check      # Check privileges
```

## Project Structure

```
aegis/
├── cmd/
│   ├── agent/               # Agent entry point
│   ├── client/              # Client CLI entry point
│   └── server/              # Server entry point
├── agent/
│   ├── crypto/              # Agent-side encryption (RSA + ECDH + AES-GCM)
│   ├── evasion/             # AMSI/ETW bypass, hardware breakpoints
│   ├── executor/            # Task execution engine
│   ├── inject/              # Process injection
│   ├── modules/             # Command modules (shell, files, process, system, network)
│   ├── priv/                # Privilege escalation
│   ├── session/             # Session management with profile integration
│   ├── sleep/               # Sleep obfuscation (memory encryption)
│   ├── syscall/             # Indirect syscall engine
│   ├── transport/           # HTTP, mTLS, WSS, DNS, NamedPipe, WireGuard
│   └── ...
├── server/
│   ├── builder/             # Dynamic payload compilation
│   ├── crypto/              # AES-GCM, RSA, replay protection
│   ├── db/                  # SQLite database layer
│   ├── dispatcher/          # Task dispatching & result collection
│   ├── http/                # HTTP server & profile-driven routing
│   ├── operator/            # Multi-operator management
│   └── ...
├── shared/
│   ├── compress/            # Gzip compression
│   ├── encoder/             # Base64/Base58/Hex encoders
│   ├── hash/                # DJB2/Jenkins API hashing
│   └── protocol/            # Communication protocol definitions
└── proto/                   # gRPC message & service definitions
```

## Comparison with Existing Frameworks

| Feature | Sliver | Havoc | Aegis |
|---------|--------|-------|-------|
| Language | Go | C | Go |
| Dynamic Payloads | Yes | No | Yes |
| Per-binary Keys | Yes | N/A | Yes |
| DNS C2 | No | No | Yes |
| WireGuard | No | Yes | Yes |
| Named Pipe | Yes | No | Yes |
| AMSI Bypass | Yes | Yes | Yes (3 methods) |
| ETW Bypass | No | Yes | Yes (2 methods) |
| Sleep Obfuscation | No | Yes (Ekko) | Yes |
| Process Injection | Yes | Yes | Yes (indirect syscall) |
| BOF Loader | Yes | Yes | Yes |
| Privilege Escalation | Limited | Limited | Yes (4 techniques) |
| .NET Execution | No | No | Yes |
| Hardware Breakpoints | No | No | Yes |
| Event System | Yes | No | Yes |
| C2 Profiles | Yes | Yes | Yes |
| Open Source | Yes | Yes | Yes |

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Sliver](https://github.com/BishopFox/sliver) — Modular C2 architecture inspiration
- [Havoc](https://github.com/HavocFramework/Havoc) — Evasion techniques and BOF loading
- [Mythic](https://github.com/its-a-feature/Mythic) — Agent tasking paradigm
