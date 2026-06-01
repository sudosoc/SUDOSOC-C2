# SUDOSOC-C2

> **Precision in the dark. Control beyond limits.**

## Overview

SUDOSOC-C2 is an advanced, operator-grade command-and-control (C2) framework
engineered for red team operations, penetration testing, and adversary simulation.
Built on a battle-tested Go foundation and significantly extended with
next-generation offensive capabilities, SUDOSOC-C2 provides unparalleled control
over target environments across Windows, Linux, and macOS.

## Core Capabilities

### Ghost Implant (Agent)
- Polymorphic implants — every generated Ghost agent is unique; no two binaries share a signature
- Multi-protocol C2 channels — HTTPS, DNS-over-HTTPS (DoH), SMB named pipes, TCP, mTLS, WebSocket
- Dead-drop C2 — beacon through GitHub Gists, OneDrive, Slack, and Microsoft Teams
- Timing-channel C2 — covert inter-packet-delay communication for air-gapped environments
- Multiplayer — multiple operators connect concurrently (port 47443)

### Evasion & Anti-Detection
- ETW patching — silences Event Tracing for Windows across all provider channels
- AMSI 4-layer bypass — stub patch, context corruption, registry CLM, Script Block Logging
- Indirect syscalls — PEB-walking SSN resolution + ntdll gadget reuse
- Thread-stack spoofing — synthetic thread-pool return-address chains defeat stack-based EDR
- Phantom DLL hollowing — in-memory execution without LoadLibrary; VirtualLock anti-dump
- Argument spoofing — fake command lines, spoofed parent PID, spoofed image path

### Privilege Escalation
- BYOVD automation — automatic EDR blinding via RTCore64.sys (CVE-2019-16098)
- Blue Pill hypervisor — Intel VT-x type-1 hypervisor; guest OS runs unmodified above it
- PatchGuard (KPP) bypass — DPC timer queue scan + KiTimerExpiration hook
- DSE bypass + kdmapper — load unsigned drivers; g_CiOptions / SeCiCallbacks / SeILSigningPolicy
- Rowhammer (D-P8) — DRAM bit-flip attack via CLFLUSH loops; PTE manipulation; no CVE required
- PCIe DMA injection (D-P7) — physical RAM scan + EPROCESS walk + shellcode via Thunderbolt

### Active Directory
- DCSync — extract credentials from domain controllers without touching the DC
- Kerberoasting — TGS ticket extraction + offline cracking
- Shadow Credentials — PKINIT + msDS-KeyCredentialLink attribute manipulation
- DCShadow — register a fake DC; push arbitrary AD changes without domain admin detection
- Golden / Diamond / Sapphire tickets — full Kerberos ticket forging suite
- AdminSDHolder persistence — ACL modification + SDProp exploitation

### Persistence
- WMI subscriptions — fileless; survives reboots; no file/registry/task artifacts
- COM hijacking — HKCU InprocServer32 without administrator privileges
- UEFI rootkit — three tiers: ESP patch / SPI flash DXE injection / NVRAM
- SMM rootkit — Ring -2 SMI handler injection; survives OS reinstall

### Harvest & Intelligence
- Browser credential extraction — Chrome/Edge/Brave (DPAPI + AES-GCM), Firefox (NSS)
- Clipboard monitoring — real-time text, file path, and image capture
- Cloud credential harvesting — AWS/Azure/GCP env vars, credential files, IMDS

### Supply Chain & Initial Access
- Compiler backdoor — Thompson's Hack 2026 for Go; self-replicating IR injection
- CI/CD pipeline poisoning — GitHub Actions, Jenkins, GitLab CI, CircleCI
- Dependency confusion — PyPI/npm/NuGet/RubyGems internal package hijacking
- Typosquatting — mass-scale developer compromise (10 typo categories, 4 ecosystems)
- Zero-click browser chain — DNS rebinding → Router CSRF → HTTP MITM → HTML smuggling
- Zero-click messaging — CVE-2021-30860 (JBIG2/iOS), CVE-2023-4863 (WebP), CVE-2019-3568

### Cryptographic Authentication
- Schnorr ZKP — zero-knowledge proof of C2 identity; implants hold only the public key
- Ring signatures — multi-key authentication with plausible deniability
- Pedersen commitments — hiding + binding commitments for protocol-level privacy

### Anti-Forensics
- USN Journal wiping — targeted deletion of filesystem activity records
- Event log pruning — selective Windows Event Log record removal

## Architecture

```
sudosoc-server ─── gRPC mTLS (port 47443) ─── sudosoc-client  (operator console)
      │
      └─── Ghost agent ─── multi-protocol C2 channels ─── target
```

| Component | Binary | Role |
|---|---|---|
| Server | `sudosoc-server` | gRPC + implant listener |
| Client | `sudosoc-client` | Interactive operator console |
| Implant | `ghost` | Polymorphic, multi-platform beacon |

## Prerequisites

| Requirement | Version |
|---|---|
| Go | ≥ 1.21 |
| MinGW-w64 (Windows cross-compile) | ≥ 8.0 |
| GNU Make | ≥ 4.0 |

## Quick Start

```bash
# Build
make sudosoc-server sudosoc-client

# Start the server
./sudosoc-server

# Connect with the client
./sudosoc-client

# Generate a Ghost implant
sudosoc > generate --os windows --arch amd64 --mtls sudosoc.com

# Start a listener
sudosoc > mtls --lport 443

# List active sessions
sudosoc > sessions
```

## Default Ports

| Service | Port | Protocol |
|---|---|---|
| Multiplayer (operator) | **47443** | gRPC / mTLS |
| mTLS listener | 8888 | mTLS |
| HTTP/S listeners | 80 / 443 | HTTP/S |
| DNS listener | 53 | UDP |

## Configuration

| Path | Purpose |
|---|---|
| `~/.sudosoc/` | Operator config, certificates, saved sessions |
| `/etc/sudosoc-C2/` | Server configuration |
| `sudosoc-c2.log` | Default log file |

## Legal Disclaimer

SUDOSOC-C2 is intended **exclusively** for authorized penetration testing,
red team operations, CTF competitions, and defensive security research.
Use only on systems and networks for which you have explicit written authorization.
Unauthorized use against systems you do not own or have permission to test is
illegal in virtually every jurisdiction.

The author accepts no liability for misuse.

## License

Copyright (C) 2026  Seif

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
