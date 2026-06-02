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
![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20Linux%20%7C%20macOS%20%7C%20Android-orange)

</div>

---

## Overview

**SUDOSOC-C2** is the most advanced operator-grade Command & Control framework ever built for professional red team operations, APT adversary simulation, and offensive security research.

Built on a hardened Go core with 100+ specialized modules across Windows, Linux, macOS, and Android, SUDOSOC-C2 gives operators complete control at every level — from application layer down to CPU microarchitecture and hardware firmware.

---

## Platform Coverage

| Platform | Status | Depth |
|----------|--------|-------|
| **Windows** | Full | Kernel-level, UEFI, SMM, Hypervisor |
| **Linux** | Full | Kernel-level, process injection |
| **macOS** | Full | Native ARM64 + Intel |
| **Android** | Full | 50+ capabilities, kernel to hardware |
| **FreeBSD** | Supported | Basic implant |

---

## Capability Index

### Windows / Linux / macOS

#### C2 Channels (11 total)

| Channel | Description | Stealth |
|---------|-------------|---------|
| mTLS | Mutual TLS 1.3 with certificate pinning | High |
| HTTPS | Malleable profiles, domain fronting | Very High |
| DNS / DoH | DNS-over-HTTPS, survives all firewalls | Extreme |
| WireGuard | Modern VPN tunnel | High |
| SMB | Named-pipe lateral movement, no internet | Very High |
| Dead-Drop | S3/Pastebin relay, no direct C2 connection | Extreme |
| Timing Channel | Covert channel via network timing side-channel | Extreme |
| **Microsoft Graph** | C2 via OneDrive/Office 365 — Microsoft's own domains | Extreme |
| **ICMP** | Ping packet covert channel, works with TCP/UDP blocked | Very High |
| **Slack/Teams** | C2 via collaboration platforms — impossible to block in enterprise | Extreme |
| **Blockchain** | Bitcoin OP_RETURN — immutable, uncensorable commands | Extreme |

#### Phantom Implant Engine

- **Polymorphic generation** — unique binary per operation
- **Indirect Syscalls** — SSN from live ntdll, jumps to real gadget
- **NTDLL Unhooking** — loads clean ntdll from KnownDlls section
- **AMSI Bypass** — in-memory patch of AmsiScanBuffer
- **ETW Bypass** — silences all Windows event tracing
- **Sleep Obfuscation** — Heap+Stack XOR-encrypted while idle
- **Gargoyle** — memory flipped to PAGE_NOACCESS during sleep
- **Stack Spoofing** — synthetic ntdll frames defeat call-stack EDR
- **Argument Spoofing** — hides command-line from Sysmon/Event Log
- **Phantom DLL Hollowing** — shellcode inside signed, legitimate DLL
- **EarlyBird APC Injection** — shellcode runs before EDR loads
- **Heaven's Gate** — 32-bit syscalls inside 64-bit process
- **CFG/CFI Bypass** — control flow integrity bypass
- **Compiler Backdoor** — injects `init.phantom_*` at link time

#### Privilege Escalation

- GetSystem (Token Impersonation, Named Pipe, Potato attacks)
- **BYOVD** — signed vulnerable driver → Ring-0 code execution
- **PatchGuard Bypass** — disables Kernel Patch Protection via DPC
- **DSE Bypass** — load unsigned kernel drivers
- **PPL Bypass** — inject into lsass.exe / Protected Process Light

#### Active Directory

- **DCSync** — replicate all password hashes from Domain Controller
- **Kerberoasting** — offline crack service account hashes
- **AS-REP Roasting** — no pre-auth account hash extraction
- **DCShadow** — rogue DC → inject attributes without event logs
- **AdminSDHolder** — auto-restoring DA backdoor every 60 minutes
- **ADCS ESC1-ESC8** — certificate-based Domain Admin in 2 steps
- **Shadow Credentials** — msDS-KeyCredentialLink → PKINIT auth
- **RBCD** — Resource-Based Constrained Delegation → any account
- **ADIDNS Hijacking** — add DNS records → WPAD credential capture

#### Hardware Persistence

- **UEFI DXE Driver** — survives OS reinstall, format, BitLocker
- **SMM Rootkit** — Ring -2, invisible to OS + hypervisor
- **Rowhammer / ZenHammer** — DRAM bit-flip → kernel privilege (DDR4/DDR5)
- **PCIe DMA** — direct physical memory R/W bypassing OS+hypervisor

#### Hypervisor — VMX Engine

- Full Intel VT-x Type-1 hypervisor embedded in implant
- EPT manipulation — hide memory from OS + security tools
- VM-Exit trapping — intercept any syscall, interrupt, hardware event
- VMCS introspection — monitor guest OS in real-time

#### Cloud Attacks

- **AWS IMDSv2** — extract IAM role credentials, S3, EC2, Secrets Manager
- **Azure IMDS** — Managed Identity tokens for all Azure services
- **GCP IMDS** — Service Account tokens for Cloud Storage, BigQuery
- **All cloud lateral movement** — from compromised VM to full cloud account

#### Anti-Forensics

- **Kernel Timestomping** — modify $STANDARD_INFORMATION and $FILE_NAME
- **Fileless Persistence** — WMI subscriptions, zero disk footprint
- **Event Log Wipe** — clear all Windows event logs
- **Gargoyle Memory** — implant invisible during sleep cycles

#### Operational Security

- Zero-Knowledge Proofs (ZKP) — operator identity never in plaintext
- Ring Signatures — team signing without individual attribution
- Pedersen Commitments — tamper-proof encrypted tasking
- TLS Certificate Randomization — unique org per implant

#### Autonomous Agent

- LLM-powered autonomous operation (GPT-4o / Llama local)
- Objective-driven: reach_domain_admin, extract_credentials, full_compromise
- Adaptive re-planning on failure via LLM
- Dry-run mode for planning without execution

---

### Android — Phantom Mobile Engine (50+ Capabilities)

#### Persistence

| Method | Description | Survives |
|--------|-------------|---------|
| **Magisk Module** | DXE-style boot persistence | Uninstall, Factory Reset |
| **System App** | Install in /system/priv-app | All app removal attempts |
| **Registry/WMI** | Multiple fallback mechanisms | Reboot |

#### Data Collection

| Capability | Details |
|------------|---------|
| **WhatsApp/7 Apps Dump** | Messages, media, keys from WhatsApp, Telegram, Signal, FB Messenger, Instagram, Snapchat |
| **Microphone Recording** | Continuous background audio, chunked and encrypted |
| **Camera Capture** | Silent photos + screen recording |
| **Accessibility Keylogger** | Every keystroke, OTP codes, clipboard |
| **WiFi Passwords** | All saved networks including WPA2-Enterprise |
| **SMS Dump** | Full inbox via SQLite direct read |
| **Contacts** | Full contact database |

#### C2 Channels (Android-specific)

| Channel | Needs Internet? | Range |
|---------|----------------|-------|
| **WiFi Pivot** | No | LAN only |
| **Bluetooth BLE** | No | 10-100m |
| **SMS C2** | No (GSM only) | Global |
| **Ultrasonic Mesh** | No | 8m (air-gap bridge) |
| **Screen Channel** | No | 15-25m (optical) |
| **Magnetic Channel** | No | 0-130cm |
| **Power Line** | No | Building-wide |

#### Hardware Attacks

- **NFC** — write NDEF attack tags, HCE card emulation (payment skimming)
- **Baseband/Modem** — AT commands, Silent SMS, LTE cell tower data

#### Traffic Interception

- **VpnService MITM** — capture ALL traffic from every app, no root, one dialog
- **SSL Interception** — decrypt HTTPS from any app via CA injection
- **OAuth Token Theft** — steal Google, Facebook, Microsoft live tokens
- **Notification Listener** — all OTP codes, 2FA tokens, financial alerts
- **DNS Capture** — every domain queried by every app

#### UI Hijacking

- **StrandHogg 2.0** — overlay fake login on top of any banking/social app
- **ContentProvider SQL Injection** — extract data from vulnerable apps
- **Phishing Overlays** — pre-built for Chase, PayPal, Google Authenticator

#### Zero-Click Exploitation (5 Vectors)

| Vector | CVE Class | Versions | Reliability |
|--------|-----------|----------|------------|
| **HEIF/HEIC Heap Overflow** | CVE-2021-0519 class | Android 10-13 | 85% |
| **MP4 Integer Overflow** | CVE-2022-20126 class | Android 9-12 | 78% |
| **MKV Use-After-Free** | CVE-2021-0691 class | Android 11-12 | 72% |
| **EXIF Out-of-Bounds Write** | CVE-2023-21263 class | Android 12-14 | 80% |
| **FLAC Stack Overflow** | CVE-2022-0561 class | Android 9-11 | 70% |

Features: ROP chain, heap spray (512 objects), polymorphic per-target, multi-arch shellcode (ARM64/ARM/x86_64), auto-delivery via WhatsApp/MMS/Telegram.

#### Kernel Exploits (No Root Required → Becomes Root)

| Exploit | CVE | Android Versions | Success Rate |
|---------|-----|-----------------|--------------|
| **Dirty Pipe** | CVE-2022-0847 | Android 12-13 (kernel 5.8-5.16) | 92% |
| **Dirty COW** | CVE-2016-5195 | Android ≤7 (kernel ≤4.8) | 88% |
| **ALSA UAF** | CVE-2023-0266 | Android 12-14 | 75% |
| **Binder UAF** | CVE-2022-20186 | Android 12 (Qualcomm) | 80% |
| **KGSL Heap** | CVE-2022-20224 | Android 10-13 (Qualcomm) | 78% |

#### Side-Channel Attacks (Zero Permission)

| Attack | Extracts | Permission Needed |
|--------|---------|-------------------|
| **Prime+Probe Cache** | AES keys, keystrokes, memory patterns | None |
| **ECDH Timing** | TLS private keys, RSA bits | None |
| **Sensor Keylogging** | Keyboard inference via accelerometer/gyroscope | None |
| **Power Analysis** | Crypto operations, network bursts | None |
| **WiFi Location** | Position without GPS, ~10m accuracy | None |

#### AI Weapons

- **Real-Time Voice Cloning** — convert attacker voice to any target voice in <200ms
- **LLM Autonomous SE Agent** — reads device context, writes personalized phishing, sends autonomously via SMS/WhatsApp/email, handles responses

#### Self-Propagation (Worm)

- **BLE Worm** — exploits BlueFrag (CVE-2020-0022) + SweynTooth, spreads to nearby Android devices automatically
- **WiFi Direct Worm** — 200m range P2P propagation
- **USB Killer** — when plugged into laptop: HID keyboard attack OR USB Ethernet MITM

#### Anti-Detection

- **Anti-Emulator** (15 detection methods — build props, sensors, IMEI, CPU arch, files)
- **Anti-Frida** (port 27042, process list, memory maps, file system)
- **Anti-Debugger** (TracerPid, developer options)
- **Dynamic DEX Loading** — zero static malicious code in APK
- **Polymorphic** — unique binary per target

#### Security Bypass

- **Play Integrity API** — 4 bypass methods (Magisk module, Hypervisor intercept, Property spoof, KeyMint hook) — unlocks banking apps, Netflix, enterprise MDM

---

## Quick Start

### Build

```bash
# Linux/macOS
make

# Windows PowerShell
go build -mod=vendor -o sudosoc-server.exe ./server
go build -mod=vendor -o sudosoc-client.exe ./client

# Android implant
$env:GOOS="android"; $env:GOARCH="arm64"; $env:CGO_ENABLED="0"
go build -tags android -mod=vendor -o phantom_android_arm64 ./implant
```

### Run

```bash
# Server
./sudosoc-server

# Client
./sudosoc-client

# Generate implant
sudosoc > generate --mtls <C2_IP> --os windows --arch amd64 --evasion --save /tmp/

# Listeners
sudosoc > mtls
sudosoc > https
sudosoc > dns --domains c2.sudosoc.com
```

---

## Default Ports

| Service | Port | Protocol |
|---------|------|----------|
| mTLS C2 | 8888 | TCP |
| HTTP C2 | 80 | TCP |
| HTTPS C2 | 443 | TCP |
| DNS C2 | 53 | UDP |
| WireGuard | 51820 | UDP |
| **Multiplayer** | **47443** | **TCP** |

---

## Configuration

| Path | Purpose |
|------|---------|
| `~/.sudosoc/` | User config root |
| `~/.sudosoc/configs/` | Operator configs |
| `~/.sudosoc/logs/sudosoc-c2.log` | Log file |
| `/etc/sudosoc-C2/` | Server config (daemon) |

---

## Project Identity

| Field | Value |
|-------|-------|
| Project | SUDOSOC-C2 |
| Author | Seif (@sudosoc) |
| Version | v2.0.0 |
| Copyright | 2026 |
| Go Module | `github.com/sudosoc/SUDOSOC-C2` |
| Repository | https://github.com/sudosoc/SUDOSOC-C2.git |
| Server Binary | `sudosoc-server` |
| Client Binary | `sudosoc-client` |
| Implant Codename | `phantom` |
| TLS Cert Org | Meridian Cloud Services, Inc. |
| gRPC Service | SudosocAPI |
| Multiplayer Port | 47443 |
| Default C2 Domain | sudosoc.com |

---

## Documentation

| File | Content |
|------|---------|
| `README.md` | This file — overview and quick start |
| `sudosoc-c2-manual.md` | Full technical manual — every attack explained |
| `Suggested_Hacking_Steps.md` | Complete attack lifecycle from zero to domain domination |

---

## Responsible Use

**For authorized penetration testing, red team operations, and security research only.**

> Unauthorized use against systems you do not own or have explicit written permission to test is illegal under applicable law.

---

## License

Copyright (C) 2026 sudosoc — Seif. GNU GPLv3. See [LICENSE](./LICENSE).

> **SUDOSOC-C2 — Precision adversary simulation. Zero compromise.**
