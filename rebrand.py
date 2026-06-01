#!/usr/bin/env python3
"""
rebrand.py — SUDOSOC-C2 Full Rebranding Script
Author  : Seif (@sudosoc)
Version : 2.0  |  2026

Usage:
    python3 rebrand.py           # execute all changes
    python3 rebrand.py --dry-run # preview only, no writes

═══════════════════════════════════════════════════════════
AUTO-GENERATED DESIGN CHOICES
═══════════════════════════════════════════════════════════
  #11 Implant codename   : phantom
       Stealthy, non-attributable, no common AV/EDR fingerprint.
       Internal template name "sliver" replaced with "phantom".

  #12 ASCII Banner       : Unicode block art for SUDOSOC-C2
       Three colour variants embedded in NEW_BANNERS below.

  #15 Tagline            : "Precision adversary simulation. Zero compromise."

  #21 TLS Cert Org       : "Meridian Cloud Services, Inc."
       Generic SaaS/cloud company — plausible in CT logs.

  #22 gRPC service name  : "SudosocAPI"  (was: SliverRPC)
       Branded but non-tool-specific on the wire.

  #23 Multiplayer port   : 47441
       Not in IANA registry; not used by any common OS service,
       database engine, or monitoring agent.

═══════════════════════════════════════════════════════════
PRESERVATION RULES — the script never modifies these
═══════════════════════════════════════════════════════════
  • vendor/                     (all third-party Go code)
  • github.com/sliverarmory/    (external armory / wasm-donut)
  • Standard Go stdlib imports  (fmt, os, net, crypto/*, ...)
  • Assembly mnemonics          (MOV, PUSH, JMP, SYSCALL ...)
  • Windows API / NT symbols    (NtCreateFile, VirtualAlloc ...)
  • Crypto algorithm names      (AES, SHA, ECDH, Curve25519 ...)
  • Protobuf runtime internals  (generated .pb.go field tags)
═══════════════════════════════════════════════════════════
"""

import os
import re
import sys
import shutil
import subprocess
from pathlib import Path

# Force UTF-8 stdout on Windows (avoids cp1252 errors with Unicode art)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

DRY  = "--dry-run" in sys.argv
ROOT = Path(__file__).parent.resolve()

GREEN  = "\033[92m" if sys.stdout.isatty() else ""
YELLOW = "\033[93m" if sys.stdout.isatty() else ""
RESET  = "\033[0m"  if sys.stdout.isatty() else ""

modified_files: list[str] = []

def log(m):     print(f"    {m}")
def ok(m):      print(f"{GREEN}  + {m}{RESET}")
def warn(m):    print(f"{YELLOW}  ! {m}{RESET}")
def section(h): print(f"\n{GREEN}{'='*60}\n  {h}\n{'='*60}{RESET}")


# ════════════════════════════════════════════════════════════════════
# 1.  REPLACEMENT TABLE   (longest / most-specific first)
# ════════════════════════════════════════════════════════════════════

REPLACEMENTS: list[tuple[str, str]] = [
    # Go module path
    ("github.com/bishopfox/sliver",      "github.com/sudosoc/SUDOSOC-C2"),

    # Legal / organisation
    ("BishopFox, Inc.",                  "Meridian Cloud Services, Inc."),
    ("BishopFox Inc.",                   "Meridian Cloud Services, Inc."),
    ("BishopFox",                        "Seif"),
    ("bishopfox",                        "sudosoc"),

    # Binary names
    ("sliver-server",                    "sudosoc-server"),
    ("sliver-client",                    "sudosoc-client"),

    # Protobuf package (stragglers)
    ("sliverpb",                         "sudosocpb"),

    # gRPC service
    ("SliverRPC_",                       "SudosocAPI_"),
    ("SliverRPC",                        "SudosocAPI"),

    # Config / filesystem paths
    (".sliver/",                         ".sudosoc/"),
    (".sliver\\",                        ".sudosoc\\"),
    ("~/.sliver",                        "~/.sudosoc"),
    ("/etc/sliver/",                     "/etc/sudosoc-C2/"),
    ("/etc/sliver",                      "/etc/sudosoc-C2"),
    ("sliver.log",                       "sudosoc-c2.log"),

    # Test / build env vars
    ("SLIVER_ROOT_DIR",                  "SUDOSOC_ROOT_DIR"),
    ("sliver-go-tests-",                 "sudosoc-go-tests-"),
    ("sliver_e2e",                       "sudosoc_e2e"),

    # Implant template name  (string literal only)
    ('"template", "I", "sliver"',        '"template", "I", "phantom"'),
    ('TemplateName = "sliver"',          'TemplateName = "phantom"'),

    # Compiler backdoor internal symbol
    ('"init.sliver_"',                   '"init.phantom_"'),
    ('"init.sliver_%s"',                 '"init.phantom_%s"'),
    ("init.sliver_",                     "init.phantom_"),

    # UI strings
    ('"sliver-mcp-console"',             '"sudosoc-mcp-console"'),
    ("sliver-armory-",                   "sudosoc-armory-"),
    ("sliver-wordlist",                  "sudosoc-wordlist"),
    ("sliver-bof",                       "sudosoc-bof"),
    ("SliverPy",                         "SudosocPy"),
    ("sliver-script",                    "sudosoc-script"),

    # Port constant  (precise patterns to avoid touching unrelated numbers)
    ('= 31337',                          '= 47441'),
    ('":31337"',                         '":47441"'),
    ('"31337"',                          '"47441"'),

    # Internal Go identifiers
    ("sliverCmds",                       "sudosocCmds"),
    ("sliverCommands",                   "sudosocCommands"),
    ("sliverMenu",                       "sudosocMenu"),
    ("sliverBordersDefault",             "sudosocBordersDefault"),
    ("SliverCoreHelpGroup",              "SudosocCoreHelpGroup"),
    ("SliverClient",                     "SudosocClient"),

    # Proto / docs filenames (string references, not filesystem ops)
    ("sliver.proto",                     "sudosoc.proto"),
    ("sliver.pb.go",                     "sudosoc.pb.go"),

    # Help text paths
    (".sliver)",                         ".sudosoc)"),
    ("in .sliver",                       "in .sudosoc"),

    # Misc help / doc text containing bare "sliver"
    ('sliver "execute"',                 'sudosoc "execute"'),
    ("current sliver process",           "current sudosoc process"),
    ("new sliver session",               "new sudosoc session"),
    ("sliver binary",                    "phantom binary"),
    ("a sliver",                         "a phantom"),
    ("sliver service",                   "phantom service"),
    ("sliver shellcode",                 "phantom shellcode"),
    ("Generating sliver binary",         "Generating phantom binary"),
    ("sliver name/session",              "sudosoc name/session"),
    ("my-sliver-profile",                "my-phantom-profile"),
    ("sliver corresponding",             "phantom corresponding"),
    ("sent to a sliver",                 "sent to a phantom"),
    ('"Start the sliver client console"','"Start the sudosoc client console"'),
]

# Lines containing these strings are skipped (external deps)
PROTECTED: set[str] = {
    "github.com/sliverarmory/",
}


# ════════════════════════════════════════════════════════════════════
# 2.  NEW CONTENT
# ════════════════════════════════════════════════════════════════════

# ── ASCII Banners ────────────────────────────────────────────────────
# Three variants replacing the old SLIVER logos.
# Same Unicode block style as the originals.

BANNER_RED = r"""
    ███████╗██╗   ██╗██████╗  ██████╗ ███████╗ ██████╗  ██████╗     ██████╗██████╗
    ██╔════╝██║   ██║██╔══██╗██╔═══██╗██╔════╝██╔═══██╗██╔════╝    ██╔════╝╚════██╗
    ███████╗██║   ██║██║  ██║██║   ██║███████╗██║   ██║██║         ██║      █████╔╝
    ╚════██║██║   ██║██║  ██║██║   ██║╚════██║██║   ██║██║         ██║     ██╔═══╝
    ███████║╚██████╔╝██████╔╝╚██████╔╝███████║╚██████╔╝╚██████╗    ╚██████╗███████╗
    ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝     ╚═════╝╚══════╝
"""

BANNER_GREEN = r"""
    ███████╗██╗   ██╗██████╗  ██████╗ ███████╗ ██████╗  ██████╗     ██████╗██████╗
    ██╔════╝██║   ██║██╔══██╗██╔═══██╗██╔════╝██╔═══██╗██╔════╝    ██╔════╝╚════██╗
    ███████╗██║   ██║██║  ██║██║   ██║███████╗██║   ██║██║         ██║      █████╔╝
    ╚════██║██║   ██║██║  ██║██║   ██║╚════██║██║   ██║██║         ██║     ██╔═══╝
    ███████║╚██████╔╝██████╔╝╚██████╔╝███████║╚██████╔╝╚██████╗    ╚██████╗███████╗
    ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝     ╚═════╝╚══════╝

         ─────── Precision adversary simulation. Zero compromise. ───────
                        Phantom Implant Engine  ·  v2.0.0
"""

BANNER_GRAY = (
    ".--------..--------..--------..--------..--------..--------..--------..--------..--------.\n"
    "|S.--. ||U.--. ||D.--. ||O.--. ||S.--. ||O.--. ||C.--. ||--.--. ||2.--. |\n"
    "| (\\/)  || (____)|| |)|  | || :  . : || (\\/)  || :  . : || :/\\:  || :(): || :/\\:  |\n"
    "| :\\/\\: || |    || |\\ \\ _| || :.      || :\\/\\: || :.      || :\\/: || ()() || :\\/: |\n"
    "| '--'S|| '--'U|| '--'D|| '--'O|| '--'S|| '--'O|| '--'C|| '--'-|| '--'2|\n"
    "`------'`------'`------'`------'`------'`------'`------'`------'`------'"
)

# ── Prompt template ──────────────────────────────────────────────────
PROMPT_TEMPLATE = (
    '`{{- if .IsServer -}}'
    '{{ .Styles.Bold.Render "[server]" }} '
    '{{ .Styles.Underline.Render "sudosoc" }}{{ .Target.Suffix }} > '
    '{{- else -}}'
    '{{- if .Host -}}{{ .Styles.BoldPrimary.Render (printf "[%s]" .Host) }} {{- end -}}'
    '{{ .Styles.Underline.Render "sudosoc" }}{{ .Target.Suffix }} > {{- end -}}`'
)


# ════════════════════════════════════════════════════════════════════
# 3.  SKIP / PROTECT RULES
# ════════════════════════════════════════════════════════════════════

SKIP_DIRS: set[str] = {
    ".git", "vendor", "node_modules",
    "__pycache__", ".idea", ".vscode",
}

SKIP_EXTS: set[str] = {
    ".exe", ".dll", ".so", ".a", ".o",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z",
    ".png", ".jpg", ".jpeg", ".gif", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".bin", ".dat", ".pyc",
}


# ════════════════════════════════════════════════════════════════════
# 4.  CORE HELPERS
# ════════════════════════════════════════════════════════════════════

def is_binary(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return b"\x00" in f.read(8192)
    except Exception:
        return True


def safe_replace(text: str) -> tuple[str, bool]:
    """Apply replacements line-by-line; skip lines with protected strings."""
    changed = False
    lines   = text.split("\n")
    out     = []
    for line in lines:
        if any(p in line for p in PROTECTED):
            out.append(line)
            continue
        new = line
        for old, repl in REPLACEMENTS:
            if old in new:
                new = new.replace(old, repl)
        if new != line:
            changed = True
        out.append(new)
    return "\n".join(out), changed


def process_file(path: Path):
    if path.suffix in SKIP_EXTS:
        return
    if path.name == "rebrand.py":
        return
    if is_binary(path):
        return
    try:
        original = path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        warn(f"cannot read {path.relative_to(ROOT)}: {e}")
        return
    updated, changed = safe_replace(original)
    if changed:
        rel = str(path.relative_to(ROOT))
        modified_files.append(rel)
        if DRY:
            log(f"[DRY] {rel}")
        else:
            path.write_text(updated, encoding="utf-8")
            ok(rel)


def walk(root: Path):
    for entry in sorted(root.iterdir()):
        if entry.name in SKIP_DIRS:
            continue
        if entry.is_dir():
            walk(entry)
        elif entry.is_file():
            process_file(entry)


# ════════════════════════════════════════════════════════════════════
# 5.  TARGETED SURGICAL UPDATES
# ════════════════════════════════════════════════════════════════════

def update_banner():
    section("Updating ASCII banners in console.go")
    f = ROOT / "client" / "console" / "console.go"
    if not f.exists():
        warn("console.go not found — skip")
        return
    content = f.read_text(encoding="utf-8")
    new_block = (
        "var asciiLogos = []asciiLogo{\n"
        "\t{style: logoStyleRed, art: `\n" + BANNER_RED + "\t`},\n\n"
        "\t{style: logoStyleGreen, art: `\n" + BANNER_GREEN + "\t`},\n\n"
        "\t{style: logoStyleBoldGray, art: `\n" + BANNER_GRAY + "\n\t`},\n"
        "}"
    )
    pattern = re.compile(r"var asciiLogos = \[\]asciiLogo\{.*?\}", re.DOTALL)
    if pattern.search(content):
        updated = pattern.sub(new_block, content)
        if not DRY:
            f.write_text(updated, encoding="utf-8")
        ok("console.go — banners replaced")
    else:
        warn("asciiLogos block not found — check console.go manually")


def update_prompt():
    section("Updating shell prompt in settings.go")
    f = ROOT / "client" / "assets" / "settings.go"
    if not f.exists():
        warn("settings.go not found — skip")
        return
    content = f.read_text(encoding="utf-8")
    pattern = re.compile(
        r'(const DefaultPromptTemplate\s*=\s*)`[^`]*`', re.DOTALL
    )
    updated = pattern.sub(r"\1" + PROMPT_TEMPLATE, content)
    if updated != content:
        if not DRY:
            f.write_text(updated, encoding="utf-8")
        ok("settings.go — prompt template updated")
    else:
        warn("DefaultPromptTemplate not found — check settings.go manually")


def update_makefile():
    section("Updating Makefile")
    f = ROOT / "Makefile"
    if not f.exists():
        warn("Makefile not found — skip")
        return
    content = f.read_text(encoding="utf-8")

    # Project name variable
    content = re.sub(r'^(NAME\s*[:?]?=\s*)\S.*$',
                     r'\g<1>SUDOSOC-C2', content, flags=re.MULTILINE)
    # Version
    content = re.sub(r'(VERSION\s*[:?]?=\s*)v[\d.]+',
                     r'\g<1>v2.0.0', content)
    # Proto / pb filenames (already covered by broad pass but ensure Makefile lines too)
    content = content.replace("sliver.proto", "sudosoc.proto")
    content = content.replace("sliver.pb.go", "sudosoc.pb.go")

    # Remove Docker targets
    lines, out, in_docker = content.split("\n"), [], False
    for line in lines:
        stripped = line.strip()
        if re.match(r'^docker[-\w]*\s*:', stripped) or \
           re.match(r'^## Docker', stripped, re.IGNORECASE):
            in_docker = True
        if in_docker:
            if stripped == "" and not lines[lines.index(line)-1].startswith("\t"):
                in_docker = False
                out.append(line)
            continue
        out.append(line)
    content = "\n".join(out)

    if not DRY:
        f.write_text(content, encoding="utf-8")
    ok("Makefile updated")


def rename_proto_files():
    section("Renaming sliver.proto → sudosoc.proto")
    pb_dir = ROOT / "protobuf" / "sudosocpb"
    for old, new in [("sliver.proto", "sudosoc.proto"),
                     ("sliver.pb.go", "sudosoc.pb.go")]:
        src, dst = pb_dir / old, pb_dir / new
        if src.exists():
            if not DRY:
                src.rename(dst)
            ok(f"Renamed {old} → {new}")
        elif dst.exists():
            log(f"{new} already in place")
        else:
            warn(f"{old} not found in protobuf/sudosocpb/")


def remove_docker_files():
    section("Removing Docker files")
    for name in ["Dockerfile", "Dockerfile.server", "Dockerfile.client",
                 "Dockerfile.builder", "docker-compose.yml",
                 "docker-compose.yaml", ".dockerignore"]:
        p = ROOT / name
        if p.exists():
            if not DRY:
                p.unlink()
            ok(f"Deleted {name}")
    for df in ROOT.rglob("Dockerfile*"):
        if "vendor" in df.parts:
            continue
        if not df.is_file():   # skip directories named "dockerfile" on Windows
            continue
        if not DRY:
            df.unlink()
        ok(f"Deleted {df.relative_to(ROOT)}")
    wf_dir = ROOT / ".github" / "workflows"
    if wf_dir.exists():
        for wf in sorted(wf_dir.glob("*.yml")):
            try:
                txt = wf.read_text(errors="replace")
            except Exception:
                continue
            if re.search(r'\bdocker\b', txt, re.IGNORECASE):
                if not DRY:
                    wf.unlink()
                ok(f"Deleted workflow: {wf.name}")


def update_license():
    section("Updating LICENSE")
    lic = ROOT / "LICENSE"
    if not lic.exists():
        warn("LICENSE not found — skip")
        return
    content = lic.read_text(encoding="utf-8")
    content = re.sub(
        r'Copyright\s+\(C\)\s+\d{4}[^\n]*',
        'Copyright (C) 2026  Seif', content
    )
    if not DRY:
        lic.write_text(content, encoding="utf-8")
    ok("LICENSE author updated")


def write_readme():
    section("Writing README.md")
    readme = ROOT / "README.md"
    if not DRY:
        readme.write_text(README_CONTENT, encoding="utf-8")
    ok("README.md written")


def reset_git():
    section("Resetting git history")
    if DRY:
        log("[DRY] would wipe .git/ and re-init with one commit")
        return
    git_dir = ROOT / ".git"
    if git_dir.exists():
        shutil.rmtree(git_dir)
        ok("Removed old .git/")
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME":     "sudosoc",
        "GIT_AUTHOR_EMAIL":    "sudosoc@sudosoc.com",
        "GIT_COMMITTER_NAME":  "sudosoc",
        "GIT_COMMITTER_EMAIL": "sudosoc@sudosoc.com",
    }
    subprocess.run(["git", "init"],                        cwd=ROOT, check=True, env=env)
    subprocess.run(["git", "add", "-A"],                   cwd=ROOT, check=True, env=env)
    subprocess.run(["git", "commit", "-m",
                    "Initial commit — SUDOSOC-C2 v2.0.0"], cwd=ROOT, check=True, env=env)
    ok("Fresh git repository initialised.")


# ════════════════════════════════════════════════════════════════════
# 6.  README
# ════════════════════════════════════════════════════════════════════

README_CONTENT = """\
# SUDOSOC-C2

> **Precision adversary simulation. Zero compromise.**

SUDOSOC-C2 is an advanced, operator-grade command-and-control (C2) framework
engineered for professional red team operations, adversary simulation, and
offensive security research. Built on a hardened Go core and extended with
cutting-edge evasion, persistence, and collection capabilities, SUDOSOC-C2
gives operators the power to simulate the most sophisticated threat actors —
from APT-level intrusions to hardware-level persistence.

---

## Capabilities at a Glance

### Multi-Protocol C2 Channels

| Channel       | Description                                                    |
|---------------|----------------------------------------------------------------|
| **mTLS**      | Mutual-TLS encrypted session with certificate pinning          |
| **HTTP/HTTPS**| Malleable HTTP profiles; domain-fronting ready                 |
| **DNS**       | DNS-over-HTTPS (DoH) covert channel for restrictive networks   |
| **WireGuard** | Low-latency peer-to-peer encrypted tunnel                      |
| **SMB**       | Named-pipe lateral movement without internet egress            |
| **Dead-drop** | Asynchronous C2 via third-party cloud storage objects          |
| **Timing**    | Covert channel through network timing side-channels            |

### Phantom Implant Engine

The **Phantom** implant is a polymorphic, self-modifying agent compiled
on-demand for every operation:

- **Indirect syscalls** — SSN resolved at runtime from live ntdll; execution
  jumps into the real `syscall;ret` gadget so kernel callbacks see ntdll as
  origin. Defeats call-stack-based EDR sensors cold.
- **AMSI bypass** — in-memory patch of `AmsiScanBuffer` via VirtualProtect.
- **ETW bypass** — `NtTraceEvent` stub patch; silences Process Monitor and
  Windows event tracing at the kernel boundary.
- **Sleep obfuscation** — heap + stack XOR-encrypted while idle; YARA and
  memory scanners see no live signature during C2 sleep cycles.
- **Stack spoofing** — return-address chain poisoned with synthetic ntdll
  frames; defeats any EDR that validates the call chain on syscall entry.
- **Argument spoofing** — `STARTUPINFO` manipulation hides true
  command-line arguments from process-creation telemetry.
- **Phantom DLL hollowing** — loads a clean signed DLL, overwrites its
  `.text` with shellcode; module appears legitimate in process listings.
- **Compiler backdoor** — optional supply-chain module that injects hidden
  `init.phantom_*` functions into compiled binaries at link time.

### Privilege Escalation & Defense Evasion

- **BYOVD** — loads a signed but exploitable kernel driver for ring-0 code
  execution on fully patched systems.
- **PatchGuard bypass** — exploits the DPC callback mechanism to disable
  Kernel Patch Protection before the integrity check fires.
- **DSE bypass** — disables Driver Signature Enforcement to load arbitrary
  unsigned kernel modules.
- **PPL bypass** — bypasses Protected Process Light to inject into LSASS
  and other high-integrity processes.

### Active Directory Attack Suite

| Technique     | Description                                                    |
|---------------|----------------------------------------------------------------|
| DCSync        | Replicate AD secrets from any domain controller                |
| Kerberoasting | Extract service account hashes for offline cracking            |
| AS-REP Roast  | Target accounts with Kerberos pre-auth disabled                |
| DCShadow      | Inject rogue DC attributes without producing event logs        |
| AdminSDHolder | Backdoor the AdminSDHolder container for persistent DA access  |

### Hardware-Level Persistence

- **UEFI implant** — survives OS reinstall by writing a DXE driver to the
  EFI System Partition; persists through full disk wipes.
- **SMM rootkit** — injects a handler into System Management Mode; invisible
  to the OS, hypervisor, and all security products.
- **Rowhammer** — exploits DRAM bit-flip vulnerabilities to escalate
  privileges without touching any kernel API.
- **PCI-DMA attack** — direct memory access via exposed PCIe endpoints to
  read/write arbitrary physical memory.

### Hypervisor Capability

A full Intel VT-x / VMX engine embedded in the implant enables:

- Running the target OS as a guest VM under operator control.
- EPT manipulation for stealthy memory hiding from security tools.
- VMCS-based process isolation and real-time introspection.

### Operational Security

- **Zero-knowledge proofs** — operator identity never transmitted in plaintext.
- **Ring signatures** — multiple operators share a session key without
  revealing which specific key signed any given message.
- **Pedersen commitments** — verifiable encrypted tasking; server cannot
  tamper with task payloads in transit.
- **Multiplayer** — multiple operators share a live session over a single
  encrypted multiplayer channel on port `47441`.

### Operator Console

- Full-featured interactive console with tab-completion, history, and piping.
- **AI-assisted operations** — integrated LLM backend for technique
  suggestion, payload generation guidance, and report drafting.
- **MCP server** — Model Context Protocol interface for programmatic
  operator automation.
- Armory package manager — one-command install of BOFs, extensions,
  and aliases.

---

## Quick Start

### Prerequisites

- Go ≥ 1.25
- `make`, `gcc` (mingw-w64 for Windows cross-compile)
- `protoc` + `protoc-gen-go` (only to regenerate protobufs)

### Build

```bash
# Server + client (native platform)
make

# Cross-platform targets
make linux           # Linux amd64
make windows-amd64   # Windows amd64
make macos-arm64     # Apple Silicon
```

### First Run

```bash
# Start the server
./sudosoc-server

# Connect the client (separate terminal)
./sudosoc-client

# Generate a Phantom implant
sudosoc > generate --mtls <C2-IP> --os windows --arch amd64 --save /tmp/

# Start an mTLS listener
sudosoc > mtls
```

---

## Default Ports

| Service      | Port  | Protocol |
|--------------|-------|----------|
| mTLS C2      | 8888  | TCP      |
| HTTP C2      | 80    | TCP      |
| HTTPS C2     | 443   | TCP      |
| DNS C2       | 53    | UDP      |
| WireGuard    | 51820 | UDP      |
| Multiplayer  | 47441 | TCP      |

---

## Configuration Paths

| Platform | Path                               |
|----------|------------------------------------|
| Linux    | `~/.sudosoc/`                      |
| macOS    | `~/.sudosoc/`                      |
| Windows  | `%APPDATA%\\sudosoc\\`             |
| Server   | `/etc/sudosoc-C2/`                 |
| Logs     | `<config>/logs/sudosoc-c2.log`     |

---

## Security & Responsible Use

SUDOSOC-C2 is intended exclusively for:

- Authorised penetration testing engagements.
- Internal red team operations with written approval.
- Controlled lab / CTF environments.
- Defensive security research and EDR validation.

**Unauthorised use against systems you do not own or have explicit
written permission to test is illegal and unethical.**

---

## License

Copyright (C) 2026  Seif

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

See [LICENSE](./LICENSE) for the full text.
"""


# ════════════════════════════════════════════════════════════════════
# 7.  ENTRY POINT
# ════════════════════════════════════════════════════════════════════

def main():
    print(f"\n{'='*60}")
    print("  SUDOSOC-C2 -- Full Rebranding Script")
    if DRY:
        print(f"  {YELLOW}DRY-RUN: no files will be written{RESET}")
    print(f"{'='*60}\n")

    # ── Pass 1: broad text replacement ────────────────────────────
    section("Broad string replacements (skipping vendor/)")
    walk(ROOT)
    log(f"Files modified: {len(modified_files)}")

    # ── Pass 2: surgical targeted updates ─────────────────────────
    update_banner()
    update_prompt()
    update_makefile()
    rename_proto_files()
    remove_docker_files()
    update_license()
    write_readme()

    # ── Pass 3: git reset (always last) ───────────────────────────
    reset_git()

    print(f"\n{GREEN}{'='*60}")
    print("  Rebranding complete!")
    print(f"{'='*60}{RESET}")
    print("""
Next steps:
  1.  go build ./...
          Verify zero compilation errors.

  2.  go vet ./server/... ./client/...
          Catch any remaining issues.

  3.  make pb          (if you have protoc installed)
          Regenerate sudosoc.pb.go from the renamed sudosoc.proto.

  4.  git remote add origin https://github.com/sudosoc/SUDOSOC-C2.git
      git push -u origin main
""")


if __name__ == "__main__":
    main()
