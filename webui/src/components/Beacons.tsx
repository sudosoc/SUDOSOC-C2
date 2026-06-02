import { useState } from 'react'
import { useAPI, apiPost, apiFetch } from '../hooks/useAPI'
import type { Beacon } from '../types'
import { Radio, RefreshCw, Send, List, Clock, CheckCircle2, AlertCircle, Loader, ChevronDown, ChevronUp, Eye, X } from 'lucide-react'

interface BeaconTask {
  id:           string
  state:        string
  description:  string
  created_at:   number
  sent_at:      number
  completed_at: number
}

interface BeaconTaskContent extends BeaconTask {
  output:       string
  has_response: boolean
}

interface TaskResult {
  message:    string
  state:      string
  queued_at:  number
  command:    string
}

function fmtInterval(ms: number) {
  if (!ms || ms <= 0) return '—'
  const s = Math.floor(ms / 1000)
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`
}

function fmtUnix(ts: number) {
  return ts ? new Date(ts * 1000).toLocaleString() : '—'
}

const STATE_ICON: Record<string, React.ReactNode> = {
  pending:   <Clock     size={11} className="text-warn" />,
  sent:      <Loader    size={11} className="text-accent animate-spin" />,
  completed: <CheckCircle2 size={11} className="text-primary" />,
  failed:    <AlertCircle size={11} className="text-danger" />,
}

export default function Beacons() {
  const { data, loading, error, refresh } = useAPI<Beacon[]>('/api/beacons', 8_000)
  const beacons = data ?? []

  const [expanded,   setExpanded]   = useState<string | null>(null)
  const [tasks,      setTasks]      = useState<Record<string, BeaconTask[]>>({})
  const [loadingT,   setLoadingT]   = useState<string | null>(null)
  const [customCmd,  setCustomCmd]  = useState<Record<string, string>>({})
  const [sending,    setSending]    = useState<string | null>(null)
  const [result,     setResult]     = useState<Record<string, TaskResult | null>>({})
  const [taskOutput, setTaskOutput] = useState<BeaconTaskContent | null>(null)
  const [loadingOut, setLoadingOut] = useState<string | null>(null)

  async function expandBeacon(beaconID: string) {
    if (expanded === beaconID) {
      setExpanded(null); return
    }
    setExpanded(beaconID)
    setLoadingT(beaconID)
    try {
      const t = await apiFetch<BeaconTask[]>(`/api/beacons/${beaconID}/tasks`)
      setTasks(prev => ({ ...prev, [beaconID]: t }))
    } catch { setTasks(prev => ({ ...prev, [beaconID]: [] })) }
    finally  { setLoadingT(null) }
  }

  async function viewOutput(beaconID: string, taskID: string) {
    setLoadingOut(taskID)
    try {
      const res = await apiFetch<BeaconTaskContent>(`/api/beacons/${beaconID}/tasks/${taskID}`)
      setTaskOutput(res)
    } catch { /* ignore */ }
    finally { setLoadingOut(null) }
  }

  async function queueTask(beaconID: string) {
    const cmd = customCmd[beaconID]?.trim()
    if (!cmd) return
    setSending(beaconID)
    setResult(prev => ({ ...prev, [beaconID]: null }))
    try {
      const res = await apiPost<TaskResult>(`/api/beacons/${beaconID}/execute`, { command: cmd })
      setResult(prev => ({ ...prev, [beaconID]: res }))
      setCustomCmd(prev => ({ ...prev, [beaconID]: '' }))
      // Refresh task list
      const t = await apiFetch<BeaconTask[]>(`/api/beacons/${beaconID}/tasks`)
      setTasks(prev => ({ ...prev, [beaconID]: t }))
    } catch (e) {
      setResult(prev => ({ ...prev, [beaconID]: { message: String(e), state: 'error', queued_at: 0, command: cmd } }))
    } finally { setSending(null) }
  }

  return (
    <div className="flex flex-col gap-4 h-full">

      {/* ── Toolbar ──────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <h2 className="text-accent font-bold text-lg flex items-center gap-2">
          <Radio size={18} /> Beacons
          <span className="text-muted text-sm font-normal">({beacons.length})</span>
        </h2>
        <button onClick={refresh}
          className="flex items-center gap-1 text-muted hover:text-text text-xs px-2 py-1 rounded border border-border">
          <RefreshCw size={12} /> Refresh
        </button>
      </div>

      {error && <div className="text-danger text-xs bg-danger/10 border border-danger/30 rounded p-2">{error}</div>}

      {loading && beacons.length === 0 ? (
        <div className="text-muted text-sm">Loading…</div>
      ) : beacons.length === 0 ? (
        <div className="flex-1 flex flex-col items-center justify-center gap-3 text-center py-12">
          <Radio size={40} className="text-border" />
          <p className="text-muted text-sm">No beacons registered.</p>
          <p className="text-muted text-xs">Generate a beacon-mode implant and deploy it to a target.</p>
        </div>
      ) : (
        <div className="flex flex-col gap-2">
          {beacons.map(b => {
            const isExpanded = expanded === b.id
            const bTasks     = tasks[b.id] ?? []
            const pending    = bTasks.filter(t => t.state === 'pending').length
            const sent       = bTasks.filter(t => t.state === 'sent').length
            const completed  = bTasks.filter(t => t.state === 'completed').length

            return (
              <div key={b.id} className="rounded-lg border border-border bg-surface">

                {/* ── Beacon header ─────────────────────────────── */}
                <div className="flex items-center gap-3 px-4 py-3">

                  {/* Pulse indicator */}
                  <span className="w-2 h-2 rounded-full bg-accent animate-pulse shrink-0" />

                  {/* Identity */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-accent font-bold text-sm">{b.name}</span>
                      <span className="text-muted text-[10px] font-mono">{b.id.slice(0,8)}</span>
                      <span className="text-muted text-[10px] bg-border/40 px-1.5 py-0.5 rounded">{b.os}</span>
                      <span className="text-muted text-[10px] bg-border/40 px-1.5 py-0.5 rounded">{b.transport}</span>
                    </div>
                    <div className="text-muted text-[10px] mt-0.5 truncate">
                      {b.username}@{b.hostname} · interval {fmtInterval(b.interval)} · next checkin: {fmtUnix(b.next_checkin)}
                    </div>
                  </div>

                  {/* Task counts */}
                  <div className="hidden sm:flex items-center gap-2 text-[10px]">
                    {pending > 0   && <span className="text-warn">{pending} pending</span>}
                    {sent > 0      && <span className="text-accent">{sent} in-flight</span>}
                    {completed > 0 && <span className="text-primary">{completed} done</span>}
                  </div>

                  {/* Expand */}
                  <button onClick={() => expandBeacon(b.id)}
                    className="flex items-center gap-1 px-2 py-1.5 rounded text-xs text-accent bg-accent/10 hover:bg-accent/20 border border-accent/30 transition-colors">
                    <List size={12} /> Tasks
                    {isExpanded ? <ChevronUp size={10} /> : <ChevronDown size={10} />}
                  </button>
                </div>

                {/* ── Expanded: task panel ──────────────────────── */}
                {isExpanded && (
                  <div className="border-t border-border/60 px-4 py-3 flex flex-col gap-3">

                    {/* Queue new task */}
                    <div>
                      <label className="text-[10px] text-muted uppercase tracking-widest mb-2 block">Queue Task (executes on next check-in)</label>
                      <div className="flex gap-2">
                        <input
                          value={customCmd[b.id] ?? ''}
                          onChange={e => setCustomCmd(prev => ({ ...prev, [b.id]: e.target.value }))}
                          onKeyDown={e => e.key === 'Enter' && queueTask(b.id)}
                          placeholder="e.g. cmd.exe /c whoami"
                          className="flex-1 bg-bg border border-border rounded px-3 py-2 text-xs font-mono text-text placeholder-muted focus:border-accent outline-none"
                          disabled={sending === b.id}
                        />
                        <button onClick={() => queueTask(b.id)}
                          disabled={!customCmd[b.id]?.trim() || sending === b.id}
                          className="px-3 py-2 rounded bg-accent/10 border border-accent/30 text-accent hover:bg-accent/20 disabled:opacity-40">
                          {sending === b.id
                            ? <Loader size={13} className="animate-spin" />
                            : <Send size={13} />}
                        </button>
                      </div>
                      {result[b.id] && (
                        <div className={`mt-2 text-xs p-2 rounded border ${
                          result[b.id]?.state === 'error'
                            ? 'text-danger bg-danger/10 border-danger/30'
                            : 'text-primary bg-primary/10 border-primary/30'
                        }`}>
                          {result[b.id]?.message}
                        </div>
                      )}
                    </div>

                    {/* Task list */}
                    <div>
                      <div className="flex items-center justify-between mb-1.5">
                        <label className="text-[10px] text-muted uppercase tracking-widest">Task History</label>
                        <button onClick={async () => {
                          setLoadingT(b.id)
                          const t = await apiFetch<BeaconTask[]>(`/api/beacons/${b.id}/tasks`).catch(() => [])
                          setTasks(prev => ({ ...prev, [b.id]: t }))
                          setLoadingT(null)
                        }} className="text-[10px] text-muted hover:text-accent">
                          <RefreshCw size={10} />
                        </button>
                      </div>

                      {loadingT === b.id ? (
                        <div className="text-muted text-xs">Loading tasks…</div>
                      ) : bTasks.length === 0 ? (
                        <div className="text-muted text-xs italic">No tasks yet — queue one above</div>
                      ) : (
                        <div className="flex flex-col gap-1 max-h-48 overflow-y-auto">
                          {bTasks.map(t => (
                            <div key={t.id} className="flex items-start gap-2 py-1.5 border-b border-border/30 text-xs">
                              <span className="shrink-0 mt-0.5">{STATE_ICON[t.state] ?? STATE_ICON.pending}</span>
                              <div className="flex-1 min-w-0">
                                <div className="text-text truncate">{t.description || t.id.slice(0,12)}</div>
                                <div className="text-[10px] text-muted">
                                  {t.state === 'completed'
                                    ? `Completed ${fmtUnix(t.completed_at)}`
                                    : t.state === 'sent'
                                    ? `Sent ${fmtUnix(t.sent_at)}`
                                    : `Queued ${fmtUnix(t.created_at)}`}
                                </div>
                              </div>
                              <div className="flex items-center gap-1 shrink-0">
                                {(t.state === 'completed' || t.state === 'sent') && (
                                  <button onClick={() => viewOutput(b.id, t.id)}
                                    disabled={loadingOut === t.id}
                                    className="text-muted hover:text-primary" title="View output">
                                    {loadingOut === t.id
                                      ? <Loader size={10} className="animate-spin"/>
                                      : <Eye size={10}/>}
                                  </button>
                                )}
                                <span className={`text-[9px] px-1.5 py-0.5 rounded border ${
                                  t.state === 'completed' ? 'border-primary/30 text-primary'
                                  : t.state === 'sent'    ? 'border-accent/30  text-accent'
                                  : t.state === 'failed'  ? 'border-danger/30  text-danger'
                                  :                         'border-warn/30    text-warn'
                                }`}>{t.state}</span>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}

      {/* ── Task Output Modal ─────────────────────────────────────────── */}
      {taskOutput && (
        <div className="fixed inset-0 bg-bg/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-xl shadow-2xl w-full max-w-3xl max-h-[70vh] flex flex-col">
            <div className="flex items-center justify-between px-4 py-3 border-b border-border">
              <div>
                <h3 className="text-primary font-semibold text-sm flex items-center gap-2">
                  <Eye size={13}/> Task Output
                </h3>
                <p className="text-muted text-[10px] mt-0.5">{taskOutput.description} · {taskOutput.state}</p>
              </div>
              <button onClick={() => setTaskOutput(null)} className="text-muted hover:text-danger"><X size={14}/></button>
            </div>
            <div className="flex-1 overflow-auto p-4">
              {taskOutput.output ? (
                <pre className="text-[11px] font-mono text-text whitespace-pre-wrap break-all bg-bg rounded p-3 border border-border/40">
                  {taskOutput.output}
                </pre>
              ) : taskOutput.has_response ? (
                <p className="text-muted text-xs italic">Response received but could not be decoded (non-execute task type).</p>
              ) : (
                <p className="text-muted text-xs italic">
                  {taskOutput.state === 'pending'
                    ? 'Task is still pending — waiting for beacon to check in.'
                    : 'No output available for this task.'}
                </p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
