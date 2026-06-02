import { useState } from 'react'
import { useAPI, apiDelete } from '../hooks/useAPI'
import type { Session } from '../types'
import { Monitor, Skull, Terminal, RefreshCw } from 'lucide-react'

interface Props {
  onOpenTerminal: (sessionID: string, sessionName: string) => void
}

export default function Sessions({ onOpenTerminal }: Props) {
  const { data, loading, error, refresh } = useAPI<Session[]>('/api/sessions', 8_000)
  const [killing, setKilling] = useState<string | null>(null)

  const sessions = data ?? []

  async function killSession(id: string) {
    if (!confirm(`Kill session ${id}?`)) return
    setKilling(id)
    try {
      await apiDelete(`/api/sessions/${id}/kill`)
      refresh()
    } catch (e) {
      alert(String(e))
    } finally {
      setKilling(null)
    }
  }

  return (
    <div className="flex flex-col gap-4 h-full">

      {/* ── Toolbar ──────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <h2 className="text-primary font-bold text-lg flex items-center gap-2">
          <Monitor size={18} /> Sessions
          <span className="text-muted text-sm font-normal ml-1">({sessions.length})</span>
        </h2>
        <button
          onClick={refresh}
          className="flex items-center gap-1 text-muted hover:text-text text-xs px-2 py-1 rounded border border-border hover:border-muted transition-colors"
        >
          <RefreshCw size={12} /> Refresh
        </button>
      </div>

      {/* ── Error ─────────────────────────────────────────────────────────── */}
      {error && (
        <div className="text-danger text-xs bg-danger/10 border border-danger/30 rounded p-2">{error}</div>
      )}

      {/* ── Table ─────────────────────────────────────────────────────────── */}
      {loading && sessions.length === 0 ? (
        <div className="text-muted text-sm">Loading…</div>
      ) : sessions.length === 0 ? (
        <div className="flex-1 flex items-center justify-center text-muted text-sm">
          No active sessions.
        </div>
      ) : (
        <div className="flex-1 overflow-auto rounded-lg border border-border">
          <table className="w-full text-xs font-mono border-collapse">
            <thead>
              <tr className="bg-surface text-muted uppercase tracking-widest text-[10px]">
                {['Status','ID','Name','Host','User','OS/Arch','Transport','Address','Last Seen','Actions']
                  .map(h => (
                    <th key={h} className="text-left px-3 py-2 border-b border-border whitespace-nowrap">{h}</th>
                  ))}
              </tr>
            </thead>
            <tbody>
              {sessions.map(s => {
                const lastSeen = new Date(s.last_checkin * 1000).toLocaleTimeString()
                return (
                  <tr
                    key={s.id}
                    className={`border-b border-border/40 hover:bg-surface/60 transition-colors ${s.is_dead ? 'opacity-50' : ''}`}
                  >
                    <td className="px-3 py-2">
                      <span className={`inline-block w-2 h-2 rounded-full ${s.is_dead ? 'bg-danger' : 'bg-primary'}`} />
                    </td>
                    <td className="px-3 py-2 text-muted">{s.id.slice(0, 8)}</td>
                    <td className="px-3 py-2 text-primary font-semibold">{s.name}</td>
                    <td className="px-3 py-2">{s.hostname}</td>
                    <td className="px-3 py-2 text-accent">{s.username}</td>
                    <td className="px-3 py-2">{s.os}/{s.arch}</td>
                    <td className="px-3 py-2">
                      <span className="bg-border/60 px-1.5 py-0.5 rounded text-[10px]">{s.transport}</span>
                    </td>
                    <td className="px-3 py-2 text-muted">{s.remote_address}</td>
                    <td className="px-3 py-2 text-muted">{lastSeen}</td>
                    <td className="px-3 py-2">
                      <div className="flex gap-1">
                        <button
                          onClick={() => onOpenTerminal(s.id, s.name)}
                          title="Open terminal"
                          className="p-1 rounded hover:bg-primary/20 text-primary transition-colors"
                        >
                          <Terminal size={13} />
                        </button>
                        <button
                          onClick={() => killSession(s.id)}
                          disabled={killing === s.id}
                          title="Kill session"
                          className="p-1 rounded hover:bg-danger/20 text-danger transition-colors disabled:opacity-40"
                        >
                          <Skull size={13} />
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
