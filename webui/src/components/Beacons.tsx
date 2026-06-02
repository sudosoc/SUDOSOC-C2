import { useAPI } from '../hooks/useAPI'
import type { Beacon } from '../types'
import { Radio, RefreshCw } from 'lucide-react'

function fmtInterval(ms: number) {
  if (ms <= 0) return '—'
  const s = Math.floor(ms / 1000)
  if (s < 60) return `${s}s`
  return `${Math.floor(s / 60)}m ${s % 60}s`
}

function fmtUnix(ts: number) {
  if (!ts) return '—'
  return new Date(ts * 1000).toLocaleString()
}

export default function Beacons() {
  const { data, loading, error, refresh } = useAPI<Beacon[]>('/api/beacons', 10_000)
  const beacons = data ?? []

  return (
    <div className="flex flex-col gap-4 h-full">
      <div className="flex items-center justify-between">
        <h2 className="text-accent font-bold text-lg flex items-center gap-2">
          <Radio size={18} /> Beacons
          <span className="text-muted text-sm font-normal ml-1">({beacons.length})</span>
        </h2>
        <button
          onClick={refresh}
          className="flex items-center gap-1 text-muted hover:text-text text-xs px-2 py-1 rounded border border-border hover:border-muted transition-colors"
        >
          <RefreshCw size={12} /> Refresh
        </button>
      </div>

      {error && (
        <div className="text-danger text-xs bg-danger/10 border border-danger/30 rounded p-2">{error}</div>
      )}

      {loading && beacons.length === 0 ? (
        <div className="text-muted text-sm">Loading…</div>
      ) : beacons.length === 0 ? (
        <div className="flex-1 flex items-center justify-center text-muted text-sm">
          No beacons registered.
        </div>
      ) : (
        <div className="flex-1 overflow-auto rounded-lg border border-border">
          <table className="w-full text-xs font-mono border-collapse">
            <thead>
              <tr className="bg-surface text-muted uppercase tracking-widest text-[10px]">
                {['ID','Name','Host','User','OS','Transport','Last Checkin','Next Checkin','Interval']
                  .map(h => (
                    <th key={h} className="text-left px-3 py-2 border-b border-border whitespace-nowrap">{h}</th>
                  ))}
              </tr>
            </thead>
            <tbody>
              {beacons.map(b => (
                <tr key={b.id} className="border-b border-border/40 hover:bg-surface/60 transition-colors">
                  <td className="px-3 py-2 text-muted">{b.id.slice(0, 8)}</td>
                  <td className="px-3 py-2 text-accent font-semibold">{b.name}</td>
                  <td className="px-3 py-2">{b.hostname}</td>
                  <td className="px-3 py-2">{b.username}</td>
                  <td className="px-3 py-2">{b.os}</td>
                  <td className="px-3 py-2">
                    <span className="bg-border/60 px-1.5 py-0.5 rounded text-[10px]">{b.transport}</span>
                  </td>
                  <td className="px-3 py-2 text-muted">{fmtUnix(b.last_checkin)}</td>
                  <td className="px-3 py-2 text-warn">{fmtUnix(b.next_checkin)}</td>
                  <td className="px-3 py-2">{fmtInterval(b.interval)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
