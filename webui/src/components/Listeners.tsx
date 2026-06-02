import { useAPI } from '../hooks/useAPI'
import type { Listener } from '../types'
import { Antenna, RefreshCw } from 'lucide-react'

const protocolColor: Record<string, string> = {
  mtls:       'text-primary',
  https:      'text-accent',
  http:       'text-warn',
  dns:        'text-purple',
  wg:         'text-text',
  wireguard:  'text-text',
  smb:        'text-warn',
  tcp:        'text-muted',
}

export default function Listeners() {
  const { data, loading, error, refresh } = useAPI<Listener[]>('/api/listeners', 10_000)
  const listeners = data ?? []

  return (
    <div className="flex flex-col gap-4 h-full">
      <div className="flex items-center justify-between">
        <h2 className="text-warn font-bold text-lg flex items-center gap-2">
          <Antenna size={18} /> Listeners
          <span className="text-muted text-sm font-normal ml-1">({listeners.length})</span>
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

      {loading && listeners.length === 0 ? (
        <div className="text-muted text-sm">Loading…</div>
      ) : listeners.length === 0 ? (
        <div className="flex-1 flex items-center justify-center text-muted text-sm">
          No active listeners.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
          {listeners.map(l => {
            const colorClass = protocolColor[l.protocol.toLowerCase()] ?? 'text-text'
            return (
              <div key={l.id} className="rounded-lg border border-border bg-surface p-4 flex flex-col gap-2">
                <div className="flex items-center justify-between">
                  <span className={`font-bold text-sm uppercase ${colorClass}`}>{l.protocol}</span>
                  <span className="text-muted text-xs">Job #{l.id}</span>
                </div>
                <div className="text-text font-mono text-xs">{l.name}</div>
                <div className="flex items-center gap-2 mt-1">
                  <span className="text-muted text-xs">Port</span>
                  <span className={`font-bold text-sm ${colorClass}`}>{l.port}</span>
                </div>
                {l.domains && l.domains.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-1">
                    {l.domains.map(d => (
                      <span key={d} className="bg-border/60 text-accent px-1.5 py-0.5 rounded text-[10px] font-mono">
                        {d}
                      </span>
                    ))}
                  </div>
                )}
                {/* Active indicator */}
                <div className="flex items-center gap-1.5 mt-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
                  <span className="text-muted text-[10px]">ACTIVE</span>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
