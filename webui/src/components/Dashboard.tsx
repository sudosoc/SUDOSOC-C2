import { useAPI } from '../hooks/useAPI'
import { useEventStream } from '../hooks/useWebSocket'
import type { Stats, WSEvent } from '../types'
import { useCallback, useState } from 'react'
import { Activity, Cpu, Radio, Users, Clock } from 'lucide-react'

function StatCard({
  icon: Icon,
  label,
  value,
  color,
}: {
  icon: React.ElementType
  label: string
  value: string | number
  color: string
}) {
  return (
    <div className="flex flex-col gap-2 rounded-lg border border-border bg-surface p-4 min-w-[140px]">
      <div className="flex items-center gap-2 text-muted text-xs uppercase tracking-widest">
        <Icon size={14} color={color} />
        {label}
      </div>
      <div className="text-3xl font-bold" style={{ color }}>
        {value}
      </div>
    </div>
  )
}

export default function Dashboard() {
  const { data, loading, refresh } = useAPI<Stats>('/api/stats', 10_000)
  const [events, setEvents] = useState<{ time: string; msg: string }[]>([])

  const onEvent = useCallback((e: WSEvent) => {
    if (e.type === 'heartbeat') return
    const time = new Date(e.time * 1000).toLocaleTimeString()
    const msg  = `[${e.type}] ${JSON.stringify(e.payload)}`
    setEvents(prev => [{ time, msg }, ...prev].slice(0, 50))
    refresh()
  }, [refresh])

  useEventStream(onEvent)

  const stats = data ?? { sessions: 0, beacons: 0, listeners: 0, operators: 0, uptime: '—' }

  return (
    <div className="flex flex-col gap-6 h-full p-2">

      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-primary">SUDOSOC-C2</h1>
          <p className="text-muted text-xs mt-1">Precision adversary simulation. Zero compromise.</p>
        </div>
        <div className="flex items-center gap-1 text-muted text-xs">
          <Clock size={12} />
          <span>Uptime: <span className="text-accent">{stats.uptime}</span></span>
        </div>
      </div>

      {/* ── Stat cards ─────────────────────────────────────────────────── */}
      <div className="flex flex-wrap gap-4">
        <StatCard icon={Activity} label="Sessions"  value={loading ? '…' : stats.sessions}  color="#00ff88" />
        <StatCard icon={Radio}    label="Beacons"   value={loading ? '…' : stats.beacons}   color="#00d4ff" />
        <StatCard icon={Cpu}      label="Listeners" value={loading ? '…' : stats.listeners} color="#ffaa00" />
        <StatCard icon={Users}    label="Operators" value={loading ? '…' : stats.operators} color="#aa88ff" />
      </div>

      {/* ── Live event feed ─────────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col gap-2 min-h-0">
        <h2 className="text-xs uppercase tracking-widest text-muted">Live Event Feed</h2>
        <div className="flex-1 overflow-y-auto rounded-lg border border-border bg-surface p-3 font-mono text-xs min-h-0">
          {events.length === 0 ? (
            <span className="text-muted">Waiting for events…</span>
          ) : (
            events.map((e, i) => (
              <div key={i} className="flex gap-3 py-0.5">
                <span className="text-muted shrink-0">{e.time}</span>
                <span className="text-text break-all">{e.msg}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}
