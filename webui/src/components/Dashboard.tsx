import { useAPI, apiFetch } from '../hooks/useAPI'
import type { Stats, Session, Beacon, Listener } from '../types'
import { useCallback, useState, useEffect } from 'react'
import { useEventStream } from '../hooks/useWebSocket'
import type { WSEvent } from '../types'
import {
  Activity, Cpu, Radio, Users, Clock, Shield,
  Monitor, Antenna, TrendingUp, AlertCircle,
  Crosshair, Map, ChevronRight, Zap,
} from 'lucide-react'

// ─── Mini stat card ────────────────────────────────────────────────────────────

function StatCard({
  icon: Icon, label, value, color, sub
}: {
  icon: React.ElementType; label: string; value: string | number; color: string; sub?: string
}) {
  return (
    <div className="flex flex-col gap-3 rounded-xl border bg-surface p-4 min-w-[130px] flex-1"
      style={{ borderColor: color + '30' }}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-muted text-[10px] uppercase tracking-widest">
          <Icon size={13} style={{ color }} />
          {label}
        </div>
        <div className="w-2 h-2 rounded-full" style={{ background: color, boxShadow: `0 0 6px ${color}` }} />
      </div>
      <div className="text-4xl font-bold tabular-nums" style={{ color }}>
        {value}
      </div>
      {sub && <div className="text-[10px] text-muted">{sub}</div>}
    </div>
  )
}

// ─── Kill chain stage ─────────────────────────────────────────────────────────

function KillChainBar({ sessions, beacons, listeners }: { sessions: number; beacons: number; listeners: number }) {
  const stages = [
    { label: 'Recon',         done: listeners > 0, color: '#aa88ff' },
    { label: 'Delivery',      done: listeners > 0, color: '#aa88ff' },
    { label: 'Exploitation',  done: sessions + beacons > 0, color: '#ffaa00' },
    { label: 'Installation',  done: sessions + beacons > 0, color: '#ffaa00' },
    { label: 'C2',            done: sessions + beacons > 0, color: '#00d4ff' },
    { label: 'Actions',       done: sessions > 0, color: '#ff4444' },
  ]
  return (
    <div className="rounded-xl border border-border bg-surface p-4 flex flex-col gap-3">
      <div className="flex items-center gap-2 text-[10px] text-muted uppercase tracking-widest">
        <Zap size={12} className="text-primary" />
        Kill Chain Progress
      </div>
      <div className="flex gap-1">
        {stages.map((s, i) => (
          <div key={s.label} className="flex-1 flex flex-col gap-1">
            <div className="h-2 rounded-full transition-all"
              style={{ background: s.done ? s.color : '#1a1a2e', boxShadow: s.done ? `0 0 6px ${s.color}40` : 'none' }} />
            <div className="text-[8px] text-center" style={{ color: s.done ? s.color : '#555577' }}>
              {s.label}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Component ────────────────────────────────────────────────────────────────

interface Props { onOpenTerminal: (id: string, name: string) => void }

export default function Dashboard({ onOpenTerminal }: Props) {
  const { data: stats,   loading: sL, refresh: rStats   } = useAPI<Stats>('/api/stats', 8_000)
  const { data: sessions } = useAPI<Session[]>('/api/sessions', 8_000)
  const { data: beacons  } = useAPI<Beacon[]>('/api/beacons',   10_000)
  const { data: listeners} = useAPI<Listener[]>('/api/listeners', 10_000)

  const [events, setEvents] = useState<{ ts: number; icon: string; msg: string; urgent: boolean }[]>([])
  const [totalEvents, setTotalEvents] = useState(0)

  const onEvent = useCallback((e: WSEvent) => {
    if (e.type === 'heartbeat') return
    rStats()
    setTotalEvents(c => c + 1)
    const payload = e.payload as Record<string, string>
    const name = payload.session_name ?? payload.beacon_name ?? payload.operator ?? ''
    const typeMap: Record<string, [string, boolean]> = {
      'session-connected':    ['💀', true],
      'session-disconnected': ['🔴', true],
      'beacon-registered':    ['📡', true],
      'operator-joined':      ['👤', false],
      'job-started':          ['▶️', false],
    }
    const [icon, urgent] = typeMap[e.type] ?? ['•', false]
    const msg = name ? `${e.type} — ${name}` : e.type
    setEvents(prev => [{ ts: Date.now(), icon, msg, urgent }, ...prev].slice(0, 80))
  }, [rStats])

  useEventStream(onEvent)

  const s = stats ?? { sessions: 0, beacons: 0, listeners: 0, operators: 0, uptime: '—' }
  const sessList = sessions ?? []
  const bcnList  = beacons  ?? []
  const lstList  = listeners ?? []
  const totalAgents = s.sessions + s.beacons

  return (
    <div className="flex flex-col gap-4 h-full">

      {/* ── Hero header ─────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-primary flex items-center gap-2">
            <Shield size={24} className="text-primary" />
            SUDOSOC-C2
          </h1>
          <p className="text-muted text-xs mt-1">Precision adversary simulation · Zero compromise</p>
        </div>
        <div className="flex items-center gap-3 text-[11px]">
          <div className="flex items-center gap-1.5 text-muted">
            <Clock size={12} />
            <span>Uptime: <span className="text-accent font-semibold">{s.uptime}</span></span>
          </div>
          <div className="flex items-center gap-1.5 text-muted">
            <Activity size={12} />
            <span><span className="text-accent font-semibold">{totalEvents}</span> events</span>
          </div>
        </div>
      </div>

      {/* ── Stat cards row ──────────────────────────────────────────────── */}
      <div className="flex gap-3 flex-wrap shrink-0">
        <StatCard icon={Crosshair} label="Agents"    value={sL ? '…' : totalAgents}   color="#ff4444" sub={`${s.sessions} sessions · ${s.beacons} beacons`} />
        <StatCard icon={Monitor}   label="Sessions"  value={sL ? '…' : s.sessions}    color="#00d4ff" sub="Interactive shells" />
        <StatCard icon={Radio}     label="Beacons"   value={sL ? '…' : s.beacons}     color="#ffaa00" sub="Async task queue" />
        <StatCard icon={Antenna}   label="Listeners" value={sL ? '…' : s.listeners}   color="#aa88ff" sub={lstList.map(l=>`${l.protocol}:${l.port}`).join(' · ') || 'None active'} />
        <StatCard icon={Users}     label="Operators" value={sL ? '…' : s.operators}   color="#00ff88" sub="Online operators" />
      </div>

      {/* ── Kill chain ──────────────────────────────────────────────────── */}
      <KillChainBar sessions={s.sessions} beacons={s.beacons} listeners={s.listeners} />

      {/* ── Bottom two-column grid ────────────────────────────────────── */}
      <div className="flex gap-3 flex-1 min-h-0">

        {/* Active agents (left) */}
        <div className="flex-1 flex flex-col gap-2 min-h-0 min-w-0">
          <div className="text-[10px] text-muted uppercase tracking-widest flex items-center gap-1.5">
            <Crosshair size={11} className="text-[#ff4444]" />
            Active Agents
            <span className="text-[#ff4444] font-bold">{totalAgents}</span>
          </div>
          <div className="flex-1 overflow-y-auto rounded-xl border border-border bg-surface">
            {totalAgents === 0 ? (
              <div className="flex flex-col items-center justify-center h-full gap-2 text-muted p-6">
                <Crosshair size={28} className="text-border" />
                <p className="text-sm">No active agents</p>
                <p className="text-xs">Deploy an implant to see agents here</p>
              </div>
            ) : (
              <div className="flex flex-col">
                {/* Sessions */}
                {sessList.map(s => (
                  <div key={s.id}
                    className="flex items-center gap-3 px-4 py-2.5 border-b border-border/30 hover:bg-white/3 group transition-colors">
                    <span className={`w-2 h-2 rounded-full shrink-0 ${s.is_dead ? 'bg-danger' : 'bg-primary animate-pulse'}`} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-text text-xs font-bold truncate">{s.name}</span>
                        <span className="text-primary text-[9px] bg-primary/10 px-1.5 rounded">SESSION</span>
                        <span className="text-[10px]">
                          {s.os?.toLowerCase().includes('windows') ? '🪟' :
                           s.os?.toLowerCase().includes('android') ? '🤖' :
                           s.os?.toLowerCase().includes('mac')     ? '🍎' : '🐧'}
                        </span>
                      </div>
                      <div className="text-muted text-[10px] truncate">
                        {s.username}@{s.hostname} · {s.transport} · {s.remote_address}
                      </div>
                    </div>
                    <button onClick={() => onOpenTerminal(s.id, s.name)}
                      className="opacity-0 group-hover:opacity-100 p-1.5 rounded border border-primary/40 text-primary hover:bg-primary/10 transition-all">
                      <ChevronRight size={11} />
                    </button>
                  </div>
                ))}
                {/* Beacons */}
                {bcnList.map(b => (
                  <div key={b.id}
                    className="flex items-center gap-3 px-4 py-2.5 border-b border-border/30 hover:bg-white/3">
                    <span className="w-2 h-2 rounded-full shrink-0 bg-warn" />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-text text-xs font-bold truncate">{b.name}</span>
                        <span className="text-warn text-[9px] bg-warn/10 px-1.5 rounded">BEACON</span>
                      </div>
                      <div className="text-muted text-[10px] truncate">
                        {b.username}@{b.hostname} · {b.transport} · interval {b.interval ? Math.round(b.interval/1000)+'s' : '?'}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Live event feed (right) */}
        <div className="w-80 xl:w-96 flex flex-col gap-2 shrink-0">
          <div className="text-[10px] text-muted uppercase tracking-widest flex items-center gap-1.5">
            <Activity size={11} className="text-primary" />
            Live Events
          </div>
          <div className="flex-1 overflow-y-auto rounded-xl border border-border bg-surface font-mono text-[11px] min-h-0">
            {events.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full gap-2 text-muted p-6">
                <Activity size={28} className="text-border" />
                <p className="text-sm">No events yet</p>
                <p className="text-xs text-center">Events appear here when agents connect/disconnect</p>
              </div>
            ) : (
              events.map((ev, i) => (
                <div key={i}
                  className={`flex items-start gap-2 px-3 py-1.5 border-b border-border/20 ${ev.urgent ? 'bg-danger/5' : ''}`}>
                  <span className="shrink-0">{ev.icon}</span>
                  <span className="text-muted shrink-0 tabular-nums text-[9px] mt-0.5">
                    {new Date(ev.ts).toLocaleTimeString()}
                  </span>
                  <span className={`break-all ${ev.urgent ? 'text-warn' : 'text-muted'}`}>{ev.msg}</span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
