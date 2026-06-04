import { useAPI, apiFetch } from '../hooks/useAPI'
import type { Stats, Session, Beacon, Listener } from '../types'
import { useCallback, useState, useEffect } from 'react'
import { useEventStream } from '../hooks/useWebSocket'
import type { WSEvent } from '../types'
import {
  Activity, Radio, Antenna, Shield,
  Monitor, Crosshair, ChevronRight, Zap,
  Clock, Users, Terminal,
} from 'lucide-react'

// ─── Helpers ─────────────────────────────────────────────────────────────────

function osIcon(os?: string) {
  const o = (os ?? '').toLowerCase()
  if (o.includes('windows')) return '🪟'
  if (o.includes('android')) return '🤖'
  if (o.includes('darwin') || o.includes('mac')) return '🍎'
  return '🐧'
}

function checkinAgo(ts: number) {
  const s = Math.floor((Date.now() / 1000) - (ts > 1e10 ? ts / 1000 : ts))
  if (s < 30)   return { label: `${s}s ago`,                        cls: 'text-primary' }
  if (s < 120)  return { label: `${s}s ago`,                        cls: 'text-primary' }
  if (s < 600)  return { label: `${Math.floor(s/60)}m ago`,         cls: 'text-warn' }
  return          { label: `${Math.floor(s/60)}m ago`,              cls: 'text-danger' }
}

function fmtInterval(ms: number) {
  if (!ms) return '—'
  const s = Math.floor(ms / 1000)
  return s < 60 ? `${s}s` : `${Math.floor(s/60)}m`
}

// ─── Event type map ───────────────────────────────────────────────────────────

const EVT: Record<string, { icon: string; cls: string; label: string }> = {
  'session-connected':    { icon: '💀', cls: 'text-primary', label: 'Session connected' },
  'session-disconnected': { icon: '🔴', cls: 'text-danger',  label: 'Session lost' },
  'beacon-registered':    { icon: '📡', cls: 'text-accent',  label: 'Beacon checked in' },
  'operator-joined':      { icon: '👤', cls: 'text-muted',   label: 'Operator joined' },
  'operator-left':        { icon: '👤', cls: 'text-muted',   label: 'Operator left' },
  'job-started':          { icon: '▶',  cls: 'text-muted',   label: 'Listener started' },
  'job-stopped':          { icon: '⏹',  cls: 'text-muted',   label: 'Listener stopped' },
}

// ─── Component ────────────────────────────────────────────────────────────────

interface Props { onOpenTerminal: (id: string, name: string) => void }

export default function Dashboard({ onOpenTerminal }: Props) {
  const { data: stats,    refresh: rStats }   = useAPI<Stats>('/api/stats', 6_000)
  const { data: sessions }                    = useAPI<Session[]>('/api/sessions', 6_000)
  const { data: beacons  }                    = useAPI<Beacon[]>('/api/beacons',   8_000)
  const { data: listeners }                   = useAPI<Listener[]>('/api/listeners', 10_000)

  const [events, setEvents] = useState<{ ts: number; icon: string; msg: string; cls: string; type: string }[]>([])

  const onEvent = useCallback((e: WSEvent) => {
    if (e.type === 'heartbeat') return
    rStats()
    const p    = e.payload as Record<string, string>
    const name = p.session_name ?? p.beacon_name ?? p.operator ?? ''
    const ev   = EVT[e.type] ?? { icon: '·', cls: 'text-muted', label: e.type }
    setEvents(prev => [
      { ts: Date.now(), icon: ev.icon, msg: name ? `${ev.label} — ${name}` : ev.label, cls: ev.cls, type: e.type },
      ...prev,
    ].slice(0, 120))
  }, [rStats])

  useEventStream(onEvent)

  const s    = stats ?? { sessions: 0, beacons: 0, listeners: 0, operators: 0, uptime: '—' }
  const sL   = sessions ?? []
  const bL   = beacons  ?? []
  const lstL = listeners ?? []
  const total = s.sessions + s.beacons

  // Kill chain stages
  const stages = [
    { label: 'Recon',      done: lstL.length > 0,   color: '#444' },
    { label: 'Weaponize',  done: lstL.length > 0,   color: '#555' },
    { label: 'Deliver',    done: total > 0,          color: '#666' },
    { label: 'Exploit',    done: total > 0,          color: '#888' },
    { label: 'Install',    done: total > 0,          color: '#aaa' },
    { label: 'C2',         done: s.sessions > 0,     color: '#b91c1c' },
    { label: 'Actions',    done: s.sessions > 0,     color: '#ef4444' },
  ]

  return (
    <div className="flex flex-col gap-5 h-full overflow-y-auto">

      {/* ── Page title ──────────────────────────────────────────────────── */}
      <div className="flex items-end justify-between shrink-0 pb-1 border-b border-border">
        <div>
          <div className="flex items-center gap-2.5">
            <Shield size={18} className="text-primary" />
            <span className="text-lg font-bold text-text tracking-tight">SUDOSOC-C2</span>
            <span className="badge badge-live">LIVE</span>
          </div>
          <p className="text-muted text-[10px] mt-0.5 ml-7">Precision adversary simulation platform</p>
        </div>
        <div className="flex items-center gap-4 text-[10px] text-muted mb-0.5">
          <span className="flex items-center gap-1.5"><Clock size={11}/> {s.uptime}</span>
          <span className="flex items-center gap-1.5"><Users size={11}/> {s.operators} op{s.operators !== 1 ? 's' : ''}</span>
          <span className="flex items-center gap-1.5"><Activity size={11}/> {events.length} events</span>
        </div>
      </div>

      {/* ── Stat cards ──────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 shrink-0">
        {[
          { icon: Crosshair, label: 'Total Agents',  value: total,          sub: `${s.sessions} sessions · ${s.beacons} beacons`, color: '#b91c1c' },
          { icon: Monitor,   label: 'Sessions',      value: s.sessions,     sub: 'Interactive shells',  color: '#d0d0d0' },
          { icon: Radio,     label: 'Beacons',       value: s.beacons,      sub: 'Async callbacks',     color: '#888888' },
          { icon: Antenna,   label: 'Listeners',     value: s.listeners,    sub: lstL.map(l => `${l.protocol}:${l.port}`).join(' · ') || 'None active', color: '#6b6b6b' },
        ].map(c => {
          const Icon = c.icon
          return (
            <div key={c.label} className="stat-card" style={{ '--c-accent': c.color } as React.CSSProperties}>
              <div className="flex items-center justify-between">
                <span className="stat-card-label">{c.label}</span>
                <Icon size={13} style={{ color: c.color, opacity: .7 }} />
              </div>
              <div className="stat-card-value" style={{ color: c.color }}>{c.value}</div>
              <div className="stat-card-sub truncate">{c.sub}</div>
            </div>
          )
        })}
      </div>

      {/* ── Kill chain ──────────────────────────────────────────────────── */}
      <div className="panel shrink-0">
        <div className="section-hdr">
          <Zap size={11} className="text-primary" />
          Kill Chain
        </div>
        <div className="flex gap-0 p-4">
          {stages.map((st, i) => (
            <div key={st.label} className="killchain-stage">
              {i > 0 && (
                <div className="w-full flex items-center" style={{ marginTop: '2px' }}>
                  <div style={{ width: '100%', height: 1, background: st.done ? st.color : 'var(--border)' }} />
                </div>
              )}
              {i === 0 && <div style={{ width: '100%', height: 1 }} />}
              <div className="killchain-bar" style={{
                background: st.done ? st.color : 'var(--dim)',
                boxShadow: st.done ? `0 0 8px ${st.color}50` : 'none',
              }} />
              <div className="killchain-label" style={{ color: st.done ? st.color : 'var(--muted)' }}>
                {st.label}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── Bottom grid ─────────────────────────────────────────────────── */}
      <div className="flex gap-3 flex-1 min-h-0" style={{ minHeight: 280 }}>

        {/* ── Agent roster ── */}
        <div className="flex-1 panel flex flex-col min-h-0 min-w-0">
          <div className="section-hdr">
            <Crosshair size={11} className="text-primary" />
            Agent Roster
            {total > 0 && <span className="badge badge-live ml-1">{total}</span>}
          </div>

          {total === 0 ? (
            <div className="flex-1 flex flex-col items-center justify-center gap-3 p-8 text-center">
              <Crosshair size={32} style={{ color: 'var(--dim)' }} />
              <div className="text-muted text-xs">No active agents</div>
              <div className="text-muted" style={{ fontSize: 10 }}>
                Generate an implant → Deploy → Agents appear here
              </div>
            </div>
          ) : (
            <div className="flex-1 overflow-y-auto">
              <table className="c2-table">
                <thead>
                  <tr>
                    <th>Status</th>
                    <th>Name</th>
                    <th>User @ Host</th>
                    <th>OS</th>
                    <th>Transport</th>
                    <th>Last seen</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {sL.map(s => {
                    const ci = checkinAgo(s.last_checkin)
                    return (
                      <tr key={s.id}>
                        <td><span className={`dot ${s.is_dead ? 'dot-dead' : 'dot-live'}`} /></td>
                        <td>
                          <div className="flex items-center gap-1.5">
                            <span>{osIcon(s.os)}</span>
                            <span className="text-text font-semibold" style={{ fontSize: 11 }}>{s.name}</span>
                            <span className="badge badge-session" style={{ fontSize: 8 }}>SESSION</span>
                          </div>
                        </td>
                        <td className="text-muted" style={{ fontSize: 10 }}>{s.username}@{s.hostname}</td>
                        <td className="text-muted" style={{ fontSize: 10 }}>{s.os} / {s.arch}</td>
                        <td><span className="badge badge-ghost" style={{ fontSize: 8, background: 'rgba(255,255,255,.04)', borderColor: 'var(--border)', color: 'var(--muted)' }}>{s.transport}</span></td>
                        <td className={`tabnum ${ci.cls}`} style={{ fontSize: 10 }}>{ci.label}</td>
                        <td>
                          <button onClick={() => onOpenTerminal(s.id, s.name)}
                            className="btn btn-ghost btn-sm" title="Open shell">
                            <Terminal size={9} />
                          </button>
                        </td>
                      </tr>
                    )
                  })}
                  {bL.map(b => {
                    const ci = checkinAgo(b.last_checkin)
                    return (
                      <tr key={b.id}>
                        <td><span className="dot dot-pending" /></td>
                        <td>
                          <div className="flex items-center gap-1.5">
                            <span>{osIcon(b.os)}</span>
                            <span className="text-text font-semibold" style={{ fontSize: 11 }}>{b.name}</span>
                            <span className="badge badge-beacon" style={{ fontSize: 8 }}>BEACON</span>
                          </div>
                        </td>
                        <td className="text-muted" style={{ fontSize: 10 }}>{b.username}@{b.hostname}</td>
                        <td className="text-muted" style={{ fontSize: 10 }}>{b.os} / {b.arch}</td>
                        <td>
                          <span style={{ fontSize: 9, color: 'var(--muted)' }}>
                            ⏱ {fmtInterval(b.interval)}
                          </span>
                        </td>
                        <td className={`tabnum ${ci.cls}`} style={{ fontSize: 10 }}>{ci.label}</td>
                        <td />
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* ── Event feed ── */}
        <div className="w-72 shrink-0 panel flex flex-col min-h-0">
          <div className="section-hdr">
            <Activity size={11} className="text-primary" />
            Live Events
            {events.length > 0 && <span className="ml-auto text-muted" style={{ fontSize: 9 }}>{events.length}</span>}
          </div>

          {events.length === 0 ? (
            <div className="flex-1 flex flex-col items-center justify-center gap-2 p-6 text-center">
              <Activity size={22} style={{ color: 'var(--dim)' }} />
              <div className="text-muted" style={{ fontSize: 10 }}>Awaiting C2 activity…</div>
            </div>
          ) : (
            <div className="flex-1 overflow-y-auto">
              {events.map((ev, i) => (
                <div key={i} className="flex items-start gap-2.5 px-3 py-2 border-b border-border/30 hover:bg-white/2 transition-colors">
                  <span style={{ fontSize: 13, lineHeight: 1.3 }}>{ev.icon}</span>
                  <div className="min-w-0 flex-1">
                    <div className={`${ev.cls} truncate`} style={{ fontSize: 10 }}>{ev.msg}</div>
                    <div className="text-muted tabnum" style={{ fontSize: 9 }}>
                      {new Date(ev.ts).toLocaleTimeString()}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* ── Listeners panel ── */}
        <div className="w-52 shrink-0 panel flex flex-col min-h-0">
          <div className="section-hdr">
            <Antenna size={11} className="text-primary" />
            Listeners
          </div>
          {lstL.length === 0 ? (
            <div className="flex-1 flex flex-col items-center justify-center gap-2 p-4 text-center">
              <Antenna size={20} style={{ color: 'var(--dim)' }} />
              <div className="text-muted" style={{ fontSize: 10 }}>No active listeners</div>
            </div>
          ) : (
            <div className="flex-1 overflow-y-auto py-1">
              {lstL.map(l => (
                <div key={l.id} className="flex items-center gap-2 px-3 py-2 border-b border-border/20">
                  <span className="dot dot-live" />
                  <div className="min-w-0 flex-1">
                    <div className="text-text font-semibold truncate" style={{ fontSize: 10 }}>{l.name}</div>
                    <div className="text-muted" style={{ fontSize: 9 }}>
                      {l.protocol.toUpperCase()} :{l.port}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

      </div>
    </div>
  )
}
