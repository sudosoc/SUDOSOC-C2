/**
 * SUDOSOC-C2 — Operator Dashboard
 * Cobalt Strike / Mythic / Havoc inspired layout:
 *   Top bar   : live stats + WS status + quick actions
 *   Main area : agent roster (full table, primary view)
 *   Right rail: event feed + listeners
 */
import { useState, useCallback, useRef, useEffect } from 'react'
import { useAPI, apiPost, apiFetch } from '../hooks/useAPI'
import type { Stats, Session, Beacon, Listener } from '../types'
import { useEventStream } from '../hooks/useWebSocket'
import type { WSEvent } from '../types'
import {
  Crosshair, Monitor, Radio, Antenna, Activity, Shield,
  Terminal, Skull, RefreshCw, ChevronRight, Zap,
  Wifi, Clock, Users, Copy, CheckCheck, X,
  FolderOpen, Camera, MoreVertical,
} from 'lucide-react'

// ─── helpers ─────────────────────────────────────────────────────────────────

function osIcon(os?: string) {
  const o = (os ?? '').toLowerCase()
  if (o.includes('windows')) return '🪟'
  if (o.includes('android')) return '🤖'
  if (o.includes('darwin') || o.includes('mac')) return '🍎'
  return '🐧'
}

function osNav(os?: string): string {
  const o = (os ?? '').toLowerCase()
  if (o.includes('windows')) return 'windows'
  if (o.includes('android')) return 'android'
  if (o.includes('darwin') || o.includes('mac')) return 'macos'
  return 'linux'
}

function checkinColor(ts: number) {
  const s = Math.floor((Date.now() / 1000) - (ts > 1e10 ? ts / 1000 : ts))
  if (s < 60)  return 'text-primary'
  if (s < 300) return 'text-warn'
  return 'text-danger'
}

function checkinLabel(ts: number) {
  const s = Math.floor((Date.now() / 1000) - (ts > 1e10 ? ts / 1000 : ts))
  if (s < 60)  return `${s}s`
  if (s < 3600) return `${Math.floor(s/60)}m`
  return `${Math.floor(s/3600)}h`
}

function fmtInterval(ms: number) {
  if (!ms) return '—'
  const s = Math.floor(ms / 1000)
  return s < 60 ? `${s}s` : `${Math.floor(s/60)}m`
}

const EVT_MAP: Record<string, { icon: string; cls: string }> = {
  'session-connected':    { icon: '💀', cls: 'text-primary' },
  'session-disconnected': { icon: '🔴', cls: 'text-danger' },
  'beacon-registered':    { icon: '📡', cls: 'text-accent' },
  'operator-joined':      { icon: '👤', cls: 'text-muted' },
  'operator-left':        { icon: '👤', cls: 'text-muted' },
  'job-started':          { icon: '▶',  cls: 'text-muted' },
  'job-stopped':          { icon: '⏹',  cls: 'text-muted' },
}

// ─── Context menu ─────────────────────────────────────────────────────────────

interface CtxMenu {
  x: number; y: number
  id: string; name: string; kind: 'session' | 'beacon'; os: string
}

// ─── Component ────────────────────────────────────────────────────────────────

interface Props { onOpenTerminal: (id: string, name: string) => void }

export default function Dashboard({ onOpenTerminal }: Props) {
  const { data: stats,     refresh: rS }  = useAPI<Stats>('/api/stats', 6_000)
  const { data: sessions, refresh: rSes } = useAPI<Session[]>('/api/sessions', 5_000)
  const { data: beacons,  refresh: rBcn } = useAPI<Beacon[]>('/api/beacons',   6_000)
  const { data: listeners }               = useAPI<Listener[]>('/api/listeners', 10_000)

  const [events,  setEvents]  = useState<{ ts: number; icon: string; msg: string; cls: string }[]>([])
  const [ctx,     setCtx]     = useState<CtxMenu | null>(null)
  const [selId,   setSelId]   = useState<string | null>(null)
  const [filter,  setFilter]  = useState<'all'|'session'|'beacon'|'windows'|'linux'|'android'>('all')
  const [search,  setSearch]  = useState('')
  const [copied,  setCopied]  = useState<string | null>(null)
  const ctxRef = useRef<HTMLDivElement>(null)

  const onEvent = useCallback((e: WSEvent) => {
    if (e.type === 'heartbeat') return
    rS(); rSes(); rBcn()
    const p = e.payload as Record<string, string>
    const name = p.session_name ?? p.beacon_name ?? p.operator ?? ''
    const ev = EVT_MAP[e.type] ?? { icon: '·', cls: 'text-muted' }
    const label: Record<string, string> = {
      'session-connected': 'Session connected',
      'session-disconnected': 'Session lost',
      'beacon-registered': 'Beacon checked in',
      'operator-joined': 'Operator joined',
      'job-started': 'Listener started',
      'job-stopped': 'Listener stopped',
    }
    setEvents(p => [{ ts: Date.now(), icon: ev.icon, cls: ev.cls,
      msg: name ? `${label[e.type] ?? e.type} — ${name}` : (label[e.type] ?? e.type) },
      ...p].slice(0, 200))
  }, [rS, rSes, rBcn])

  useEventStream(onEvent)

  // Close context menu on outside click
  useEffect(() => {
    function handler(e: MouseEvent) {
      if (ctxRef.current && !ctxRef.current.contains(e.target as Node)) {
        setCtx(null)
      }
    }
    window.addEventListener('mousedown', handler)
    return () => window.removeEventListener('mousedown', handler)
  }, [])

  const s      = stats ?? { sessions: 0, beacons: 0, listeners: 0, operators: 0, uptime: '—' }
  const sesList = sessions ?? []
  const bcnList = beacons  ?? []
  const lstList = listeners ?? []
  const total   = s.sessions + s.beacons

  // ── Build unified agent list ────────────────────────────────────────────────
  type Agent = {
    id: string; name: string; hostname: string; username: string
    os: string; arch: string; transport: string; remote_address: string
    pid?: number; last_checkin: number; is_dead?: boolean
    kind: 'session' | 'beacon'; interval?: number; next_checkin?: number
  }

  const agents: Agent[] = [
    ...sesList.map(s => ({ ...s, kind: 'session' as const })),
    ...bcnList.map(b => ({ ...b, kind: 'beacon' as const, is_dead: false, pid: 0 })),
  ].filter(a => {
    if (filter === 'session' && a.kind !== 'session') return false
    if (filter === 'beacon'  && a.kind !== 'beacon')  return false
    if (filter === 'windows' && !a.os?.toLowerCase().includes('windows')) return false
    if (filter === 'linux'   && (a.os?.toLowerCase().includes('windows') ||
        a.os?.toLowerCase().includes('android') || a.os?.toLowerCase().includes('darwin'))) return false
    if (filter === 'android' && !a.os?.toLowerCase().includes('android')) return false
    if (search && !a.name?.toLowerCase().includes(search.toLowerCase()) &&
        !a.hostname?.toLowerCase().includes(search.toLowerCase()) &&
        !a.username?.toLowerCase().includes(search.toLowerCase())) return false
    return true
  })

  // ── Context menu actions ────────────────────────────────────────────────────
  function openCtx(e: React.MouseEvent, agent: Agent) {
    e.preventDefault()
    setCtx({ x: e.clientX, y: e.clientY, id: agent.id,
      name: agent.name || agent.hostname, kind: agent.kind, os: agent.os })
  }

  async function ctxKill() {
    if (!ctx) return
    if (!confirm(`Kill agent ${ctx.name}?`)) return
    try {
      await apiFetch(`/api/sessions/${ctx.id}/kill`, { method: 'DELETE' })
    } catch {}
    setCtx(null); rSes()
  }

  async function ctxScreenshot() {
    if (!ctx) return
    setCtx(null)
    try {
      const r = await apiFetch<{ data: string }>(`/api/sessions/${ctx.id}/screenshot`)
      if (r.data) {
        const w = window.open('', '_blank')
        w?.document.write(`<img src="data:image/png;base64,${r.data}" style="max-width:100%">`)
      }
    } catch (e) { alert('Screenshot failed: ' + e) }
  }

  function copy(text: string, key: string) {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(key); setTimeout(() => setCopied(null), 1500)
    })
  }

  return (
    <div className="flex flex-col h-full gap-0 overflow-hidden" style={{ background: 'var(--bg)' }}>

      {/* ══ TOP STATS BAR ═══════════════════════════════════════════════════ */}
      <div className="shrink-0 flex items-center gap-4 px-4 py-2 border-b border-border"
        style={{ background: '#090909' }}>
        <div className="flex items-center gap-1.5">
          <Shield size={14} className="text-primary" />
          <span className="font-bold tracking-widest text-primary" style={{ fontSize: 11, letterSpacing: '.15em' }}>
            SUDOSOC-C2
          </span>
        </div>

        <div className="w-px h-4 bg-border" />

        {/* Stat chips */}
        {[
          { icon: Crosshair, label: 'Agents',    val: total,      color: '#b91c1c', active: total > 0 },
          { icon: Monitor,   label: 'Sessions',  val: s.sessions, color: '#d0d0d0', active: s.sessions > 0 },
          { icon: Radio,     label: 'Beacons',   val: s.beacons,  color: '#888888', active: s.beacons > 0 },
          { icon: Antenna,   label: 'Listeners', val: s.listeners,color: '#6b6b6b', active: s.listeners > 0 },
          { icon: Users,     label: 'Operators', val: s.operators,color: '#d0d0d0', active: s.operators > 0 },
        ].map(c => {
          const Icon = c.icon
          return (
            <div key={c.label} className="flex items-center gap-1.5 px-2 py-1 rounded"
              style={{ background: c.active ? c.color + '15' : 'transparent',
                       border: '1px solid ' + (c.active ? c.color + '30' : 'transparent') }}>
              <Icon size={11} style={{ color: c.color }} />
              <span className="tabnum font-bold" style={{ fontSize: 12, color: c.color }}>
                {c.val}
              </span>
              <span className="text-muted" style={{ fontSize: 9 }}>{c.label}</span>
            </div>
          )
        })}

        <div className="flex-1" />

        <div className="flex items-center gap-1.5 text-muted" style={{ fontSize: 9 }}>
          <Clock size={10} />
          <span>{s.uptime}</span>
        </div>
        <button onClick={() => { rS(); rSes(); rBcn() }}
          className="text-muted hover:text-primary transition-colors">
          <RefreshCw size={11} />
        </button>
      </div>

      {/* ══ KILL CHAIN ══════════════════════════════════════════════════════ */}
      <div className="shrink-0 flex items-center gap-0 px-4 py-1.5 border-b border-border/50"
        style={{ background: 'rgba(255,255,255,.01)' }}>
        <Zap size={10} className="text-primary mr-2 shrink-0" />
        {[
          { l: 'Reconnaissance', done: lstList.length > 0 },
          { l: 'Weaponize',      done: lstList.length > 0 },
          { l: 'Deliver',        done: total > 0 },
          { l: 'Exploit',        done: total > 0 },
          { l: 'Install',        done: total > 0 },
          { l: 'C2',             done: s.sessions > 0 },
          { l: 'ACTIONS',        done: s.sessions > 0 },
        ].map((st, i) => (
          <div key={st.l} className="flex items-center">
            {i > 0 && (
              <div style={{ width: 20, height: 1, background: st.done ? '#b91c1c' : '#242424' }} />
            )}
            <div className="flex items-center gap-1">
              <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                st.done ? 'bg-primary' : 'bg-dim'
              } ${st.done && i >= 5 ? 'ring-1 ring-primary/40' : ''}`}
              style={{ animation: st.done && i >= 5 ? 'pulse 2s infinite' : 'none' }} />
              <span style={{
                fontSize: 8, fontWeight: 700, letterSpacing: '.06em',
                textTransform: 'uppercase',
                color: st.done ? (i >= 5 ? '#ef4444' : '#888') : '#333',
              }}>
                {st.l}
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* ══ MAIN CONTENT ════════════════════════════════════════════════════ */}
      <div className="flex-1 flex min-h-0">

        {/* ── Agent Roster (main, Cobalt Strike style) ── */}
        <div className="flex-1 flex flex-col min-h-0 min-w-0">

          {/* Toolbar */}
          <div className="shrink-0 flex items-center gap-2 px-3 py-2 border-b border-border"
            style={{ background: 'rgba(255,255,255,.012)' }}>
            <Crosshair size={11} className="text-primary" />
            <span className="text-muted font-bold uppercase tracking-widest" style={{ fontSize: 9 }}>
              Agent Roster
            </span>
            {total > 0 && <span className="badge badge-live">{total}</span>}

            <div className="flex-1" />

            {/* Filter chips */}
            {(['all','session','beacon','windows','linux','android'] as const).map(f => (
              <button key={f} onClick={() => setFilter(f)}
                className={`btn btn-sm ${filter === f ? 'btn-primary' : 'btn-ghost'}`}
                style={{ fontSize: 9, padding: '2px 7px' }}>
                {f === 'all' ? 'All' : f === 'session' ? 'Sessions' : f === 'beacon' ? 'Beacons' :
                 f === 'windows' ? '🪟' : f === 'linux' ? '🐧' : '🤖'}
              </button>
            ))}

            <div className="flex items-center gap-1.5 bg-bg/60 border border-border rounded px-2 py-0.5" style={{ fontSize: 10 }}>
              <input value={search} onChange={e => setSearch(e.target.value)}
                placeholder="filter…"
                className="bg-transparent text-text placeholder-muted/50 outline-none w-24"
                style={{ fontSize: 10 }} />
              {search && <button onClick={() => setSearch('')} className="text-muted hover:text-text"><X size={9} /></button>}
            </div>
          </div>

          {/* Agent table */}
          {agents.length === 0 ? (
            <div className="flex-1 flex flex-col items-center justify-center gap-4 p-8 text-center">
              <div className="w-20 h-20 rounded-2xl border border-border/30 flex items-center justify-center"
                style={{ background: 'rgba(185,28,28,.04)' }}>
                <Crosshair size={32} style={{ color: 'rgba(185,28,28,.3)' }} />
              </div>
              <div>
                <div className="font-bold text-accent" style={{ fontSize: 13 }}>No Active Agents</div>
                <div className="text-muted mt-1" style={{ fontSize: 11 }}>
                  Deploy an implant → agents will appear here in real-time
                </div>
              </div>
              <div className="flex gap-2">
                <button className="btn btn-primary" onClick={() => {}}>
                  <Zap size={10} /> Generate Implant
                </button>
              </div>
            </div>
          ) : (
            <div className="flex-1 overflow-y-auto">
              <table className="c2-table">
                <thead>
                  <tr>
                    <th style={{ width: 22 }} />
                    <th>Name</th>
                    <th>User @ Hostname</th>
                    <th>OS / Arch</th>
                    <th>PID</th>
                    <th>Transport</th>
                    <th>Address</th>
                    <th>Last Seen</th>
                    <th style={{ width: 80 }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {agents.map(a => {
                    const alive = !a.is_dead
                    const ci = checkinLabel(a.last_checkin)
                    const cc = checkinColor(a.last_checkin)
                    const sel = a.id === selId
                    return (
                      <tr key={a.id}
                        className={sel ? 'selected' : ''}
                        onClick={() => setSelId(a.id)}
                        onContextMenu={e => openCtx(e, a)}
                        style={{ cursor: 'pointer' }}>
                        <td>
                          <span className={`dot ${alive ? 'dot-live' : 'dot-dead'}`} />
                        </td>
                        <td>
                          <div className="flex items-center gap-1.5">
                            <span>{osIcon(a.os)}</span>
                            <span className="text-text font-semibold" style={{ fontSize: 11 }}>
                              {a.name || a.hostname}
                            </span>
                            <span className={`badge ${a.kind === 'session' ? 'badge-session' : 'badge-beacon'}`}
                              style={{ fontSize: 7.5 }}>
                              {a.kind === 'session' ? 'SESSION' : `BEACON ${a.interval ? fmtInterval(a.interval) : ''}`}
                            </span>
                          </div>
                        </td>
                        <td className="text-muted" style={{ fontSize: 10 }}>
                          <span className="text-accent">{a.username}</span>
                          <span className="text-muted/50 mx-1">@</span>
                          <span>{a.hostname}</span>
                        </td>
                        <td className="text-muted" style={{ fontSize: 10 }}>
                          {a.os} / {a.arch}
                        </td>
                        <td className="text-muted tabnum" style={{ fontSize: 10 }}>
                          {a.pid || '—'}
                        </td>
                        <td>
                          <span className="badge" style={{
                            fontSize: 8, background: 'rgba(255,255,255,.04)',
                            borderColor: 'var(--border)', color: 'var(--muted)'
                          }}>
                            {a.transport}
                          </span>
                        </td>
                        <td className="text-muted tabnum" style={{ fontSize: 10 }}>
                          {a.remote_address}
                        </td>
                        <td className={`tabnum ${cc}`} style={{ fontSize: 10 }}>
                          {ci}
                        </td>
                        <td>
                          <div className="flex items-center gap-1">
                            {a.kind === 'session' && (
                              <>
                                <button title="Shell"
                                  onClick={e => { e.stopPropagation(); onOpenTerminal(a.id, a.name || a.hostname) }}
                                  className="btn btn-ghost" style={{ padding: 4 }}>
                                  <Terminal size={10} />
                                </button>
                                <button title="Screenshot"
                                  onClick={async e => {
                                    e.stopPropagation()
                                    try {
                                      const r = await apiFetch<{ data: string }>(`/api/sessions/${a.id}/screenshot`)
                                      if (r.data) {
                                        const w = window.open('', '_blank')
                                        w?.document.write(`<body style="margin:0;background:#000"><img src="data:image/png;base64,${r.data}" style="max-width:100%"></body>`)
                                      }
                                    } catch {}
                                  }}
                                  className="btn btn-ghost" style={{ padding: 4 }}>
                                  <Camera size={10} />
                                </button>
                              </>
                            )}
                            <button title="More" onClick={e => openCtx(e, a)}
                              className="btn btn-ghost" style={{ padding: 4 }}>
                              <MoreVertical size={10} />
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

        {/* ── Right rail ── */}
        <div className="w-64 shrink-0 flex flex-col border-l border-border min-h-0"
          style={{ background: '#090909' }}>

          {/* Live events */}
          <div className="flex-1 flex flex-col min-h-0">
            <div className="section-hdr">
              <Activity size={10} className="text-primary" />
              Live Events
              {events.length > 0 && <span className="ml-auto text-muted" style={{ fontSize: 8 }}>{events.length}</span>}
            </div>
            <div className="flex-1 overflow-y-auto">
              {events.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-full gap-2 p-4 text-center">
                  <Wifi size={18} style={{ color: 'var(--dim)' }} />
                  <div className="text-muted" style={{ fontSize: 10 }}>Waiting for C2 activity…</div>
                </div>
              ) : events.map((ev, i) => (
                <div key={i} className="flex items-start gap-2 px-3 py-1.5 border-b border-border/20"
                  style={{ fontSize: 10 }}>
                  <span style={{ fontSize: 12, lineHeight: 1.3 }}>{ev.icon}</span>
                  <div className="flex-1 min-w-0">
                    <div className={`${ev.cls} truncate`}>{ev.msg}</div>
                    <div className="text-muted tabnum" style={{ fontSize: 8 }}>
                      {new Date(ev.ts).toLocaleTimeString()}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Listeners */}
          <div className="shrink-0 border-t border-border">
            <div className="section-hdr">
              <Antenna size={10} className="text-primary" />
              Listeners
              <span className={`ml-auto badge ${lstList.length > 0 ? 'badge-live' : ''}`}
                style={{ fontSize: 7.5 }}>
                {lstList.length}
              </span>
            </div>
            {lstList.length === 0 ? (
              <div className="px-3 py-2 text-muted" style={{ fontSize: 9 }}>No active listeners</div>
            ) : (
              lstList.map(l => (
                <div key={l.id} className="flex items-center gap-2 px-3 py-1.5 border-b border-border/20">
                  <span className="dot dot-live" />
                  <div className="flex-1 min-w-0">
                    <div className="text-text truncate" style={{ fontSize: 10 }}>{l.name}</div>
                    <div className="text-muted" style={{ fontSize: 8.5 }}>
                      {l.protocol.toUpperCase()} :{l.port}
                    </div>
                  </div>
                  <button onClick={() => copy(`${l.protocol}://${l.port}`, `lst-${l.id}`)}
                    className="text-muted hover:text-primary shrink-0">
                    {copied === `lst-${l.id}` ? <CheckCheck size={9} /> : <Copy size={9} />}
                  </button>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* ══ CONTEXT MENU ════════════════════════════════════════════════════ */}
      {ctx && (
        <div ref={ctxRef}
          className="fixed z-50 panel py-1 min-w-[160px]"
          style={{ left: ctx.x, top: ctx.y, boxShadow: '0 8px 32px rgba(0,0,0,.6)' }}>
          <div className="px-3 py-1.5 border-b border-border/50">
            <div className="font-semibold text-text" style={{ fontSize: 10 }}>{ctx.name}</div>
            <div className="text-muted" style={{ fontSize: 8.5 }}>
              {ctx.kind === 'session' ? 'Live Session' : 'Beacon'} · {osIcon(ctx.os)} {ctx.os}
            </div>
          </div>
          {ctx.kind === 'session' && ([
            { icon: Terminal, label: 'Interactive Shell', action: () => { onOpenTerminal(ctx.id, ctx.name); setCtx(null) } },
            { icon: Camera,   label: 'Screenshot',        action: ctxScreenshot },
            { icon: FolderOpen, label: 'File Browser',    action: () => { setCtx(null) } },
          ].map(item => (
            <button key={item.label}
              onClick={item.action}
              className="w-full flex items-center gap-2.5 px-3 py-2 hover:bg-primary/10 hover:text-primary transition-colors text-left"
              style={{ fontSize: 10, color: 'var(--accent)' }}>
              <item.icon size={11} />
              {item.label}
            </button>
          )))}
          <div className="border-t border-border/50 mt-0.5" />
          <button onClick={() => {
            copy(ctx.id, 'ctx-id')
            setCtx(null)
          }}
            className="w-full flex items-center gap-2.5 px-3 py-2 hover:bg-white/5 transition-colors text-left"
            style={{ fontSize: 10, color: 'var(--muted)' }}>
            <Copy size={11} /> Copy ID
          </button>
          <button onClick={ctxKill}
            className="w-full flex items-center gap-2.5 px-3 py-2 hover:bg-danger/10 hover:text-danger transition-colors text-left"
            style={{ fontSize: 10, color: 'var(--danger)' }}>
            <Skull size={11} /> Kill Agent
          </button>
        </div>
      )}
    </div>
  )
}
