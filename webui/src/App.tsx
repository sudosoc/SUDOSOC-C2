/**
 * SUDOSOC-C2 — Operator Console
 * Layout inspired by Havoc C2 / Mythic C2 / Cobalt Strike
 *
 * Structure:
 *   [Narrow Icon Sidebar 48px | Expanded 180px]
 *   [Top status bar 34px]
 *   [Content area — full remaining space]
 *   [Terminal slide-up panel]
 *   [Status bar 22px bottom]
 */

import { useState, useCallback, useRef, useEffect } from 'react'
import Dashboard  from './components/Dashboard'
import Agents     from './components/Agents'
import Sessions   from './components/Sessions'
import Beacons    from './components/Beacons'
import Listeners  from './components/Listeners'
import Loot       from './components/Loot'
import Android    from './components/Android'
import Windows    from './components/Windows'
import Linux      from './components/Linux'
import MacOS      from './components/MacOS'
import Generate   from './components/Generate'
import AI         from './components/AI'
import Settings   from './components/Settings'
import NetworkMap from './components/NetworkMap'
import Reports    from './components/Reports'
import Terminal   from './components/Terminal'
import { useEventStream }  from './hooks/useWebSocket'
import { useAPI }          from './hooks/useAPI'
import type { WSEvent, Stats } from './types'
import {
  LayoutDashboard, Monitor, Radio, Antenna, Package,
  Smartphone, Cpu, Bot, Settings2, Map as MapIcon, FileText,
  Terminal as TermIcon, Wifi, WifiOff, Loader, Shield,
  ChevronLeft, ChevronRight, Activity, Crosshair, X,
  Bell, BellOff, Zap, Clock, Users, LogOut,
} from 'lucide-react'

// ═══════════════════════════════════════════════════════════════
// NAV CONFIG
// ═══════════════════════════════════════════════════════════════

type TabID =
  | 'dashboard' | 'agents'   | 'sessions'  | 'beacons'
  | 'windows'   | 'linux'    | 'macos'     | 'android'
  | 'listeners' | 'loot'     | 'netmap'    | 'generate'
  | 'reports'   | 'ai'       | 'settings'

interface NavItem { id: TabID; label: string; icon: React.ElementType; color: string }
interface NavGroup { label: string; items: NavItem[] }

const NAV_GROUPS: NavGroup[] = [
  {
    label: 'Operations',
    items: [
      { id: 'dashboard', label: 'Dashboard',   icon: LayoutDashboard, color: '#d0d0d0' },
      { id: 'agents',    label: 'All Agents',  icon: Crosshair,       color: '#b91c1c' },
    ],
  },
  {
    label: 'Targets',
    items: [
      { id: 'windows',   label: 'Windows',     icon: Monitor,         color: '#b91c1c' },
      { id: 'linux',     label: 'Linux',       icon: Shield,          color: '#d0d0d0' },
      { id: 'macos',     label: 'macOS',       icon: Cpu,             color: '#d0d0d0' },
      { id: 'android',   label: 'Android',     icon: Smartphone,      color: '#d0d0d0' },
    ],
  },
  {
    label: 'C2 Infrastructure',
    items: [
      { id: 'sessions',  label: 'Sessions',    icon: Monitor,         color: '#d0d0d0' },
      { id: 'beacons',   label: 'Beacons',     icon: Radio,           color: '#d0d0d0' },
      { id: 'listeners', label: 'Listeners',   icon: Antenna,         color: '#d0d0d0' },
    ],
  },
  {
    label: 'Toolkit',
    items: [
      { id: 'generate',  label: 'Generate',    icon: Zap,             color: '#b91c1c' },
      { id: 'loot',      label: 'Loot',        icon: Package,         color: '#d0d0d0' },
      { id: 'netmap',    label: 'Net Map',     icon: MapIcon,         color: '#d0d0d0' },
      { id: 'reports',   label: 'Reports',     icon: FileText,        color: '#6b6b6b' },
      { id: 'ai',        label: 'AI Copilot',  icon: Bot,             color: '#b91c1c' },
    ],
  },
]

const NAV_BOTTOM: NavItem[] = [
  { id: 'settings', label: 'Settings', icon: Settings2, color: '#6b6b6b' },
]

const NAV_FLAT: NavItem[] = [...NAV_GROUPS.flatMap(g => g.items), ...NAV_BOTTOM]

// ═══════════════════════════════════════════════════════════════
// EVENT PARSING
// ═══════════════════════════════════════════════════════════════

let _eid = 0
interface Ev { id: number; ts: number; type: string; msg: string; icon: string; urgent: boolean }

function parseEv(e: WSEvent): Ev {
  const p = e.payload as Record<string, string>
  const name = p.session_name ?? p.beacon_name ?? p.operator ?? ''
  const map: Record<string, [string, boolean]> = {
    'session-connected':    ['💀', true ],
    'session-disconnected': ['🔴', true ],
    'beacon-registered':    ['📡', true ],
    'operator-joined':      ['👤', false],
    'operator-left':        ['👤', false],
    'job-started':          ['▶',  false],
    'job-stopped':          ['⏹',  false],
  }
  const [icon, urgent] = map[e.type] ?? ['·', false]
  return { id: ++_eid, ts: e.time ? e.time * 1000 : Date.now(), type: e.type,
    msg: name ? `${e.type} — ${name}` : e.type, icon, urgent }
}

function ago(ts: number) {
  const s = Math.floor((Date.now() - ts) / 1000)
  if (s < 60)   return `${s}s`
  if (s < 3600) return `${Math.floor(s/60)}m`
  return `${Math.floor(s/3600)}h`
}

// ═══════════════════════════════════════════════════════════════
// APP
// ═══════════════════════════════════════════════════════════════

interface ActiveTerminal { sessionID: string; sessionName: string }

export default function App() {
  const [tab,       setTab]       = useState<TabID>('dashboard')
  const [terminal,  setTerminal]  = useState<ActiveTerminal | null>(null)
  const [sideOpen,  setSideOpen]  = useState(true)
  const [evOpen,    setEvOpen]    = useState(false)
  const [events,    setEvents]    = useState<Ev[]>([])
  const [unread,    setUnread]    = useState(0)
  const [agentCnt,  setAgentCnt]  = useState({ s: 0, b: 0 })
  const evRef = useRef<HTMLDivElement>(null)

  const { data: stats } = useAPI<Stats>('/api/stats', 8_000)

  const onWs = useCallback((e: WSEvent) => {
    if (e.type === 'heartbeat') return
    const ev = parseEv(e)
    setEvents(p => [ev, ...p].slice(0, 200))
    if (!evOpen) setUnread(c => c + 1)
    if (e.type === 'session-connected')    setAgentCnt(c => ({ ...c, s: c.s + 1 }))
    if (e.type === 'session-disconnected') setAgentCnt(c => ({ ...c, s: Math.max(0, c.s - 1) }))
    if (e.type === 'beacon-registered')    setAgentCnt(c => ({ ...c, b: c.b + 1 }))
  }, [evOpen])

  const wsStatus = useEventStream(onWs)

  useEffect(() => {
    if (evOpen && evRef.current) evRef.current.scrollTop = 0
  }, [events.length, evOpen])

  function openTerm(sessionID: string, sessionName = '') {
    setTerminal({ sessionID, sessionName: sessionName || sessionID.slice(0, 8) })
  }

  const totalAgents = agentCnt.s + agentCnt.b
  const activeItem = NAV_FLAT.find(n => n.id === tab)
  const sideW = sideOpen ? 180 : 48

  return (
    <div className="flex h-screen overflow-hidden" style={{ background: '#0a0a0a', color: '#f0f0f0', fontFamily: 'JetBrains Mono, Fira Code, monospace' }}>

      {/* ══════════════════════════════════════════════════════
          SIDEBAR
          ══════════════════════════════════════════════════════ */}
      <nav
        style={{
          width: sideW,
          background: '#080808',
          borderRight: '1px solid #1e1e1e',
          display: 'flex',
          flexDirection: 'column',
          flexShrink: 0,
          transition: 'width 0.15s ease',
          overflow: 'hidden',
        }}>

        {/* Logo */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          padding: sideOpen ? '14px 12px 12px' : '14px 0 12px',
          justifyContent: sideOpen ? 'flex-start' : 'center',
          borderBottom: '1px solid #1a1a1a',
          flexShrink: 0,
        }}>
          <div style={{
            width: 26, height: 26, borderRadius: 5, flexShrink: 0,
            background: 'rgba(185,28,28,.18)',
            border: '1px solid rgba(185,28,28,.4)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <Shield size={13} style={{ color: '#b91c1c' }} />
          </div>
          {sideOpen && (
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 10, fontWeight: 800, letterSpacing: '.16em', color: '#b91c1c', textTransform: 'uppercase' }}>
                SUDOSOC
              </div>
              <div style={{ fontSize: 8, color: '#444', letterSpacing: '.06em' }}>C2 FRAMEWORK</div>
            </div>
          )}
          {sideOpen && (
            <button onClick={() => setSideOpen(false)}
              style={{ color: '#333', background: 'none', border: 'none', cursor: 'pointer', flexShrink: 0, padding: 2 }}>
              <ChevronLeft size={12} />
            </button>
          )}
        </div>

        {/* Nav groups */}
        <div style={{ flex: 1, overflowY: 'auto', overflowX: 'hidden', padding: '6px 4px' }}>
          {NAV_GROUPS.map((group, gi) => (
            <div key={group.label} style={{ marginBottom: 4 }}>
              {/* Group label */}
              {sideOpen ? (
                <div style={{
                  fontSize: 7.5, fontWeight: 700, letterSpacing: '.14em',
                  textTransform: 'uppercase', color: '#2a2a2a',
                  padding: '6px 6px 3px', userSelect: 'none',
                }}>
                  {group.label}
                </div>
              ) : (
                gi > 0 && <div style={{ height: 1, background: '#1a1a1a', margin: '6px 4px' }} />
              )}

              {/* Nav items */}
              {group.items.map(item => {
                const Icon   = item.icon
                const active = tab === item.id
                const isAgents = item.id === 'agents'
                return (
                  <button key={item.id}
                    onClick={() => { setTab(item.id); if (!sideOpen) setSideOpen(true) }}
                    title={sideOpen ? undefined : item.label}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 9,
                      width: '100%',
                      padding: sideOpen ? '5px 8px' : '7px 0',
                      justifyContent: sideOpen ? 'flex-start' : 'center',
                      borderRadius: 4,
                      border: active ? `1px solid ${item.color}22` : '1px solid transparent',
                      background: active ? `${item.color}12` : 'transparent',
                      borderLeft: active ? `2px solid ${item.color}` : '2px solid transparent',
                      color: active ? item.color : '#3a3a3a',
                      cursor: 'pointer',
                      fontSize: 11,
                      fontFamily: 'inherit',
                      fontWeight: active ? 700 : 400,
                      transition: 'all .1s',
                      marginBottom: 1,
                      textAlign: 'left',
                    }}
                    onMouseEnter={e => {
                      if (!active) (e.currentTarget as HTMLButtonElement).style.color = '#888'
                    }}
                    onMouseLeave={e => {
                      if (!active) (e.currentTarget as HTMLButtonElement).style.color = '#3a3a3a'
                    }}>
                    <Icon size={13} style={{ flexShrink: 0, color: active ? item.color : 'currentColor' }} />
                    {sideOpen && (
                      <>
                        <span style={{ flex: 1, textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>
                          {item.label}
                        </span>
                        {isAgents && totalAgents > 0 && (
                          <span style={{
                            fontSize: 8, fontWeight: 800, padding: '1px 5px',
                            borderRadius: 3, background: 'rgba(185,28,28,.2)',
                            color: '#ef4444', border: '1px solid rgba(185,28,28,.35)',
                          }}>
                            {totalAgents}
                          </span>
                        )}
                      </>
                    )}
                  </button>
                )
              })}
            </div>
          ))}
        </div>

        {/* Collapse toggle when closed */}
        {!sideOpen && (
          <div style={{ padding: '4px 0 8px', display: 'flex', justifyContent: 'center' }}>
            <button onClick={() => setSideOpen(true)}
              style={{ color: '#333', background: 'none', border: 'none', cursor: 'pointer', padding: 4 }}>
              <ChevronRight size={12} />
            </button>
          </div>
        )}

        {/* Bottom: settings */}
        <div style={{ borderTop: '1px solid #1a1a1a', padding: '6px 4px' }}>
          {NAV_BOTTOM.map(item => {
            const Icon = item.icon
            const active = tab === item.id
            return (
              <button key={item.id}
                onClick={() => setTab(item.id)}
                title={sideOpen ? undefined : item.label}
                style={{
                  display: 'flex', alignItems: 'center', gap: 9, width: '100%',
                  padding: sideOpen ? '5px 8px' : '7px 0',
                  justifyContent: sideOpen ? 'flex-start' : 'center',
                  borderRadius: 4, border: '1px solid transparent',
                  background: active ? 'rgba(255,255,255,.04)' : 'transparent',
                  color: active ? '#d0d0d0' : '#333',
                  cursor: 'pointer', fontSize: 11, fontFamily: 'inherit',
                }}>
                <Icon size={13} style={{ flexShrink: 0 }} />
                {sideOpen && <span style={{ overflow: 'hidden', whiteSpace: 'nowrap' }}>{item.label}</span>}
              </button>
            )
          })}
        </div>
      </nav>

      {/* ══════════════════════════════════════════════════════
          MAIN AREA
          ══════════════════════════════════════════════════════ */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0, overflow: 'hidden' }}>

        {/* ── Top status bar ── */}
        <header style={{
          height: 34,
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '0 14px',
          borderBottom: '1px solid #1a1a1a',
          background: '#080808',
          flexShrink: 0,
        }}>
          {/* Left: breadcrumb */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {activeItem && (
              <>
                <activeItem.icon size={12} style={{ color: activeItem.color }} />
                <span style={{ fontSize: 11, fontWeight: 700, color: activeItem.color === '#b91c1c' ? '#ef4444' : '#d0d0d0',
                  letterSpacing: '.04em' }}>
                  {activeItem.label}
                </span>
              </>
            )}
          </div>

          {/* Right: controls */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>

            {/* Stat chips */}
            {stats && [
              { v: stats.sessions, l: 'sess', c: '#d0d0d0' },
              { v: stats.beacons,  l: 'bcns', c: '#888' },
              { v: stats.listeners,l: 'lstn', c: '#555' },
            ].map(({ v, l, c }) => v > 0 && (
              <span key={l} style={{
                fontSize: 9, padding: '2px 6px', borderRadius: 3,
                background: 'rgba(255,255,255,.04)', border: '1px solid #1e1e1e',
                color: c, fontVariantNumeric: 'tabular-nums',
              }}>
                {v} {l}
              </span>
            ))}

            {/* Events toggle */}
            <button
              onClick={() => { setEvOpen(v => !v); setUnread(0) }}
              style={{
                display: 'flex', alignItems: 'center', gap: 5,
                padding: '3px 8px', borderRadius: 3, fontSize: 9, cursor: 'pointer',
                background: evOpen ? 'rgba(185,28,28,.12)' : 'rgba(255,255,255,.03)',
                border: `1px solid ${evOpen ? 'rgba(185,28,28,.3)' : '#222'}`,
                color: evOpen ? '#ef4444' : '#555',
                fontFamily: 'inherit', position: 'relative',
              }}>
              {evOpen ? <BellOff size={10} /> : <Bell size={10} />}
              <span>Events</span>
              {unread > 0 && !evOpen && (
                <span style={{
                  position: 'absolute', top: -4, right: -4,
                  width: 14, height: 14, borderRadius: '50%',
                  background: '#b91c1c', fontSize: 8, fontWeight: 800,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  color: '#fff',
                }}>
                  {unread > 9 ? '9+' : unread}
                </span>
              )}
            </button>

            {/* Terminal indicator */}
            {terminal && (
              <span style={{
                display: 'flex', alignItems: 'center', gap: 5,
                padding: '3px 8px', borderRadius: 3, fontSize: 9,
                background: 'rgba(185,28,28,.1)', border: '1px solid rgba(185,28,28,.3)',
                color: '#ef4444',
              }}>
                <TermIcon size={9} />
                {terminal.sessionName}
              </span>
            )}

            {/* WS status */}
            <div style={{
              display: 'flex', alignItems: 'center', gap: 5,
              padding: '3px 8px', borderRadius: 3, fontSize: 9,
              border: '1px solid #1e1e1e',
              color: wsStatus === 'connected' ? '#b91c1c' : wsStatus === 'disconnected' ? '#555' : '#b45309',
            }}>
              {wsStatus === 'connected'    && <><span style={{ width: 5, height: 5, borderRadius: '50%', background: '#b91c1c', flexShrink: 0, animation: 'pulse 2s infinite' }} /><span>ONLINE</span></>}
              {wsStatus === 'disconnected' && <><WifiOff size={9} /><span>OFFLINE</span></>}
              {wsStatus === 'connecting'   && <><Loader size={9} style={{ animation: 'spin 1s linear infinite' }} /><span>...</span></>}
            </div>
          </div>
        </header>

        {/* ── Content + optional panels ── */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0, overflow: 'hidden' }}>

          {/* Main content */}
          <div style={{ flex: 1, minHeight: 0, overflow: 'auto', padding: '12px 14px' }}>
            {tab === 'dashboard' && <Dashboard  onOpenTerminal={openTerm} />}
            {tab === 'agents'    && <Agents     onOpenTerminal={openTerm} />}
            {tab === 'sessions'  && <Sessions   onOpenTerminal={openTerm} />}
            {tab === 'beacons'   && <Beacons    />}
            {tab === 'windows'   && <Windows    onOpenTerminal={openTerm} />}
            {tab === 'linux'     && <Linux      onOpenTerminal={openTerm} />}
            {tab === 'macos'     && <MacOS      onOpenTerminal={openTerm} />}
            {tab === 'android'   && <Android    onOpenTerminal={openTerm} />}
            {tab === 'listeners' && <Listeners  />}
            {tab === 'loot'      && <Loot       />}
            {tab === 'netmap'    && <NetworkMap  onOpenTerminal={openTerm} />}
            {tab === 'generate'  && <Generate   />}
            {tab === 'reports'   && <Reports    />}
            {tab === 'ai'        && <AI         />}
            {tab === 'settings'  && <Settings   />}
          </div>

          {/* Terminal panel (slide up) */}
          {terminal && (
            <div style={{
              flexShrink: 0,
              height: '38vh',
              borderTop: '1px solid rgba(185,28,28,.3)',
              background: '#040404',
            }}>
              <Terminal
                sessionID={terminal.sessionID}
                sessionName={terminal.sessionName}
                onClose={() => setTerminal(null)}
              />
            </div>
          )}

          {/* Event log panel (slide up) */}
          {evOpen && (
            <div ref={evRef} style={{
              flexShrink: 0,
              height: terminal ? '22vh' : '28vh',
              borderTop: '1px solid #1e1e1e',
              background: '#060606',
              display: 'flex', flexDirection: 'column',
              overflow: 'hidden',
            }}>
              {/* Header */}
              <div style={{
                display: 'flex', alignItems: 'center', gap: 8,
                padding: '6px 14px', borderBottom: '1px solid #1a1a1a',
                flexShrink: 0,
              }}>
                <Activity size={11} style={{ color: '#b91c1c' }} />
                <span style={{ fontSize: 9, fontWeight: 700, letterSpacing: '.1em', textTransform: 'uppercase', color: '#555' }}>
                  Event Log
                </span>
                <span style={{ fontSize: 8, color: '#333' }}>({events.length})</span>
                <div style={{ flex: 1 }} />
                <button onClick={() => setEvents([])} style={{
                  fontSize: 8.5, color: '#333', background: 'none', border: 'none', cursor: 'pointer',
                }}>
                  Clear
                </button>
                <button onClick={() => setEvOpen(false)} style={{
                  color: '#333', background: 'none', border: 'none', cursor: 'pointer', padding: 2,
                }}>
                  <X size={11} />
                </button>
              </div>
              {/* Events */}
              <div style={{ flex: 1, overflowY: 'auto', padding: '2px 0' }}>
                {events.length === 0 ? (
                  <div style={{ padding: '12px 14px', fontSize: 9.5, color: '#2a2a2a' }}>
                    No events yet — waiting for C2 activity…
                  </div>
                ) : events.map(ev => (
                  <div key={ev.id} style={{
                    display: 'flex', alignItems: 'center', gap: 10,
                    padding: '4px 14px',
                    borderBottom: '1px solid rgba(255,255,255,.02)',
                    background: ev.urgent ? 'rgba(185,28,28,.04)' : 'transparent',
                  }}>
                    <span style={{ fontSize: 12, lineHeight: 1, flexShrink: 0 }}>{ev.icon}</span>
                    <span style={{ fontSize: 9, color: '#333', flexShrink: 0, fontVariantNumeric: 'tabular-nums' }}>
                      {new Date(ev.ts).toLocaleTimeString()}
                    </span>
                    <span style={{
                      fontSize: 7.5, padding: '1px 5px', borderRadius: 3,
                      background: ev.urgent ? 'rgba(185,28,28,.15)' : 'rgba(255,255,255,.04)',
                      color: ev.urgent ? '#ef4444' : '#333',
                      border: `1px solid ${ev.urgent ? 'rgba(185,28,28,.25)' : '#1a1a1a'}`,
                      flexShrink: 0, fontWeight: 700, letterSpacing: '.05em',
                    }}>
                      {ev.type}
                    </span>
                    <span style={{ fontSize: 9.5, color: '#555', flex: 1, overflow: 'hidden', whiteSpace: 'nowrap', textOverflow: 'ellipsis' }}>
                      {ev.msg}
                    </span>
                    <span style={{ fontSize: 8.5, color: '#2a2a2a', flexShrink: 0 }}>{ago(ev.ts)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* ── Status bar (bottom, Cobalt Strike style) ── */}
        <div style={{
          height: 22,
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '0 14px',
          borderTop: '1px solid #161616',
          background: '#060606',
          flexShrink: 0,
          fontSize: 8.5,
          color: '#2e2e2e',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <span style={{ color: '#1e1e1e' }}>SUDOSOC-C2 v2.0</span>
            {stats?.uptime && (
              <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#2a2a2a' }}>
                <Clock size={8} /> {stats.uptime}
              </span>
            )}
            {stats && stats.operators > 0 && (
              <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#2a2a2a' }}>
                <Users size={8} /> {stats.operators} operator{stats.operators > 1 ? 's' : ''}
              </span>
            )}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <span style={{
              color: wsStatus === 'connected' ? '#3a1a1a' : '#1e1e1e',
              display: 'flex', alignItems: 'center', gap: 4,
            }}>
              {wsStatus === 'connected' && (
                <>
                  <span style={{ width: 5, height: 5, borderRadius: '50%', background: '#b91c1c', animation: 'pulse 2s infinite' }} />
                  C2 ONLINE
                </>
              )}
              {wsStatus === 'disconnected' && '● OFFLINE'}
              {wsStatus === 'connecting'   && '○ CONNECTING…'}
            </span>
            <span style={{ color: '#1a1a1a' }}>
              For authorized security testing only
            </span>
          </div>
        </div>

      </div>
    </div>
  )
}
