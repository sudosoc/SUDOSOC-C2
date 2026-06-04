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
import { useEventStream } from './hooks/useWebSocket'
import type { WSEvent } from './types'
import {
  LayoutDashboard, Monitor, Radio, Antenna, Package,
  Smartphone, Cpu, Bot, Settings2, Map as MapIcon, FileText,
  Terminal as TermIcon, Wifi, WifiOff, Loader, Shield,
  Users, ChevronLeft, Bell, BellOff, Activity,
  Crosshair, X, Clock, AlertCircle,
} from 'lucide-react'

// ─── Event log entry ──────────────────────────────────────────────────────────
interface EventEntry {
  id:      number
  ts:      number
  type:    string
  msg:     string
  icon:    string
  urgent:  boolean
}

// ─── Tab config ───────────────────────────────────────────────────────────────
type TabID =
  | 'dashboard' | 'agents'   | 'sessions'  | 'beacons'
  | 'windows'   | 'linux'    | 'macos'     | 'android'
  | 'listeners' | 'loot'     | 'netmap'    | 'generate'
  | 'reports'   | 'ai'       | 'settings'

interface NavItem {
  id:    TabID
  label: string
  icon:  React.ElementType
  color: string
  badge?: string
}

// ─── Nav groups — gives the sidebar visual structure ─────────────────────────
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
    label: 'C2',
    items: [
      { id: 'sessions',  label: 'Sessions',    icon: Monitor,         color: '#d0d0d0' },
      { id: 'beacons',   label: 'Beacons',     icon: Radio,           color: '#d0d0d0' },
      { id: 'listeners', label: 'Listeners',   icon: Antenna,         color: '#d0d0d0' },
    ],
  },
  {
    label: 'Toolkit',
    items: [
      { id: 'generate',  label: 'Generate',    icon: Cpu,             color: '#d0d0d0' },
      { id: 'loot',      label: 'Loot',        icon: Package,         color: '#d0d0d0' },
      { id: 'netmap',    label: 'Network Map', icon: MapIcon,         color: '#d0d0d0' },
      { id: 'reports',   label: 'Reports',     icon: FileText,        color: '#6b6b6b' },
      { id: 'ai',        label: 'AI Agent',    icon: Bot,             color: '#b91c1c' },
    ],
  },
]

// Flat NAV for existing lookup code
const NAV: NavItem[] = NAV_GROUPS.flatMap(g => g.items)

const NAV_BOTTOM: NavItem[] = [
  { id: 'settings',  label: 'Settings',     icon: Settings2,       color: '#6b6b6b' },
]

// ─── Helpers ─────────────────────────────────────────────────────────────────
let _evId = 0
function parseEvent(e: WSEvent): EventEntry {
  const payload = e.payload as Record<string, string>
  const name    = payload.session_name ?? payload.beacon_name ?? payload.operator ?? ''
  const typeMap: Record<string, [string, boolean]> = {
    'session-connected':    ['💀', true  ],
    'session-disconnected': ['🔴', true  ],
    'beacon-registered':    ['📡', true  ],
    'operator-joined':      ['👤', false ],
    'operator-left':        ['👤', false ],
    'job-started':          ['▶️', false ],
    'job-stopped':          ['⏹️', false ],
  }
  const [icon, urgent] = typeMap[e.type] ?? ['•', false]
  const ts = e.time ? e.time * 1000 : Date.now()
  return {
    id:     ++_evId,
    ts,
    type:   e.type,
    msg:    name ? `${e.type}  ${name}` : e.type,
    icon,
    urgent,
  }
}

function tsAgo(ts: number) {
  const s = Math.floor((Date.now() - ts) / 1000)
  if (s < 60)   return `${s}s ago`
  if (s < 3600) return `${Math.floor(s/60)}m ago`
  return `${Math.floor(s/3600)}h ago`
}

// ─── App ─────────────────────────────────────────────────────────────────────

interface ActiveTerminal { sessionID: string; sessionName: string }

export default function App() {
  const [activeTab,    setActiveTab]   = useState<TabID>('dashboard')
  const [terminal,     setTerminal]    = useState<ActiveTerminal | null>(null)
  const [sidebarOpen,  setSidebarOpen] = useState(true)
  const [showEvents,   setShowEvents]  = useState(false)
  const [events,       setEvents]      = useState<EventEntry[]>([])
  const [unreadCount,  setUnreadCount] = useState(0)
  const [agentCount,   setAgentCount]  = useState({ sessions: 0, beacons: 0 })
  const evLogRef = useRef<HTMLDivElement>(null)

  // ── WebSocket event handler ─────────────────────────────────────────────
  const onWsEvent = useCallback((e: WSEvent) => {
    if (e.type === 'heartbeat') return
    const entry = parseEvent(e)
    setEvents(prev => [entry, ...prev].slice(0, 200))
    if (!showEvents) setUnreadCount(c => c + 1)

    // Update agent badge counts on connect/disconnect
    if (e.type === 'session-connected')    setAgentCount(c => ({ ...c, sessions: c.sessions + 1 }))
    if (e.type === 'session-disconnected') setAgentCount(c => ({ ...c, sessions: Math.max(0, c.sessions - 1) }))
    if (e.type === 'beacon-registered')    setAgentCount(c => ({ ...c, beacons: c.beacons + 1 }))
  }, [showEvents])

  const wsStatus = useEventStream(onWsEvent)

  // Auto-scroll event log to top when new events arrive
  useEffect(() => {
    if (showEvents && evLogRef.current) {
      evLogRef.current.scrollTop = 0
    }
  }, [events.length, showEvents])

  function openTerminal(sessionID: string, sessionName = '') {
    setTerminal({ sessionID, sessionName: sessionName || sessionID.slice(0, 8) })
  }

  function openEventsPanel() {
    setShowEvents(v => !v)
    setUnreadCount(0)
  }

  const totalAgents = agentCount.sessions + agentCount.beacons

  const activeItem = [...NAV, ...NAV_BOTTOM].find(n => n.id === activeTab)

  const sidebarW = sidebarOpen ? 200 : 56

  return (
    <div className="flex h-screen bg-bg text-text font-mono overflow-hidden">

      {/* ── Sidebar ──────────────────────────────────────────────────────── */}
      <aside
        className="flex flex-col bg-[#080812] border-r border-border shrink-0 transition-all duration-150 overflow-hidden"
        style={{ width: sidebarW }}>

        {/* Logo + collapse toggle */}
        <div className={`flex items-center py-4 border-b border-border/50 shrink-0 ${sidebarOpen ? 'px-4 gap-3' : 'justify-center'}`}>
          <div className="w-8 h-8 rounded-md bg-primary/10 border border-primary/30 flex items-center justify-center shrink-0">
            <Shield size={16} className="text-primary" />
          </div>
          {sidebarOpen && (
            <div className="flex-1 min-w-0">
              <div className="text-primary font-bold text-xs tracking-wider truncate">SUDOSOC-C2</div>
              <div className="text-muted text-[9px]">v2.0.0</div>
            </div>
          )}
          {sidebarOpen && (
            <button onClick={() => setSidebarOpen(false)} className="text-muted hover:text-text shrink-0">
              <ChevronLeft size={14} />
            </button>
          )}
        </div>

        {/* Nav items — grouped */}
        <div className="flex-1 overflow-y-auto py-1 flex flex-col px-1.5">
          {NAV_GROUPS.map(group => (
            <div key={group.label} className="mb-1">
              {/* Section label (only when sidebar open) */}
              {sidebarOpen && (
                <div className="px-2 py-1.5 text-[8px] font-bold tracking-[0.15em] text-muted/50 uppercase select-none">
                  {group.label}
                </div>
              )}
              {/* Divider when collapsed */}
              {!sidebarOpen && (
                <div className="my-1 mx-2 border-t border-border/30" />
              )}
              <div className="flex flex-col gap-0.5">
                {group.items.map(item => {
                  const Icon     = item.icon
                  const active   = activeTab === item.id
                  const isAgents = item.id === 'agents'
                  return (
                    <button key={item.id}
                      onClick={() => { setActiveTab(item.id); if (!sidebarOpen) setSidebarOpen(true) }}
                      title={sidebarOpen ? undefined : item.label}
                      className={`flex items-center gap-2.5 px-2 py-1.5 rounded-md text-xs transition-all group ${
                        active
                          ? 'font-semibold'
                          : 'text-muted hover:text-text hover:bg-white/5'
                      } ${sidebarOpen ? '' : 'justify-center'}`}
                      style={active ? { background: item.color + '18', color: item.color } : {}}>
                      <Icon size={14} className="shrink-0" style={active ? { color: item.color } : {}} />
                      {sidebarOpen && <span className="truncate">{item.label}</span>}
                      {isAgents && totalAgents > 0 && sidebarOpen && (
                        <span className="ml-auto shrink-0 rounded-full text-[9px] font-bold px-1.5 py-0.5"
                          style={{ background: '#b91c1c33', color: '#ef4444' }}>
                          {totalAgents}
                        </span>
                      )}
                    </button>
                  )
                })}
              </div>
            </div>
          ))}
        </div>

        {/* Collapse toggle (when closed) */}
        {!sidebarOpen && (
          <div className="px-1.5 pb-1">
            <button onClick={() => setSidebarOpen(true)}
              className="w-full flex justify-center py-2 text-muted hover:text-primary transition-colors">
              <ChevronLeft size={14} className="rotate-180" />
            </button>
          </div>
        )}

        {/* Bottom nav */}
        <div className="border-t border-border/50 py-2 flex flex-col gap-0.5 px-1.5">
          {NAV_BOTTOM.map(item => {
            const Icon   = item.icon
            const active = activeTab === item.id
            return (
              <button key={item.id}
                onClick={() => setActiveTab(item.id)}
                title={sidebarOpen ? undefined : item.label}
                className={`flex items-center gap-2.5 px-2 py-2 rounded-md text-xs transition-all ${
                  active ? 'font-semibold' : 'text-muted hover:text-text hover:bg-white/5'
                } ${sidebarOpen ? '' : 'justify-center'}`}
                style={active ? { background: item.color + '18', color: item.color } : {}}>
                <Icon size={15} className="shrink-0" />
                {sidebarOpen && <span className="truncate">{item.label}</span>}
              </button>
            )
          })}
        </div>
      </aside>

      {/* ── Main area ────────────────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col min-w-0">

        {/* ── Top header bar ──────────────────────────────────────────── */}
        <header className="flex items-center justify-between px-4 py-2 border-b border-border bg-surface shrink-0 h-11">
          <div className="flex items-center gap-2">
            {activeItem && (
              <>
                <activeItem.icon size={14} style={{ color: activeItem.color }} />
                <span className="text-text text-sm font-semibold">{activeItem.label}</span>
              </>
            )}
          </div>

          <div className="flex items-center gap-2">
            {/* Event log toggle */}
            <button onClick={openEventsPanel}
              title="Event log"
              className={`relative flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] border transition-colors ${
                showEvents
                  ? 'border-primary/40 bg-primary/10 text-primary'
                  : 'border-border text-muted hover:border-primary/30 hover:text-primary'
              }`}>
              {showEvents ? <BellOff size={11} /> : <Bell size={11} />}
              <span className="hidden sm:inline">Events</span>
              {unreadCount > 0 && !showEvents && (
                <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-danger text-[8px] text-white flex items-center justify-center font-bold">
                  {unreadCount > 9 ? '9+' : unreadCount}
                </span>
              )}
            </button>

            {/* Terminal toggle */}
            {terminal && (
              <button
                className="flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] border border-primary/40 bg-primary/10 text-primary"
                title="Active terminal">
                <TermIcon size={11} />
                <span className="hidden sm:inline max-w-[80px] truncate">{terminal.sessionName}</span>
              </button>
            )}

            {/* WS status */}
            <div className="flex items-center gap-1.5 text-[11px] border border-border rounded px-2.5 py-1">
              {wsStatus === 'connected'  && <><Wifi    size={11} className="text-primary" /><span className="text-primary hidden sm:inline">connected</span></>}
              {wsStatus === 'disconnected' && <><WifiOff size={11} className="text-danger"  /><span className="text-danger  hidden sm:inline">offline</span></>}
              {wsStatus === 'connecting'   && <><Loader  size={11} className="text-warn animate-spin" /><span className="text-warn hidden sm:inline">…</span></>}
            </div>
          </div>
        </header>

        {/* ── Content stack ──────────────────────────────────────────── */}
        <div className="flex-1 flex flex-col min-h-0">

          {/* Main tab content */}
          <div className="flex-1 min-h-0 overflow-auto p-4">
            {activeTab === 'dashboard' && <Dashboard  onOpenTerminal={openTerminal} />}
            {activeTab === 'agents'    && <Agents     onOpenTerminal={openTerminal} />}
            {activeTab === 'sessions'  && <Sessions   onOpenTerminal={openTerminal} />}
            {activeTab === 'beacons'   && <Beacons    />}
            {activeTab === 'windows'   && <Windows    onOpenTerminal={openTerminal} />}
            {activeTab === 'linux'     && <Linux      onOpenTerminal={openTerminal} />}
            {activeTab === 'macos'     && <MacOS      onOpenTerminal={openTerminal} />}
            {activeTab === 'android'   && <Android    onOpenTerminal={openTerminal} />}
            {activeTab === 'listeners' && <Listeners  />}
            {activeTab === 'loot'      && <Loot       />}
            {activeTab === 'netmap'    && <NetworkMap  onOpenTerminal={openTerminal} />}
            {activeTab === 'generate'  && <Generate   />}
            {activeTab === 'reports'   && <Reports    />}
            {activeTab === 'ai'        && <AI         />}
            {activeTab === 'settings'  && <Settings   />}
          </div>

          {/* ── Terminal panel (slide up) ────────────────────────────── */}
          {terminal && (
            <div className="shrink-0 border-t border-primary/30" style={{ height: '38vh' }}>
              <Terminal
                sessionID={terminal.sessionID}
                sessionName={terminal.sessionName}
                onClose={() => setTerminal(null)}
              />
            </div>
          )}

          {/* ── Event log panel (slide up) ───────────────────────────── */}
          {showEvents && (
            <div className="shrink-0 border-t border-border bg-[#080812]" style={{ height: terminal ? '25vh' : '30vh' }}>
              <div className="flex items-center justify-between px-4 py-2 border-b border-border/50">
                <div className="flex items-center gap-2 text-[11px]">
                  <Activity size={12} className="text-primary" />
                  <span className="text-primary font-semibold">Event Log</span>
                  <span className="text-muted">({events.length} events)</span>
                </div>
                <div className="flex items-center gap-2">
                  <button onClick={() => setEvents([])} className="text-muted hover:text-danger text-[10px]">Clear</button>
                  <button onClick={() => setShowEvents(false)} className="text-muted hover:text-text">
                    <X size={12} />
                  </button>
                </div>
              </div>
              <div ref={evLogRef} className="overflow-y-auto h-[calc(100%-36px)] font-mono text-[11px]">
                {events.length === 0 ? (
                  <div className="p-3 text-muted">No events yet — waiting for C2 activity…</div>
                ) : (
                  events.map(ev => (
                    <div key={ev.id}
                      className={`flex items-start gap-3 px-4 py-1.5 border-b border-border/20 hover:bg-white/3 ${
                        ev.urgent ? 'bg-danger/5' : ''
                      }`}>
                      <span className="shrink-0 text-base leading-none mt-0.5">{ev.icon}</span>
                      <span className="text-muted shrink-0 tabular-nums">
                        {new Date(ev.ts).toLocaleTimeString()}
                      </span>
                      <span className={`shrink-0 rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider ${
                        ev.urgent
                          ? 'bg-danger/20 text-danger'
                          : 'bg-border/40 text-muted'
                      }`}>
                        {ev.type}
                      </span>
                      <span className="text-text break-all">{ev.msg}</span>
                      <span className="text-muted text-[9px] shrink-0 ml-auto">{tsAgo(ev.ts)}</span>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
