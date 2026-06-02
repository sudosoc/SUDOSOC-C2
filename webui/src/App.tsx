import { useState, useCallback } from 'react'
import Dashboard  from './components/Dashboard'
import Sessions   from './components/Sessions'
import Beacons    from './components/Beacons'
import Listeners  from './components/Listeners'
import Loot       from './components/Loot'
import Terminal   from './components/Terminal'
import { useEventStream } from './hooks/useWebSocket'
import type { WSEvent }   from './types'
import {
  LayoutDashboard, Monitor, Radio,
  Antenna, Package, Terminal as TermIcon,
  Wifi, WifiOff, Loader,
} from 'lucide-react'

// ─────────────────────────────────────────────────────────────────────────────
// Tab definitions
// ─────────────────────────────────────────────────────────────────────────────

type TabID = 'dashboard' | 'sessions' | 'beacons' | 'listeners' | 'loot'

const TABS: { id: TabID; label: string; icon: React.ElementType; color: string }[] = [
  { id: 'dashboard', label: 'Dashboard',  icon: LayoutDashboard, color: '#00ff88' },
  { id: 'sessions',  label: 'Sessions',   icon: Monitor,          color: '#00ff88' },
  { id: 'beacons',   label: 'Beacons',    icon: Radio,            color: '#00d4ff' },
  { id: 'listeners', label: 'Listeners',  icon: Antenna,          color: '#ffaa00' },
  { id: 'loot',      label: 'Loot',       icon: Package,          color: '#aa88ff' },
]

// ─────────────────────────────────────────────────────────────────────────────
// Active terminal state
// ─────────────────────────────────────────────────────────────────────────────

interface ActiveTerminal {
  sessionID:   string
  sessionName: string
}

// ─────────────────────────────────────────────────────────────────────────────
// App
// ─────────────────────────────────────────────────────────────────────────────

export default function App() {
  const [activeTab, setActiveTab]   = useState<TabID>('dashboard')
  const [terminal,  setTerminal]    = useState<ActiveTerminal | null>(null)
  const [notification, setNote]     = useState<string | null>(null)

  // ── Connection indicator ─────────────────────────────────────────────────
  const onEvent = useCallback((e: WSEvent) => {
    if (e.type === 'heartbeat') return
    // Flash a notification on meaningful events.
    const payload = e.payload as Record<string, string>
    const subject = payload.session_name ?? payload.beacon_name ?? payload.operator ?? ''
    const note    = subject ? `[${e.type}] ${subject}` : `[${e.type}]`
    setNote(note)
    setTimeout(() => setNote(null), 4000)
  }, [])

  const wsStatus = useEventStream(onEvent)

  function openTerminal(sessionID: string, sessionName = '') {
    setTerminal({ sessionID, sessionName: sessionName || sessionID.slice(0, 8) })
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Layout
  // ─────────────────────────────────────────────────────────────────────────

  return (
    <div className="flex flex-col h-screen bg-bg text-text font-mono overflow-hidden">

      {/* ── Top navigation bar ─────────────────────────────────────────── */}
      <nav className="flex items-center justify-between border-b border-border bg-surface shrink-0 px-4 py-0">

        {/* Logo */}
        <div className="flex items-center gap-3 py-3">
          <span className="text-primary font-bold text-sm tracking-wider">SUDOSOC-C2</span>
          <span className="text-muted text-[10px] hidden md:block">v2.0.0</span>
        </div>

        {/* Tabs */}
        <div className="flex">
          {TABS.map(t => {
            const Icon    = t.icon
            const active  = activeTab === t.id
            return (
              <button
                key={t.id}
                onClick={() => setActiveTab(t.id)}
                className={[
                  'flex items-center gap-1.5 px-4 py-3 text-xs border-b-2 transition-colors whitespace-nowrap',
                  active
                    ? 'border-b-2 font-semibold'
                    : 'border-transparent text-muted hover:text-text',
                ].join(' ')}
                style={active ? { borderColor: t.color, color: t.color } : {}}
              >
                <Icon size={13} />
                <span className="hidden sm:inline">{t.label}</span>
              </button>
            )
          })}

          {/* Terminal tab — shown only when a session is open */}
          {terminal && (
            <button
              onClick={() => {/* already visible below */}}
              className="flex items-center gap-1.5 px-4 py-3 text-xs border-b-2 font-semibold whitespace-nowrap"
              style={{ borderColor: '#00d4ff', color: '#00d4ff' }}
            >
              <TermIcon size={13} />
              <span className="hidden sm:inline">{terminal.sessionName}</span>
            </button>
          )}
        </div>

        {/* Right: WS status + notification */}
        <div className="flex items-center gap-3 py-3">
          {notification && (
            <span className="text-[10px] text-warn animate-pulse max-w-[160px] truncate">
              {notification}
            </span>
          )}
          <div className="flex items-center gap-1 text-[10px]">
            {wsStatus === 'connected'    && <><Wifi size={11} className="text-primary" /><span className="text-primary hidden md:inline">connected</span></>}
            {wsStatus === 'disconnected' && <><WifiOff size={11} className="text-danger" /><span className="text-danger hidden md:inline">disconnected</span></>}
            {wsStatus === 'connecting'   && <><Loader size={11} className="text-warn animate-spin" /><span className="text-warn hidden md:inline">connecting…</span></>}
          </div>
        </div>
      </nav>

      {/* ── Content area ───────────────────────────────────────────────── */}
      <div className={`flex-1 min-h-0 ${terminal ? 'grid grid-rows-2' : 'flex flex-col'}`}>

        {/* Main panel */}
        <div className="flex-1 min-h-0 overflow-auto p-4">
          {activeTab === 'dashboard' && <Dashboard />}
          {activeTab === 'sessions'  && (
            <Sessions onOpenTerminal={(id, name) => openTerminal(id, name)} />
          )}
          {activeTab === 'beacons'   && <Beacons />}
          {activeTab === 'listeners' && <Listeners />}
          {activeTab === 'loot'      && <Loot />}
        </div>

        {/* Embedded terminal (shown when a session is selected) */}
        {terminal && (
          <div className="min-h-0 border-t border-border">
            <Terminal
              sessionID={terminal.sessionID}
              sessionName={terminal.sessionName}
              onClose={() => setTerminal(null)}
            />
          </div>
        )}
      </div>
    </div>
  )
}
