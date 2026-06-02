import { useState, useCallback } from 'react'
import Dashboard  from './components/Dashboard'
import Sessions   from './components/Sessions'
import Beacons    from './components/Beacons'
import Listeners  from './components/Listeners'
import Loot       from './components/Loot'
import Android    from './components/Android'
import Generate   from './components/Generate'
import AI         from './components/AI'
import Settings   from './components/Settings'
import NetworkMap from './components/NetworkMap'
import Reports    from './components/Reports'
import Terminal   from './components/Terminal'
import { useEventStream } from './hooks/useWebSocket'
import type { WSEvent }   from './types'
import {
  LayoutDashboard, Monitor, Radio, Antenna, Package,
  Smartphone, Cpu, Bot, Settings2, Map as MapIcon, FileText,
  Terminal as TermIcon, Wifi, WifiOff, Loader,
} from 'lucide-react'

// ─────────────────────────────────────────────────────────────────────────────
// Tab definitions
// ─────────────────────────────────────────────────────────────────────────────

type TabID =
  | 'dashboard' | 'sessions' | 'beacons'  | 'android'
  | 'listeners' | 'loot'     | 'netmap'   | 'generate'
  | 'reports'   | 'ai'       | 'settings'

const TABS: { id: TabID; label: string; icon: React.ElementType; color: string }[] = [
  { id: 'dashboard', label: 'Dashboard',   icon: LayoutDashboard, color: '#00ff88' },
  { id: 'sessions',  label: 'Sessions',    icon: Monitor,          color: '#00ff88' },
  { id: 'beacons',   label: 'Beacons',     icon: Radio,            color: '#00d4ff' },
  { id: 'android',   label: 'Android',     icon: Smartphone,       color: '#00ff88' },
  { id: 'listeners', label: 'Listeners',   icon: Antenna,          color: '#ffaa00' },
  { id: 'loot',      label: 'Loot',        icon: Package,          color: '#aa88ff' },
  { id: 'netmap',    label: 'Network Map', icon: MapIcon,          color: '#00d4ff' },
  { id: 'generate',  label: 'Generate',    icon: Cpu,              color: '#00d4ff' },
  { id: 'reports',   label: 'Reports',     icon: FileText,         color: '#aa88ff' },
  { id: 'ai',        label: 'AI Agent',    icon: Bot,              color: '#aa88ff' },
  { id: 'settings',  label: 'Settings',    icon: Settings2,        color: '#555577' },
]

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

interface ActiveTerminal {
  sessionID:   string
  sessionName: string
}

// ─────────────────────────────────────────────────────────────────────────────
// App
// ─────────────────────────────────────────────────────────────────────────────

export default function App() {
  const [activeTab,    setActiveTab]   = useState<TabID>('dashboard')
  const [terminal,     setTerminal]    = useState<ActiveTerminal | null>(null)
  const [notification, setNote]        = useState<string | null>(null)

  // ── Live event stream ─────────────────────────────────────────────────────
  const onEvent = useCallback((e: WSEvent) => {
    if (e.type === 'heartbeat') return
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
  // Render
  // ─────────────────────────────────────────────────────────────────────────

  return (
    <div className="flex flex-col h-screen bg-bg text-text font-mono overflow-hidden">

      {/* ── Navigation bar ───────────────────────────────────────────────── */}
      <nav className="flex items-center justify-between border-b border-border bg-surface shrink-0 px-4 py-0">

        {/* Logo */}
        <div className="flex items-center gap-2 py-3 shrink-0">
          <span className="text-primary font-bold text-sm tracking-wider">SUDOSOC-C2</span>
          <span className="text-muted text-[10px] hidden lg:block">v2.0.0</span>
        </div>

        {/* Tab bar — scrollable on small screens */}
        <div className="flex overflow-x-auto no-scrollbar">
          {TABS.map(t => {
            const Icon   = t.icon
            const active = activeTab === t.id
            return (
              <button
                key={t.id}
                onClick={() => setActiveTab(t.id)}
                className={[
                  'flex items-center gap-1.5 px-3 py-3 text-xs border-b-2 transition-colors whitespace-nowrap shrink-0',
                  active
                    ? 'border-b-2 font-semibold'
                    : 'border-transparent text-muted hover:text-text',
                ].join(' ')}
                style={active ? { borderColor: t.color, color: t.color } : {}}
              >
                <Icon size={12} />
                <span className="hidden md:inline">{t.label}</span>
              </button>
            )
          })}

          {/* Terminal tab — visible when a session is open */}
          {terminal && (
            <button
              className="flex items-center gap-1.5 px-3 py-3 text-xs border-b-2 font-semibold whitespace-nowrap shrink-0 animate-pulse"
              style={{ borderColor: '#00d4ff', color: '#00d4ff' }}
              onClick={() => {/* already shown below */}}
            >
              <TermIcon size={12} />
              <span className="hidden md:inline">{terminal.sessionName}</span>
            </button>
          )}
        </div>

        {/* Status bar */}
        <div className="flex items-center gap-3 py-3 shrink-0">
          {notification && (
            <span className="text-[10px] text-warn animate-pulse max-w-[140px] truncate hidden lg:block">
              {notification}
            </span>
          )}
          <div className="flex items-center gap-1 text-[10px]">
            {wsStatus === 'connected'    && <><Wifi     size={11} className="text-primary" /><span className="text-primary hidden md:inline">connected</span></>}
            {wsStatus === 'disconnected' && <><WifiOff  size={11} className="text-danger"  /><span className="text-danger  hidden md:inline">disconnected</span></>}
            {wsStatus === 'connecting'   && <><Loader   size={11} className="text-warn animate-spin" /><span className="text-warn hidden md:inline">connecting…</span></>}
          </div>
        </div>
      </nav>

      {/* ── Main content ─────────────────────────────────────────────────── */}
      <div className={`flex-1 min-h-0 ${terminal ? 'grid grid-rows-[1fr_40%]' : 'flex flex-col'}`}>

        {/* Active tab panel */}
        <div className="flex-1 min-h-0 overflow-auto p-4">
          {activeTab === 'dashboard' && <Dashboard />}
          {activeTab === 'sessions'  && <Sessions  onOpenTerminal={openTerminal} />}
          {activeTab === 'beacons'   && <Beacons   />}
          {activeTab === 'android'   && <Android   onOpenTerminal={openTerminal} />}
          {activeTab === 'listeners' && <Listeners />}
          {activeTab === 'loot'      && <Loot      />}
          {activeTab === 'netmap'    && <NetworkMap />}
          {activeTab === 'generate'  && <Generate  />}
          {activeTab === 'reports'   && <Reports   />}
          {activeTab === 'ai'        && <AI        />}
          {activeTab === 'settings'  && <Settings  />}
        </div>

        {/* Embedded terminal — opens at bottom when a session is selected */}
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
