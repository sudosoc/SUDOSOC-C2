import { useState } from 'react'
import { useAPI, apiPost, apiDelete } from '../hooks/useAPI'
import type { Listener } from '../types'
import { Antenna, Plus, X, RefreshCw, Square, Play, ChevronDown } from 'lucide-react'

// ─── Protocol metadata ────────────────────────────────────────────────────────

const PROTOCOLS = [
  { value: 'mtls',  label: 'mTLS',       default_port: 31337, color: 'text-primary', desc: 'Mutual TLS 1.3 — certificate pinned' },
  { value: 'https', label: 'HTTPS',      default_port: 443,   color: 'text-accent',  desc: 'HTTPS with domain fronting support' },
  { value: 'http',  label: 'HTTP',       default_port: 80,    color: 'text-warn',    desc: 'Plain HTTP' },
  { value: 'dns',   label: 'DNS/DoH',    default_port: 53,    color: 'text-purple',  desc: 'DNS-over-HTTPS — survives all firewalls' },
  { value: 'wg',    label: 'WireGuard',  default_port: 51820, color: 'text-text',    desc: 'WireGuard VPN tunnel — ports: main, main+1 (netstack), main+2 (key)' },
]

const protocolColor: Record<string, string> = {
  mtls: 'text-primary', https: 'text-accent', http: 'text-warn',
  dns: 'text-purple', wg: 'text-text', smb: 'text-warn',
}

// ─── Component ────────────────────────────────────────────────────────────────

export default function Listeners() {
  const { data, loading, error, refresh } = useAPI<Listener[]>('/api/listeners', 5_000)
  const listeners = data ?? []

  const [showNew,    setShowNew]    = useState(false)
  const [proto,      setProto]      = useState('mtls')
  const [host,       setHost]       = useState('')
  const [port,       setPort]       = useState(31337)
  const [domains,    setDomains]    = useState('')
  const [starting,   setStarting]   = useState(false)
  const [stopping,   setStopping]   = useState<number | null>(null)
  const [startErr,   setStartErr]   = useState<string | null>(null)
  const [startOk,    setStartOk]    = useState<string | null>(null)

  const isDNS = proto === 'dns'

  function onProtoChange(p: string) {
    setProto(p)
    setPort(PROTOCOLS.find(x => x.value === p)?.default_port ?? 8888)
  }

  async function startListener() {
    setStarting(true); setStartErr(null); setStartOk(null)
    try {
      const body: Record<string, unknown> = { protocol: proto, host, port }
      if (isDNS) body.domains = domains.split(',').map(d => d.trim()).filter(Boolean)
      const res = await apiPost<{ id: number; name: string; protocol: string; port: number }>('/api/listeners', body)
      setStartOk(`✓ ${res.name} started on port ${res.port}`)
      setShowNew(false)
      refresh()
    } catch (e) {
      setStartErr(String(e))
    } finally {
      setStarting(false)
    }
  }

  async function stopListener(id: number) {
    setStopping(id)
    try {
      await apiDelete(`/api/listeners/${id}`)
      refresh()
    } catch { /* ignore */ }
    finally { setStopping(null) }
  }

  return (
    <div className="flex flex-col gap-4 h-full">

      {/* ── Toolbar ──────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <h2 className="text-warn font-bold text-lg flex items-center gap-2">
          <Antenna size={18} /> Listeners
          <span className="text-muted text-sm font-normal">({listeners.length} active)</span>
        </h2>
        <div className="flex items-center gap-2">
          <button onClick={refresh}
            className="flex items-center gap-1 text-muted hover:text-text text-xs px-2 py-1 rounded border border-border">
            <RefreshCw size={12} /> Refresh
          </button>
          <button onClick={() => { setShowNew(!showNew); setStartErr(null); setStartOk(null) }}
            className={`flex items-center gap-1 text-xs px-3 py-1.5 rounded border transition-colors ${
              showNew
                ? 'border-danger/40 text-danger bg-danger/10'
                : 'border-primary/40 text-primary bg-primary/10 hover:bg-primary/20'
            }`}>
            {showNew ? <><X size={12} /> Cancel</> : <><Plus size={12} /> New Listener</>}
          </button>
        </div>
      </div>

      {/* ── Start New Listener Panel ──────────────────────────────────────── */}
      {showNew && (
        <div className="rounded-lg border border-primary/30 bg-surface p-4 flex flex-col gap-4">
          <h3 className="text-primary text-xs font-semibold uppercase tracking-widest flex items-center gap-1">
            <Play size={11} /> Start New Listener
          </h3>

          {/* Protocol selector */}
          <div>
            <label className="text-[10px] text-muted mb-2 block">Protocol</label>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              {PROTOCOLS.map(p => (
                <button key={p.value} onClick={() => onProtoChange(p.value)}
                  className={`flex flex-col gap-1 p-3 rounded-lg border text-xs transition-all ${
                    proto === p.value
                      ? 'border-primary bg-primary/10'
                      : 'border-border hover:border-muted'
                  }`}>
                  <span className={`font-bold ${proto === p.value ? 'text-primary' : protocolColor[p.value] ?? 'text-text'}`}>
                    {p.label}
                  </span>
                  <span className="text-muted text-[10px]">{p.desc}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Host + Port */}
          <div className="grid grid-cols-3 gap-3">
            <div className="col-span-2">
              <label className="text-[10px] text-muted mb-1 block">
                {isDNS ? 'Domains (comma-separated)' : 'Bind Host (empty = 0.0.0.0)'}
              </label>
              {isDNS ? (
                <input value={domains} onChange={e => setDomains(e.target.value)}
                  placeholder="c2.example.com, backup.example.com"
                  className="w-full bg-bg border border-border rounded px-3 py-2 text-xs text-text placeholder-muted focus:border-primary outline-none font-mono" />
              ) : (
                <input value={host} onChange={e => setHost(e.target.value)}
                  placeholder="0.0.0.0 (all interfaces)"
                  className="w-full bg-bg border border-border rounded px-3 py-2 text-xs text-text placeholder-muted focus:border-primary outline-none font-mono" />
              )}
            </div>
            <div>
              <label className="text-[10px] text-muted mb-1 block">Port</label>
              <input type="number" value={port} onChange={e => setPort(parseInt(e.target.value) || 0)}
                className="w-full bg-bg border border-border rounded px-3 py-2 text-xs text-text focus:border-primary outline-none font-mono" />
            </div>
          </div>

          {startErr && (
            <div className="text-danger text-xs bg-danger/10 border border-danger/30 rounded p-2">{startErr}</div>
          )}

          <button onClick={startListener} disabled={starting || port === 0}
            className="flex items-center justify-center gap-2 w-full py-2.5 rounded-lg bg-primary/10 border border-primary/40 text-primary font-semibold text-sm hover:bg-primary/20 transition-colors disabled:opacity-50">
            <Play size={14} />
            {starting ? 'Starting…' : `Start ${PROTOCOLS.find(p => p.value === proto)?.label ?? proto} on :${port}`}
          </button>
        </div>
      )}

      {/* ── Success notification ─────────────────────────────────────────── */}
      {startOk && (
        <div className="text-primary text-xs bg-primary/10 border border-primary/30 rounded p-2">{startOk}</div>
      )}

      {/* ── Error ────────────────────────────────────────────────────────── */}
      {error && (
        <div className="text-danger text-xs bg-danger/10 border border-danger/30 rounded p-2">{error}</div>
      )}

      {/* ── Active Listeners ────────────────────────────────────────────── */}
      {loading && listeners.length === 0 ? (
        <div className="text-muted text-sm">Loading…</div>
      ) : listeners.length === 0 && !showNew ? (
        <div className="flex-1 flex flex-col items-center justify-center gap-4 py-12 text-center">
          <Antenna size={40} className="text-border" />
          <div>
            <p className="text-muted text-sm">No active listeners.</p>
            <p className="text-muted text-xs mt-1">Click "New Listener" to start accepting implant connections.</p>
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
          {listeners.map(l => {
            const colorClass = protocolColor[l.protocol?.toLowerCase() ?? ''] ?? 'text-text'
            const isStopping = stopping === l.id
            return (
              <div key={l.id} className="rounded-lg border border-border bg-surface p-4 flex flex-col gap-3 relative">

                {/* Stop button */}
                <button onClick={() => stopListener(l.id)} disabled={isStopping}
                  title="Stop listener"
                  className="absolute top-3 right-3 p-1.5 rounded text-muted hover:text-danger hover:bg-danger/10 transition-colors disabled:opacity-40">
                  <Square size={12} />
                </button>

                {/* Header */}
                <div className="flex items-center gap-2 pr-7">
                  <span className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse shrink-0" />
                  <span className={`font-bold text-sm uppercase ${colorClass}`}>{l.protocol}</span>
                  <span className="text-muted text-xs">Job #{l.id}</span>
                </div>

                {/* Name */}
                <div className="text-text font-mono text-xs truncate">{l.name}</div>

                {/* Port */}
                <div className="flex items-center justify-between">
                  <span className="text-muted text-xs">Port</span>
                  <span className={`font-bold text-lg ${colorClass} font-mono`}>{l.port}</span>
                </div>

                {/* Domains */}
                {l.domains && l.domains.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {l.domains.map(d => (
                      <span key={d} className="bg-border/60 text-accent px-1.5 py-0.5 rounded text-[10px] font-mono truncate max-w-[140px]">
                        {d}
                      </span>
                    ))}
                  </div>
                )}

                {/* Status */}
                <div className="flex items-center gap-1.5 pt-1 border-t border-border/40">
                  <span className="w-1 h-1 rounded-full bg-primary" />
                  <span className="text-muted text-[10px]">{isStopping ? 'Stopping…' : 'ACTIVE — Accepting connections'}</span>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
