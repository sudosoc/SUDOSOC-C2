import { useState } from 'react'
import { useAPI } from '../hooks/useAPI'
import type { Operator } from '../types'
import { Settings2, Users, Server, Shield, RefreshCw, Copy, CheckCheck, Globe } from 'lucide-react'

export default function Settings() {
  const { data: operators, loading, refresh } = useAPI<Operator[]>('/api/operators', 15_000)
  const [copiedItem, setCopied] = useState<string | null>(null)

  function copy(text: string, key: string) {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(key)
      setTimeout(() => setCopied(null), 2000)
    })
  }

  const ops = operators ?? []

  return (
    <div className="flex flex-col gap-6 h-full max-w-3xl mx-auto w-full">

      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div>
        <h2 className="text-primary font-bold text-lg flex items-center gap-2">
          <Settings2 size={18} /> Settings
        </h2>
        <p className="text-muted text-xs mt-1">Server configuration and operator management</p>
      </div>

      {/* ── Operators ───────────────────────────────────────────────────── */}
      <section className="rounded-lg border border-border bg-surface p-4 flex flex-col gap-3">
        <div className="flex items-center justify-between">
          <h3 className="text-xs uppercase tracking-widest text-muted flex items-center gap-1.5">
            <Users size={12} /> Operators
          </h3>
          <button onClick={refresh} className="flex items-center gap-1 text-muted hover:text-text text-[10px]">
            <RefreshCw size={10} /> Refresh
          </button>
        </div>

        {loading ? (
          <div className="text-muted text-xs">Loading…</div>
        ) : ops.length === 0 ? (
          <div className="text-muted text-xs">No operators connected.</div>
        ) : (
          <div className="flex flex-col gap-1.5">
            {ops.map(op => (
              <div key={op.name} className="flex items-center justify-between py-1.5 border-b border-border/40">
                <div className="flex items-center gap-2">
                  <span className={`w-1.5 h-1.5 rounded-full ${op.online ? 'bg-primary animate-pulse' : 'bg-muted'}`} />
                  <span className="text-xs text-text font-mono">{op.name}</span>
                </div>
                <span className={`text-[10px] px-2 py-0.5 rounded border ${
                  op.online ? 'border-primary/30 text-primary' : 'border-border text-muted'
                }`}>
                  {op.online ? 'online' : 'offline'}
                </span>
              </div>
            ))}
          </div>
        )}

        {/* How to add operator */}
        <div className="mt-2 p-3 rounded bg-bg border border-border text-[10px] text-muted">
          <div className="text-text mb-1 text-xs">Add new operator:</div>
          {[
            { key: 'op1', cmd: 'sudosoc > new-operator --name <name> --lhost <server_ip> --save ~/.sudosoc-client/configs/' },
            { key: 'op2', cmd: './sudosoc-client   # on the operator machine' },
          ].map(({ key, cmd }) => (
            <div key={key} className="flex items-center justify-between mt-1.5 gap-2">
              <span className="text-primary font-mono break-all">{cmd}</span>
              <button onClick={() => copy(cmd, key)} className="shrink-0 text-muted hover:text-primary">
                {copiedItem === key ? <CheckCheck size={10} className="text-primary" /> : <Copy size={10} />}
              </button>
            </div>
          ))}
        </div>
      </section>

      {/* ── Server info ─────────────────────────────────────────────────── */}
      <section className="rounded-lg border border-border bg-surface p-4 flex flex-col gap-3">
        <h3 className="text-xs uppercase tracking-widest text-muted flex items-center gap-1.5">
          <Server size={12} /> Server
        </h3>
        <div className="grid grid-cols-1 gap-2 text-xs">
          {[
            { label: 'Version',       value: 'v2.0.0' },
            { label: 'Config dir',    value: '~/.sudosoc/' },
            { label: 'Log file',      value: '~/.sudosoc/logs/sudosoc-c2.log' },
            { label: 'Multiplayer',   value: ':47443 (TCP)' },
            { label: 'TLS Org',       value: 'Meridian Cloud Services, Inc.' },
            { label: 'gRPC service',  value: 'SudosocAPI' },
          ].map(({ label, value }) => (
            <div key={label} className="flex items-center justify-between py-1.5 border-b border-border/30">
              <span className="text-muted">{label}</span>
              <span className="text-text font-mono">{value}</span>
            </div>
          ))}
        </div>
      </section>

      {/* ── Default ports ───────────────────────────────────────────────── */}
      <section className="rounded-lg border border-border bg-surface p-4 flex flex-col gap-3">
        <h3 className="text-xs uppercase tracking-widest text-muted flex items-center gap-1.5">
          <Globe size={12} /> Default Ports
        </h3>
        <div className="grid grid-cols-2 gap-x-6 gap-y-1.5 text-xs">
          {[
            { proto: 'mTLS C2',     port: '8888', color: 'text-primary' },
            { proto: 'HTTP C2',     port: '80',   color: 'text-warn' },
            { proto: 'HTTPS C2',    port: '443',  color: 'text-accent' },
            { proto: 'DNS C2',      port: '53',   color: 'text-purple' },
            { proto: 'WireGuard',   port: '51820',color: 'text-text' },
            { proto: 'Multiplayer', port: '47443',color: 'text-primary' },
            { proto: 'Web UI',      port: '8080', color: 'text-primary' },
          ].map(({ proto, port, color }) => (
            <div key={proto} className="flex items-center justify-between">
              <span className="text-muted">{proto}</span>
              <span className={`font-mono font-bold ${color}`}>{port}</span>
            </div>
          ))}
        </div>
      </section>

      {/* ── Security ────────────────────────────────────────────────────── */}
      <section className="rounded-lg border border-border bg-surface p-4 flex flex-col gap-3">
        <h3 className="text-xs uppercase tracking-widest text-muted flex items-center gap-1.5">
          <Shield size={12} /> Operational Security
        </h3>
        <div className="flex flex-col gap-1.5 text-[11px] text-muted">
          {[
            '✓ Mutual TLS 1.3 — all operator connections are certificate-pinned',
            '✓ Zero-Knowledge Proofs — operator identity never transmitted in plaintext',
            '✓ Ring Signatures — team signing without individual attribution',
            '✓ TLS Certificate Randomization — unique org per implant',
            '✓ Pedersen Commitments — tamper-proof encrypted tasking',
          ].map(item => <div key={item} className="flex items-start gap-1.5">{item}</div>)}
        </div>
      </section>
    </div>
  )
}
