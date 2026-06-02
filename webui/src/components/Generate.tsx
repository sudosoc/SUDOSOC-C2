import { useState, useEffect } from 'react'
import { Cpu, Copy, CheckCheck, Terminal as TermIcon, Zap, Shield, AlertCircle, CheckCircle2, Radio } from 'lucide-react'
import { apiFetch, apiPost, useAPI } from '../hooks/useAPI'
import type { Listener } from '../types'

// ─── Types ────────────────────────────────────────────────────────────────────

interface OptionItem  { value: string; label: string; description?: string }
interface EvasionOpt  { key: string; label: string; description: string; default: boolean }
interface GenOptions  {
  os: string; arch: string
  formats: OptionItem[]; protocols: OptionItem[]; evasion: EvasionOpt[]
  arches: string[]; default_ports: Record<string, number>
}

const OS_LIST = [
  { value: 'windows', label: 'Windows', icon: '🪟' },
  { value: 'linux',   label: 'Linux',   icon: '🐧' },
  { value: 'macos',   label: 'macOS',   icon: '🍎' },
  { value: 'android', label: 'Android', icon: '🤖' },
]

// ─── Component ────────────────────────────────────────────────────────────────

export default function Generate() {
  const [os,       setOS]       = useState('windows')
  const [arch,     setArch]     = useState('amd64')
  const [protocol, setProtocol] = useState('mtls')
  const [format,   setFormat]   = useState('exe')
  const [c2host,   setC2Host]   = useState('')
  const [c2port,   setC2Port]   = useState(8888)
  const [name,     setName]     = useState('')
  const [evasion,  setEvasion]  = useState<Record<string, boolean>>({})
  const [domains,  setDomains]  = useState('')

  const [opts,     setOpts]     = useState<GenOptions | null>(null)
  const [loading,  setLoading]  = useState(false)
  const [result,   setResult]   = useState<{ command: string; message: string } | null>(null)
  const [error,    setError]    = useState<string | null>(null)
  const [copied,   setCopied]   = useState(false)

  // ── Live listeners for the picker ─────────────────────────────────────
  const { data: listeners } = useAPI<Listener[]>('/api/listeners', 5_000)

  function pickListener(l: Listener) {
    // The listener tells us:
    //   - protocol: what channel the implant should use (mtls, https, http, dns)
    //   - port: what port the listener is on → this IS the implant's C2 port
    //
    // The operator still needs to set C2 host = the server's PUBLIC IP
    // (not 0.0.0.0 which is what the listener binds to)
    const proto = l.protocol?.toLowerCase() ?? 'mtls'
    // Only set protocol if it's supported by the current OS options
    if (opts?.protocols?.some(p => p.value === proto)) {
      setProtocol(proto)
    }
    // Set port to match the listener
    setC2Port(l.port)
    // For DNS, pre-fill domains from the listener config
    if (proto === 'dns' && l.domains && l.domains.length > 0) {
      setDomains(l.domains.join(', '))
    }
  }

  // ── Load smart options when OS or arch changes ──────────────────────────
  useEffect(() => {
    setLoading(true)
    setResult(null)
    setError(null)
    apiFetch<GenOptions>(`/api/generate/options?os=${os}&arch=${arch}`)
      .then(o => {
        setOpts(o)
        // Set smart defaults from new OS
        setFormat(o.formats[0]?.value ?? 'exe')
        setProtocol(o.protocols[0]?.value ?? 'mtls')
        setC2Port(o.default_ports[o.protocols[0]?.value ?? 'mtls'] ?? 8888)
        // Apply default evasion checkboxes
        const def: Record<string, boolean> = {}
        o.evasion.forEach(e => { def[e.key] = e.default })
        setEvasion(def)
        // Default arch for android
        if (os === 'android') setArch('arm64')
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [os])

  // ── Update port when protocol changes ───────────────────────────────────
  useEffect(() => {
    if (opts?.default_ports?.[protocol]) {
      setC2Port(opts.default_ports[protocol])
    }
  }, [protocol, opts])

  // ── Submit generate request ─────────────────────────────────────────────
  async function submit() {
    if (!c2host.trim()) { setError('C2 host is required'); return }
    setLoading(true); setError(null); setResult(null)
    try {
      const res = await apiPost<{ command: string; message: string }>('/api/generate', {
        os, arch, protocol, c2host: c2host.trim(), c2port, format,
        name: name.trim(), evasion,
        domains: domains.split(',').map(d => d.trim()).filter(Boolean),
      })
      setResult(res)
    } catch (e) {
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }

  function copyCmd() {
    if (!result) return
    navigator.clipboard.writeText(result.command).then(() => {
      setCopied(true); setTimeout(() => setCopied(false), 2000)
    })
  }

  const isAndroid = os === 'android'
  const isDNS     = protocol === 'dns'

  return (
    <div className="flex flex-col gap-6 h-full">

      {/* ── Header ────────────────────────────────────────────────────── */}
      <div>
        <h2 className="text-primary font-bold text-lg flex items-center gap-2">
          <Cpu size={18} /> Generate Implant
        </h2>
        <p className="text-muted text-xs mt-1">Smart adaptive form — options change automatically based on target OS</p>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 flex-1 min-h-0">

        {/* ── Left: Config ────────────────────────────────────────────── */}
        <div className="flex flex-col gap-4 overflow-y-auto">

          {/* OS Selector */}
          <section className="rounded-lg border border-border bg-surface p-4">
            <label className="text-[10px] text-muted uppercase tracking-widest mb-3 block">Target OS</label>
            <div className="grid grid-cols-4 gap-2">
              {OS_LIST.map(o => (
                <button key={o.value} onClick={() => setOS(o.value)}
                  className={`flex flex-col items-center gap-1.5 p-3 rounded-lg border transition-all text-xs ${
                    os === o.value
                      ? 'border-primary bg-primary/10 text-primary'
                      : 'border-border text-muted hover:border-muted hover:text-text'
                  }`}>
                  <span className="text-xl">{o.icon}</span>
                  <span>{o.label}</span>
                </button>
              ))}
            </div>
          </section>

          {/* Architecture */}
          {opts && (
            <section className="rounded-lg border border-border bg-surface p-4 flex flex-col gap-2">
              <label className="text-[10px] text-muted uppercase tracking-widest">Architecture</label>
              <div className="flex flex-wrap gap-2">
                {opts.arches.map(a => (
                  <button key={a} onClick={() => setArch(a)}
                    className={`px-3 py-1.5 rounded border text-xs transition-colors ${
                      arch === a ? 'border-accent text-accent bg-accent/10' : 'border-border text-muted hover:border-muted'
                    }`}>
                    {a}
                  </button>
                ))}
              </div>
            </section>
          )}

          {/* Output Format */}
          {opts && (
            <section className="rounded-lg border border-border bg-surface p-4 flex flex-col gap-2">
              <label className="text-[10px] text-muted uppercase tracking-widest flex items-center gap-1">
                <TermIcon size={10} /> Output Format
              </label>
              <div className="flex flex-col gap-1.5">
                {opts.formats.map(f => (
                  <label key={f.value} className="flex items-center gap-3 cursor-pointer group p-2 rounded hover:bg-bg">
                    <input type="radio" name="format" value={f.value} checked={format === f.value}
                      onChange={() => setFormat(f.value)}
                      className="accent-primary" />
                    <div>
                      <div className="text-xs text-text font-semibold">{f.label}</div>
                      {f.description && <div className="text-[10px] text-muted">{f.description}</div>}
                    </div>
                  </label>
                ))}
              </div>
            </section>
          )}

          {/* ── Step 1: Pick a running listener ─────────────────── */}
          <section className={`rounded-lg border p-3 flex flex-col gap-2 ${
            listeners && listeners.length > 0
              ? 'border-primary/30 bg-primary/5'
              : 'border-border bg-surface opacity-60'
          }`}>
            <label className="text-[10px] text-primary uppercase tracking-widest flex items-center gap-1.5">
              <Radio size={10} />
              Step 1 — Pick a running listener (auto-fills protocol + port)
            </label>

            {(!listeners || listeners.length === 0) ? (
              <div className="text-[10px] text-muted italic">
                No active listeners yet. Go to the Listeners tab and start one first, then come back here.
              </div>
            ) : (
              <>
                <div className="flex flex-wrap gap-1.5">
                  {listeners.map(l => {
                    const proto = l.protocol?.toLowerCase() ?? '?'
                    const isCompatible = !opts || opts.protocols.some(p => p.value === proto)
                    const isSelected = protocol === proto && c2port === l.port
                    return (
                      <button key={l.id}
                        onClick={() => isCompatible && pickListener(l)}
                        title={isCompatible ? `Use ${proto.toUpperCase()} on port ${l.port}` : `${proto} not supported for ${os}`}
                        className={`flex items-center gap-1.5 px-3 py-1.5 rounded border text-xs transition-all ${
                          isSelected
                            ? 'border-primary bg-primary/20 text-primary font-bold'
                            : isCompatible
                            ? 'border-border bg-surface hover:border-primary hover:bg-primary/10 text-text cursor-pointer'
                            : 'border-border/30 bg-surface/30 text-muted cursor-not-allowed opacity-50'
                        }`}>
                        <span className={`w-1.5 h-1.5 rounded-full animate-pulse shrink-0 ${isSelected ? 'bg-primary' : 'bg-green-400'}`} />
                        <span className="font-bold uppercase">{proto}</span>
                        <span className="text-muted">:{l.port}</span>
                        {isSelected && <span className="text-[9px] text-primary">✓ selected</span>}
                        {!isCompatible && <span className="text-[9px] text-muted">(n/a for {os})</span>}
                      </button>
                    )
                  })}
                </div>
                <p className="text-[9px] text-muted">
                  Selecting a listener sets the <strong>protocol</strong> and <strong>port</strong> automatically.
                  The implant will connect back to these settings.
                </p>
              </>
            )}
          </section>

          {/* ── Step 2: Set C2 host ─────────────────────────────── */}
          <section className="rounded-lg border border-border bg-surface p-3 flex flex-col gap-2">
            <label className="text-[10px] text-warn uppercase tracking-widest">
              Step 2 — Set your public C2 host (the IP or domain the implant will connect to)
            </label>
            <div className="grid grid-cols-3 gap-2">
              <div className="col-span-2">
                <input value={c2host} onChange={e => setC2Host(e.target.value)}
                  placeholder="e.g. 192.168.1.50  (NOT 0.0.0.0 or localhost!)"
                  className={`w-full bg-bg border rounded px-3 py-2 text-xs text-text placeholder-muted focus:border-warn outline-none font-mono ${
                    !c2host.trim() ? 'border-warn/50' : 'border-border'
                  }`} />
              </div>
              <div>
                <input type="number" value={c2port} onChange={e => setC2Port(parseInt(e.target.value) || 0)}
                  className="w-full bg-bg border border-border rounded px-3 py-2 text-xs text-text focus:border-primary outline-none font-mono" />
              </div>
            </div>
            {!c2host.trim() && (
              <p className="text-[9px] text-warn">
                ⚠ Enter your server's reachable IP. The implant on the target device will connect TO this address.
              </p>
            )}
          </section>

          {/* ── Step 3: Choose channel (or override after picking listener) ── */}
          {opts && (
            <section className="rounded-lg border border-border bg-surface p-3 flex flex-col gap-2">
              <label className="text-[10px] text-muted uppercase tracking-widest flex items-center gap-1">
                <Zap size={10} /> Step 3 — C2 Channel
                <span className="text-muted font-normal normal-case ml-1">
                  (auto-set by listener picker above, or choose manually)
                </span>
              </label>
              <div className="flex flex-col gap-1">
                {opts.protocols.map(p => (
                  <label key={p.value} className={`flex items-start gap-3 cursor-pointer px-2 py-1.5 rounded hover:bg-bg transition-colors ${
                    protocol === p.value ? 'bg-bg' : ''
                  }`}>
                    <input type="radio" name="protocol" value={p.value} checked={protocol === p.value}
                      onChange={() => { setProtocol(p.value); if (opts.default_ports?.[p.value]) setC2Port(opts.default_ports[p.value]) }}
                      className="accent-primary mt-0.5 shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between gap-2">
                        <span className={`text-xs font-semibold ${protocol === p.value ? 'text-primary' : 'text-text'}`}>{p.label}</span>
                        <span className="text-[10px] text-muted font-mono shrink-0">:{opts.default_ports?.[p.value] ?? c2port}</span>
                      </div>
                      {p.description && <div className="text-[10px] text-muted truncate">{p.description}</div>}
                    </div>
                  </label>
                ))}
              </div>
              {isDNS && (
                <div className="mt-1">
                  <label className="text-[10px] text-muted mb-1 block">DNS Domains (comma-separated)</label>
                  <input value={domains} onChange={e => setDomains(e.target.value)}
                    placeholder="c2.example.com, backup.example.com"
                    className="w-full bg-bg border border-border rounded px-2 py-1.5 text-xs text-text placeholder-muted focus:border-primary outline-none font-mono" />
                </div>
              )}
            </section>
          )}

          {/* Evasion */}
          {opts && opts.evasion.length > 0 && (
            <section className="rounded-lg border border-border bg-surface p-4 flex flex-col gap-2">
              <label className="text-[10px] text-muted uppercase tracking-widest flex items-center gap-1">
                <Shield size={10} /> {isAndroid ? 'Anti-Analysis' : 'Evasion & Obfuscation'}
              </label>
              <div className="grid grid-cols-1 gap-1.5">
                {opts.evasion.map(e => (
                  <label key={e.key} className="flex items-start gap-3 cursor-pointer p-2 rounded hover:bg-bg group">
                    <div className="relative mt-0.5 shrink-0">
                      <input type="checkbox" checked={!!evasion[e.key]}
                        onChange={ev => setEvasion(prev => ({ ...prev, [e.key]: ev.target.checked }))}
                        className="sr-only" />
                      <div className={`w-7 h-4 rounded-full transition-colors ${evasion[e.key] ? 'bg-primary' : 'bg-border'}`}>
                        <div className={`absolute top-0.5 w-3 h-3 rounded-full bg-bg transition-transform ${evasion[e.key] ? 'translate-x-3.5' : 'translate-x-0.5'}`} />
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-text">{e.label}</div>
                      <div className="text-[10px] text-muted">{e.description}</div>
                    </div>
                  </label>
                ))}
              </div>
            </section>
          )}

          {/* Optional name */}
          <div className="flex flex-col gap-1">
            <label className="text-[10px] text-muted">Implant Name <span className="text-muted italic">(optional)</span></label>
            <input value={name} onChange={e => setName(e.target.value)}
              placeholder="phantom_001"
              className="w-full bg-surface border border-border rounded px-3 py-2 text-xs text-text placeholder-muted focus:border-primary outline-none font-mono" />
          </div>
        </div>

        {/* ── Right: Output ─────────────────────────────────────────── */}
        <div className="flex flex-col gap-4">

          {/* Generate button */}
          <button onClick={submit} disabled={loading}
            className="w-full py-3 rounded-lg border-2 border-primary text-primary font-bold text-sm flex items-center justify-center gap-2 hover:bg-primary hover:text-bg transition-all disabled:opacity-50 disabled:cursor-not-allowed">
            <Cpu size={16} />
            {loading ? 'Configuring…' : 'Generate Implant'}
          </button>

          {/* Error */}
          {error && (
            <div className="flex items-start gap-2 bg-danger/10 border border-danger/30 rounded p-3 text-xs text-danger">
              <AlertCircle size={13} className="shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {/* Result */}
          {result && (
            <div className="flex flex-col gap-3">
              <div className="flex items-center gap-2 text-primary text-xs bg-primary/10 border border-primary/30 rounded p-3">
                <CheckCircle2 size={13} />
                <span>{result.message}</span>
              </div>

              <div className="flex flex-col gap-1.5">
                <div className="flex items-center justify-between">
                  <label className="text-[10px] text-muted uppercase tracking-widest">Console Command</label>
                  <button onClick={copyCmd}
                    className="flex items-center gap-1 text-[10px] text-muted hover:text-primary transition-colors">
                    {copied ? <><CheckCheck size={10} className="text-primary" /> Copied!</> : <><Copy size={10} /> Copy</>}
                  </button>
                </div>
                <div className="rounded-lg border border-border bg-surface p-4 font-mono text-xs text-primary">
                  <span className="text-muted select-none">sudosoc {'>'} </span>
                  <span className="whitespace-pre-wrap break-all">{result.command}</span>
                </div>
              </div>

              <div className="rounded-lg border border-border bg-surface p-3 text-xs text-muted">
                <div className="text-text text-[10px] font-semibold uppercase tracking-widest mb-2">Next Steps</div>
                <ol className="list-decimal list-inside flex flex-col gap-1 text-[11px]">
                  <li>Start listener: <span className="text-accent font-mono">sudosoc {'>'} {protocol}</span></li>
                  <li>Copy the command above and paste it in the server console</li>
                  <li>Transfer the generated binary to your target</li>
                  <li>Execute it — new session appears in Sessions tab</li>
                </ol>
              </div>
            </div>
          )}

          {/* Summary card */}
          {opts && !result && (
            <div className="rounded-lg border border-border bg-surface p-4 flex flex-col gap-2 text-xs">
              <div className="text-muted text-[10px] uppercase tracking-widest mb-1">Current Config</div>
              {[
                ['OS',       `${os} (${arch})`],
                ['Format',   opts.formats.find(f => f.value === format)?.label ?? format],
                ['Channel',  opts.protocols.find(p => p.value === protocol)?.label ?? protocol],
                ['C2',       c2host ? `${c2host}:${c2port}` : '<not set>'],
                ['Evasion',  Object.entries(evasion).filter(([,v]) => v).map(([k]) => k).join(', ') || 'none'],
              ].map(([k, v]) => (
                <div key={k} className="flex justify-between items-start gap-3">
                  <span className="text-muted shrink-0">{k}</span>
                  <span className={`text-right break-all ${v === '<not set>' ? 'text-danger' : 'text-text'}`}>{v}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
