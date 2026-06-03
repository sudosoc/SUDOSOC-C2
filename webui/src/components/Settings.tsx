import { useState, useEffect } from 'react'
import { useAPI, apiPost, apiFetch } from '../hooks/useAPI'
import type { Operator } from '../types'
import { Settings2, Users, Server, Shield, RefreshCw, Copy, CheckCheck, Globe, Plus, Download, Loader, Bot, Eye, EyeOff, CheckCircle, AlertCircle } from 'lucide-react'

interface OperatorNewResp {
  name:        string
  config_json: string
  save_path:   string
}

export default function Settings() {
  const { data: operators, loading, refresh } = useAPI<Operator[]>('/api/operators', 15_000)
  const [copiedItem,    setCopied]    = useState<string | null>(null)
  const [opName,        setOpName]    = useState('')
  const [opHost,        setOpHost]    = useState('')
  const [opPort,        setOpPort]    = useState(47443)
  const [genLoading,    setGenLoading]= useState(false)
  const [genResult,     setGenResult] = useState<OperatorNewResp | null>(null)
  const [genError,      setGenError]  = useState<string | null>(null)

  function copy(text: string, key: string) {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(key)
      setTimeout(() => setCopied(null), 2000)
    })
  }

  async function generateOperator() {
    if (!opName.trim() || !opHost.trim()) return
    setGenLoading(true); setGenResult(null); setGenError(null)
    try {
      const res = await apiPost<OperatorNewResp>('/api/operators/new', {
        name: opName.trim(), lhost: opHost.trim(), lport: opPort,
      })
      setGenResult(res)
    } catch (e) {
      setGenError(String(e))
    } finally { setGenLoading(false) }
  }

  function downloadConfig() {
    if (!genResult) return
    const blob = new Blob([genResult.config_json], { type: 'application/json' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href = url; a.download = genResult.save_path; a.click()
    URL.revokeObjectURL(url)
  }

  // ── AI Settings state ─────────────────────────────────────────────────────
  const [aiProvider, setAiProvider] = useState('openrouter')
  const [aiKey,      setAiKey]      = useState('')
  const [aiModel,    setAiModel]    = useState('')
  const [aiBaseURL,  setAiBaseURL]  = useState('')
  const [aiKeyShow,  setAiKeyShow]  = useState(false)
  const [aiSaving,   setAiSaving]   = useState(false)
  const [aiStatus,   setAiStatus]   = useState<{ configured: boolean; provider?: string; model?: string; api_key_masked?: string } | null>(null)
  const [aiMsg,      setAiMsg]      = useState<{ ok: boolean; text: string } | null>(null)

  useEffect(() => {
    apiFetch<typeof aiStatus>('/api/settings/ai').then(s => {
      setAiStatus(s)
      if (s?.provider) setAiProvider(s.provider)
      if (s?.model) setAiModel(s.model)
    }).catch(() => {})
  }, [])

  async function saveAI() {
    if (!aiKey.trim() && !aiStatus?.api_key_masked) {
      setAiMsg({ ok: false, text: 'API key is required' }); return
    }
    setAiSaving(true); setAiMsg(null)
    try {
      await apiPost('/api/settings/ai', {
        provider: aiProvider,
        api_key: aiKey.trim() || undefined,
        model: aiModel.trim() || undefined,
        base_url: aiBaseURL.trim() || undefined,
      })
      setAiMsg({ ok: true, text: 'AI provider saved — restart server for changes to take effect' })
      setAiKey('')
      apiFetch<typeof aiStatus>('/api/settings/ai').then(s => setAiStatus(s)).catch(() => {})
    } catch(e) {
      setAiMsg({ ok: false, text: String(e) })
    } finally { setAiSaving(false) }
  }

  const AI_PROVIDERS = [
    { id: 'openrouter',   label: 'OpenRouter',         placeholder: 'sk-or-v1-…',      models: ['anthropic/claude-3-5-sonnet', 'openai/gpt-4o', 'meta-llama/llama-3.1-70b-instruct'] },
    { id: 'openai',       label: 'OpenAI',             placeholder: 'sk-…',             models: ['gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo'] },
    { id: 'anthropic',    label: 'Anthropic',          placeholder: 'sk-ant-…',         models: ['claude-3-5-sonnet-20241022', 'claude-3-5-haiku-20241022'] },
    { id: 'openai-compat',label: 'OpenAI-Compatible',  placeholder: 'your-api-key',     models: [] },
  ]
  const currentProvider = AI_PROVIDERS.find(p => p.id === aiProvider)

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

      {/* ── Generate Operator Config ────────────────────────────────────── */}
      <section className="rounded-lg border border-border bg-surface p-4 flex flex-col gap-3">
        <h3 className="text-xs uppercase tracking-widest text-muted flex items-center gap-1.5">
          <Plus size={12} /> Generate Operator Config
        </h3>
        <p className="text-muted text-[10px]">
          Create an operator config file that lets an operator connect to this server via sudosoc-client.
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
          <div>
            <label className="text-[10px] text-muted mb-1 block">Operator Name</label>
            <input value={opName} onChange={e => setOpName(e.target.value)}
              placeholder="seif" className="w-full bg-bg border border-border rounded px-2 py-1.5 text-xs focus:border-primary outline-none text-text" />
          </div>
          <div>
            <label className="text-[10px] text-muted mb-1 block">Server IP / Host</label>
            <input value={opHost} onChange={e => setOpHost(e.target.value)}
              placeholder="192.168.1.50" className="w-full bg-bg border border-border rounded px-2 py-1.5 text-xs focus:border-primary outline-none text-text" />
          </div>
          <div>
            <label className="text-[10px] text-muted mb-1 block">Multiplayer Port</label>
            <input type="number" value={opPort} onChange={e => setOpPort(parseInt(e.target.value) || 47443)}
              className="w-full bg-bg border border-border rounded px-2 py-1.5 text-xs focus:border-primary outline-none text-text" />
          </div>
        </div>
        <button onClick={generateOperator} disabled={!opName.trim() || !opHost.trim() || genLoading}
          className="flex items-center justify-center gap-2 py-2 rounded border border-primary/40 text-primary bg-primary/10 hover:bg-primary/20 text-xs font-semibold disabled:opacity-40 transition-colors">
          {genLoading ? <><Loader size={12} className="animate-spin"/> Generating…</> : <><Plus size={12}/> Generate Config</>}
        </button>
        {genError && <div className="text-danger text-xs bg-danger/10 border border-danger/30 rounded p-2">{genError}</div>}
        {genResult && (
          <div className="flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <span className="text-primary text-xs">✓ Config generated for <b>{genResult.name}</b></span>
              <div className="flex gap-2">
                <button onClick={() => copy(genResult.config_json, 'cfg')}
                  className="flex items-center gap-1 text-[10px] text-muted hover:text-primary">
                  {copiedItem === 'cfg' ? <><CheckCheck size={10} className="text-primary"/>Copied</> : <><Copy size={10}/>Copy</>}
                </button>
                <button onClick={downloadConfig}
                  className="flex items-center gap-1 text-[10px] text-accent hover:text-primary">
                  <Download size={10}/> Download .cfg
                </button>
              </div>
            </div>
            <div className="text-[10px] text-muted bg-bg border border-border rounded p-2 font-mono">
              Save as: <span className="text-text">{genResult.save_path}</span><br/>
              Put in: <span className="text-text">~/.sudosoc-client/configs/</span><br/>
              Run: <span className="text-accent">./sudosoc-client</span>
            </div>
          </div>
        )}
      </section>

      {/* ── AI Provider Configuration ───────────────────────────────────── */}
      <section className="rounded-lg border border-border bg-surface p-4 flex flex-col gap-3">
        <div className="flex items-center justify-between">
          <h3 className="text-xs uppercase tracking-widest text-muted flex items-center gap-1.5">
            <Bot size={12} className="text-primary" /> AI Copilot Configuration
          </h3>
          {aiStatus?.configured ? (
            <div className="flex items-center gap-1.5 text-[10px] text-primary">
              <CheckCircle size={10} /> {aiStatus.provider} · {aiStatus.model}
            </div>
          ) : (
            <div className="flex items-center gap-1.5 text-[10px] text-warn">
              <AlertCircle size={10} /> Not configured
            </div>
          )}
        </div>

        <p className="text-[10px] text-muted">
          Configure your AI provider to enable the AI Copilot tab. The API key is stored in the server config file.
        </p>

        {/* Provider selector */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-1.5">
          {AI_PROVIDERS.map(p => (
            <button key={p.id} onClick={() => { setAiProvider(p.id); setAiModel(''); setAiBaseURL('') }}
              className={`py-2 px-3 rounded border text-[11px] transition-colors ${
                aiProvider === p.id
                  ? 'border-primary bg-primary/10 text-primary font-semibold'
                  : 'border-border text-muted hover:border-muted'
              }`}>
              {p.label}
            </button>
          ))}
        </div>

        {/* API Key */}
        <div>
          <label className="text-[10px] text-muted mb-1 block">
            API Key
            {aiStatus?.api_key_masked && <span className="text-primary ml-2">current: {aiStatus.api_key_masked}</span>}
          </label>
          <div className="flex gap-2">
            <div className="relative flex-1">
              <input
                type={aiKeyShow ? 'text' : 'password'}
                value={aiKey}
                onChange={e => setAiKey(e.target.value)}
                placeholder={aiStatus?.api_key_masked ? 'Leave blank to keep current key' : (currentProvider?.placeholder ?? 'your-api-key')}
                className="w-full bg-bg border border-border rounded px-3 py-1.5 text-xs text-text font-mono focus:border-primary outline-none pr-8" />
              <button onClick={() => setAiKeyShow(v => !v)}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-muted hover:text-text">
                {aiKeyShow ? <EyeOff size={12} /> : <Eye size={12} />}
              </button>
            </div>
          </div>
        </div>

        {/* Model */}
        <div className="grid grid-cols-2 gap-2">
          <div>
            <label className="text-[10px] text-muted mb-1 block">Model</label>
            {currentProvider && currentProvider.models.length > 0 ? (
              <select value={aiModel} onChange={e => setAiModel(e.target.value)}
                className="w-full bg-bg border border-border rounded px-2 py-1.5 text-xs text-text focus:border-primary outline-none">
                <option value="">Auto-select</option>
                {currentProvider.models.map(m => <option key={m} value={m}>{m}</option>)}
              </select>
            ) : (
              <input value={aiModel} onChange={e => setAiModel(e.target.value)}
                placeholder="e.g. gpt-4o, llama-3.1-70b"
                className="w-full bg-bg border border-border rounded px-2 py-1.5 text-xs text-text font-mono focus:border-primary outline-none" />
            )}
          </div>
          {aiProvider === 'openai-compat' && (
            <div>
              <label className="text-[10px] text-muted mb-1 block">Base URL</label>
              <input value={aiBaseURL} onChange={e => setAiBaseURL(e.target.value)}
                placeholder="https://your-endpoint/v1"
                className="w-full bg-bg border border-border rounded px-2 py-1.5 text-xs text-text font-mono focus:border-primary outline-none" />
            </div>
          )}
        </div>

        {/* Save */}
        <button onClick={saveAI} disabled={aiSaving}
          className="flex items-center justify-center gap-2 py-2 rounded border border-primary/40 text-primary bg-primary/10 hover:bg-primary/20 text-xs font-semibold disabled:opacity-40 transition-colors">
          {aiSaving ? <><Loader size={12} className="animate-spin" /> Saving…</> : <><Bot size={12} /> Save AI Configuration</>}
        </button>

        {aiMsg && (
          <div className={`flex items-center gap-2 p-2 rounded text-xs ${aiMsg.ok ? 'text-primary bg-primary/10 border border-primary/30' : 'text-danger bg-danger/10 border border-danger/30'}`}>
            {aiMsg.ok ? <CheckCircle size={12} /> : <AlertCircle size={12} />}
            {aiMsg.text}
          </div>
        )}

        {/* Quick docs */}
        <div className="text-[10px] text-muted bg-bg border border-border/40 rounded p-2 font-mono">
          <div className="text-text font-semibold mb-1">Quick setup (OpenRouter — recommended):</div>
          <div>1. Sign up at <span className="text-primary">openrouter.ai</span></div>
          <div>2. Create API key at <span className="text-primary">openrouter.ai/keys</span></div>
          <div>3. Paste key above · Select model · Save · Restart server</div>
        </div>
      </section>

      {/* ── Default ports ───────────────────────────────────────────────── */}
      <section className="rounded-lg border border-border bg-surface p-4 flex flex-col gap-3">
        <h3 className="text-xs uppercase tracking-widest text-muted flex items-center gap-1.5">
          <Globe size={12} /> Default Ports
        </h3>
        <div className="grid grid-cols-2 gap-x-6 gap-y-1.5 text-xs">
          {[
            { proto: 'mTLS C2',     port: '31337', color: 'text-primary' },
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
