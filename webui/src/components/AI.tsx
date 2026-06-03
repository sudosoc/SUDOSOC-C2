import { useState, useRef, useEffect, useCallback } from 'react'
import { useAPI, apiPost, apiFetch } from '../hooks/useAPI'
import type { Session, Beacon } from '../types'
import {
  Bot, Send, Trash2, AlertTriangle, Loader, Copy, CheckCheck,
  Zap, Shield, Search, Target, Key, Globe, RefreshCw,
  ChevronRight, Info, AlertCircle, CheckCircle,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

interface Message {
  role:    'user' | 'assistant' | 'system'
  content: string
  ts:      string
  pending?: boolean
  error?:  boolean
}

interface AIStatus {
  configured: boolean
  provider?:  string
  model?:     string
  message?:   string
}

interface AIChatResp {
  reply:     string
  model?:    string
  provider?: string
  error?:    string
}

// ─── Quick objective prompts ──────────────────────────────────────────────────

const OBJECTIVES = [
  { id: 'privesc',    icon: '⬆️', label: 'Privilege Escalation', color: 'text-danger',
    prompt: 'What are the best privilege escalation paths from current sessions? Analyze OS, users, and running services.' },
  { id: 'creds',      icon: '🔑', label: 'Credential Harvest',   color: 'text-warn',
    prompt: 'Suggest the most effective credential harvesting techniques for the connected sessions. Include LSASS, SAM, browser creds, and cloud tokens.' },
  { id: 'lateral',    icon: '↔️', label: 'Lateral Movement',    color: 'text-accent',
    prompt: 'Plan lateral movement from current sessions. Identify targets, pivoting techniques, and SMB/WMI/PSExec options.' },
  { id: 'persist',    icon: '🔒', label: 'Persistence',          color: 'text-primary',
    prompt: 'Recommend persistence mechanisms for each connected session OS. Include fileless options and AD persistence if applicable.' },
  { id: 'exfil',      icon: '📤', label: 'Data Exfiltration',    color: 'text-warn',
    prompt: 'What data exfiltration strategies are available via current C2 channels? Include covert channels and data staging techniques.' },
  { id: 'da',         icon: '👑', label: 'Domain Admin',         color: 'text-danger',
    prompt: 'Plan the attack path to Domain Admin from current sessions. Include Kerberoasting, ADCS ESC attacks, Shadow Credentials, and DCSync.' },
  { id: 'android',    icon: '🤖', label: 'Android Analysis',     color: 'text-primary',
    prompt: 'Analyze connected Android sessions and suggest what high-value data can be extracted. Include SMS, contacts, location, credentials, and app data.' },
  { id: 'evasion',    icon: '🌫️', label: 'Detection Evasion',   color: 'text-muted',
    prompt: 'What OPSEC improvements can be made to current implants and C2 channels? Analyze network traffic patterns and suggest evasion improvements.' },
]

// ─── Markdown-like renderer ───────────────────────────────────────────────────

function renderContent(text: string) {
  // Simple code block + bold highlighting
  const parts = text.split(/(```[\s\S]*?```|`[^`]+`|\*\*[^*]+\*\*)/g)
  return parts.map((part, i) => {
    if (part.startsWith('```') && part.endsWith('```')) {
      const code = part.slice(3, -3).replace(/^\w+\n/, '')
      return <pre key={i} className="bg-bg border border-border rounded p-2 my-1 overflow-x-auto text-[10px] font-mono text-primary">{code}</pre>
    }
    if (part.startsWith('`') && part.endsWith('`')) {
      return <code key={i} className="bg-bg border border-border px-1 rounded text-primary text-[10px]">{part.slice(1,-1)}</code>
    }
    if (part.startsWith('**') && part.endsWith('**')) {
      return <strong key={i} className="text-text font-semibold">{part.slice(2,-2)}</strong>
    }
    return <span key={i}>{part}</span>
  })
}

// ─── Component ────────────────────────────────────────────────────────────────

export default function AI() {
  const { data: sessions } = useAPI<Session[]>('/api/sessions', 10_000)
  const { data: beacons  } = useAPI<Beacon[]>('/api/beacons',   12_000)
  const [status,  setStatus]  = useState<AIStatus | null>(null)
  const [messages,setMessages]= useState<Message[]>([])
  const [input,   setInput]   = useState('')
  const [liveMode,setLiveMode]= useState(false)
  const [copied,  setCopied]  = useState<number | null>(null)
  const bottomRef = useRef<HTMLDivElement>(null)
  const inputRef  = useRef<HTMLTextAreaElement>(null)

  // ── Load AI status ────────────────────────────────────────────────────────
  useEffect(() => {
    apiFetch<AIStatus>('/api/ai/status').then(setStatus).catch(() => {
      setStatus({ configured: false, message: 'Could not reach AI endpoint' })
    })
  }, [])

  // ── Auto scroll ────────────────────────────────────────────────────────────
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  // ── Build C2 context string ───────────────────────────────────────────────
  function buildContext() {
    const s = sessions ?? []
    const b = beacons  ?? []
    if (s.length === 0 && b.length === 0) return ''
    const lines: string[] = []
    if (s.length > 0) {
      lines.push(`Active sessions (${s.length}):`)
      s.slice(0,5).forEach(x => lines.push(`  • ${x.name}  ${x.os}/${x.arch}  ${x.username}@${x.hostname}  via ${x.transport}`))
    }
    if (b.length > 0) {
      lines.push(`Active beacons (${b.length}):`)
      b.slice(0,3).forEach(x => lines.push(`  • ${x.name}  ${x.os}/${x.arch}  ${x.username}@${x.hostname}`))
    }
    return lines.join('\n')
  }

  // ── Send message ──────────────────────────────────────────────────────────
  async function send(overrideInput?: string) {
    const content = (overrideInput ?? input).trim()
    if (!content) return
    setInput('')

    const userMsg: Message = { role: 'user', content, ts: new Date().toLocaleTimeString() }
    const pendingMsg: Message = { role: 'assistant', content: '', ts: '', pending: true }

    setMessages(prev => [...prev, userMsg, pendingMsg])

    // Build messages history for API
    const history = [...messages.filter(m => m.role !== 'system' && !m.error && !m.pending), userMsg]
      .map(m => ({ role: m.role, content: m.content }))

    try {
      const res = await apiPost<AIChatResp>('/api/ai/chat', {
        messages: history,
        context:  buildContext(),
      })

      const reply: Message = {
        role:    'assistant',
        content: res.reply || res.error || '(empty response)',
        ts:      new Date().toLocaleTimeString(),
        error:   !!res.error,
      }
      setMessages(prev => [...prev.slice(0, -1), reply]) // replace pending
    } catch(e) {
      const errMsg = String(e).replace('Error: 503: ', '').replace('Error: 500: ', '')
      setMessages(prev => [
        ...prev.slice(0, -1),
        { role: 'assistant', content: `⚠️ ${errMsg}`, ts: new Date().toLocaleTimeString(), error: true }
      ])
    }
  }

  function clearChat() { setMessages([]) }

  function copyMsg(i: number, text: string) {
    navigator.clipboard.writeText(text)
    setCopied(i); setTimeout(() => setCopied(null), 1500)
  }

  const isThinking = messages.length > 0 && messages[messages.length - 1]?.pending

  return (
    <div className="flex h-full gap-3">

      {/* ── Left panel: controls + objectives ─────────────────────────── */}
      <div className="w-56 shrink-0 flex flex-col gap-2">

        {/* AI Status */}
        <div className={`rounded-xl border p-3 flex flex-col gap-1.5 ${
          status?.configured
            ? 'border-primary/30 bg-primary/5'
            : 'border-warn/30 bg-warn/5'
        }`}>
          <div className="flex items-center gap-2 text-xs font-semibold">
            <Bot size={13} className={status?.configured ? 'text-primary' : 'text-warn'} />
            <span className={status?.configured ? 'text-primary' : 'text-warn'}>
              {status === null ? 'Checking…' : status.configured ? 'AI Connected' : 'AI Not Configured'}
            </span>
          </div>
          {status?.configured && (
            <div className="text-[9px] text-muted">
              <div>Provider: <span className="text-text">{status.provider}</span></div>
              <div>Model: <span className="text-text font-mono">{status.model}</span></div>
            </div>
          )}
          {status && !status.configured && (
            <div className="text-[9px] text-warn/80">
              Configure an AI provider in server config to enable live AI.
            </div>
          )}
        </div>

        {/* Live mode toggle */}
        <div className="rounded-xl border border-border bg-surface p-3 flex flex-col gap-2">
          <label className="flex items-center justify-between cursor-pointer">
            <span className="text-xs text-muted">Live Execution</span>
            <div className="relative" onClick={() => setLiveMode(v => !v)}>
              <div className={`w-8 h-4 rounded-full transition-colors ${liveMode ? 'bg-danger' : 'bg-border'}`}>
                <div className={`absolute top-0.5 w-3 h-3 rounded-full bg-bg transition-transform ${liveMode ? 'translate-x-4' : 'translate-x-0.5'}`} />
              </div>
            </div>
          </label>
          <p className="text-[9px] text-muted">
            {liveMode
              ? '⚠️ LIVE — agent may suggest real execution commands'
              : 'DRY-RUN — analysis & suggestions only'}
          </p>
        </div>

        {/* Context info */}
        <div className="rounded-xl border border-border bg-surface p-3">
          <div className="text-[9px] text-muted uppercase tracking-widest mb-1.5">Live Context</div>
          <div className="flex flex-col gap-1 text-[10px]">
            <div className="flex items-center justify-between">
              <span className="text-muted">Sessions</span>
              <span className="text-primary font-semibold">{sessions?.length ?? 0}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted">Beacons</span>
              <span className="text-warn font-semibold">{beacons?.length ?? 0}</span>
            </div>
          </div>
          {(sessions?.length ?? 0) > 0 && (
            <div className="mt-2 flex flex-col gap-0.5">
              {sessions!.slice(0,3).map(s => (
                <div key={s.id} className="text-[9px] text-muted truncate">
                  {s.os?.toLowerCase().includes('windows') ? '🪟' :
                   s.os?.toLowerCase().includes('android') ? '🤖' : '🐧'}
                  {' '}{s.name}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Quick objectives */}
        <div className="flex-1 overflow-y-auto flex flex-col gap-1">
          <div className="text-[9px] text-muted uppercase tracking-widest px-1">Quick Objectives</div>
          {OBJECTIVES.map(o => (
            <button key={o.id} onClick={() => send(o.prompt)}
              disabled={isThinking}
              className="flex items-center gap-2 px-2.5 py-2 rounded-lg border border-border bg-surface hover:border-primary/40 hover:bg-primary/5 transition-colors text-left disabled:opacity-40">
              <span className="text-sm shrink-0">{o.icon}</span>
              <span className={`text-[10px] ${o.color}`}>{o.label}</span>
              <ChevronRight size={9} className="text-muted ml-auto shrink-0" />
            </button>
          ))}
        </div>
      </div>

      {/* ── Right panel: chat ──────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col gap-2 min-w-0">

        {/* Header */}
        <div className="flex items-center justify-between shrink-0">
          <h2 className="text-primary font-bold text-lg flex items-center gap-2">
            <Bot size={18} /> AI Copilot
            {isThinking && <Loader size={14} className="text-primary animate-spin" />}
          </h2>
          <button onClick={clearChat} className="flex items-center gap-1 text-muted hover:text-danger text-[11px] px-2 py-1 rounded border border-border transition-colors">
            <Trash2 size={11} /> Clear
          </button>
        </div>

        {/* Warnings */}
        {liveMode && (
          <div className="flex items-center gap-2 bg-danger/10 border border-danger/30 rounded-lg p-2.5 text-xs text-danger shrink-0">
            <AlertTriangle size={13} />
            <span>LIVE MODE — AI responses may suggest commands that execute on real sessions.</span>
          </div>
        )}
        {status !== null && !status.configured && (
          <div className="flex items-center gap-2 bg-warn/10 border border-warn/30 rounded-lg p-2.5 text-xs text-warn shrink-0">
            <AlertCircle size={13} />
            <span>AI provider not configured. Configure OpenRouter, OpenAI, or compatible provider in server settings.</span>
          </div>
        )}

        {/* Chat window */}
        <div className="flex-1 min-h-0 overflow-y-auto flex flex-col gap-2 rounded-xl border border-border bg-surface p-3">

          {messages.length === 0 && (
            <div className="flex-1 flex flex-col items-center justify-center gap-4 text-center py-8">
              <div className="w-16 h-16 rounded-2xl bg-primary/10 border border-primary/30 flex items-center justify-center">
                <Bot size={28} className="text-primary" />
              </div>
              <div>
                <p className="text-text text-sm font-semibold">SUDOSOC-C2 AI Copilot</p>
                <p className="text-muted text-xs mt-1">Select an objective from the left or type a question.</p>
                <p className="text-muted text-xs mt-0.5">The AI has live context about your connected agents.</p>
              </div>
              <div className="flex flex-wrap gap-2 justify-center max-w-md">
                {['What sessions do I have?', 'Suggest privilege escalation', 'How to stay stealthy?'].map(q => (
                  <button key={q} onClick={() => send(q)}
                    className="px-3 py-1.5 rounded-full border border-primary/30 text-primary text-[11px] hover:bg-primary/10 transition-colors">
                    {q}
                  </button>
                ))}
              </div>
            </div>
          )}

          {messages.map((m, i) => (
            <div key={i} className={`flex flex-col gap-0.5 ${m.role === 'user' ? 'items-end' : 'items-start'}`}>
              <div className={`flex items-center gap-1.5 text-[9px] text-muted ${m.role === 'user' ? 'flex-row-reverse' : ''}`}>
                {m.role === 'assistant' && <Bot size={9} className="text-primary" />}
                <span>{m.role === 'user' ? 'operator' : 'copilot'}</span>
                {m.ts && <span>{m.ts}</span>}
              </div>
              <div className={`relative group max-w-[88%] px-3 py-2.5 rounded-xl text-[11px] leading-relaxed ${
                m.role === 'user'
                  ? 'bg-primary/15 border border-primary/25 text-text rounded-tr-sm'
                  : m.pending
                  ? 'bg-surface border border-border text-muted italic'
                  : m.error
                  ? 'bg-danger/10 border border-danger/30 text-danger rounded-tl-sm'
                  : 'bg-[#0d0d20] border border-border text-text rounded-tl-sm'
              }`}>
                {m.pending ? (
                  <span className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-primary animate-bounce" style={{ animationDelay: '0ms' }} />
                    <span className="w-1.5 h-1.5 rounded-full bg-primary animate-bounce" style={{ animationDelay: '150ms' }} />
                    <span className="w-1.5 h-1.5 rounded-full bg-primary animate-bounce" style={{ animationDelay: '300ms' }} />
                  </span>
                ) : (
                  <div className="whitespace-pre-wrap">{renderContent(m.content)}</div>
                )}
                {/* Copy button */}
                {!m.pending && m.role === 'assistant' && (
                  <button onClick={() => copyMsg(i, m.content)}
                    className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-all text-muted hover:text-primary">
                    {copied === i ? <CheckCheck size={10} className="text-primary" /> : <Copy size={10} />}
                  </button>
                )}
              </div>
            </div>
          ))}
          <div ref={bottomRef} />
        </div>

        {/* Input area */}
        <div className="flex gap-2 shrink-0">
          <textarea
            ref={inputRef}
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault()
                send()
              }
            }}
            placeholder={status?.configured
              ? 'Ask the AI copilot… (Enter to send, Shift+Enter for newline)'
              : 'AI not configured — configure a provider in server settings'}
            rows={2}
            className="flex-1 bg-surface border border-border rounded-xl px-3 py-2 text-xs text-text placeholder-muted focus:border-primary outline-none font-mono resize-none"
          />
          <button onClick={() => send()}
            disabled={!input.trim() || isThinking || !status?.configured}
            className="px-4 rounded-xl bg-primary/15 border border-primary/40 text-primary hover:bg-primary/25 transition-colors disabled:opacity-40 self-end py-2">
            {isThinking ? <Loader size={15} className="animate-spin" /> : <Send size={15} />}
          </button>
        </div>
        <div className="text-[9px] text-muted text-center">
          For authorized security testing only · All requests include live C2 context
        </div>
      </div>
    </div>
  )
}
