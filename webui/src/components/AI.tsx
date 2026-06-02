import { useState, useRef, useEffect } from 'react'
import { Bot, Send, Trash2, AlertTriangle } from 'lucide-react'

interface Message {
  role: 'user' | 'assistant' | 'system'
  content: string
  ts: string
}

const OBJECTIVES = [
  'reach_domain_admin',
  'extract_credentials',
  'full_compromise',
  'lateral_movement',
  'persistence',
  'custom',
]

export default function AI() {
  const [messages, setMessages]   = useState<Message[]>([
    {
      role: 'system',
      content: 'SUDOSOC-C2 Autonomous Agent — LLM-powered red team automation.\n\nSelect an objective and let the agent plan and execute your operation. The agent uses live session context to make decisions.',
      ts: new Date().toLocaleTimeString(),
    }
  ])
  const [input,       setInput]     = useState('')
  const [objective,   setObjective] = useState('reach_domain_admin')
  const [dryRun,      setDryRun]    = useState(true)
  const [isThinking,  setThinking]  = useState(false)
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  async function sendMessage() {
    if (!input.trim() && !isThinking) return
    const userMsg: Message = { role: 'user', content: input, ts: new Date().toLocaleTimeString() }
    setMessages(prev => [...prev, userMsg])
    setInput('')
    setThinking(true)

    // Simulate AI response (real implementation hooks into server AI endpoint)
    setTimeout(() => {
      const reply: Message = {
        role: 'assistant',
        content: buildAgentResponse(userMsg.content, objective, dryRun),
        ts: new Date().toLocaleTimeString(),
      }
      setMessages(prev => [...prev, reply])
      setThinking(false)
    }, 1200)
  }

  function startObjective() {
    const msg: Message = {
      role: 'user',
      content: `Start objective: ${objective}${dryRun ? ' (dry-run mode)' : ''}`,
      ts: new Date().toLocaleTimeString(),
    }
    setMessages(prev => [...prev, msg])
    setThinking(true)
    setTimeout(() => {
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: buildObjectivePlan(objective, dryRun),
        ts: new Date().toLocaleTimeString(),
      }])
      setThinking(false)
    }, 1500)
  }

  function clearChat() {
    setMessages([{
      role: 'system',
      content: 'Chat cleared. Ready for new operation.',
      ts: new Date().toLocaleTimeString(),
    }])
  }

  return (
    <div className="flex flex-col h-full gap-4">

      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-primary font-bold text-lg flex items-center gap-2">
            <Bot size={18} /> Autonomous Agent
          </h2>
          <p className="text-muted text-xs mt-1">LLM-powered red team automation — GPT-4o / Llama local</p>
        </div>
        <button onClick={clearChat} className="flex items-center gap-1 text-muted hover:text-danger text-xs">
          <Trash2 size={12} /> Clear
        </button>
      </div>

      {/* ── Dry-run warning ─────────────────────────────────────────────── */}
      {!dryRun && (
        <div className="flex items-center gap-2 bg-danger/10 border border-danger/30 rounded p-2 text-xs text-danger">
          <AlertTriangle size={12} />
          <span>LIVE MODE — agent will execute actions on real sessions. Ensure you have authorization.</span>
        </div>
      )}

      {/* ── Objective selector ──────────────────────────────────────────── */}
      <div className="flex flex-wrap gap-3 items-center rounded-lg border border-border bg-surface p-3">
        <div className="flex-1 min-w-[200px]">
          <label className="text-[10px] text-muted mb-1 block">Objective</label>
          <select value={objective} onChange={e => setObjective(e.target.value)}
            className="w-full bg-bg border border-border rounded px-2 py-1.5 text-xs text-text focus:border-primary outline-none">
            {OBJECTIVES.map(o => <option key={o} value={o}>{o}</option>)}
          </select>
        </div>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-1.5 cursor-pointer">
            <div className="relative">
              <input type="checkbox" checked={dryRun} onChange={e => setDryRun(e.target.checked)} className="sr-only" />
              <div className={`w-8 h-4 rounded-full transition-colors ${dryRun ? 'bg-primary' : 'bg-danger'}`}>
                <div className={`absolute top-0.5 w-3 h-3 rounded-full bg-bg transition-transform ${dryRun ? 'translate-x-4' : 'translate-x-0.5'}`} />
              </div>
            </div>
            <span className={`text-xs ${dryRun ? 'text-primary' : 'text-danger'}`}>
              {dryRun ? 'Dry-run' : 'Live'}
            </span>
          </label>
          <button onClick={startObjective}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-primary/10 border border-primary/40 text-primary text-xs hover:bg-primary/20 transition-colors">
            <Bot size={12} /> Start Agent
          </button>
        </div>
      </div>

      {/* ── Chat messages ───────────────────────────────────────────────── */}
      <div className="flex-1 min-h-0 overflow-y-auto flex flex-col gap-2 rounded-lg border border-border bg-surface p-3 font-mono text-xs">
        {messages.map((m, i) => (
          <div key={i} className={`flex flex-col gap-0.5 ${m.role === 'user' ? 'items-end' : 'items-start'}`}>
            <div className={`flex items-center gap-1.5 text-[10px] text-muted ${m.role === 'user' ? 'flex-row-reverse' : ''}`}>
              {m.role === 'assistant' && <Bot size={10} className="text-primary" />}
              <span>{m.role === 'system' ? 'system' : m.role === 'user' ? 'operator' : 'agent'}</span>
              <span>{m.ts}</span>
            </div>
            <div className={`max-w-[85%] px-3 py-2 rounded-lg text-[11px] whitespace-pre-wrap break-words ${
              m.role === 'user'
                ? 'bg-primary/10 border border-primary/20 text-text'
                : m.role === 'system'
                ? 'bg-border/40 text-muted italic'
                : 'bg-surface border border-border text-text'
            }`}>
              {m.content}
            </div>
          </div>
        ))}
        {isThinking && (
          <div className="flex items-center gap-2 text-muted text-[10px]">
            <Bot size={10} className="text-primary" />
            <span className="animate-pulse">Agent is thinking…</span>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* ── Input ───────────────────────────────────────────────────────── */}
      <div className="flex gap-2">
        <input
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && !e.shiftKey && sendMessage()}
          placeholder="Ask the agent anything, or give it a custom instruction…"
          className="flex-1 bg-surface border border-border rounded px-3 py-2 text-xs text-text placeholder-muted focus:border-primary outline-none font-mono"
        />
        <button onClick={sendMessage} disabled={!input.trim() || isThinking}
          className="px-3 py-2 rounded bg-primary/10 border border-primary/40 text-primary hover:bg-primary/20 transition-colors disabled:opacity-40">
          <Send size={14} />
        </button>
      </div>
    </div>
  )
}

// ─── Local response generators ────────────────────────────────────────────────

function buildAgentResponse(input: string, objective: string, dryRun: boolean): string {
  const mode = dryRun ? '[DRY-RUN] ' : '[LIVE] '
  if (input.toLowerCase().includes('status') || input.toLowerCase().includes('progress')) {
    return `${mode}Current objective: ${objective}\nStatus: Awaiting active sessions to begin enumeration.\n\nOnce an implant connects, I will:\n1. Enumerate the environment\n2. Identify privilege escalation paths\n3. Execute the ${objective} objective\n4. Report findings`
  }
  return `${mode}Understood. Processing your instruction in the context of objective: ${objective}.\n\nI'll analyze available sessions and plan the next steps accordingly.\nConnect an implant to a target to begin active operations.`
}

function buildObjectivePlan(objective: string, dryRun: boolean): string {
  const mode = dryRun ? 'DRY-RUN ' : 'LIVE '
  const plans: Record<string, string> = {
    reach_domain_admin: `[${mode}PLAN] reach_domain_admin\n\n1. Enumerate: AD users, groups, GPOs, ACLs\n2. Check: Kerberoastable accounts, AS-REP roasting\n3. Identify: ADCS misconfigurations (ESC1-ESC8)\n4. Attempt: Shadow Credentials, RBCD, DCSync\n5. Goal: DA credentials or equivalent access`,
    extract_credentials: `[${mode}PLAN] extract_credentials\n\n1. Dump: LSASS via PPL bypass + Mimikatz\n2. Extract: SAM hive, NTDS.dit if DC\n3. Harvest: Browser credentials, SSH keys, config files\n4. Collect: Cloud credentials (AWS/Azure/GCP)\n5. Exfil: Encrypted loot via C2 channel`,
    lateral_movement: `[${mode}PLAN] lateral_movement\n\n1. Map: Network subnets, open ports\n2. Identify: Lateral targets via SMB, WMI, PSExec\n3. Pass: PTH with harvested NTLM hashes\n4. Pivot: Via SMB named pipes (no internet)\n5. Establish: Persistence on each new host`,
    full_compromise: `[${mode}PLAN] full_compromise\n\n1. Phase 1: Initial access + privilege escalation\n2. Phase 2: Credential harvesting\n3. Phase 3: Lateral movement to DC\n4. Phase 4: Domain persistence (AdminSDHolder, golden ticket)\n5. Phase 5: Data exfiltration + cleanup`,
    persistence: `[${mode}PLAN] persistence\n\n1. Registry: Run keys, services\n2. Fileless: WMI subscriptions (zero disk footprint)\n3. UEFI: DXE driver (survives reinstall) if Ring-0 achieved\n4. AD: AdminSDHolder backdoor (auto-restores every 60 min)\n5. Scheduled: Task with SYSTEM privileges`,
  }
  return plans[objective] ?? `[${mode}PLAN] ${objective}\n\nCustom objective. Please describe the specific actions you want the agent to take.`
}
