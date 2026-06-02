import { useEffect, useRef, useState } from 'react'
import { useAPI } from '../hooks/useAPI'
import type { Session, Beacon, Listener } from '../types'
import { Map, RefreshCw, ZoomIn, ZoomOut, Maximize2 } from 'lucide-react'

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

// ─── Component ────────────────────────────────────────────────────────────────

export default function NetworkMap() {
  const { data: sessions,  refresh: rS } = useAPI<Session[]>('/api/sessions',  10_000)
  const { data: beacons,   refresh: rB } = useAPI<Beacon[]>('/api/beacons',    10_000)
  const { data: listeners, refresh: rL } = useAPI<Listener[]>('/api/listeners', 10_000)

  const svgRef   = useRef<SVGSVGElement>(null)
  const [scale,  setScale]  = useState(1)
  const [offset, setOffset] = useState({ x: 0, y: 0 })
  const [drag,   setDrag]   = useState<{ sx: number; sy: number; ox: number; oy: number } | null>(null)
  const [tooltip, setTooltip] = useState<{ node: Node; px: number; py: number } | null>(null)

  function refresh() { rS(); rB(); rL() }

  // ── Build nodes + links ──────────────────────────────────────────────────
  const W = 800, H = 500
  const cx = W / 2, cy = H / 2

  const nodes: Node[] = []
  const links: Link[] = []

  // C2 server at center
  nodes.push({ id: 'c2', label: 'SUDOSOC-C2', type: 'c2', x: cx, y: cy })

  // Listeners — circle above C2
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

  // Sessions — ring around C2
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

  // Beacons — outer ring
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

  // ── Mouse handlers ────────────────────────────────────────────────────────
  function onMouseDown(e: React.MouseEvent) {
    setDrag({ sx: e.clientX, sy: e.clientY, ox: offset.x, oy: offset.y })
    setTooltip(null)
  }
  function onMouseMove(e: React.MouseEvent) {
    if (!drag) return
    setOffset({ x: drag.ox + (e.clientX - drag.sx), y: drag.oy + (e.clientY - drag.sy) })
  }
  function onMouseUp() { setDrag(null) }

  function onNodeClick(node: Node, e: React.MouseEvent) {
    e.stopPropagation()
    setTooltip({ node, px: e.clientX, py: e.clientY })
  }

  const totalNodes = nodes.length - 1  // exclude C2

  return (
    <div className="flex flex-col gap-4 h-full">

      {/* ── Header ─────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-primary font-bold text-lg flex items-center gap-2">
            <Map size={18} /> Network Map
          </h2>
          <p className="text-muted text-xs mt-1">
            {sessList.length} sessions · {beaconList.length} beacons · {lstList.length} listeners
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
        <span className="text-muted">Click node for details · Drag to pan · Scroll/±buttons to zoom</span>
      </div>

      {/* ── SVG Canvas ─────────────────────────────────────────────── */}
      <div className="flex-1 min-h-0 rounded-lg border border-border bg-surface overflow-hidden relative cursor-grab active:cursor-grabbing"
        onClick={() => setTooltip(null)}>
        <svg ref={svgRef} className="w-full h-full select-none"
          onMouseDown={onMouseDown} onMouseMove={onMouseMove}
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
              return (
                <g key={node.id} onClick={e => onNodeClick(node, e)} className="cursor-pointer">
                  {/* Glow ring for C2 */}
                  {node.type === 'c2' && (
                    <circle cx={node.x} cy={node.y} r={r + 6} fill="none" stroke="#00ff88" strokeWidth="1" opacity="0.3" />
                  )}
                  {/* Node circle */}
                  <circle cx={node.x} cy={node.y} r={r}
                    fill={color + '22'} stroke={color} strokeWidth="1.5" />
                  {/* Icon */}
                  <text x={node.x} y={node.y - 1} textAnchor="middle" dominantBaseline="middle" fontSize={r * 0.9}>{icon}</text>
                  {/* Label */}
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
            <Map size={40} className="text-border" />
            <p className="text-muted text-sm">No nodes yet</p>
            <p className="text-muted text-xs">Start a listener and deploy implants to see the network map</p>
          </div>
        )}

        {/* Tooltip */}
        {tooltip && (
          <div className="absolute z-10 bg-surface border border-border rounded-lg p-3 text-xs shadow-lg min-w-[160px]"
            style={{ left: Math.min(tooltip.px + 10, window.innerWidth - 200), top: Math.min(tooltip.py + 10, window.innerHeight - 150) }}
            onClick={e => e.stopPropagation()}>
            <div className="font-bold mb-1" style={{ color: NODE_COLORS[tooltip.node.type] }}>
              {tooltip.node.label}
            </div>
            <div className="text-muted text-[10px] uppercase tracking-widest mb-1">{tooltip.node.type}</div>
            {tooltip.node.os && <div className="text-muted">OS: {tooltip.node.os} {OS_ICON[tooltip.node.os]}</div>}
            <div className="text-muted text-[9px] mt-1 font-mono">{tooltip.node.id}</div>
          </div>
        )}
      </div>
    </div>
  )
}
