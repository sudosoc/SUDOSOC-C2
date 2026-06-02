import { useState } from 'react'
import { useAPI } from '../hooks/useAPI'
import type { Session, Beacon, Listener, LootItem, Stats } from '../types'
import { FileText, Download, RefreshCw, Printer } from 'lucide-react'

// ─── Report generation ───────────────────────────────────────────────────────

function generateHTML(
  stats: Stats | null,
  sessions: Session[],
  beacons: Beacon[],
  listeners: Listener[],
  loot: LootItem[],
  opName: string,
  notes: string
): string {
  const now = new Date().toLocaleString()
  const fmtTime = (ts: number) => ts ? new Date(ts * 1000).toLocaleString() : '—'
  const fmtBytes = (b: number) => b >= 1 << 20 ? `${(b / (1 << 20)).toFixed(1)} MB` : `${(b / 1024).toFixed(1)} KB`

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>SUDOSOC-C2 — Engagement Report</title>
<style>
  body { font-family: 'Consolas', monospace; background: #0a0a0f; color: #e0e0e0; margin: 0; padding: 2rem; }
  h1 { color: #00ff88; font-size: 1.8rem; border-bottom: 1px solid #222244; padding-bottom: 1rem; }
  h2 { color: #00d4ff; font-size: 1.1rem; margin-top: 2rem; border-left: 3px solid #00d4ff; padding-left: 0.8rem; }
  h3 { color: #ffaa00; font-size: 0.9rem; margin-top: 1rem; }
  table { width: 100%; border-collapse: collapse; margin-top: 0.5rem; font-size: 0.8rem; }
  th { background: #111122; color: #aaaacc; text-align: left; padding: 0.5rem 0.8rem; border-bottom: 1px solid #222244; text-transform: uppercase; font-size: 0.7rem; letter-spacing: 0.05em; }
  td { padding: 0.4rem 0.8rem; border-bottom: 1px solid #1a1a2e; }
  tr:hover td { background: #111122; }
  .stat { display: inline-block; background: #111122; border: 1px solid #222244; border-radius: 8px; padding: 0.8rem 1.5rem; margin: 0.3rem; text-align: center; }
  .stat-n { font-size: 2rem; font-weight: bold; color: #00ff88; }
  .stat-l { font-size: 0.75rem; color: #555577; text-transform: uppercase; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; border: 1px solid; }
  .badge-ok   { border-color: #00ff88; color: #00ff88; }
  .badge-dead { border-color: #ff4444; color: #ff4444; }
  .badge-pending   { border-color: #ffaa00; color: #ffaa00; }
  .badge-completed { border-color: #00ff88; color: #00ff88; }
  .meta { color: #555577; font-size: 0.8rem; margin-bottom: 2rem; }
  .notes { background: #111122; border: 1px solid #222244; border-radius: 8px; padding: 1rem; margin-top: 1rem; white-space: pre-wrap; font-size: 0.85rem; color: #aaaacc; }
  @media print { body { background: white; color: black; } h1,h2 { color: black; } .stat-n { color: #007700; } }
</style>
</head>
<body>
<h1>SUDOSOC-C2 — Engagement Report</h1>
<div class="meta">
  Generated: ${now}<br/>
  Operation: ${opName || 'Unnamed'}<br/>
  Uptime: ${stats?.uptime ?? '—'}
</div>

<h2>Executive Summary</h2>
<div>
  <div class="stat"><div class="stat-n">${sessions.length}</div><div class="stat-l">Active Sessions</div></div>
  <div class="stat"><div class="stat-n">${beacons.length}</div><div class="stat-l">Beacons</div></div>
  <div class="stat"><div class="stat-n">${listeners.length}</div><div class="stat-l">Listeners</div></div>
  <div class="stat"><div class="stat-n">${loot.length}</div><div class="stat-l">Loot Items</div></div>
</div>

<h2>Active Sessions</h2>
${sessions.length === 0 ? '<p style="color:#555577">No active sessions at report time.</p>' : `
<table>
<tr><th>Name</th><th>ID</th><th>Host</th><th>User</th><th>OS / Arch</th><th>Transport</th><th>Address</th><th>Last Seen</th><th>Status</th></tr>
${sessions.map(s => `
<tr>
  <td><b style="color:#00ff88">${s.name}</b></td>
  <td style="color:#555577;font-size:.75rem">${s.id.slice(0,8)}</td>
  <td>${s.hostname}</td>
  <td style="color:#00d4ff">${s.username}</td>
  <td>${s.os}/${s.arch}</td>
  <td><span class="badge badge-ok">${s.transport}</span></td>
  <td style="color:#555577;font-size:.75rem">${s.remote_address}</td>
  <td style="font-size:.75rem">${fmtTime(s.last_checkin)}</td>
  <td><span class="badge ${s.is_dead ? 'badge-dead' : 'badge-ok'}">${s.is_dead ? 'dead' : 'live'}</span></td>
</tr>`).join('')}
</table>`}

<h2>Beacons</h2>
${beacons.length === 0 ? '<p style="color:#555577">No beacons.</p>' : `
<table>
<tr><th>Name</th><th>ID</th><th>Host</th><th>User</th><th>OS</th><th>Transport</th><th>Interval</th><th>Last Checkin</th><th>Next Checkin</th></tr>
${beacons.map(b => `
<tr>
  <td><b style="color:#ffaa00">${b.name}</b></td>
  <td style="color:#555577;font-size:.75rem">${b.id.slice(0,8)}</td>
  <td>${b.hostname}</td>
  <td>${b.username}</td>
  <td>${b.os}</td>
  <td>${b.transport}</td>
  <td>${(b.interval / 1000).toFixed(0)}s</td>
  <td style="font-size:.75rem">${fmtTime(b.last_checkin)}</td>
  <td style="font-size:.75rem">${fmtTime(b.next_checkin)}</td>
</tr>`).join('')}
</table>`}

<h2>Listeners</h2>
${listeners.length === 0 ? '<p style="color:#555577">No listeners.</p>' : `
<table>
<tr><th>#</th><th>Name</th><th>Protocol</th><th>Port</th><th>Domains</th></tr>
${listeners.map(l => `
<tr>
  <td style="color:#555577">${l.id}</td>
  <td>${l.name}</td>
  <td><span class="badge badge-ok">${l.protocol}</span></td>
  <td style="font-size:1.1rem;font-weight:bold;color:#aa88ff">${l.port}</td>
  <td style="font-size:.75rem;color:#555577">${(l.domains ?? []).join(', ') || '—'}</td>
</tr>`).join('')}
</table>`}

<h2>Loot</h2>
${loot.length === 0 ? '<p style="color:#555577">No loot collected.</p>' : `
<table>
<tr><th>ID</th><th>Name</th><th>Type</th><th>Size</th></tr>
${loot.map(l => `
<tr>
  <td style="color:#555577;font-size:.75rem">${l.id.slice(0,8)}</td>
  <td>${l.name}</td>
  <td>${['file','binary','text'][l.file_type] ?? 'file'}</td>
  <td>${fmtBytes(l.size)}</td>
</tr>`).join('')}
</table>`}

${notes ? `<h2>Operator Notes</h2><div class="notes">${notes.replace(/</g,'&lt;')}</div>` : ''}

<div style="margin-top:3rem;color:#333355;font-size:.75rem;border-top:1px solid #1a1a2e;padding-top:1rem">
  SUDOSOC-C2 v2.0.0 — For authorized use only — ${now}
</div>
</body>
</html>`
}

// ─── Component ────────────────────────────────────────────────────────────────

export default function Reports() {
  const { data: stats }     = useAPI<Stats>('/api/stats')
  const { data: sessions }  = useAPI<Session[]>('/api/sessions')
  const { data: beacons }   = useAPI<Beacon[]>('/api/beacons')
  const { data: listeners } = useAPI<Listener[]>('/api/listeners')
  const { data: loot }      = useAPI<LootItem[]>('/api/loot')

  const [opName,  setOpName]  = useState('')
  const [notes,   setNotes]   = useState('')
  const [preview, setPreview] = useState(false)

  function buildReport() {
    return generateHTML(stats, sessions ?? [], beacons ?? [], listeners ?? [], loot ?? [], opName, notes)
  }

  function downloadReport() {
    const html = buildReport()
    const blob = new Blob([html], { type: 'text/html' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href     = url
    a.download = `sudosoc-report-${new Date().toISOString().slice(0,10)}.html`
    a.click()
    URL.revokeObjectURL(url)
  }

  function printReport() {
    const win = window.open('', '_blank')
    if (!win) return
    win.document.write(buildReport())
    win.document.close()
    win.print()
  }

  return (
    <div className="flex flex-col gap-6 h-full max-w-3xl mx-auto w-full">

      {/* ── Header ────────────────────────────────────────────────── */}
      <div>
        <h2 className="text-primary font-bold text-lg flex items-center gap-2">
          <FileText size={18} /> Reports
        </h2>
        <p className="text-muted text-xs mt-1">Generate HTML engagement reports — save as HTML or print to PDF</p>
      </div>

      {/* ── Snapshot ──────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: 'Sessions',  value: sessions?.length  ?? 0, color: 'text-primary' },
          { label: 'Beacons',   value: beacons?.length   ?? 0, color: 'text-accent'  },
          { label: 'Listeners', value: listeners?.length ?? 0, color: 'text-warn'    },
          { label: 'Loot',      value: loot?.length      ?? 0, color: 'text-purple'  },
        ].map(s => (
          <div key={s.label} className="rounded-lg border border-border bg-surface p-3 text-center">
            <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
            <div className="text-muted text-[10px] mt-0.5">{s.label}</div>
          </div>
        ))}
      </div>

      {/* ── Options ───────────────────────────────────────────────── */}
      <div className="rounded-lg border border-border bg-surface p-4 flex flex-col gap-4">
        <h3 className="text-xs uppercase tracking-widest text-muted">Report Options</h3>
        <div>
          <label className="text-[10px] text-muted mb-1 block">Operation Name</label>
          <input value={opName} onChange={e => setOpName(e.target.value)}
            placeholder="e.g. Pentest Q3-2026"
            className="w-full bg-bg border border-border rounded px-3 py-2 text-xs text-text placeholder-muted focus:border-primary outline-none" />
        </div>
        <div>
          <label className="text-[10px] text-muted mb-1 block">Operator Notes</label>
          <textarea value={notes} onChange={e => setNotes(e.target.value)}
            rows={4}
            placeholder="Key findings, attack paths, recommendations…"
            className="w-full bg-bg border border-border rounded px-3 py-2 text-xs text-text placeholder-muted focus:border-primary outline-none resize-none font-mono" />
        </div>
      </div>

      {/* ── Actions ───────────────────────────────────────────────── */}
      <div className="flex flex-wrap gap-3">
        <button onClick={downloadReport}
          className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-primary/10 border border-primary/40 text-primary font-semibold text-sm hover:bg-primary/20 transition-colors">
          <Download size={15} /> Download HTML
        </button>
        <button onClick={printReport}
          className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-accent/10 border border-accent/40 text-accent font-semibold text-sm hover:bg-accent/20 transition-colors">
          <Printer size={15} /> Print / Save as PDF
        </button>
        <button onClick={() => setPreview(!preview)}
          className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-border/30 border border-border text-muted text-sm hover:text-text transition-colors">
          <FileText size={15} /> {preview ? 'Hide' : 'Preview'}
        </button>
      </div>

      {/* ── Inline Preview ────────────────────────────────────────── */}
      {preview && (
        <div className="flex-1 min-h-[400px] rounded-lg border border-border overflow-hidden">
          <iframe
            srcDoc={buildReport()}
            className="w-full h-full min-h-[400px]"
            title="Report Preview"
            sandbox="allow-same-origin"
          />
        </div>
      )}
    </div>
  )
}
