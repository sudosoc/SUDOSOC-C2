import { useAPI } from '../hooks/useAPI'
import type { LootItem } from '../types'
import { Package, RefreshCw, FileText, Binary, File } from 'lucide-react'

function fmtBytes(b: number) {
  if (b >= 1 << 30) return `${(b / (1 << 30)).toFixed(1)} GB`
  if (b >= 1 << 20) return `${(b / (1 << 20)).toFixed(1)} MB`
  if (b >= 1 << 10) return `${(b / (1 << 10)).toFixed(1)} KB`
  return `${b} B`
}

const typeIcon: Record<number, React.ElementType> = {
  1: Binary,
  2: FileText,
}

const typeLabel: Record<number, string> = {
  0: 'file',
  1: 'binary',
  2: 'text',
}

export default function Loot() {
  const { data, loading, error, refresh } = useAPI<LootItem[]>('/api/loot', 15_000)
  const loot = data ?? []

  return (
    <div className="flex flex-col gap-4 h-full">
      <div className="flex items-center justify-between">
        <h2 className="text-primary font-bold text-lg flex items-center gap-2">
          <Package size={18} /> Loot
          <span className="text-muted text-sm font-normal ml-1">({loot.length})</span>
        </h2>
        <button
          onClick={refresh}
          className="flex items-center gap-1 text-muted hover:text-text text-xs px-2 py-1 rounded border border-border hover:border-muted transition-colors"
        >
          <RefreshCw size={12} /> Refresh
        </button>
      </div>

      {error && (
        <div className="text-danger text-xs bg-danger/10 border border-danger/30 rounded p-2">{error}</div>
      )}

      {loading && loot.length === 0 ? (
        <div className="text-muted text-sm">Loading…</div>
      ) : loot.length === 0 ? (
        <div className="flex-1 flex items-center justify-center text-muted text-sm">
          No loot collected yet.
        </div>
      ) : (
        <div className="flex-1 overflow-auto rounded-lg border border-border">
          <table className="w-full text-xs font-mono border-collapse">
            <thead>
              <tr className="bg-surface text-muted uppercase tracking-widest text-[10px]">
                {['Type','ID','Name','Size']
                  .map(h => (
                    <th key={h} className="text-left px-3 py-2 border-b border-border">{h}</th>
                  ))}
              </tr>
            </thead>
            <tbody>
              {loot.map(l => {
                const Icon = typeIcon[l.file_type] ?? File
                const label = typeLabel[l.file_type] ?? 'file'
                return (
                  <tr key={l.id} className="border-b border-border/40 hover:bg-surface/60 transition-colors">
                    <td className="px-3 py-2">
                      <span className="flex items-center gap-1.5 text-purple">
                        <Icon size={12} />
                        <span className="text-[10px] uppercase">{label}</span>
                      </span>
                    </td>
                    <td className="px-3 py-2 text-muted">{l.id.slice(0, 8)}</td>
                    <td className="px-3 py-2 text-text">{l.name}</td>
                    <td className="px-3 py-2 text-muted">{fmtBytes(l.size)}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
