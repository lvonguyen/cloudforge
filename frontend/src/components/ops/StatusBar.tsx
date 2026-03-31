import { useMemo } from 'react'
import { SEVERITY_DOT_COLORS } from '@/lib/severity'
import type { Finding } from '@/types/compliance'

interface StatusBarProps {
  filteredFindings: Finding[]
  totalFindings: number
  attackPathCount: number
  toxicComboCount: number
  dateRange?: { start: string | null; end: string | null }
  onDateRangeChange?: (range: { start: string | null; end: string | null }) => void
  onShowShortcuts?: () => void
}

export function StatusBar({
  filteredFindings,
  totalFindings,
  attackPathCount,
  toxicComboCount,
  dateRange,
  onDateRangeChange,
  onShowShortcuts,
}: StatusBarProps) {
  const counts = useMemo(() => {
    const m: Record<string, number> = {}
    for (const f of filteredFindings) {
      m[f.severity] = (m[f.severity] ?? 0) + 1
    }
    return m
  }, [filteredFindings])

  const hasDateFilter = dateRange?.start || dateRange?.end

  return (
    <div
      className="flex items-center justify-between px-4 h-10 bg-[#0a0a0f] border-t border-[#1e2330] text-[10px] font-mono select-none"
      role="status"
      aria-label="Command center status summary"
    >
      {/* Severity classification legend */}
      <div className="flex items-center gap-5">
        <Indicator color={SEVERITY_DOT_COLORS.CRITICAL} label="CRITICAL" count={counts.CRITICAL ?? 0} />
        <Indicator color={SEVERITY_DOT_COLORS.HIGH} label="HIGH" count={counts.HIGH ?? 0} />
        <Indicator color={SEVERITY_DOT_COLORS.MEDIUM} label="MEDIUM" count={counts.MEDIUM ?? 0} />
        <Indicator color={SEVERITY_DOT_COLORS.LOW} label="LOW" count={counts.LOW ?? 0} />
      </div>

      {/* Center — date range filter */}
      {onDateRangeChange && (
        <div className="flex items-center gap-2">
          <input
            type="date"
            value={dateRange?.start ?? ''}
            onChange={(e) =>
              onDateRangeChange({ start: e.target.value || null, end: dateRange?.end ?? null })
            }
            className="bg-transparent text-[10px] font-mono text-gray-400 border border-[#1e2330] h-5 px-1 [color-scheme:dark]"
            aria-label="Start date"
          />
          <span className="text-gray-600">–</span>
          <input
            type="date"
            value={dateRange?.end ?? ''}
            onChange={(e) =>
              onDateRangeChange({ start: dateRange?.start ?? null, end: e.target.value || null })
            }
            className="bg-transparent text-[10px] font-mono text-gray-400 border border-[#1e2330] h-5 px-1 [color-scheme:dark]"
            aria-label="End date"
          />
          {hasDateFilter && (
            <button
              onClick={() => onDateRangeChange({ start: null, end: null })}
              className="text-gray-500 hover:text-gray-300 transition-colors text-xs px-1"
              aria-label="Clear date filter"
            >
              ✕
            </button>
          )}
        </div>
      )}

      {/* Right-side summary + shortcuts hint */}
      <div className="flex items-center gap-5 text-gray-600">
        <span>
          {filteredFindings.length.toLocaleString()}/{totalFindings.toLocaleString()} findings
        </span>
        <span>
          {toxicComboCount} toxic combo{toxicComboCount !== 1 ? 's' : ''}
        </span>
        <span>
          {attackPathCount} path{attackPathCount !== 1 ? 's' : ''}
        </span>
        {onShowShortcuts && (
          <button
            onClick={onShowShortcuts}
            className="text-gray-600 hover:text-gray-300 transition-colors border border-[#1e2330] px-1.5 py-0 text-[10px]"
            aria-label="Keyboard shortcuts"
            title="Keyboard shortcuts (?)"
          >
            ?
          </button>
        )}
      </div>
    </div>
  )
}

function Indicator({ color, label, count }: { color: string; label: string; count: number }) {
  return (
    <span className="flex items-center gap-1.5 tabular-nums">
      <span className={`h-2 w-2 ${color}`} aria-hidden="true" />
      <span className="text-gray-500">{label}</span>
      <span className="text-gray-300">{count.toLocaleString()}</span>
    </span>
  )
}
