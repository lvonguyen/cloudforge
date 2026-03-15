import { useMemo } from 'react'
import type { Finding } from '@/types/compliance'

interface StatusBarProps {
  filteredFindings: Finding[]
  totalFindings: number
  attackPathCount: number
  toxicComboCount: number
}

export function StatusBar({
  filteredFindings,
  totalFindings,
  attackPathCount,
  toxicComboCount,
}: StatusBarProps) {
  const counts = useMemo(() => {
    const m: Record<string, number> = {}
    for (const f of filteredFindings) {
      m[f.severity] = (m[f.severity] ?? 0) + 1
    }
    return m
  }, [filteredFindings])

  return (
    <div className="flex items-center justify-between px-4 h-10 bg-[#0a0a0f] border-t border-[#1e2330] text-[10px] font-mono select-none">
      {/* Severity classification legend */}
      <div className="flex items-center gap-5">
        <Indicator color="bg-red-400" label="CRITICAL" count={counts.CRITICAL ?? 0} />
        <Indicator color="bg-orange-400" label="HIGH" count={counts.HIGH ?? 0} />
        <Indicator color="bg-yellow-500" label="MEDIUM" count={counts.MEDIUM ?? 0} />
        <Indicator color="bg-blue-400" label="LOW" count={counts.LOW ?? 0} />
      </div>

      {/* Right-side summary */}
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
      </div>
    </div>
  )
}

function Indicator({ color, label, count }: { color: string; label: string; count: number }) {
  return (
    <span className="flex items-center gap-1.5 tabular-nums">
      <span className={`h-2 w-2 ${color}`} />
      <span className="text-gray-500">{label}</span>
      <span className="text-gray-300">{count.toLocaleString()}</span>
    </span>
  )
}
