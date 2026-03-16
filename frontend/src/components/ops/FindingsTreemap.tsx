import { useMemo, useCallback } from 'react'
import { Treemap, ResponsiveContainer, Tooltip } from 'recharts'
import type { Finding } from '@/types/compliance'

const SEV_FILL: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
}

const TOOLTIP_STYLE = {
  background: '#161b22',
  border: '1px solid #1e2330',
  borderRadius: 0,
  fontSize: 11,
}

interface TreeNode {
  name: string
  children?: TreeNode[]
  size?: number
  fill?: string
  findingId?: string
  severity?: string
  [key: string]: unknown
}

interface Props {
  findings: Finding[]
  onSelect: (f: Finding) => void
}

function buildTreeData(findings: Finding[]): TreeNode[] {
  const providerMap = new Map<string, Map<string, Finding[]>>()

  for (const f of findings) {
    const provider = f.cloud_provider.toUpperCase()
    if (!providerMap.has(provider)) providerMap.set(provider, new Map())
    const catMap = providerMap.get(provider)!
    if (!catMap.has(f.category)) catMap.set(f.category, [])
    catMap.get(f.category)!.push(f)
  }

  return Array.from(providerMap.entries()).map(([provider, catMap]) => ({
    name: provider,
    children: Array.from(catMap.entries()).map(([category, fs]) => ({
      name: category,
      children: fs.map(f => ({
        name: f.resource_name || f.id.slice(0, 8),
        size: f.ai_risk_score || 1,
        fill: SEV_FILL[f.severity] ?? '#6b7280',
        findingId: f.id,
        severity: f.severity,
      })),
    })),
  }))
}

// Custom cell renderer for per-cell fill colors + truncated labels
function CustomCell(props: Record<string, unknown>) {
  const { x, y, width, height, name, fill } = props as {
    x: number
    y: number
    width: number
    height: number
    name: string
    fill: string
  }

  if (width < 4 || height < 4) return null

  return (
    <g>
      <rect
        x={x}
        y={y}
        width={width}
        height={height}
        fill={fill ?? '#6b7280'}
        stroke="#0a0a0f"
        strokeWidth={1}
        style={{ cursor: 'pointer' }}
      />
      {width > 30 && height > 14 && (
        <text
          x={x + 4}
          y={y + 12}
          fill="#ffffff"
          fontSize={9}
          fontFamily="monospace"
          stroke="#000000"
          strokeWidth={0.3}
          paintOrder="stroke"
        >
          {String(name ?? '').length > Math.floor(width / 5)
            ? String(name ?? '').slice(0, Math.floor(width / 5)) + '…'
            : String(name ?? '')}
        </text>
      )}
    </g>
  )
}

export function FindingsTreemap({ findings, onSelect }: Props) {
  const treeData = useMemo(() => buildTreeData(findings), [findings])

  const handleClick = useCallback(
    (node: Record<string, unknown>) => {
      const fid = node.findingId as string | undefined
      if (!fid) return
      const f = findings.find(f => f.id === fid)
      if (f) onSelect(f)
    },
    [findings, onSelect],
  )

  if (findings.length === 0) return null

  return (
    <div className="p-4 h-full flex flex-col" data-testid="findings-treemap">
      <div className="text-[10px] font-semibold uppercase tracking-widest text-gray-500 mb-3">
        Severity Heatmap
      </div>
      <div className="flex-1 min-h-0">
        <ResponsiveContainer width="100%" height="100%">
          <Treemap
            data={treeData}
            dataKey="size"
            stroke="#0a0a0f"
            content={<CustomCell />}
            onClick={handleClick}
          >
            <Tooltip
              contentStyle={TOOLTIP_STYLE}
              labelStyle={{ color: '#9ca3af' }}
            />
          </Treemap>
        </ResponsiveContainer>
      </div>
      <div className="flex items-center gap-4 mt-3">
        {Object.entries(SEV_FILL).map(([sev, color]) => (
          <span key={sev} className="flex items-center gap-1 text-[9px] font-mono text-gray-500">
            <span className="h-2 w-2" style={{ background: color }} />
            {sev}
          </span>
        ))}
      </div>
    </div>
  )
}
