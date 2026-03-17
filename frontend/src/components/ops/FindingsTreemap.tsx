import { useMemo, useCallback } from 'react'
import { Treemap, ResponsiveContainer, Tooltip } from 'recharts'
import type { Finding } from '@/types/compliance'

const SEV_FILL: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
}

const SEV_ABBR: Record<string, string> = {
  CRITICAL: 'CRT',
  HIGH: 'HI',
  MEDIUM: 'MED',
  LOW: 'LOW',
}

const PROVIDER_INITIAL: Record<string, string> = {
  AWS: 'A',
  AZURE: 'Z',
  GCP: 'G',
}

interface TreeNode {
  name: string
  children?: TreeNode[]
  size?: number
  fill?: string
  findingId?: string
  severity?: string
  provider?: string
  resourceName?: string
  findingTitle?: string
  [key: string]: unknown
}

interface Props {
  findings: Finding[]
  onSelect: (f: Finding) => void
}

// Provider -> Severity -> Findings for contiguous same-color clusters
function buildTreeData(findings: Finding[]): TreeNode[] {
  const providerMap = new Map<string, Map<string, Finding[]>>()

  for (const f of findings) {
    const provider = f.cloud_provider.toUpperCase()
    if (!providerMap.has(provider)) providerMap.set(provider, new Map())
    const sevMap = providerMap.get(provider)!
    const sev = f.severity ?? 'MEDIUM'
    if (!sevMap.has(sev)) sevMap.set(sev, [])
    sevMap.get(sev)!.push(f)
  }

  return Array.from(providerMap.entries()).map(([provider, sevMap]) => ({
    name: provider,
    children: Array.from(sevMap.entries()).map(([severity, fs]) => ({
      name: severity,
      children: fs.map(f => ({
        name: f.resource_name || f.id.slice(0, 8),
        size: f.ai_risk_score || 1,
        fill: SEV_FILL[f.severity] ?? '#6b7280',
        findingId: f.id,
        severity: f.severity,
        provider: f.cloud_provider.toUpperCase(),
        resourceName: f.resource_name || f.id.slice(0, 8),
        findingTitle: f.title,
      })),
    })),
  }))
}

// Adaptive cell renderer: full label > abbreviated label > no label
function CustomCell(props: Record<string, unknown>) {
  const { x, y, width, height, name, fill, severity, provider } = props as {
    x: number; y: number; width: number; height: number
    name: string; fill: string; severity?: string; provider?: string
  }

  if (width < 6 || height < 6) return null

  const showFull = width > 30 && height > 14
  const showAbbr = !showFull && width > 20 && height > 10

  let label: string | null = null
  if (showFull) {
    const maxChars = Math.floor(width / 5)
    const raw = String(name ?? '')
    label = raw.length > maxChars ? raw.slice(0, maxChars) + '\u2026' : raw
  } else if (showAbbr && severity) {
    const sAbbr = SEV_ABBR[severity] ?? severity.slice(0, 3)
    const pInit = provider ? (PROVIDER_INITIAL[provider] ?? provider.charAt(0)) : ''
    label = pInit ? `${sAbbr}\u00b7${pInit}` : sAbbr
  }

  return (
    <g>
      <rect
        x={x} y={y} width={width} height={height}
        fill={fill ?? '#6b7280'}
        stroke="#0a0a0f"
        strokeWidth={1}
        style={{ cursor: 'pointer' }}
      />
      {label && (
        <>
          <rect
            x={x + 2}
            y={y + (showFull ? 1 : 0)}
            width={Math.min(label.length * (showFull ? 5.5 : 5) + 4, width - 4)}
            height={showFull ? 14 : 11}
            fill="rgba(0,0,0,0.5)"
            rx={2}
          />
          <text
            x={x + 4}
            y={y + (showFull ? 12 : 9)}
            fill="#ffffff"
            fontSize={showFull ? 9 : 8}
            fontFamily="monospace"
          >
            {label}
          </text>
        </>
      )}
    </g>
  )
}

function TreemapTooltip({ active, payload }: {
  active?: boolean
  payload?: Array<{ payload: Record<string, unknown> }>
}) {
  if (!active || !payload?.length) return null
  const d = payload[0].payload
  if (!d.findingId) return null

  return (
    <div style={{
      background: '#161b22',
      border: '1px solid #1e2330',
      borderRadius: 4,
      padding: '8px 10px',
      fontSize: 11,
      maxWidth: 300,
    }}>
      <div style={{
        color: SEV_FILL[d.severity as string] ?? '#9ca3af',
        fontWeight: 600,
        marginBottom: 2,
      }}>
        {String(d.severity)} — {String(d.provider)}
      </div>
      <div style={{ color: '#e5e7eb', marginBottom: 4 }}>
        {String(d.findingTitle ?? d.name)}
      </div>
      <div style={{ color: '#9ca3af' }}>{String(d.resourceName)}</div>
    </div>
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
            <Tooltip content={<TreemapTooltip />} />
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
