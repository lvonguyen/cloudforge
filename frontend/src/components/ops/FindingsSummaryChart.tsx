import { useMemo } from 'react'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts'
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

interface Props {
  findings: Finding[]
}

export function FindingsSummaryChart({ findings }: Props) {
  const providerData = useMemo(() => {
    const m: Record<string, Record<string, number>> = {}
    for (const f of findings) {
      const p = f.cloud_provider.toUpperCase()
      if (!m[p]) m[p] = {}
      m[p][f.severity] = (m[p][f.severity] ?? 0) + 1
    }
    return Object.entries(m)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([provider, counts]) => ({ provider, ...counts }))
  }, [findings])

  const statusData = useMemo(() => {
    const m: Record<string, number> = {}
    for (const f of findings) {
      const s = f.workflow_status.replace(/_/g, ' ')
      m[s] = (m[s] ?? 0) + 1
    }
    return Object.entries(m)
      .map(([status, count]) => ({ status, count }))
      .sort((a, b) => b.count - a.count)
  }, [findings])

  if (findings.length === 0) return null

  return (
    <div className="p-4 space-y-6">
      <div>
        <div className="text-[10px] font-semibold uppercase tracking-widest text-gray-500 mb-3">
          Severity by Provider
        </div>
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={providerData} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e2330" />
            <XAxis
              dataKey="provider"
              tick={{ fontSize: 10, fill: '#6b7280' }}
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              tick={{ fontSize: 10, fill: '#6b7280' }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip contentStyle={TOOLTIP_STYLE} labelStyle={{ color: '#9ca3af' }} />
            <Legend wrapperStyle={{ fontSize: 10 }} />
            <Bar dataKey="CRITICAL" stackId="a" fill={SEV_FILL.CRITICAL} />
            <Bar dataKey="HIGH" stackId="a" fill={SEV_FILL.HIGH} />
            <Bar dataKey="MEDIUM" stackId="a" fill={SEV_FILL.MEDIUM} />
            <Bar dataKey="LOW" stackId="a" fill={SEV_FILL.LOW} />
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div>
        <div className="text-[10px] font-semibold uppercase tracking-widest text-gray-500 mb-3">
          Workflow Status
        </div>
        <ResponsiveContainer width="100%" height={180}>
          <BarChart
            data={statusData}
            layout="vertical"
            margin={{ top: 4, right: 8, left: 0, bottom: 0 }}
          >
            <CartesianGrid strokeDasharray="3 3" stroke="#1e2330" horizontal={false} />
            <XAxis
              type="number"
              tick={{ fontSize: 10, fill: '#6b7280' }}
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              type="category"
              dataKey="status"
              tick={{ fontSize: 10, fill: '#6b7280' }}
              axisLine={false}
              tickLine={false}
              width={70}
            />
            <Tooltip contentStyle={TOOLTIP_STYLE} labelStyle={{ color: '#9ca3af' }} />
            <Bar dataKey="count" fill="#6366f1" radius={[0, 2, 2, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
