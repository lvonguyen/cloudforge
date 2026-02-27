import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts'
import type { DailyProviderCost } from '@/types/finops'

interface Props {
  data: DailyProviderCost[]
  days?: number
}

export function SpendChart({ data, days = 30 }: Props) {
  const slice = data.slice(-days)
  const formatter = (v: number) => `$${(v / 1000).toFixed(0)}K`

  return (
    <ResponsiveContainer width="100%" height={240}>
      <AreaChart data={slice} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
        <defs>
          <linearGradient id="aws" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.4} />
            <stop offset="95%" stopColor="#f59e0b" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="azure" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.4} />
            <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="gcp" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#22c55e" stopOpacity={0.4} />
            <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" className="stroke-border" />
        <XAxis
          dataKey="date"
          tick={{ fontSize: 10 }}
          tickFormatter={d => d.slice(5)}
          interval="preserveStartEnd"
        />
        <YAxis tick={{ fontSize: 10 }} tickFormatter={formatter} width={48} />
        <Tooltip formatter={(v: unknown) => typeof v === 'number' ? formatter(v) : String(v)} />
        <Legend iconSize={10} wrapperStyle={{ fontSize: 11 }} />
        <Area type="monotone" dataKey="aws" name="AWS" stroke="#f59e0b" fill="url(#aws)" strokeWidth={2} />
        <Area type="monotone" dataKey="azure" name="Azure" stroke="#3b82f6" fill="url(#azure)" strokeWidth={2} />
        <Area type="monotone" dataKey="gcp" name="GCP" stroke="#22c55e" fill="url(#gcp)" strokeWidth={2} />
      </AreaChart>
    </ResponsiveContainer>
  )
}
