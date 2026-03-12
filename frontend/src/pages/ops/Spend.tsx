import { useState } from 'react'
import { useCostSummary } from '@/hooks/useCosts'
import { CostSummaryCard } from '@/components/finops/CostSummaryCard'
import { AnomalyAlertCard } from '@/components/finops/AnomalyAlertCard'
import { SpendChart } from '@/components/finops/SpendChart'
import { ChargebackTable } from '@/components/finops/ChargebackTable'
import { Badge } from '@/components/ui/badge'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import type { DailyProviderCost } from '@/types/finops'

type Period = '30' | '60' | '90'

function calcMoM(daily: DailyProviderCost[], key: keyof Pick<DailyProviderCost, 'aws' | 'azure' | 'gcp' | 'total'>): number {
  const last30 = daily.slice(-30).reduce((s, d) => s + d[key], 0)
  const prev30 = daily.slice(-60, -30).reduce((s, d) => s + d[key], 0)
  if (prev30 === 0) return 0
  return ((last30 - prev30) / prev30) * 100
}

export default function Spend() {
  const [period, setPeriod] = useState<Period>('90')
  const { data: summary, isLoading, isError } = useCostSummary()

  if (isLoading) {
    return <div className="text-sm text-muted-foreground p-4">Loading cost data...</div>
  }

  if (isError || !summary) {
    return (
      <div className="text-sm text-muted-foreground p-4">
        Failed to load cost data. Please try again later.
      </div>
    )
  }

  const { daily, anomalies, chargeback, by_provider } = summary

  const trends = {
    total: calcMoM(daily, 'total'),
    aws: calcMoM(daily, 'aws'),
    azure: calcMoM(daily, 'azure'),
    gcp: calcMoM(daily, 'gcp'),
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-semibold">Spend Management</h1>
          <Badge variant="secondary" className="text-xs">{new Date().toLocaleDateString('en-US', { month: 'short', year: 'numeric' })}</Badge>
        </div>
        <Select value={period} onValueChange={v => setPeriod(v as Period)}>
          <SelectTrigger className="w-24 h-8 text-xs">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="30">30d</SelectItem>
            <SelectItem value="60">60d</SelectItem>
            <SelectItem value="90">90d</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Section 1: KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <CostSummaryCard
          label="Total Spend"
          amount={summary.total}
          trend={trends.total}
        />
        <CostSummaryCard
          label="AWS"
          amount={by_provider.aws}
          breakdown="EC2: 42%"
          trend={trends.aws}
        />
        <CostSummaryCard
          label="Azure"
          amount={by_provider.azure}
          breakdown="Compute: 38%"
          trend={trends.azure}
        />
        <CostSummaryCard
          label="GCP"
          amount={by_provider.gcp}
          breakdown="GKE: 51%"
          trend={trends.gcp}
        />
      </div>

      {/* Section 2: Spend Trend + Anomaly Alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card className="lg:col-span-2">
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
              Spend Trend ({period}d)
            </CardTitle>
          </CardHeader>
          <CardContent>
            <SpendChart data={daily} days={parseInt(period)} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
              Anomaly Alerts ({anomalies.length} active)
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 pt-0">
            {anomalies.map(a => (
              <AnomalyAlertCard key={a.id} anomaly={a} />
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Section 3: Chargeback Table */}
      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
              Chargeback by Cost Center
            </CardTitle>
            <Badge variant="outline" className="text-xs">{chargeback.period}</Badge>
          </div>
        </CardHeader>
        <CardContent>
          <ChargebackTable allocations={chargeback.allocations} />
        </CardContent>
      </Card>
    </div>
  )
}
