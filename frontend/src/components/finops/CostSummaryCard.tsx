import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { TrendingUp, TrendingDown } from 'lucide-react'
import { cn } from '@/lib/utils'

interface Props {
  label: string
  amount: number
  breakdown?: string
  trend?: number
}

export function CostSummaryCard({ label, amount, breakdown, trend }: Props) {
  const up = (trend ?? 0) >= 0
  return (
    <Card>
      <CardHeader className="pb-1">
        <CardTitle className="text-xs text-muted-foreground font-medium uppercase tracking-wide">{label}</CardTitle>
      </CardHeader>
      <CardContent>
        <p className="text-2xl font-bold">${(amount / 1000).toFixed(0)}K</p>
        {breakdown && <p className="text-xs text-muted-foreground mt-0.5">{breakdown}</p>}
        {trend !== undefined && (
          <div className={cn('flex items-center gap-1 text-xs mt-1', up ? 'text-red-600' : 'text-green-600')}>
            {up ? <TrendingUp className="h-3 w-3" /> : <TrendingDown className="h-3 w-3" />}
            {Math.abs(trend).toFixed(1)}% MoM
          </div>
        )}
      </CardContent>
    </Card>
  )
}
