import { Card, CardContent } from '@/components/ui/card'
import { AlertTriangle } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { AnomalyAlert } from '@/types/finops'

const SEVERITY_CLASS: Record<string, string> = {
  critical: 'border-red-300 bg-red-50',
  high: 'border-orange-300 bg-orange-50',
  medium: 'border-yellow-300 bg-yellow-50',
  low: 'border-blue-300 bg-blue-50',
}

export function AnomalyAlertCard({ anomaly }: { anomaly: AnomalyAlert }) {
  return (
    <Card className={cn('border', SEVERITY_CLASS[anomaly.severity] ?? SEVERITY_CLASS.medium)}>
      <CardContent className="p-3 flex items-start gap-2">
        <AlertTriangle className="h-4 w-4 mt-0.5 text-orange-500 shrink-0" />
        <div className="text-xs space-y-0.5">
          <p className="font-medium">{anomaly.service_name} +{anomaly.deviation_percent.toFixed(0)}%</p>
          <p className="text-muted-foreground">
            {anomaly.provider.toUpperCase()} · ${anomaly.actual_cost.toLocaleString()} actual vs ${anomaly.expected_cost.toLocaleString()} expected
          </p>
        </div>
      </CardContent>
    </Card>
  )
}
