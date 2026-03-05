import { CheckCircle, XCircle, AlertTriangle } from 'lucide-react'
import type { DryRunResult } from '@/types/remediation'

export function DryRunPreview({ result }: { result: DryRunResult }) {
  return (
    <div className="rounded-none border border-border bg-muted/30 p-3 space-y-2">
      <div className="flex items-center gap-2 text-sm font-medium">
        {result.would_succeed ? (
          <CheckCircle className="h-4 w-4 text-green-600" />
        ) : (
          <XCircle className="h-4 w-4 text-red-600" />
        )}
        {result.would_succeed ? 'Dry run would succeed' : 'Dry run would fail'}
      </div>

      {result.planned_actions.length > 0 && (
        <div className="space-y-1">
          <p className="text-xs font-medium text-muted-foreground">Planned actions:</p>
          {result.planned_actions.map((action, i) => (
            <p key={i} className="text-xs font-mono pl-2 border-l-2 border-primary/30">{action}</p>
          ))}
        </div>
      )}

      {result.warnings && result.warnings.length > 0 && (
        <div className="space-y-1">
          {result.warnings.map((w, i) => (
            <div key={i} className="flex items-start gap-1.5 text-xs text-yellow-700">
              <AlertTriangle className="h-3 w-3 mt-0.5 shrink-0" />
              <span>{w}</span>
            </div>
          ))}
        </div>
      )}

      <p className="text-xs text-muted-foreground">Impact: {result.estimated_impact}</p>
    </div>
  )
}
