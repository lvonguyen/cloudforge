import { CheckCircle } from 'lucide-react'
import { PolicyViolationBanner } from '@/components/grc/PolicyViolationBanner'
import type { PolicyResult } from '@/types/policy'

interface Props {
  result: PolicyResult
  onRequestException?: (code: string) => void
}

export function PolicyCheckResult({ result, onRequestException }: Props) {
  if (result.denials.length === 0 && result.warnings.length === 0) {
    return (
      <div className="flex items-center gap-2 rounded-md border border-green-200 bg-green-50 p-3 text-sm text-green-800">
        <CheckCircle className="h-4 w-4" />
        <span className="font-medium">All policy checks passed</span>
      </div>
    )
  }

  return (
    <div className="space-y-2">
      {result.denials.map(v => (
        <PolicyViolationBanner
          key={v.code}
          violation={v}
          onRequestException={onRequestException ? () => onRequestException(v.code) : undefined}
        />
      ))}
      {result.warnings.map(v => (
        <PolicyViolationBanner key={v.code} violation={{ ...v, severity: 'medium' }} />
      ))}
      {result.suggestions.length > 0 && (
        <ul className="text-xs text-muted-foreground pl-4 list-disc space-y-0.5">
          {result.suggestions.map((s, i) => <li key={i}>{s}</li>)}
        </ul>
      )}
    </div>
  )
}
