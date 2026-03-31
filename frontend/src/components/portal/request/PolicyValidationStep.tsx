import { Loader2 } from 'lucide-react'
import { PolicyCheckResult } from '@/components/portal/PolicyCheckResult'
import type { PolicyResult } from '@/types/policy'

export function PolicyValidationStep({
  policyResult,
  isLoading,
  acceptedExceptions,
  onAcceptException,
}: {
  policyResult: PolicyResult | null
  isLoading: boolean
  acceptedExceptions: string[]
  onAcceptException: (code: string) => void
}) {
  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 py-12 text-muted-foreground">
        <Loader2 className="h-8 w-8 animate-spin" />
        <p className="text-sm">Running policy validation...</p>
      </div>
    )
  }

  if (!policyResult) {
    return <p className="text-sm text-muted-foreground">Policy check not yet run.</p>
  }

  return (
    <div className="space-y-4">
      <PolicyCheckResult
        result={policyResult}
        onRequestException={(code) => onAcceptException(code)}
      />
      {acceptedExceptions.length > 0 && (
        <div className="rounded-none border border-blue-200 bg-blue-50 p-3 text-sm text-blue-800">
          <p className="font-medium">Exception requests queued ({acceptedExceptions.length})</p>
          <ul className="mt-1 list-disc pl-4 text-xs">
            {acceptedExceptions.map((code) => <li key={code}>{code}</li>)}
          </ul>
          <p className="mt-1 text-xs opacity-80">Provide business justification in the next step.</p>
        </div>
      )}
    </div>
  )
}
