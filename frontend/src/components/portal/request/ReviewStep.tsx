import { CheckCircle2 } from 'lucide-react'
import { Label } from '@/components/ui/label'
import type { PolicyResult } from '@/types/policy'
import type { RequestCatalogItem, Step1Values } from './request-shared'

export function ReviewStep({
  step1,
  formValues,
  policyResult,
  acceptedExceptions,
  businessCase,
  onBusinessCaseChange,
  catalog,
}: {
  step1: Step1Values
  formValues: Record<string, unknown>
  policyResult: PolicyResult | null
  acceptedExceptions: string[]
  businessCase: string
  onBusinessCaseChange: (value: string) => void
  catalog: RequestCatalogItem[]
}) {
  const resource = catalog.find((item) => item.id === step1.resourceId)
  const needsBusinessCase = acceptedExceptions.length > 0

  return (
    <div className="space-y-5">
      <div className="space-y-3 rounded-none border p-4">
        <h3 className="text-sm font-semibold">Request Summary</h3>
        <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
          <span className="text-muted-foreground">Resource</span>
          <span>{resource?.name} — {resource?.description}</span>
          <span className="text-muted-foreground">Provider</span>
          <span className="uppercase">{step1.cloudProvider}</span>
          <span className="text-muted-foreground">Region</span>
          <span>{step1.region}</span>
          <span className="text-muted-foreground">Service Model</span>
          <span>{step1.serviceModel}</span>
          <span className="text-muted-foreground">Application ID</span>
          <span>{String(formValues.applicationId ?? '')}</span>
          <span className="text-muted-foreground">Team</span>
          <span>{String(formValues.tagTeam ?? '')}</span>
          <span className="text-muted-foreground">Cost Center</span>
          <span>{String(formValues.tagCostCenter ?? '')}</span>
          <span className="text-muted-foreground">Environment</span>
          <span>{String(formValues.tagEnvironment ?? '')}</span>
        </div>
      </div>

      {policyResult && (
        <div className="space-y-2 rounded-none border p-4">
          <h3 className="text-sm font-semibold">Policy Check</h3>
          {policyResult.allowed && acceptedExceptions.length === 0 ? (
            <div className="flex items-center gap-2 text-sm text-green-700">
              <CheckCircle2 className="h-4 w-4" />
              <span>All checks passed</span>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">
              {acceptedExceptions.length} exception(s) requested: {acceptedExceptions.join(', ')}
            </p>
          )}
        </div>
      )}

      {needsBusinessCase && (
        <div className="space-y-1.5">
          <Label>Business Case <span className="text-destructive">*</span></Label>
          <textarea
            value={businessCase}
            onChange={(event) => onBusinessCaseChange(event.target.value)}
            placeholder="Explain why this exception is needed and how risk will be mitigated..."
            rows={4}
            className="w-full resize-none rounded-none border border-input bg-transparent px-3 py-2 text-sm shadow-xs transition-[color,box-shadow] outline-none focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px]"
          />
          {!businessCase.trim() && (
            <p className="text-xs text-destructive">Business case required when requesting exceptions</p>
          )}
        </div>
      )}
    </div>
  )
}
