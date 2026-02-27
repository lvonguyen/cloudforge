// MVP page — shell with correct imports, to be implemented by portal agent
import { useCreateException } from '@/hooks/useExceptions'
import { PolicyCheckResult } from '@/components/portal/PolicyCheckResult'
import { ResourceCatalogCard } from '@/components/portal/ResourceCatalogCard'
import type { PolicyResult } from '@/types/policy'
import type { ExceptionRequest } from '@/types/grc'

// Suppress unused import warnings during scaffold phase
void (useCreateException as unknown)
void (PolicyCheckResult as unknown)
void (ResourceCatalogCard as unknown)
void ({} as PolicyResult)
void ({} as ExceptionRequest)

export default function Request() {
  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">New Resource Request</h1>
      <p className="text-sm text-muted-foreground">
        Multi-step request form with live OPA policy validation. Implementation pending.
      </p>
    </div>
  )
}
