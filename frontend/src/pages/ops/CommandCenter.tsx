// MVP page — shell with correct imports, to be implemented by ops agent
import { useExceptions } from '@/hooks/useExceptions'
import { useFindings } from '@/hooks/useFindings'
import { ExceptionCard } from '@/components/grc/ExceptionCard'
import { FindingCard } from '@/components/findings/FindingCard'

// Suppress unused import warnings during scaffold phase
void (useExceptions as unknown)
void (useFindings as unknown)
void (ExceptionCard as unknown)
void (FindingCard as unknown)

export default function CommandCenter() {
  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Command Center</h1>
      <p className="text-sm text-muted-foreground">
        Exception queue, findings feed, remediation status. Implementation pending.
      </p>
    </div>
  )
}
