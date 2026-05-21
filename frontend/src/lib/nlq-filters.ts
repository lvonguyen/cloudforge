import type { Finding } from '@/types/compliance'
import type { NLQFilterMap } from '@/types/nlq'

function normalized(values?: string[]): Set<string> {
  return new Set((values ?? []).map(value => value.toLowerCase()))
}

function matchesAny(values: string[] | undefined, candidates: Array<string | undefined>): boolean {
  const excluded = normalized(values)
  if (excluded.size === 0) return false
  return candidates.some(candidate => candidate !== undefined && excluded.has(candidate.toLowerCase()))
}

export function hasNLQExclusions(exclude?: NLQFilterMap): boolean {
  return Object.values(exclude ?? {}).some(values => (values?.length ?? 0) > 0)
}

export function findingMatchesNLQExclusion(finding: Finding, exclude?: NLQFilterMap): boolean {
  if (!hasNLQExclusions(exclude)) return false

  return (
    matchesAny(exclude?.severity, [finding.severity]) ||
    matchesAny(exclude?.provider, [finding.cloud_provider]) ||
    matchesAny(exclude?.category, [finding.category]) ||
    matchesAny(exclude?.status, [finding.status, finding.workflow_status]) ||
    matchesAny(exclude?.environment, [finding.environment_type])
  )
}
