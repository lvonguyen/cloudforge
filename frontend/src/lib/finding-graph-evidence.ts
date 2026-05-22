import type { AttackPath, AttackPathNode } from '@/types/attack-path'
import type { Finding } from '@/types/compliance'

export interface FindingGraphEvidence {
  linkedPathCount: number
  nearbyNodeCount: number
  pathCount: number
  label: string
  detail: string
}

const EMPTY_EVIDENCE: FindingGraphEvidence = {
  linkedPathCount: 0,
  nearbyNodeCount: 0,
  pathCount: 0,
  label: 'No graph neighborhood',
  detail: 'No nearby attack-path graph evidence shares this finding account and provider.',
}

function normalize(value?: string): string {
  return (value ?? '').toLowerCase().replace(/[^a-z0-9]/g, '')
}

function nodeDirectlyMatchesFinding(finding: Finding, node: AttackPathNode): boolean {
  return node.finding_id === finding.id || node.resource_id === finding.resource_id
}

function nodeLooksNearby(finding: Finding, node: AttackPathNode): boolean {
  if (nodeDirectlyMatchesFinding(finding, node)) return false
  if (node.provider !== finding.cloud_provider) return false
  if ((node.account_id ?? '') !== (finding.account_id ?? '')) return false

  const findingCategory = normalize(finding.category)
  const nodeCategory = normalize(node.category)
  const findingResourceType = normalize(finding.resource_type)
  const nodeResourceType = normalize(node.resource_type)

  return (
    (findingCategory.length > 0 && findingCategory === nodeCategory) ||
    (findingResourceType.length > 0 && nodeResourceType.includes(findingResourceType)) ||
    (nodeResourceType.length > 0 && findingResourceType.includes(nodeResourceType))
  )
}

export function deriveFindingGraphEvidence(finding: Finding | null | undefined, paths: AttackPath[] = []): FindingGraphEvidence {
  if (!finding || paths.length === 0) return EMPTY_EVIDENCE

  let linkedPathCount = 0
  const nearbyNodeIds = new Set<string>()
  const nearbyPathIds = new Set<string>()

  for (const path of paths) {
    const directlyLinked = path.finding_ids.includes(finding.id) ||
      path.nodes.some(node => nodeDirectlyMatchesFinding(finding, node))
    if (directlyLinked) linkedPathCount += 1

    for (const node of path.nodes) {
      if (!nodeLooksNearby(finding, node)) continue
      nearbyNodeIds.add(node.resource_id)
      nearbyPathIds.add(path.id)
    }
  }

  if (nearbyNodeIds.size === 0) {
    return {
      ...EMPTY_EVIDENCE,
      linkedPathCount,
    }
  }

  const signalLabel = `${nearbyNodeIds.size} neighboring graph signal${nearbyNodeIds.size === 1 ? '' : 's'}`
  return {
    linkedPathCount,
    nearbyNodeCount: nearbyNodeIds.size,
    pathCount: nearbyPathIds.size,
    label: 'Graph evidence nearby',
    detail: `${signalLabel} shares the same account and provider across ${nearbyPathIds.size} attack path${nearbyPathIds.size === 1 ? '' : 's'}.`,
  }
}
