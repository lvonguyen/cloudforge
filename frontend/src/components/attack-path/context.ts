import type { AttackPathNode } from '@/types/attack-path'
import type { CVEReference, Finding } from '@/types/compliance'
import { formatWorkflowStatus, getFindingSlaState } from '@/components/ops/finding-detail/helpers'

interface AttackPathFindingLookup {
  byId: Map<string, Finding>
  byResourceId: Map<string, Finding>
}

export interface AttackPathRemediationState {
  label: string
  badgeClass: string
  detail: string
}

const RESOLVED_WORKFLOW_STATUSES = new Set(['closed', 'verified', 'remediated'])
const ACTIVE_WORKFLOW_STATUSES = new Set(['triaged', 'assigned', 'in_progress', 'pending_info', 'pending_approval'])
const ACCEPTED_WORKFLOW_STATUSES = new Set(['suppressed', 'false_positive', 'risk_accepted', 'wont_fix'])

export function buildAttackPathFindingLookup(findings: Finding[]): AttackPathFindingLookup {
  const byId = new Map<string, Finding>()
  const byResourceId = new Map<string, Finding>()

  for (const finding of findings) {
    byId.set(finding.id, finding)
    if (!byResourceId.has(finding.resource_id)) {
      byResourceId.set(finding.resource_id, finding)
    }
  }

  return { byId, byResourceId }
}

export function findAttackPathNodeFinding(
  node: Pick<AttackPathNode, 'finding_id' | 'resource_id'>,
  lookup?: AttackPathFindingLookup,
): Finding | undefined {
  if (!lookup) return undefined
  return lookup.byId.get(node.finding_id) ?? lookup.byResourceId.get(node.resource_id)
}

export function getAttackPathRemediationState(
  finding?: Pick<Finding, 'workflow_status' | 'due_date' | 'sla_breach_date' | 'resolved_at'>,
): AttackPathRemediationState {
  if (!finding) {
    return {
      label: 'Open',
      badgeClass: 'border-rose-300 bg-rose-50 text-rose-700 dark:border-rose-500/30 dark:bg-rose-500/10 dark:text-rose-200',
      detail: 'Path evidence still needs remediation owner context',
    }
  }

  const workflowStatus = finding.workflow_status
  const slaState = getFindingSlaState(finding)

  if (RESOLVED_WORKFLOW_STATUSES.has(workflowStatus) || finding.resolved_at) {
    return {
      label: 'Fixed',
      badgeClass: 'border-emerald-300 bg-emerald-50 text-emerald-700 dark:border-emerald-500/30 dark:bg-emerald-500/10 dark:text-emerald-200',
      detail: 'Remediation verified or closed',
    }
  }

  if (ACCEPTED_WORKFLOW_STATUSES.has(workflowStatus)) {
    return {
      label: 'Accepted',
      badgeClass: 'border-slate-300 bg-slate-100 text-slate-700 dark:border-slate-600 dark:bg-slate-800 dark:text-slate-200',
      detail: formatWorkflowStatus(workflowStatus),
    }
  }

  if (ACTIVE_WORKFLOW_STATUSES.has(workflowStatus)) {
    return {
      label: 'In progress',
      badgeClass: 'border-amber-300 bg-amber-50 text-amber-700 dark:border-amber-500/30 dark:bg-amber-500/10 dark:text-amber-200',
      detail: slaState.detail,
    }
  }

  return {
    label: 'Open',
    badgeClass: 'border-rose-300 bg-rose-50 text-rose-700 dark:border-rose-500/30 dark:bg-rose-500/10 dark:text-rose-200',
    detail: slaState.detail,
  }
}

export function getPrimaryAttackPathCve(finding?: Pick<Finding, 'cves'>): CVEReference | undefined {
  return finding?.cves?.[0]
}

export function formatAttackPathCveLabel(cve?: Pick<CVEReference, 'id' | 'cvss'>): string | null {
  if (!cve?.id) return null
  if (typeof cve.cvss === 'number' && Number.isFinite(cve.cvss)) {
    return `${cve.id} · CVSS ${cve.cvss.toFixed(1)}`
  }
  return cve.id
}
