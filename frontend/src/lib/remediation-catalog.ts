import type { Finding, FindingCategory } from '@/types/compliance'
import type { AttackPathNode, AttackPath } from '@/types/attack-path'
import type { RemediationRecord } from '@/types/remediation'

export type ImpactLevel = 'low' | 'medium' | 'high'
export type TierLevel = 1 | 2 | 3

export interface RemediationCandidate {
  id: string
  handler: string
  label: string
  tier: TierLevel
  target: string
  reversible: boolean
  estimatedImpact: ImpactLevel
  permissions: string[]
  plannedActions: string[]
  rollbackPlan: string[]
  estimatedRollbackWindow?: string
  prerequisites?: string[]
  warnings?: string[]
}

type CatalogSpec = Omit<RemediationCandidate, 'id' | 'target'>

export const HANDLER_CATALOG: Record<string, CatalogSpec> = {
  'sg-rule-remediator': {
    handler: 'sg-rule-remediator',
    label: 'Restrict security group ingress',
    tier: 1,
    reversible: true,
    estimatedImpact: 'low',
    permissions: ['ec2:RevokeSecurityGroupIngress', 'ec2:AuthorizeSecurityGroupIngress', 'ec2:DescribeSecurityGroups'],
    plannedActions: [
      'Audit current ingress rules',
      'Revoke unrestricted (0.0.0.0/0) rules',
      'Add scoped CIDR rule from approved sources',
    ],
    rollbackPlan: [
      'Restore previous security group rule set from captured state',
      'Verify connectivity from monitored hosts',
    ],
    estimatedRollbackWindow: '48h',
  },
  's3-acl-remediator': {
    handler: 's3-acl-remediator',
    label: 'Lock down S3 bucket access',
    tier: 1,
    reversible: true,
    estimatedImpact: 'low',
    permissions: ['s3:PutBucketAcl', 's3:PutBucketPublicAccessBlock', 's3:GetBucketAcl'],
    plannedActions: [
      'Set bucket ACL to private',
      'Enable block public access (all four flags)',
      'Verify downstream consumers are not broken',
    ],
    rollbackPlan: [
      'Restore previous public access block configuration',
      'Re-apply previous ACL document',
    ],
    estimatedRollbackWindow: '48h',
  },
  'iam-policy-scoper': {
    handler: 'iam-policy-scoper',
    label: 'Scope IAM policy to least privilege',
    tier: 2,
    reversible: true,
    estimatedImpact: 'medium',
    permissions: ['iam:PutRolePolicy', 'iam:GetRolePolicy', 'iam:GenerateServiceLastAccessedDetails'],
    plannedActions: [
      'Pull Access Advisor data for unused actions',
      'Generate scoped least-privilege policy',
      'Apply scoped policy',
      'Verify expected operations still succeed',
    ],
    rollbackPlan: [
      'Restore previous policy document from captured state',
      'Run policy simulator against the prior deployment workflow',
    ],
    estimatedRollbackWindow: '48h',
    prerequisites: ['Access Advisor data available for the last 30 days'],
  },
  'rds-access-remediator': {
    handler: 'rds-access-remediator',
    label: 'Restrict RDS network exposure',
    tier: 2,
    reversible: true,
    estimatedImpact: 'medium',
    permissions: ['rds:ModifyDBInstance', 'rds:DescribeDBInstances', 'ec2:DescribeSecurityGroups'],
    plannedActions: [
      'Disable public accessibility flag',
      'Apply changes immediately',
      'Verify connectivity from VPC clients',
    ],
    rollbackPlan: [
      'Re-enable public accessibility',
      'Restore previous security group associations',
    ],
    estimatedRollbackWindow: '24h',
    warnings: ['Instance will reboot briefly during apply'],
  },
  'encryption-enabler': {
    handler: 'encryption-enabler',
    label: 'Enable encryption at rest',
    tier: 1,
    reversible: true,
    estimatedImpact: 'low',
    permissions: ['s3:PutBucketEncryption', 'kms:DescribeKey', 'kms:GenerateDataKey'],
    plannedActions: [
      'Enable SSE (AES-256 or KMS) on the resource',
      'Verify encryption flag on a sample object',
    ],
    rollbackPlan: [
      'Disable bucket-level encryption configuration',
      'New objects revert to default cloud-managed encryption',
    ],
    estimatedRollbackWindow: '24h',
  },
  'eks-config-remediator': {
    handler: 'eks-config-remediator',
    label: 'Harden EKS cluster configuration',
    tier: 2,
    reversible: true,
    estimatedImpact: 'medium',
    permissions: ['eks:UpdateClusterConfig', 'logs:CreateLogGroup', 'logs:DescribeLogGroups'],
    plannedActions: [
      'Enable cluster audit logging',
      'Stream to CloudWatch Logs',
      'Verify log group is active',
    ],
    rollbackPlan: ['Disable audit logging on cluster'],
    estimatedRollbackWindow: '24h',
  },
  'tag-enforcer': {
    handler: 'tag-enforcer',
    label: 'Apply required cost-center tags',
    tier: 1,
    reversible: true,
    estimatedImpact: 'low',
    permissions: ['ec2:CreateTags', 'tag:TagResources', 'tag:GetResources'],
    plannedActions: [
      'Enumerate untagged resources',
      'Apply Environment / Owner / CostCenter tags from inferred owner',
      'Verify Config rule compliance',
    ],
    rollbackPlan: ['Remove tags applied during this run'],
    estimatedRollbackWindow: '24h',
  },
  'nsg-rule-remediator': {
    handler: 'nsg-rule-remediator',
    label: 'Restrict Azure NSG rules',
    tier: 2,
    reversible: true,
    estimatedImpact: 'medium',
    permissions: ['Microsoft.Network/networkSecurityGroups/securityRules/write'],
    plannedActions: [
      'Remove "Any" source rules',
      'Add scoped CIDR rules from approved sources',
      'Verify connectivity from monitored hosts',
    ],
    rollbackPlan: ['Restore prior NSG rule set from captured state'],
    estimatedRollbackWindow: '24h',
    warnings: ['May be blocked by Azure Policy on shared NSGs'],
  },
  'manual-escalation': {
    handler: 'manual-escalation',
    label: 'Open Asana ticket for manual remediation',
    tier: 3,
    reversible: false,
    estimatedImpact: 'high',
    permissions: ['Asana: project write'],
    plannedActions: [
      'Open Asana ticket with finding context',
      'Assign to platform-team queue',
      'Track resolution + evidence in ticket',
    ],
    rollbackPlan: [
      'Open a linked rollback ticket',
      'Operator-defined rollback (no SDK path)',
    ],
  },
}

const FINDING_CATEGORY_HANDLERS: Record<FindingCategory, string> = {
  NETWORK: 'sg-rule-remediator',
  IDENTITY: 'iam-policy-scoper',
  MISCONFIGURATION: 's3-acl-remediator',
  VULNERABILITY: 'manual-escalation',
  COMPLIANCE: 'tag-enforcer',
  DATA_PROTECTION: 'encryption-enabler',
  STORAGE: 's3-acl-remediator',
  COMPUTE: 'sg-rule-remediator',
  DATABASE: 'rds-access-remediator',
  CONTAINER: 'eks-config-remediator',
  SERVERLESS: 'iam-policy-scoper',
  THREAT: 'manual-escalation',
}

const NODE_CATEGORY_HANDLERS: Record<string, string[]> = {
  NETWORK: ['sg-rule-remediator', 'nsg-rule-remediator'],
  IDENTITY: ['iam-policy-scoper'],
  MISCONFIGURATION: ['s3-acl-remediator', 'rds-access-remediator', 'eks-config-remediator'],
  VULNERABILITY: ['encryption-enabler', 'manual-escalation'],
  COMPLIANCE: ['tag-enforcer', 'manual-escalation'],
}

export function getCatalogSpec(handler: string): CatalogSpec {
  return HANDLER_CATALOG[handler] ?? HANDLER_CATALOG['manual-escalation']
}

export function buildCandidateForFinding(finding: Finding): RemediationCandidate {
  const handler = FINDING_CATEGORY_HANDLERS[finding.category] ?? 'manual-escalation'
  const spec = getCatalogSpec(handler)
  return {
    id: `cand-${finding.id}`,
    ...spec,
    target: finding.resource_name || finding.resource_id,
  }
}

export function buildCandidateForRemediation(rec: RemediationRecord): RemediationCandidate {
  const spec = getCatalogSpec(rec.handler)
  const tier = (rec.tier >= 1 && rec.tier <= 3 ? rec.tier : spec.tier) as TierLevel
  return {
    id: rec.id,
    ...spec,
    tier,
    target: rec.result?.resource_id ?? rec.finding_id,
  }
}

export function buildCandidatesForNode(node: AttackPathNode, path?: AttackPath): RemediationCandidate[] {
  const handlers = NODE_CATEGORY_HANDLERS[node.category] ?? ['manual-escalation']
  const target = node.resource_name || node.resource_id
  return handlers.map((handler, idx) => {
    const spec = getCatalogSpec(handler)
    return {
      id: `hop-${node.id}-${idx}`,
      ...spec,
      target,
      warnings: composeNodeWarnings(spec.warnings, path),
    }
  })
}

function composeNodeWarnings(existing: string[] | undefined, path?: AttackPath): string[] | undefined {
  if (!path?.recommended_breaks?.length) return existing
  const breakHint = `Path-level break: ${path.recommended_breaks[0]}`
  return existing ? [...existing, breakHint] : [breakHint]
}

export function impactBadgeClass(level: ImpactLevel): string {
  switch (level) {
    case 'low':
      return 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/30 dark:text-emerald-300 dark:border-emerald-900/40'
    case 'medium':
      return 'bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-950/30 dark:text-amber-300 dark:border-amber-900/40'
    case 'high':
      return 'bg-red-50 text-red-700 border-red-200 dark:bg-red-950/30 dark:text-red-300 dark:border-red-900/40'
  }
}
