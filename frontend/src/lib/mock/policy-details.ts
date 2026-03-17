import { brandEmail } from '@/lib/mock-data-utils'
import policiesData from '@/lib/mock/policies.json'

// ── Types ────────────────────────────────────────────────────────────────────

export interface PolicyEvaluation {
  timestamp: string
  resource: string
  result: 'allow' | 'deny'
  reason?: string
}

export interface PolicyDenial {
  timestamp: string
  resource: string
  reason: string
  requestor: string
}

export interface PolicyDetailData {
  id: string
  name: string
  namespace: string
  status: 'active' | 'inactive' | 'draft'
  category: string
  evaluations: number
  denials: number
  last_updated: string
  created: string
  version: string
  description: string
  rego: string
  recent_evaluations: PolicyEvaluation[]
  recent_denials: PolicyDenial[]
}

// ── Mock data ────────────────────────────────────────────────────────────────

export const POLICY_DETAILS: Record<string, PolicyDetailData> = {
  'pol-001': {
    id: 'pol-001',
    name: 'approved-regions',
    namespace: 'cloudforge.provisioning',
    status: 'active',
    category: 'provisioning',
    evaluations: 4821,
    denials: 38,
    last_updated: '2026-02-20',
    created: '2025-09-14',
    version: '2.1.0',
    description: 'Restricts provisioning to a pre-approved set of cloud regions. Blocks any deployment request targeting a region not in the approved list.',
    rego: `package cloudforge.provisioning.approved_regions

import future.keywords.in

default allow := false

approved_regions := {
  "us-east-1", "us-west-2", "eu-west-1",
  "ap-southeast-1", "ap-northeast-1"
}

deny[msg] {
  input.region
  not input.region in approved_regions
  msg := sprintf(
    "Region '%s' is not in the approved list. Allowed: %v",
    [input.region, approved_regions]
  )
}

allow {
  input.region in approved_regions
}`,
    recent_evaluations: [
      { timestamp: '2026-02-20T14:32:10Z', resource: 'ec2-web-prod-03', result: 'allow' },
      { timestamp: '2026-02-20T14:18:44Z', resource: 'rds-analytics-stg', result: 'allow' },
      { timestamp: '2026-02-20T13:55:02Z', resource: 'lambda-etl-cn-north', result: 'deny', reason: "Region 'cn-north-1' is not in the approved list" },
      { timestamp: '2026-02-20T12:41:30Z', resource: 'ecs-api-gateway', result: 'allow' },
      { timestamp: '2026-02-20T11:09:18Z', resource: 's3-data-lake-prod', result: 'allow' },
    ],
    recent_denials: [
      { timestamp: '2026-02-20T13:55:02Z', resource: 'lambda-etl-cn-north', reason: "Region 'cn-north-1' is not in the approved list", requestor: 'operator1@contoso.dev' },
      { timestamp: '2026-02-19T09:22:41Z', resource: 'ec2-ml-training', reason: "Region 'me-south-1' is not in the approved list", requestor: 'user1@contoso.dev' },
      { timestamp: '2026-02-17T16:05:33Z', resource: 'rds-reporting-sa', reason: "Region 'sa-east-1' is not in the approved list", requestor: 'operator2@contoso.dev' },
    ],
  },
  'pol-002': {
    id: 'pol-002',
    name: 'instance-size-limits',
    namespace: 'cloudforge.provisioning',
    status: 'active',
    category: 'provisioning',
    evaluations: 2103,
    denials: 12,
    last_updated: '2026-02-18',
    created: '2025-10-02',
    version: '1.3.0',
    description: 'Enforces maximum instance sizes per environment tier. Prevents over-provisioning in non-production environments.',
    rego: `package cloudforge.provisioning.instance_size_limits

import future.keywords.in

default allow := false

# Maximum vCPUs per environment tier
max_vcpus := {
  "development": 4,
  "staging":     8,
  "production": 96,
}

# Maximum memory (GB) per environment tier
max_memory_gb := {
  "development": 16,
  "staging":     32,
  "production": 768,
}

deny[msg] {
  tier := input.environment
  max := max_vcpus[tier]
  input.instance.vcpus > max
  msg := sprintf(
    "Instance requests %d vCPUs but %s tier allows max %d",
    [input.instance.vcpus, tier, max]
  )
}

deny[msg] {
  tier := input.environment
  max := max_memory_gb[tier]
  input.instance.memory_gb > max
  msg := sprintf(
    "Instance requests %dGB memory but %s tier allows max %dGB",
    [input.instance.memory_gb, tier, max]
  )
}

allow {
  tier := input.environment
  input.instance.vcpus <= max_vcpus[tier]
  input.instance.memory_gb <= max_memory_gb[tier]
}`,
    recent_evaluations: [
      { timestamp: '2026-02-18T16:10:05Z', resource: 'ec2-api-prod-12', result: 'allow' },
      { timestamp: '2026-02-18T15:48:22Z', resource: 'ec2-ml-dev-gpu', result: 'deny', reason: 'Instance requests 32 vCPUs but development tier allows max 4' },
      { timestamp: '2026-02-18T14:33:11Z', resource: 'ecs-worker-stg', result: 'allow' },
      { timestamp: '2026-02-18T13:21:40Z', resource: 'ec2-batch-prod', result: 'allow' },
      { timestamp: '2026-02-18T11:55:09Z', resource: 'ec2-jenkins-dev', result: 'allow' },
    ],
    recent_denials: [
      { timestamp: '2026-02-18T15:48:22Z', resource: 'ec2-ml-dev-gpu', reason: 'Instance requests 32 vCPUs but development tier allows max 4', requestor: 'user2@contoso.dev' },
      { timestamp: '2026-02-15T10:12:08Z', resource: 'ec2-analytics-stg', reason: 'Instance requests 64GB memory but staging tier allows max 32GB', requestor: 'operator1@contoso.dev' },
      { timestamp: '2026-02-10T08:44:55Z', resource: 'ec2-load-test-dev', reason: 'Instance requests 16 vCPUs but development tier allows max 4', requestor: 'user1@contoso.dev' },
    ],
  },
  'pol-003': {
    id: 'pol-003',
    name: 'required-tags',
    namespace: 'cloudforge.tagging',
    status: 'active',
    category: 'tagging',
    evaluations: 9347,
    denials: 201,
    last_updated: '2026-02-15',
    created: '2025-08-20',
    version: '3.0.1',
    description: 'Enforces mandatory tagging on all provisioned resources. Requires environment, owner, cost-center, and project tags.',
    rego: `package cloudforge.tagging.required_tags

import future.keywords.in

required := {"environment", "owner", "cost-center", "project"}

deny[msg] {
  missing := required - {k | input.tags[k]}
  count(missing) > 0
  msg := sprintf("Missing required tags: %v", [missing])
}`,
    recent_evaluations: [
      { timestamp: '2026-02-15T17:20:00Z', resource: 'ec2-web-prod-05', result: 'allow' },
      { timestamp: '2026-02-15T16:55:12Z', resource: 's3-temp-bucket', result: 'deny', reason: 'Missing required tags: {"cost-center", "project"}' },
      { timestamp: '2026-02-15T16:30:44Z', resource: 'rds-main-prod', result: 'allow' },
      { timestamp: '2026-02-15T15:10:33Z', resource: 'lambda-cron-job', result: 'deny', reason: 'Missing required tags: {"owner"}' },
      { timestamp: '2026-02-15T14:45:20Z', resource: 'ecs-api-prod', result: 'allow' },
    ],
    recent_denials: [
      { timestamp: '2026-02-15T16:55:12Z', resource: 's3-temp-bucket', reason: 'Missing required tags: {"cost-center", "project"}', requestor: 'user2@contoso.dev' },
      { timestamp: '2026-02-15T15:10:33Z', resource: 'lambda-cron-job', reason: 'Missing required tags: {"owner"}', requestor: 'operator2@contoso.dev' },
      { timestamp: '2026-02-14T09:30:18Z', resource: 'ec2-scratch-dev', reason: 'Missing required tags: {"environment", "cost-center"}', requestor: 'user1@contoso.dev' },
    ],
  },
  'pol-004': {
    id: 'pol-004',
    name: 'ai-agent-tool-allow',
    namespace: 'cloudforge.ai.tools',
    status: 'active',
    category: 'ai-governance',
    evaluations: 1203,
    denials: 7,
    last_updated: '2026-02-22',
    created: '2026-01-10',
    version: '1.0.2',
    description: 'Controls which cloud API tools an AI agent can invoke. Maintains an allowlist of safe operations per agent scope.',
    rego: `package cloudforge.ai.tools.allow

import future.keywords.in

allowed_tools := {
  "ec2:DescribeInstances", "ec2:DescribeSecurityGroups",
  "s3:ListBuckets", "s3:GetBucketPolicy",
  "iam:ListRoles", "iam:GetRole",
  "cloudwatch:GetMetricData",
}

deny[msg] {
  tool := input.tool_call
  not tool in allowed_tools
  msg := sprintf("Tool '%s' is not in the agent allowlist", [tool])
}`,
    recent_evaluations: [
      { timestamp: '2026-02-22T10:15:30Z', resource: 'agent-infra-scout', result: 'allow' },
      { timestamp: '2026-02-22T10:14:58Z', resource: 'agent-infra-scout', result: 'allow' },
      { timestamp: '2026-02-22T10:14:22Z', resource: 'agent-infra-scout', result: 'deny', reason: "Tool 'ec2:TerminateInstances' is not in the agent allowlist" },
      { timestamp: '2026-02-22T09:50:11Z', resource: 'agent-cost-analyzer', result: 'allow' },
      { timestamp: '2026-02-22T09:33:44Z', resource: 'agent-cost-analyzer', result: 'allow' },
    ],
    recent_denials: [
      { timestamp: '2026-02-22T10:14:22Z', resource: 'agent-infra-scout', reason: "Tool 'ec2:TerminateInstances' is not in the agent allowlist", requestor: 'system@contoso.dev' },
      { timestamp: '2026-02-19T14:20:05Z', resource: 'agent-remediation', reason: "Tool 'iam:CreateRole' is not in the agent allowlist", requestor: 'system@contoso.dev' },
      { timestamp: '2026-02-16T08:11:42Z', resource: 'agent-infra-scout', reason: "Tool 's3:DeleteBucket' is not in the agent allowlist", requestor: 'system@contoso.dev' },
    ],
  },
  'pol-005': {
    id: 'pol-005',
    name: 'ai-agent-scope-limit',
    namespace: 'cloudforge.ai.agents',
    status: 'active',
    category: 'ai-governance',
    evaluations: 892,
    denials: 2,
    last_updated: '2026-02-22',
    created: '2026-01-10',
    version: '1.1.0',
    description: 'Limits AI agent blast radius by restricting the accounts and environments an agent can operate in.',
    rego: `package cloudforge.ai.agents.scope_limit

import future.keywords.in

deny[msg] {
  input.target_environment == "production"
  not input.agent.production_certified
  msg := sprintf("Agent '%s' is not certified for production", [input.agent.name])
}

deny[msg] {
  not input.target_account in input.agent.allowed_accounts
  msg := sprintf("Agent '%s' cannot operate in account '%s'",
    [input.agent.name, input.target_account])
}`,
    recent_evaluations: [
      { timestamp: '2026-02-22T11:00:20Z', resource: 'agent-infra-scout', result: 'allow' },
      { timestamp: '2026-02-22T10:45:10Z', resource: 'agent-cost-analyzer', result: 'allow' },
      { timestamp: '2026-02-21T16:30:55Z', resource: 'agent-remediation', result: 'deny', reason: "Agent 'remediation-bot' is not certified for production" },
      { timestamp: '2026-02-21T14:22:30Z', resource: 'agent-infra-scout', result: 'allow' },
      { timestamp: '2026-02-21T13:10:05Z', resource: 'agent-cost-analyzer', result: 'allow' },
    ],
    recent_denials: [
      { timestamp: '2026-02-21T16:30:55Z', resource: 'agent-remediation', reason: "Agent 'remediation-bot' is not certified for production", requestor: 'system@contoso.dev' },
      { timestamp: '2026-02-14T11:05:22Z', resource: 'agent-infra-scout', reason: "Agent 'infra-scout' cannot operate in account 'acct-pci-prod'", requestor: 'system@contoso.dev' },
    ],
  },
  'pol-006': {
    id: 'pol-006',
    name: 'public-s3-deny',
    namespace: 'cloudforge.storage',
    status: 'active',
    category: 'security',
    evaluations: 3441,
    denials: 19,
    last_updated: '2026-01-30',
    created: '2025-07-01',
    version: '2.0.0',
    description: 'Prevents creation of S3 buckets with public access enabled. Blocks any bucket policy or ACL that grants public read/write.',
    rego: `package cloudforge.storage.public_s3_deny

import future.keywords.in

default allow := false

public_acls := {
  "public-read", "public-read-write",
  "authenticated-read"
}

deny[msg] {
  acl := input.bucket.acl
  acl in public_acls
  msg := sprintf(
    "Bucket '%s' uses public ACL '%s'. Public access is prohibited.",
    [input.bucket.name, acl]
  )
}

deny[msg] {
  input.bucket.public_access_block == false
  msg := sprintf(
    "Bucket '%s' has PublicAccessBlock disabled. All buckets must enable PublicAccessBlock.",
    [input.bucket.name]
  )
}

deny[msg] {
  statement := input.bucket.policy.Statement[_]
  statement.Effect == "Allow"
  statement.Principal == "*"
  msg := sprintf(
    "Bucket '%s' policy grants access to Principal '*'. Wildcard principals are prohibited.",
    [input.bucket.name]
  )
}

allow {
  count(deny) == 0
}`,
    recent_evaluations: [
      { timestamp: '2026-01-30T15:42:18Z', resource: 's3-reports-internal', result: 'allow' },
      { timestamp: '2026-01-30T14:20:33Z', resource: 's3-static-assets', result: 'deny', reason: "Bucket 's3-static-assets' uses public ACL 'public-read'" },
      { timestamp: '2026-01-30T13:15:09Z', resource: 's3-backups-prod', result: 'allow' },
      { timestamp: '2026-01-30T11:50:44Z', resource: 's3-logs-archive', result: 'allow' },
      { timestamp: '2026-01-30T10:30:22Z', resource: 's3-data-lake', result: 'allow' },
    ],
    recent_denials: [
      { timestamp: '2026-01-30T14:20:33Z', resource: 's3-static-assets', reason: "Bucket 's3-static-assets' uses public ACL 'public-read'", requestor: 'user1@contoso.dev' },
      { timestamp: '2026-01-28T09:44:10Z', resource: 's3-marketing-site', reason: "Bucket 's3-marketing-site' has PublicAccessBlock disabled", requestor: 'user2@contoso.dev' },
      { timestamp: '2026-01-22T16:33:55Z', resource: 's3-shared-docs', reason: "Bucket 's3-shared-docs' policy grants access to Principal '*'", requestor: 'operator1@contoso.dev' },
    ],
  },
  'pol-007': {
    id: 'pol-007',
    name: 'mfa-enforcement',
    namespace: 'cloudforge.identity',
    status: 'draft',
    category: 'identity',
    evaluations: 0,
    denials: 0,
    last_updated: '2026-02-24',
    created: '2026-02-20',
    version: '0.1.0',
    description: 'Requires MFA for all IAM users with console access. Draft policy pending security review.',
    rego: `package cloudforge.identity.mfa_enforcement

deny[msg] {
  input.user.console_access == true
  input.user.mfa_enabled == false
  msg := sprintf("User '%s' has console access without MFA enabled", [input.user.name])
}`,
    recent_evaluations: [],
    recent_denials: [],
  },
  'pol-008': {
    id: 'pol-008',
    name: 'legacy-tls-deny',
    namespace: 'cloudforge.network',
    status: 'inactive',
    category: 'network',
    evaluations: 0,
    denials: 0,
    last_updated: '2026-01-10',
    created: '2025-11-15',
    version: '1.0.0',
    description: 'Blocks resources configured with TLS versions below 1.2. Currently inactive pending migration of legacy services.',
    rego: `package cloudforge.network.legacy_tls_deny

import future.keywords.in

legacy_versions := {"SSLv3", "TLSv1", "TLSv1.1"}

deny[msg] {
  ver := input.tls_config.min_version
  ver in legacy_versions
  msg := sprintf("TLS version '%s' is deprecated. Minimum TLS 1.2 required.", [ver])
}`,
    recent_evaluations: [],
    recent_denials: [],
  },
}

// ── Generator for uncurated policies ────────────────────────────────────────

export function generatePolicyDetail(summary: typeof policiesData[number]): PolicyDetailData {
  const packagePath = summary.namespace || `cloudforge.${summary.category}`

  const regoTemplates: Record<string, string> = {
    encryption: `package ${packagePath}

import future.keywords.in

default allow := false

deny[msg] {
  not input.resource.encryption_enabled
  msg := sprintf("Resource '%s' does not have encryption at rest enabled", [input.resource.name])
}

deny[msg] {
  input.resource.encryption_key_type == "provider-managed"
  input.resource.classification in {"confidential", "restricted"}
  msg := sprintf("Resource '%s' with classification '%s' must use customer-managed keys",
    [input.resource.name, input.resource.classification])
}`,
    security: `package ${packagePath}

import future.keywords.in

default allow := false

deny[msg] {
  input.resource.public_access == true
  msg := sprintf("Resource '%s' has public access enabled — denied by security policy", [input.resource.name])
}

deny[msg] {
  not input.resource.audit_logging
  msg := sprintf("Resource '%s' must have audit logging enabled", [input.resource.name])
}`,
    cost: `package ${packagePath}

import future.keywords.in

default allow := false

deny[msg] {
  input.request.estimated_monthly_cost > input.budget.threshold
  msg := sprintf("Estimated cost $%d exceeds budget threshold $%d for %s",
    [input.request.estimated_monthly_cost, input.budget.threshold, input.request.environment])
}`,
    container: `package ${packagePath}

import future.keywords.in

default allow := false

deny[msg] {
  not input.image.registry in {"ecr.contoso.dev", "acr.contoso.dev", "gcr.contoso.dev"}
  msg := sprintf("Image '%s' is from unapproved registry", [input.image.uri])
}

deny[msg] {
  input.container.privileged == true
  msg := "Privileged containers are not allowed"
}`,
    network: `package ${packagePath}

import future.keywords.in

default allow := false

deny[msg] {
  input.rule.direction == "ingress"
  input.rule.source == "0.0.0.0/0"
  input.rule.port != 443
  msg := sprintf("Ingress from 0.0.0.0/0 on port %d is not allowed — only 443 permitted", [input.rule.port])
}`,
    compliance: `package ${packagePath}

import future.keywords.in

default allow := false

deny[msg] {
  not input.resource.compliance_tags
  msg := sprintf("Resource '%s' is missing compliance tags", [input.resource.name])
}

deny[msg] {
  required := {"data-classification", "retention-period", "audit-scope"}
  missing := required - {k | input.resource.compliance_tags[k]}
  count(missing) > 0
  msg := sprintf("Missing compliance tags: %v", [missing])
}`,
    identity: `package ${packagePath}

import future.keywords.in

default allow := false

deny[msg] {
  input.principal.type == "user"
  not input.principal.mfa_enabled
  msg := sprintf("User '%s' must have MFA enabled", [input.principal.name])
}

deny[msg] {
  input.principal.type == "service_account"
  input.principal.key_age_days > 90
  msg := sprintf("Service account '%s' key is %d days old — max 90 days",
    [input.principal.name, input.principal.key_age_days])
}`,
    tagging: `package ${packagePath}

import future.keywords.in

required_tags := {"environment", "owner", "cost-center", "project", "team"}

deny[msg] {
  missing := required_tags - {k | input.tags[k]}
  count(missing) > 0
  msg := sprintf("Missing required tags: %v", [missing])
}`,
    'ai-governance': `package ${packagePath}

import future.keywords.in

default allow := false

deny[msg] {
  not input.model.version_pinned
  msg := sprintf("Model '%s' must have a pinned version — floating versions are not allowed", [input.model.name])
}

deny[msg] {
  input.model.output_type == "pii"
  not input.guardrails.pii_filter_enabled
  msg := "PII filter must be enabled for models that may output PII"
}`,
    storage: `package ${packagePath}

import future.keywords.in

default allow := false

deny[msg] {
  not input.resource.lifecycle_policy
  msg := sprintf("Storage resource '%s' must have a lifecycle policy configured", [input.resource.name])
}

deny[msg] {
  input.resource.retention_days < 30
  msg := sprintf("Minimum retention is 30 days — resource '%s' has %d days",
    [input.resource.name, input.resource.retention_days])
}`,
  }

  const rego = regoTemplates[summary.category] ?? `package ${packagePath}\n\ndefault allow := false\n\ndeny[msg] {\n  msg := "Policy evaluation pending configuration"\n}`

  const resources = ['ec2-web-prod-05', 'rds-analytics-stg', 'lambda-etl-prod', 'ecs-api-gateway', 's3-data-lake-prod', 'aks-platform-stg', 'gke-ml-prod', 'vm-batch-dev']
  const actors = [brandEmail('operator1'), brandEmail('user1'), brandEmail('user2'), brandEmail('operator2'), brandEmail('admin1')]

  const recentEvals: PolicyEvaluation[] = summary.evaluations > 0 ? Array.from({ length: 5 }, (_, i) => ({
    timestamp: `2026-02-${String(27 - i).padStart(2, '0')}T${String(14 - i).padStart(2, '0')}:${String(30 + i * 7).padStart(2, '0')}:00Z`,
    resource: resources[i % resources.length],
    result: (i === 2 && summary.denials > 0 ? 'deny' : 'allow') as 'allow' | 'deny',
    reason: i === 2 && summary.denials > 0 ? `Denied by ${summary.name} policy` : undefined,
  })) : []

  const recentDenials: PolicyDenial[] = summary.denials > 0 ? Array.from({ length: Math.min(3, summary.denials) }, (_, i) => ({
    timestamp: `2026-02-${String(27 - i * 3).padStart(2, '0')}T${String(10 + i * 2).padStart(2, '0')}:${String(15 + i * 12).padStart(2, '0')}:00Z`,
    resource: resources[(i + 3) % resources.length],
    reason: `Denied by ${summary.name} policy`,
    requestor: actors[i % actors.length],
  })) : []

  return {
    id: summary.id,
    name: summary.name,
    namespace: summary.namespace,
    status: summary.status as 'active' | 'inactive' | 'draft',
    category: summary.category,
    evaluations: summary.evaluations,
    denials: summary.denials,
    last_updated: summary.last_updated.split('T')[0],
    created: '2025-10-01',
    version: summary.evaluations > 5000 ? '2.0.0' : summary.evaluations > 0 ? '1.0.0' : '0.1.0',
    description: `Policy ${summary.name} in namespace ${summary.namespace}. ${summary.status === 'active' ? `Currently enforcing with ${summary.evaluations.toLocaleString()} evaluations and ${summary.denials} denials.` : `Currently ${summary.status}.`}`,
    rego,
    recent_evaluations: recentEvals,
    recent_denials: recentDenials,
  }
}
