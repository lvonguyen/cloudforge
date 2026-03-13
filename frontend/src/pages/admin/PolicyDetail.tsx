import { brandMockData, brandEmail, brandRegistryRefs } from '@/lib/mock-data-utils'
import React, { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import policiesData from '@/lib/mock/policies.json'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import {
  ArrowLeft, Copy, Check, CheckCircle2, AlertTriangle, Clock,
  FileCode, Shield, XCircle,
} from 'lucide-react'

// ── Types ────────────────────────────────────────────────────────────────────

interface PolicyEvaluation {
  timestamp: string
  resource: string
  result: 'allow' | 'deny'
  reason?: string
}

interface PolicyDenial {
  timestamp: string
  resource: string
  reason: string
  requestor: string
}

interface PolicyDetailData {
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

// ── Status / Category config (mirrored from Policies.tsx) ────────────────────

const STATUS_CONFIG: Record<string, { icon: typeof CheckCircle2; className: string; label: string }> = {
  active: { icon: CheckCircle2, className: 'text-green-600 dark:text-green-400', label: 'Active' },
  inactive: { icon: AlertTriangle, className: 'text-gray-400 dark:text-gray-500', label: 'Inactive' },
  draft: { icon: Clock, className: 'text-yellow-600 dark:text-yellow-400', label: 'Draft' },
}

const STATUS_BADGE: Record<string, string> = {
  active: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
  inactive: 'bg-gray-100 text-gray-500 dark:bg-gray-900/30 dark:text-gray-400',
  draft: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
}

const CATEGORY_COLORS: Record<string, string> = {
  provisioning: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
  tagging: 'bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-300',
  'ai-governance': 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300',
  security: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  identity: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300',
  network: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
  storage: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
}

// ── Mock data ────────────────────────────────────────────────────────────────

const POLICY_DETAILS: Record<string, PolicyDetailData> = {
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

function generatePolicyDetail(summary: typeof policiesData[number]): PolicyDetailData {
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

// ── Component ────────────────────────────────────────────────────────────────

export default function PolicyDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [copied, setCopied] = useState(false)

  const policy = (() => {
    if (!id) return undefined
    if (POLICY_DETAILS[id]) return brandMockData(POLICY_DETAILS[id])
    const summary = policiesData.find((p: { id: string }) => p.id === id)
    if (!summary) return undefined
    return generatePolicyDetail(summary)
  })()

  if (!policy) {
    return (
      <div className="space-y-4 max-w-3xl">
        <Button variant="ghost" size="sm" className="gap-1.5 -ml-2" onClick={() => navigate('/admin/policies')}>
          <ArrowLeft className="h-4 w-4" />All Policies
        </Button>
        <div className="text-sm text-muted-foreground">Policy not found.</div>
      </div>
    )
  }

  const { icon: StatusIcon, className: statusIconClass } = STATUS_CONFIG[policy.status] ?? STATUS_CONFIG.inactive
  const rego = brandRegistryRefs(policy.rego)
  const lines = rego.split('\n')

  function handleCopy() {
    navigator.clipboard.writeText(rego).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  return (
    <div className="space-y-6 pb-10">
      <Button variant="ghost" size="sm" className="gap-1.5 -ml-2" onClick={() => navigate('/admin/policies')}>
        <ArrowLeft className="h-4 w-4" />All Policies
      </Button>

      {/* Header */}
      <div>
        <div className="flex items-center gap-2 flex-wrap mb-2">
          <Badge variant="outline" className="text-[10px] font-mono uppercase tracking-wide rounded-none">{policy.id}</Badge>
          <Badge variant="secondary" className={`text-[10px] font-mono uppercase tracking-wide rounded-none ${STATUS_BADGE[policy.status] ?? ''}`}>
            {policy.status}
          </Badge>
          <Badge variant="secondary" className={`text-[10px] font-mono uppercase tracking-wide rounded-none ${CATEGORY_COLORS[policy.category] ?? ''}`}>
            {policy.category}
          </Badge>
          <Badge variant="outline" className="text-[10px] font-mono rounded-none">v{policy.version}</Badge>
        </div>
        <h1 className="text-xl font-semibold font-mono">{policy.name}</h1>
        <p className="text-sm text-muted-foreground mt-1">{policy.description}</p>
      </div>

      <Separator />

      {/* Two-column layout */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        {/* Left: metadata */}
        <div className="lg:col-span-2">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                <div className="flex items-center gap-1.5"><Shield className="h-3.5 w-3.5" />Policy Metadata</div>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {[
                { label: 'Namespace', value: policy.namespace },
                { label: 'Category', value: policy.category },
                { label: 'Status', value: policy.status, icon: true },
                { label: 'Evaluations', value: policy.evaluations.toLocaleString() },
                { label: 'Denials', value: String(policy.denials), highlight: policy.denials > 0 },
                { label: 'Last Updated', value: policy.last_updated },
                { label: 'Created', value: policy.created },
                { label: 'Version', value: policy.version },
              ].map(({ label, value, icon, highlight }) => (
                <div key={label} className="flex items-center justify-between py-1 border-b border-border/40 last:border-0">
                  <span className="text-[10px] text-muted-foreground uppercase tracking-wide">{label}</span>
                  {icon ? (
                    <div className="flex items-center gap-1">
                      <StatusIcon className={`h-3 w-3 ${statusIconClass}`} />
                      <span className={`text-xs font-medium capitalize ${statusIconClass}`}>{value}</span>
                    </div>
                  ) : (
                    <span className={`text-xs font-mono font-medium ${highlight ? 'text-red-600 dark:text-red-400' : ''}`}>{value}</span>
                  )}
                </div>
              ))}
            </CardContent>
          </Card>
        </div>

        {/* Right: policy definition */}
        <div className="lg:col-span-3">
          <Card className="overflow-hidden">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  <div className="flex items-center gap-1.5"><FileCode className="h-3.5 w-3.5" />Policy Definition (Rego)</div>
                </CardTitle>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-7 px-2 text-[10px] gap-1"
                  onClick={handleCopy}
                >
                  {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                  {copied ? 'Copied' : 'Copy'}
                </Button>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              <div className="bg-[#1a1a1a] overflow-x-auto">
                <pre className="text-[12px] leading-5 p-4 font-mono">
                  <code>
                    {lines.map((line, i) => (
                      <div key={i} className="flex">
                        <span className="inline-block w-8 text-right mr-4 text-gray-600 select-none shrink-0">{i + 1}</span>
                        <span className="text-green-400">{highlightRego(line)}</span>
                      </div>
                    ))}
                  </code>
                </pre>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Recent evaluations */}
      {policy.recent_evaluations.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
              Recent Evaluations
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-xs pl-4">Timestamp</TableHead>
                  <TableHead className="text-xs">Resource</TableHead>
                  <TableHead className="text-xs">Result</TableHead>
                  <TableHead className="text-xs">Reason</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {policy.recent_evaluations.map((ev, i) => (
                  <TableRow key={i}>
                    <TableCell className="text-[10px] font-mono text-muted-foreground pl-4 whitespace-nowrap">
                      {formatTimestamp(ev.timestamp)}
                    </TableCell>
                    <TableCell className="text-xs font-mono">{ev.resource}</TableCell>
                    <TableCell>
                      {ev.result === 'allow' ? (
                        <div className="flex items-center gap-1">
                          <CheckCircle2 className="h-3 w-3 text-green-600 dark:text-green-400" />
                          <span className="text-xs text-green-600 dark:text-green-400 font-medium">Allow</span>
                        </div>
                      ) : (
                        <div className="flex items-center gap-1">
                          <XCircle className="h-3 w-3 text-red-600 dark:text-red-400" />
                          <span className="text-xs text-red-600 dark:text-red-400 font-medium">Deny</span>
                        </div>
                      )}
                    </TableCell>
                    <TableCell className="text-[10px] text-muted-foreground max-w-xs truncate">
                      {ev.reason ?? '--'}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {/* Recent denials */}
      {policy.recent_denials.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
              <div className="flex items-center gap-1.5"><AlertTriangle className="h-3.5 w-3.5" />Recent Denials</div>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-xs pl-4">Timestamp</TableHead>
                  <TableHead className="text-xs">Resource</TableHead>
                  <TableHead className="text-xs">Reason</TableHead>
                  <TableHead className="text-xs">Requestor</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {policy.recent_denials.map((d, i) => (
                  <TableRow key={i}>
                    <TableCell className="text-[10px] font-mono text-muted-foreground pl-4 whitespace-nowrap">
                      {formatTimestamp(d.timestamp)}
                    </TableCell>
                    <TableCell className="text-xs font-mono">{d.resource}</TableCell>
                    <TableCell className="text-[10px] text-red-600 dark:text-red-400 max-w-xs truncate">{d.reason}</TableCell>
                    <TableCell className="text-[10px] font-mono text-muted-foreground">{d.requestor}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {/* Empty state for draft/inactive */}
      {policy.recent_evaluations.length === 0 && policy.recent_denials.length === 0 && (
        <Card>
          <CardContent className="p-6">
            <p className="text-sm text-muted-foreground text-center">
              No evaluations recorded. This policy is currently <strong>{policy.status}</strong>.
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function formatTimestamp(iso: string): string {
  const d = new Date(iso)
  return d.toLocaleString('en-US', {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
    hour12: false,
  })
}

function highlightRego(line: string): React.ReactElement {
  const comments = /(#.*)$/

  // Check for comment first
  const commentMatch = line.match(comments)
  if (commentMatch && line.trimStart().startsWith('#')) {
    return <span className="text-gray-500 italic">{line}</span>
  }

  const parts: Array<{ text: string; className: string }> = []
  let lastIndex = 0

  // Build a combined regex for tokenization
  const combined = /("(?:[^"\\]|\\.)*")|(#.*)|\b(package|import|default|deny|allow|not|in|as|with|some|every|if|contains|else)\b|(:=|==|!=|>=|<=)|(\{|\}|\[|\])|(\b\d+\b)/g
  let match

  while ((match = combined.exec(line)) !== null) {
    // Add text before this match as plain
    if (match.index > lastIndex) {
      parts.push({ text: line.slice(lastIndex, match.index), className: 'text-green-400' })
    }

    if (match[1]) {
      // String literal
      parts.push({ text: match[0], className: 'text-amber-300' })
    } else if (match[2]) {
      // Comment
      parts.push({ text: match[0], className: 'text-gray-500 italic' })
    } else if (match[3]) {
      // Keyword
      parts.push({ text: match[0], className: 'text-purple-400 font-semibold' })
    } else if (match[4]) {
      // Operator
      parts.push({ text: match[0], className: 'text-cyan-400' })
    } else if (match[5]) {
      // Brackets
      parts.push({ text: match[0], className: 'text-yellow-300' })
    } else if (match[6]) {
      // Number
      parts.push({ text: match[0], className: 'text-orange-400' })
    } else {
      parts.push({ text: match[0], className: 'text-green-400' })
    }

    lastIndex = match.index + match[0].length
  }

  // Add remaining text
  if (lastIndex < line.length) {
    parts.push({ text: line.slice(lastIndex), className: 'text-green-400' })
  }

  if (parts.length === 0) {
    return <span className="text-green-400">{line}</span>
  }

  return (
    <>
      {parts.map((p, i) => (
        <span key={i} className={p.className}>{p.text}</span>
      ))}
    </>
  )
}
