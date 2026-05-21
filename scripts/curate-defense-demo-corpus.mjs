#!/usr/bin/env node
/**
 * curate-defense-demo-corpus.mjs
 *
 * Adds a deterministic defense-adjacent slice to the static CloudForge demo
 * corpus without increasing the Cloudflare Pages findings payload beyond the
 * 500-finding portfolio limit.
 *
 * The records are synthetic. They model government-cloud migration and
 * defense-startup readiness scenarios, but they do not represent customer,
 * government, CUI, classified, or export-controlled data.
 */

import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const root = join(__dirname, '..')
const findingsPath = join(root, 'frontend/public/mock/findings.json')
const attackPathsPath = join(root, 'frontend/public/mock/attack-paths.json')
const MAX_FINDINGS = 500
const MAX_ATTACK_PATHS = 520

function iso(daysAgo) {
  const d = new Date('2026-05-20T16:00:00Z')
  d.setUTCDate(d.getUTCDate() - daysAgo)
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z')
}

function mapping(frameworkID, frameworkName, controlID, title, severity = 'high') {
  return {
    framework_id: frameworkID,
    framework_name: frameworkName,
    control_id: controlID,
    control_title: title,
    section: controlID.split('.')[0],
    severity,
    url: '',
  }
}

function step(order, title, description, platform, automated = false, command = '') {
  return { order, title, description, platform, automated, ...(command ? { command } : {}) }
}

function finding({
  id,
  provider,
  accountID,
  accountName,
  region,
  source,
  sourceFindingID,
  type,
  title,
  description,
  resourceType,
  resourceID,
  resourceName,
  severity,
  category,
  environment = 'production',
  risk = 8.4,
  factors = [],
  mappings = [],
  remediation,
  auto = false,
  service = 'platform-infra',
  lob = 'security',
  daysAgo = 2,
  mitre = [],
  techniques = [],
  tags = {},
  impactedResources = [],
  toxicCombo,
  cves = [],
}) {
  return {
    id,
    source,
    source_finding_id: sourceFindingID,
    type,
    title,
    description,
    resource_type: resourceType,
    resource_id: resourceID,
    resource_name: resourceName,
    resource_arn: resourceID,
    platform: 'cloud',
    cloud_provider: provider,
    region,
    account_id: accountID,
    account_name: accountName,
    environment_type: environment,
    static_severity: severity,
    severity,
    ai_risk_score: risk,
    ai_risk_level: severity.toLowerCase(),
    ai_risk_rationale: `${severity} defense-readiness signal in ${environment}. Risk factors: ${factors.join(', ')}.`,
    ai_contextual_factors: factors,
    exploit_available: cves.some(cve => cve.cisa_known_exploited),
    cves,
    mitre_tactics: mitre,
    mitre_techniques: techniques,
    compliance_mappings: mappings,
    remediation,
    remediation_steps: buildSteps(provider, type, resourceName),
    auto_remediatable: auto,
    category,
    status: 'open',
    workflow_status: auto ? 'assigned' : 'triaged',
    suppressed: false,
    service_name: service,
    line_of_business: lob,
    first_found_at: iso(daysAgo + 2),
    last_seen_at: iso(daysAgo),
    due_date: iso(-7),
    sla_breach_date: severity === 'CRITICAL' ? iso(0) : undefined,
    deduplication_key: `defense-${id}`,
    canonical_rule_id: id.toUpperCase(),
    impacted_resources: impactedResources,
    toxic_combo_details: toxicCombo,
    tags: {
      corpus: 'synthetic-defense-readiness',
      data_boundary: 'synthetic-only',
      data_classification: 'synthetic-cui',
      controlled_data: 'simulated',
      compliance_scope: 'cmmc-l2 fedramp-high nist-800-171 itar-ear-boundary',
      migration_phase: 'pre-cutover',
      workload_migration: 'true',
      ...tags,
    },
  }
}

function buildSteps(provider, type, resourceName) {
  const prefix = provider === 'azure' ? 'az' : provider === 'gcp' ? 'gcloud' : 'aws'
  return [
    step(1, 'Confirm scope', `Validate owner, environment, and restricted-data label for ${resourceName}.`, provider, true),
    step(2, 'Apply guardrail', `Apply the least disruptive ${type.replace('_', ' ')} control through IaC or policy-as-code.`, provider, false, `${prefix} # apply scoped remediation via approved change`),
    step(3, 'Capture evidence', 'Export control evidence and link it to the remediation ticket before closure.', provider, true),
  ]
}

const azureAccount = {
  provider: 'azure',
  accountID: 'sub-gov-mission-001',
  accountName: 'gcc-high-migration-landing-zone',
  region: 'usgovvirginia',
}
const gcpAccount = {
  provider: 'gcp',
  accountID: 'proj-defense-analytics-001',
  accountName: 'assured-workloads-trial',
  region: 'us-central1',
}
const awsGovAccount = {
  provider: 'aws',
  accountID: '999988887777',
  accountName: 'govcloud-mission-dev',
  region: 'us-gov-west-1',
}

const curatedFindings = [
  finding({
    ...azureAccount,
    id: 'df-az-001',
    source: 'azure-defender',
    sourceFindingID: 'azd-defense-001',
    type: 'network_exposure',
    title: 'Azure Application Gateway exposes migration API without WAF policy',
    description: 'Synthetic GCC High migration API is internet reachable and missing an enforced WAF policy before workload cutover.',
    resourceType: 'network',
    resourceID: '/subscriptions/sub-gov-mission-001/resourceGroups/rg-mission-prod/providers/Microsoft.Network/applicationGateways/agw-migration-api',
    resourceName: 'agw-migration-api',
    severity: 'HIGH',
    category: 'NETWORK',
    risk: 8.2,
    factors: ['internet_facing', 'workload_migration', 'gcc_high_boundary'],
    mappings: [
      mapping('cmmc-l2', 'CMMC Level 2', 'SC.L2-3.13.1', 'Monitor and control communications at external boundaries'),
      mapping('fedramp-high', 'FedRAMP High Rev.5', 'SC-7', 'Boundary protection'),
    ],
    remediation: 'Attach WAF policy, restrict source ranges to ZTNA ingress, and require deployment evidence before migration cutover.',
    auto: true,
    mitre: ['TA0001', 'TA0040'],
    techniques: ['T1190'],
    impactedResources: [
      { resource_id: 'azdo://pipelines/mission-release', resource_name: 'mission-release', resource_type: 'identity', relationship: 'deploys_to', impact_level: 'high' },
    ],
  }),
  finding({
    ...azureAccount,
    id: 'df-az-002',
    source: 'azure-defender',
    sourceFindingID: 'azd-defense-002',
    type: 'data_exposure',
    title: 'Blob container with synthetic CUI label allows broad read access',
    description: 'Storage account used for prototype artifact migration has anonymous access disabled but broad tenant read grants remain.',
    resourceType: 'storage',
    resourceID: '/subscriptions/sub-gov-mission-001/resourceGroups/rg-mission-prod/providers/Microsoft.Storage/storageAccounts/stmissionartifacts/blobServices/default/containers/prototype-artifacts',
    resourceName: 'prototype-artifacts',
    severity: 'CRITICAL',
    category: 'DATA_PROTECTION',
    risk: 9.4,
    factors: ['synthetic_cui_label', 'broad_tenant_access', 'production_environment'],
    mappings: [
      mapping('nist-800-171', 'NIST SP 800-171 Rev.3', 'AC.3.1.1', 'Limit system access to authorized users'),
      mapping('itar-ear', 'ITAR/EAR Boundary Checks', 'ITAR-BOUNDARY-01', 'Restrict controlled technical data repositories'),
    ],
    remediation: 'Remove tenant-wide reader assignments, require private endpoint access, and attach a restricted-data policy exemption record.',
    auto: false,
    mitre: ['TA0009', 'TA0010'],
    techniques: ['T1530', 'T1567'],
  }),
  finding({
    ...azureAccount,
    id: 'df-az-003',
    source: 'azure-sentinel',
    sourceFindingID: 'azd-defense-003',
    type: 'iam_risk',
    title: 'Azure DevOps release identity can update production Key Vault secrets',
    description: 'Pipeline service connection has contributor-level access to production secrets without environment approval gates.',
    resourceType: 'identity',
    resourceID: 'azdo://service-connections/mission-release-prod',
    resourceName: 'mission-release-prod',
    severity: 'HIGH',
    category: 'IDENTITY',
    risk: 8.7,
    factors: ['pipeline_identity', 'secret_admin', 'missing_approval_gate'],
    mappings: [
      mapping('cmmc-l2', 'CMMC Level 2', 'AC.L2-3.1.5', 'Employ least privilege'),
      mapping('fedramp-high', 'FedRAMP High Rev.5', 'IA-5', 'Authenticator management'),
    ],
    remediation: 'Scope the service connection to deployment-only permissions and require protected environment approvals for secret writes.',
    auto: false,
    mitre: ['TA0003', 'TA0004'],
    techniques: ['T1098', 'T1552'],
  }),
  finding({
    ...azureAccount,
    id: 'df-az-004',
    source: 'azure-defender',
    sourceFindingID: 'azd-defense-004',
    type: 'compliance_drift',
    title: 'Key Vault purge protection disabled for mission signing key',
    description: 'Key Vault hosting synthetic firmware signing material has soft-delete enabled but purge protection is disabled.',
    resourceType: 'security',
    resourceID: '/subscriptions/sub-gov-mission-001/resourceGroups/rg-mission-prod/providers/Microsoft.KeyVault/vaults/kv-mission-signing',
    resourceName: 'kv-mission-signing',
    severity: 'HIGH',
    category: 'COMPLIANCE',
    risk: 8.1,
    factors: ['signing_key_material', 'recoverability_gap', 'audit_evidence_gap'],
    mappings: [
      mapping('fedramp-high', 'FedRAMP High Rev.5', 'CP-9', 'System backup'),
      mapping('nist-800-171', 'NIST SP 800-171 Rev.3', 'SC.3.13.11', 'Protect confidentiality of CUI at rest'),
    ],
    remediation: 'Enable purge protection, validate RBAC, and export key-rotation evidence for the release-readiness packet.',
    auto: true,
  }),
  finding({
    ...gcpAccount,
    id: 'df-gcp-001',
    source: 'gcp-scc',
    sourceFindingID: 'gcp-defense-001',
    type: 'network_exposure',
    title: 'GCE bastion has external IP and no IAP-only access policy',
    description: 'Assured Workloads trial bastion remains internet reachable instead of forcing Identity-Aware Proxy access.',
    resourceType: 'compute',
    resourceID: 'projects/proj-defense-analytics-001/zones/us-central1-a/instances/bastion-migration-trial',
    resourceName: 'bastion-migration-trial',
    severity: 'HIGH',
    category: 'NETWORK',
    risk: 8.3,
    factors: ['external_ip', 'missing_iap', 'trial_environment'],
    mappings: [
      mapping('nist-800-171', 'NIST SP 800-171 Rev.3', 'AC.3.1.12', 'Monitor and control remote access sessions'),
      mapping('cmmc-l2', 'CMMC Level 2', 'AC.L2-3.1.12', 'Monitor and control remote access sessions'),
    ],
    remediation: 'Remove external IP, require IAP TCP forwarding, and enforce OS Login with MFA-backed groups.',
    auto: true,
    mitre: ['TA0001'],
    techniques: ['T1021'],
  }),
  finding({
    ...gcpAccount,
    id: 'df-gcp-002',
    source: 'gcp-scc',
    sourceFindingID: 'gcp-defense-002',
    type: 'iam_risk',
    title: 'Cloud Build service account has Owner on analytics trial project',
    description: 'Build identity can mutate IAM, storage, and compute resources across the synthetic defense analytics project.',
    resourceType: 'identity',
    resourceID: 'serviceAccount:cloudbuild-proj-defense-analytics-001@cloudbuild.gserviceaccount.com',
    resourceName: 'cloudbuild-defense-owner',
    severity: 'CRITICAL',
    category: 'IDENTITY',
    risk: 9.6,
    factors: ['ci_cd_identity', 'owner_role', 'cross_service_mutation'],
    mappings: [
      mapping('cmmc-l2', 'CMMC Level 2', 'AC.L2-3.1.5', 'Employ least privilege'),
      mapping('fedramp-high', 'FedRAMP High Rev.5', 'AC-6', 'Least privilege'),
    ],
    remediation: 'Replace Owner with workload-specific deployer roles and add policy validation to Cloud Build triggers.',
    auto: false,
    mitre: ['TA0003', 'TA0004'],
    techniques: ['T1078', 'T1098'],
  }),
  finding({
    ...gcpAccount,
    id: 'df-gcp-003',
    source: 'gcp-scc',
    sourceFindingID: 'gcp-defense-003',
    type: 'data_exposure',
    title: 'GCS bucket for simulation telemetry lacks uniform access enforcement',
    description: 'Bucket holding synthetic test telemetry has object ACL inheritance enabled, creating inconsistent access evidence.',
    resourceType: 'storage',
    resourceID: 'projects/_/buckets/mission-telemetry-trial',
    resourceName: 'mission-telemetry-trial',
    severity: 'HIGH',
    category: 'DATA_PROTECTION',
    risk: 8.0,
    factors: ['object_acl_drift', 'telemetry_dataset', 'evidence_gap'],
    mappings: [
      mapping('nist-800-171', 'NIST SP 800-171 Rev.3', 'AC.3.1.3', 'Control flow of CUI in accordance with approved authorizations'),
      mapping('fedramp-high', 'FedRAMP High Rev.5', 'AC-3', 'Access enforcement'),
    ],
    remediation: 'Enable uniform bucket-level access, remove legacy ACLs, and export IAM policy evidence.',
    auto: true,
  }),
  finding({
    ...gcpAccount,
    id: 'df-gcp-004',
    source: 'gcp-cspm',
    sourceFindingID: 'gcp-defense-004',
    type: 'compliance_drift',
    title: 'BigQuery data access audit logs disabled for mission analytics dataset',
    description: 'Dataset access events are not captured, blocking incident reconstruction for synthetic analytics workflows.',
    resourceType: 'database',
    resourceID: 'projects/proj-defense-analytics-001/datasets/mission_analytics',
    resourceName: 'mission_analytics',
    severity: 'HIGH',
    category: 'COMPLIANCE',
    risk: 8.5,
    factors: ['audit_logging_gap', 'analytics_dataset', 'incident_response_gap'],
    mappings: [
      mapping('fedramp-high', 'FedRAMP High Rev.5', 'AU-2', 'Event logging'),
      mapping('cmmc-l2', 'CMMC Level 2', 'AU.L2-3.3.1', 'Create and retain system audit logs and records'),
    ],
    remediation: 'Enable BigQuery data access logs, route to locked sink, and attach retention evidence to control AU-2.',
    auto: true,
  }),
  finding({
    ...gcpAccount,
    id: 'df-gcp-005',
    source: 'gcp-scc',
    sourceFindingID: 'gcp-defense-005',
    type: 'misconfiguration',
    title: 'Artifact Registry allows unsigned container promotion',
    description: 'Container images can promote to GKE trial namespaces without Binary Authorization attestation.',
    resourceType: 'container',
    resourceID: 'projects/proj-defense-analytics-001/locations/us-central1/repositories/mission-containers',
    resourceName: 'mission-containers',
    severity: 'HIGH',
    category: 'CONTAINER',
    risk: 8.2,
    factors: ['unsigned_artifact', 'deployment_guardrail_gap', 'supply_chain'],
    mappings: [
      mapping('cmmc-l2', 'CMMC Level 2', 'SI.L2-3.14.2', 'Identify, report, and correct system flaws'),
      mapping('fedramp-high', 'FedRAMP High Rev.5', 'SI-7', 'Software, firmware, and information integrity'),
    ],
    remediation: 'Require image signing attestations and block promotion without SLSA provenance evidence.',
    auto: false,
    mitre: ['TA0005'],
    techniques: ['T1562'],
  }),
  finding({
    ...awsGovAccount,
    id: 'df-aws-001',
    source: 'aws-security-hub',
    sourceFindingID: 'arn:aws-us-gov:securityhub:us-gov-west-1:999988887777:finding/df-aws-001',
    type: 'data_exposure',
    title: 'GovCloud S3 artifact bucket permits cross-account read from commercial tooling role',
    description: 'Synthetic mission artifact bucket in GovCloud trusts a commercial tooling role during migration testing.',
    resourceType: 'storage',
    resourceID: 'arn:aws-us-gov:s3:::mission-artifacts-gov-trial',
    resourceName: 'mission-artifacts-gov-trial',
    severity: 'CRITICAL',
    category: 'DATA_PROTECTION',
    risk: 9.5,
    factors: ['govcloud_boundary', 'commercial_role_trust', 'synthetic_cui_label'],
    mappings: [
      mapping('itar-ear', 'ITAR/EAR Boundary Checks', 'EAR-BOUNDARY-02', 'Prevent unauthorized cross-boundary data movement'),
      mapping('nist-800-171', 'NIST SP 800-171 Rev.3', 'AC.3.1.20', 'Verify and control external connections'),
    ],
    remediation: 'Remove commercial trust, require GovCloud-native break-glass role, and preserve access-analyzer evidence.',
    auto: false,
    mitre: ['TA0009', 'TA0010'],
    techniques: ['T1530', 'T1567'],
  }),
  finding({
    ...awsGovAccount,
    id: 'df-aws-002',
    source: 'aws-security-hub',
    sourceFindingID: 'arn:aws-us-gov:securityhub:us-gov-west-1:999988887777:finding/df-aws-002',
    type: 'iam_risk',
    title: 'OIDC deploy role trusts all repositories in organization',
    description: 'GitHub OIDC role in GovCloud permits wildcard subject claims instead of repository and branch-scoped trust.',
    resourceType: 'identity',
    resourceID: 'arn:aws-us-gov:iam::999988887777:role/gha-govcloud-deployer',
    resourceName: 'gha-govcloud-deployer',
    severity: 'HIGH',
    category: 'IDENTITY',
    risk: 8.8,
    factors: ['ci_cd_identity', 'wildcard_trust', 'govcloud_boundary'],
    mappings: [
      mapping('cmmc-l2', 'CMMC Level 2', 'AC.L2-3.1.5', 'Employ least privilege'),
      mapping('fedramp-high', 'FedRAMP High Rev.5', 'IA-2', 'Identification and authentication'),
    ],
    remediation: 'Restrict OIDC trust to approved repositories, branches, workflow refs, and environment protection gates.',
    auto: false,
    mitre: ['TA0003', 'TA0004'],
    techniques: ['T1078', 'T1098'],
  }),
  finding({
    ...awsGovAccount,
    id: 'df-aws-003',
    source: 'aws-security-hub',
    sourceFindingID: 'arn:aws-us-gov:securityhub:us-gov-west-1:999988887777:finding/df-aws-003',
    type: 'compliance_drift',
    title: 'CloudTrail log validation missing on GovCloud org trail',
    description: 'Organization trail is enabled, but log-file validation and immutable retention evidence are missing.',
    resourceType: 'monitoring',
    resourceID: 'arn:aws-us-gov:cloudtrail:us-gov-west-1:999988887777:trail/org-mission-trail',
    resourceName: 'org-mission-trail',
    severity: 'HIGH',
    category: 'COMPLIANCE',
    risk: 8.0,
    factors: ['audit_integrity_gap', 'org_trail', 'fedramp_evidence_gap'],
    mappings: [
      mapping('fedramp-high', 'FedRAMP High Rev.5', 'AU-9', 'Protection of audit information'),
      mapping('cmmc-l2', 'CMMC Level 2', 'AU.L2-3.3.8', 'Protect audit information and logging tools'),
    ],
    remediation: 'Enable log-file validation, route logs to immutable storage, and document continuous-monitoring evidence.',
    auto: true,
  }),
  finding({
    ...awsGovAccount,
    id: 'df-aws-004',
    source: 'aws-security-hub',
    sourceFindingID: 'arn:aws-us-gov:securityhub:us-gov-west-1:999988887777:finding/df-aws-004',
    type: 'misconfiguration',
    title: 'Mission bastion permits IMDSv1 during migration testing',
    description: 'GovCloud EC2 bastion used for workload migration allows optional instance metadata tokens.',
    resourceType: 'compute',
    resourceID: 'arn:aws-us-gov:ec2:us-gov-west-1:999988887777:instance/i-0defensebastion',
    resourceName: 'mission-bastion-gov',
    severity: 'HIGH',
    category: 'COMPUTE',
    risk: 8.1,
    factors: ['credential_theft', 'migration_bastion', 'metadata_service'],
    mappings: [
      mapping('fedramp-high', 'FedRAMP High Rev.5', 'SI-2', 'Flaw remediation'),
      mapping('cmmc-l2', 'CMMC Level 2', 'SI.L2-3.14.2', 'Identify, report, and correct system flaws'),
    ],
    remediation: 'Require IMDSv2, remove public administrative ingress, and validate SSM Session Manager access.',
    auto: true,
    mitre: ['TA0006'],
    techniques: ['T1552'],
  }),
  finding({
    ...awsGovAccount,
    id: 'df-aws-005',
    source: 'aws-guardduty',
    sourceFindingID: 'arn:aws-us-gov:guardduty:us-gov-west-1:999988887777:detector/df-aws-005',
    type: 'threat',
    title: 'Synthetic anomaly: unusual access to GovCloud artifact bucket from deploy role',
    description: 'GuardDuty-style synthetic signal shows deploy role reading artifacts outside its normal promotion window.',
    resourceType: 'identity',
    resourceID: 'arn:aws-us-gov:iam::999988887777:role/gha-govcloud-deployer',
    resourceName: 'gha-govcloud-deployer',
    severity: 'HIGH',
    category: 'THREAT',
    risk: 8.6,
    factors: ['behavioral_anomaly', 'deploy_role', 'artifact_access'],
    mappings: [
      mapping('fedramp-high', 'FedRAMP High Rev.5', 'IR-4', 'Incident handling'),
      mapping('cmmc-l2', 'CMMC Level 2', 'IR.L2-3.6.1', 'Establish operational incident-handling capability'),
    ],
    remediation: 'Quarantine the role session, rotate deploy credentials, and compare CloudTrail evidence against approved pipeline windows.',
    auto: false,
    mitre: ['TA0006', 'TA0010'],
    techniques: ['T1078', 'T1530'],
  }),
]

function node(finding, pathID, index) {
  return {
    id: `${pathID}-node-${index}`,
    finding_id: finding.id,
    resource_id: finding.resource_id,
    resource_name: finding.resource_name,
    resource_type: finding.resource_type,
    provider: finding.cloud_provider,
    account_id: finding.account_id,
    region: finding.region,
    severity: finding.severity,
    category: finding.category,
    label: finding.resource_name,
  }
}

function edge(pathID, index, source, target, label, edgeType) {
  return {
    id: `${pathID}-edge-${index}`,
    source: source.id,
    target: target.id,
    label,
    edge_type: edgeType,
  }
}

function path(id, title, findingIDs, severity, score, missionImpact, riskFactors, chokePoints) {
  const byID = new Map(curatedFindings.map(f => [f.id, f]))
  const findings = findingIDs.map(fid => byID.get(fid))
  const nodes = findings.map((f, index) => node(f, id, index))
  const edgeLabels = ['network_reachable', 'iam_trust', 'data_access', 'audit_gap']
  const edges = []
  for (let i = 1; i < nodes.length; i += 1) {
    const edgeType = edgeLabels[Math.min(i - 1, edgeLabels.length - 1)]
    const label = edgeType === 'iam_trust' ? 'CI/CD trust' :
      edgeType === 'data_access' ? 'Can access data' :
      edgeType === 'audit_gap' ? 'Evidence gap' :
      'Network reachable'
    edges.push(edge(id, i - 1, nodes[i - 1], nodes[i], label, edgeType))
  }

  return {
    id,
    title,
    description: `${nodes.length - 1}-hop synthetic defense-readiness path: ${nodes.map(n => n.resource_name).join(' -> ')}`,
    severity,
    score,
    hop_count: nodes.length - 1,
    entry_point: nodes[0],
    target: nodes[nodes.length - 1],
    nodes,
    edges,
    mitre_tactics: [...new Set(findings.flatMap(f => f.mitre_tactics ?? []))],
    finding_ids: findingIDs,
    ai_description: `Synthetic path showing how migration pressure can connect exposure, identity drift, and restricted-data evidence gaps.`,
    ai_remediation: riskFactors.map(factor => `Break path: ${factor}`).join('\n'),
    ai_likelihood: severity === 'CRITICAL' ? 'high' : 'medium',
    ai_confidence: 0.86,
    ai_validated: true,
    ai_risk_narrative: missionImpact,
    ai_enriched: true,
    evidence_mode: 'synthetic-defense-demo',
    mission_context: missionImpact,
    mission_impact: missionImpact,
    risk_factors: riskFactors,
    control_gaps: [...new Set(findings.flatMap(f => (f.compliance_mappings ?? []).map(m => `${m.framework_name} ${m.control_id}`)))],
    recommended_breaks: riskFactors,
    rollback_summary: 'Rollback-first remediation plan: stage IaC or policy change, capture pre-state evidence, and keep a reversible path for IAM, network, and data-access changes.',
    choke_points: chokePoints,
    control_mappings: [...new Set(findings.flatMap(f => (f.compliance_mappings ?? []).map(m => `${m.framework_name} ${m.control_id}`)))],
  }
}

const curatedPaths = [
  path(
    'ap-defense-azure-001',
    'Azure migration API to synthetic CUI artifact container',
    ['df-az-001', 'df-az-003', 'df-az-002'],
    'CRITICAL',
    98,
    'A public migration API and broad pipeline identity could expose synthetic artifact data before the GCC High cutover is evidence-ready.',
    ['Attach WAF and source restrictions to agw-migration-api', 'Scope mission-release-prod away from secret and storage administration', 'Remove broad readers on prototype-artifacts'],
    ['mission-release-prod', 'prototype-artifacts'],
  ),
  path(
    'ap-defense-gcp-001',
    'GCP trial bastion to analytics data plane',
    ['df-gcp-001', 'df-gcp-002', 'df-gcp-004'],
    'CRITICAL',
    97,
    'External bastion access plus an over-privileged build identity could mutate analytics controls and reduce auditability.',
    ['Remove bastion external IP and require IAP', 'Replace Owner role on cloudbuild-defense-owner', 'Enable BigQuery data access logs'],
    ['cloudbuild-defense-owner', 'mission_analytics'],
  ),
  path(
    'ap-defense-gcp-002',
    'Unsigned container promotion to telemetry bucket exposure',
    ['df-gcp-005', 'df-gcp-002', 'df-gcp-003'],
    'HIGH',
    90,
    'A supply-chain bypass can promote untrusted workload changes while broad build permissions expose telemetry data.',
    ['Require signed provenance for mission-containers', 'Scope Cloud Build permissions', 'Enable uniform bucket-level access'],
    ['cloudbuild-defense-owner'],
  ),
  path(
    'ap-defense-aws-001',
    'GovCloud deploy role to cross-boundary artifact access',
    ['df-aws-002', 'df-aws-005', 'df-aws-001'],
    'CRITICAL',
    99,
    'Wildcard OIDC trust and unusual deploy-role behavior create a cross-boundary artifact access scenario in synthetic GovCloud migration data.',
    ['Restrict OIDC subject claims', 'Quarantine anomalous deploy sessions', 'Remove commercial role trust from mission-artifacts-gov-trial'],
    ['gha-govcloud-deployer', 'mission-artifacts-gov-trial'],
  ),
  path(
    'ap-defense-aws-002',
    'GovCloud bastion to audit integrity gap',
    ['df-aws-004', 'df-aws-003', 'df-aws-001'],
    'HIGH',
    88,
    'A migration bastion credential-theft path becomes harder to investigate because org trail validation and immutable evidence are incomplete.',
    ['Enforce IMDSv2 and SSM access', 'Enable CloudTrail log validation', 'Lock artifact bucket access evidence'],
    ['org-mission-trail'],
  ),
]

function loadJSON(pathName) {
  return JSON.parse(readFileSync(pathName, 'utf8'))
}

function writeJSON(pathName, value, { compact = false } = {}) {
  writeFileSync(pathName, `${compact ? JSON.stringify(value) : JSON.stringify(value, null, 2)}\n`)
}

function severityRank(severity) {
  return { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }[severity] ?? 1
}

function attackPathStats(paths, totalFindings) {
  const findingIDs = new Set()
  const byProvider = {}
  for (const p of paths) {
    for (const fid of p.finding_ids ?? []) findingIDs.add(fid)
    const provider = p.entry_point?.provider ?? p.nodes?.[0]?.provider ?? 'unknown'
    byProvider[provider] = (byProvider[provider] ?? 0) + 1
  }
  return {
    total_findings: totalFindings,
    findings_in_paths: findingIDs.size,
    isolated_findings: Math.max(totalFindings - findingIDs.size, 0),
    coverage_percent: totalFindings > 0 ? Math.round((findingIDs.size / totalFindings) * 100) : 0,
    total_paths: paths.length,
    critical_paths: paths.filter(p => p.severity === 'CRITICAL').length,
    high_paths: paths.filter(p => p.severity === 'HIGH').length,
    medium_paths: paths.filter(p => severityRank(p.severity) <= 2).length,
    by_provider: byProvider,
  }
}

const existingFindings = loadJSON(findingsPath)
const curatedIDs = new Set(curatedFindings.map(f => f.id))
const nextFindings = [
  ...curatedFindings,
  ...existingFindings.filter(f => !curatedIDs.has(f.id)),
].slice(0, MAX_FINDINGS)

const existingAttackPaths = loadJSON(attackPathsPath)
const existingPaths = Array.isArray(existingAttackPaths)
  ? existingAttackPaths
  : existingAttackPaths.paths ?? []
const nextPaths = [
  ...curatedPaths,
  ...existingPaths.filter(p => !(p.id ?? '').startsWith('ap-defense-')),
].slice(0, MAX_ATTACK_PATHS)

writeJSON(findingsPath, nextFindings, { compact: true })
writeJSON(attackPathsPath, {
  paths: nextPaths,
  stats: attackPathStats(nextPaths, nextFindings.length),
})

console.log(`[curate-defense-demo-corpus] findings: ${existingFindings.length} -> ${nextFindings.length}`)
console.log(`[curate-defense-demo-corpus] attack paths: ${existingPaths.length} -> ${nextPaths.length}`)
