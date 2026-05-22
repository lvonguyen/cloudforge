#!/usr/bin/env node
/**
 * transform-real-findings.mjs
 *
 * Transforms real HAEA SecurityHub/Defender/SCC findings into CloudForge
 * Finding schema with anonymized identifiers. Keeps ARN/resource ID patterns
 * intact for demo realism (Wiz-style).
 *
 * Usage:
 *   node scripts/transform-real-findings.mjs [--attack-paths attack-paths.json]
 *
 * Reads from: testdata/cspm/raw/aws_securityhub_findings.json
 *             testdata/cspm/raw/azure_defender_assessments.json
 *             testdata/cspm/raw/gcp_scc_findings.json
 *
 * Outputs findings JSON to stdout, attack paths to --attack-paths file.
 */

import { readFileSync, writeFileSync } from 'fs';
import { createHash } from 'crypto';

const args = process.argv.slice(2);
const getArg = (name) => { const i = args.indexOf(name); return i !== -1 ? args[i + 1] : undefined };
const ATTACK_PATHS_FILE = getArg('--attack-paths');

const RAW_DIR = 'testdata/cspm/raw';

// ── Anonymization maps (deterministic) ──

const COMPANY = 'Meridian Systems';
const ACCOUNT_MAP = {};
let accountSeq = 0;

const FAKE_AWS_ACCOUNTS = [
  { id: '847291036584', name: 'meridian-payments-prod' },
  { id: '293847561029', name: 'meridian-platform-shared' },
  { id: '519283746102', name: 'meridian-data-lake-staging' },
  { id: '738294015638', name: 'meridian-security-tooling' },
  { id: '602918374650', name: 'meridian-ml-platform' },
  { id: '481029374856', name: 'meridian-networking-hub' },
];
const FAKE_AZURE_SUBS = [
  { id: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890', name: 'meridian-shared-services' },
  { id: 'f9e8d7c6-b5a4-3210-fedc-ba9876543210', name: 'meridian-workload-prod' },
  { id: 'c3d4e5f6-a7b8-9012-cdef-345678901234', name: 'meridian-identity-prod' },
];
const FAKE_GCP_PROJECTS = [
  { id: 'mrd-analytics-prod-384729', name: 'mrd-analytics-prod' },
  { id: 'mrd-ml-serving-294817', name: 'mrd-ml-serving' },
  { id: 'mrd-data-warehouse-593820', name: 'mrd-data-warehouse' },
  { id: 'mrd-dev-sandbox-102938', name: 'mrd-dev-sandbox' },
];

function scrambleAccountId(realId, provider) {
  if (ACCOUNT_MAP[realId]) return ACCOUNT_MAP[realId];
  let fakes;
  if (provider === 'aws') fakes = FAKE_AWS_ACCOUNTS;
  else if (provider === 'azure') fakes = FAKE_AZURE_SUBS;
  else fakes = FAKE_GCP_PROJECTS;
  const mapped = fakes[accountSeq % fakes.length];
  accountSeq++;
  ACCOUNT_MAP[realId] = mapped;
  return mapped;
}

// Deterministic hex scramble — keeps length, changes values
function scrambleHex(hex) {
  return createHash('md5').update(hex + 'cloudforge-salt').digest('hex').slice(0, hex.length);
}

// Scramble an ARN — keep structure, replace account + resource suffix
function scrambleArn(arn, fakeAccountId) {
  if (!arn) return arn;
  // arn:aws:service:region:account:type/id
  return arn.replace(/:\d{12}(?=:|\/|$)/g, `:${fakeAccountId}`)
    .replace(/haea|hma/gi, 'meridian');
}

// Scramble Azure resource ID
function scrambleAzureId(id, fakeSubId) {
  if (!id) return id;
  return id.replace(/\/subscriptions\/[^/]+/, `/subscriptions/${fakeSubId}`)
    .replace(/haea|hma/gi, 'meridian');
}

// Scramble GCP resource name
function scrambleGcpName(name, fakeProjectId) {
  if (!name) return name;
  return name.replace(/projects\/[^/]+/, `projects/${fakeProjectId}`)
    .replace(/organizations\/\d+/, 'organizations/847291036584')
    .replace(/haea|hma/gi, 'meridian')
    .replace(/lvn-[a-z-]+/g, `mrd-${scrambleHex('lvn').slice(0,6)}`);
}

// ── Category / type inference ──

const RESOURCE_TYPE_MAP = {
  AwsEc2SecurityGroup: 'network', AwsIamUser: 'identity', AwsAccount: 'identity',
  AwsCloudTrailTrail: 'logging', AwsRdsDbSnapshot: 'database', AwsRdsDbCluster: 'database',
  AwsDocDbDbCluster: 'database', AwsDocumentDbCluster: 'database', AwsS3Bucket: 'storage',
  AwsEcsTaskDefinition: 'container', AwsSnsTopic: 'serverless', AwsLambdaFunction: 'serverless',
  AwsRdsDbInstance: 'database', AwsKmsKey: 'encryption', AwsEcrRepository: 'container',
  AwsEc2Instance: 'compute', AwsSqsQueue: 'serverless', AwsIamPolicy: 'identity',
  AwsElbv2LoadBalancer: 'network',
};

function inferCategory(finding, provider) {
  if (provider === 'aws') {
    const gen = finding.GeneratorId ?? '';
    if (gen.includes('inspector')) return 'VULNERABILITY';
    const resType = finding.Resources?.[0]?.Type ?? '';
    if (resType.includes('Iam') || resType.includes('Account')) return 'IDENTITY';
    if (resType.includes('Ec2SecurityGroup') || resType.includes('Elb')) return 'NETWORK';
    if (resType.includes('S3') || resType.includes('Rds') || resType.includes('Kms')) return 'DATA_EXPOSURE';
    if (gen.includes('cis-aws')) return 'COMPLIANCE';
    return 'MISCONFIGURATION';
  }
  if (provider === 'azure') {
    const title = (finding.title ?? '').toLowerCase();
    if (title.includes('network') || title.includes('nsg') || title.includes('firewall')) return 'NETWORK';
    if (title.includes('identity') || title.includes('mfa') || title.includes('authentication')) return 'IDENTITY';
    if (title.includes('encrypt') || title.includes('key vault') || title.includes('tde')) return 'DATA_EXPOSURE';
    return 'MISCONFIGURATION';
  }
  // GCP
  const cat = (finding.category ?? '').toUpperCase();
  if (cat.includes('BUCKET') || cat.includes('STORAGE') || cat.includes('ENCRYPT')) return 'DATA_EXPOSURE';
  if (cat.includes('FIREWALL') || cat.includes('NETWORK') || cat.includes('SSL')) return 'NETWORK';
  if (cat.includes('IAM') || cat.includes('SERVICE_ACCOUNT') || cat.includes('MFA')) return 'IDENTITY';
  return 'MISCONFIGURATION';
}

function inferResourceType(finding, provider) {
  if (provider === 'aws') return RESOURCE_TYPE_MAP[finding.Resources?.[0]?.Type] ?? 'compute';
  if (provider === 'azure') {
    const rp = (finding.resourceId ?? '').toLowerCase();
    if (rp.includes('sql') || rp.includes('database') || rp.includes('documentdb') || rp.includes('cosmos')) return 'database';
    if (rp.includes('storage')) return 'storage';
    if (rp.includes('keyvault')) return 'encryption';
    if (rp.includes('network') || rp.includes('nsg')) return 'network';
    if (rp.includes('containerservice') || rp.includes('aks')) return 'container';
    if (rp.includes('web') || rp.includes('app')) return 'serverless';
    if (rp.includes('virtualmachine') || rp.includes('compute')) return 'compute';
    if (rp.includes('aad') || rp.includes('identity')) return 'identity';
    return 'compute';
  }
  // GCP
  const sp = finding.sourceProperties ?? {};
  const rt = (sp.ResourceType ?? finding.category ?? '').toLowerCase();
  if (rt.includes('bucket') || rt.includes('storage')) return 'storage';
  if (rt.includes('sql') || rt.includes('bigquery') || rt.includes('spanner')) return 'database';
  if (rt.includes('compute') || rt.includes('instance')) return 'compute';
  if (rt.includes('gke') || rt.includes('container')) return 'container';
  if (rt.includes('iam') || rt.includes('service_account')) return 'identity';
  if (rt.includes('firewall') || rt.includes('network') || rt.includes('vpc')) return 'network';
  if (rt.includes('kms') || rt.includes('key')) return 'encryption';
  return 'compute';
}

const MITRE_BY_CATEGORY = {
  VULNERABILITY: { tactics: ['TA0001', 'TA0002'], techniques: ['T1190', 'T1059'] },
  NETWORK: { tactics: ['TA0001', 'TA0008'], techniques: ['T1190', 'T1021'] },
  IDENTITY: { tactics: ['TA0003', 'TA0004', 'TA0005'], techniques: ['T1098', 'T1078', 'T1548.005'] },
  DATA_EXPOSURE: { tactics: ['TA0009', 'TA0010'], techniques: ['T1005', 'T1567', 'T1530'] },
  MISCONFIGURATION: { tactics: ['TA0005', 'TA0006'], techniques: ['T1562', 'T1552'] },
  COMPLIANCE: { tactics: ['TA0005'], techniques: ['T1562'] },
};

function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
function pickN(arr, n) { return [...arr].sort(() => Math.random() - 0.5).slice(0, n); }
function randRange(min, max) { return +(min + Math.random() * (max - min)).toFixed(2); }

const SEVERITY_SCORES = { CRITICAL: [8.5, 10], HIGH: [6.0, 8.4], MEDIUM: [3.5, 5.9], LOW: [1.0, 3.4] };
const EPSS_RANGES = { CRITICAL: [0.7, 0.98], HIGH: [0.3, 0.7], MEDIUM: [0.05, 0.3], LOW: [0.001, 0.05] };
const SLA_HOURS = { CRITICAL: 24, HIGH: 168, MEDIUM: 720, LOW: 2160 };
const ENVS = ['production', 'staging', 'development'];
const SERVICES = ['payments-api', 'catalog-svc', 'auth-gateway', 'data-pipeline', 'ml-inference', 'platform-core', 'monitoring', 'network-edge'];
const LOBS = ['payments', 'platform', 'data', 'security', 'ml-ops', 'analytics'];
const FRAMEWORKS = ['nist-csf', 'pci-dss', 'hipaa', 'iso-27001'];
const FRAMEWORK_NAMES = { 'nist-csf': 'NIST CSF', 'pci-dss': 'PCI-DSS v4.0', 'hipaa': 'HIPAA', 'iso-27001': 'ISO 27001:2022' };
const WORKFLOW_STATUSES_BY_STATUS = {
  open: ['new', 'triaged', 'assigned'],
  in_progress: ['in_progress'],
  resolved: ['remediated', 'verified'],
  suppressed: ['closed'],
};

// ── Transform functions ──

let findingSeq = 0;

function transformAWS(raw) {
  const sev = (raw.Severity?.Label ?? 'MEDIUM').toUpperCase();
  const res = raw.Resources?.[0] ?? {};
  const realAccountId = raw.AwsAccountId;
  const fakeAccount = scrambleAccountId(realAccountId, 'aws');
  const region = raw.Region ?? res.Region ?? 'us-east-1';
  const resType = inferResourceType(raw, 'aws');
  const category = inferCategory(raw, 'aws');
  const resId = scrambleArn(res.Id ?? `arn:aws:unknown:${region}:${realAccountId}:resource/${++findingSeq}`, fakeAccount.id);
  const resName = resId.split('/').pop()?.split(':').pop() ?? `resource-${findingSeq}`;

  return buildFinding({
    source: raw.GeneratorId?.includes('inspector') ? 'aws-inspector' : 'aws-security-hub',
    sourceId: scrambleArn(raw.Id, fakeAccount.id),
    title: raw.Title,
    description: raw.Description,
    severity: sev,
    category,
    resourceType: resType,
    resourceId: resId,
    resourceName: resName,
    resourceArn: resId,
    provider: 'aws',
    region,
    accountId: fakeAccount.id,
    accountName: fakeAccount.name,
    createdAt: raw.CreatedAt,
    updatedAt: raw.UpdatedAt,
    complianceStatus: raw.Compliance?.Status,
    generatorId: raw.GeneratorId,
  });
}

function transformAzure(raw) {
  const sev = (raw.severity ?? 'Medium').toUpperCase();
  const realSubId = raw.subscriptionId;
  const fakeSub = scrambleAccountId(realSubId, 'azure');
  const resId = scrambleAzureId(raw.resourceId ?? raw.id, fakeSub.id);
  const resName = resId.split('/').pop() ?? `resource-${++findingSeq}`;
  const resType = inferResourceType(raw, 'azure');
  const category = inferCategory(raw, 'azure');
  // Infer region from resource group name pattern or default
  const rgMatch = (raw.resourceGroup ?? '').match(/(eastus|westeurope|southeastasia|westus|northeurope)/i);
  const region = rgMatch ? rgMatch[1].toLowerCase() : 'eastus';

  return buildFinding({
    source: 'azure-defender',
    sourceId: scrambleAzureId(raw.id, fakeSub.id),
    title: raw.title,
    description: raw.description,
    severity: sev,
    category,
    resourceType: resType,
    resourceId: resId,
    resourceName: resName,
    resourceArn: resId,
    provider: 'azure',
    region,
    accountId: fakeSub.id,
    accountName: fakeSub.name,
    createdAt: undefined,
    updatedAt: undefined,
    complianceStatus: raw.status === 'Unhealthy' ? 'FAILED' : 'PASSED',
    generatorId: raw.control,
  });
}

function transformGCP(raw) {
  const sev = (raw.severity ?? 'MEDIUM').toUpperCase();
  const sp = raw.sourceProperties ?? {};
  const realProjectId = sp.ProjectId ?? 'unknown-project';
  const fakeProject = scrambleAccountId(realProjectId, 'gcp');
  const resName = scrambleGcpName(raw.resourceName ?? '', fakeProject.id);
  const resType = inferResourceType(raw, 'gcp');
  const category = inferCategory(raw, 'gcp');
  const shortName = resName.split('/').pop() ?? raw.category ?? `resource-${++findingSeq}`;
  const region = resName.includes('us-central') ? 'us-central1' :
    resName.includes('europe') ? 'europe-west1' :
    resName.includes('asia') ? 'asia-east1' : 'us-central1';

  return buildFinding({
    source: 'gcp-scc',
    sourceId: scrambleGcpName(raw.name ?? '', fakeProject.id),
    title: (raw.category ?? '').replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, c => c.toUpperCase()),
    description: raw.description ?? sp.Explanation ?? '',
    severity: sev,
    category,
    resourceType: resType,
    resourceId: resName,
    resourceName: shortName,
    resourceArn: resName,
    provider: 'gcp',
    region,
    accountId: fakeProject.id,
    accountName: fakeProject.name,
    createdAt: raw.createTime,
    updatedAt: raw.eventTime,
    complianceStatus: raw.state === 'ACTIVE' ? 'FAILED' : 'PASSED',
    generatorId: raw.category,
  });
}

function buildFinding(f) {
  const id = `f-${String(++findingSeq).padStart(5, '0')}`;
  const sev = f.severity;
  const [riskMin, riskMax] = SEVERITY_SCORES[sev] ?? [3, 6];
  const aiRiskScore = randRange(riskMin, riskMax);
  const exploitAvailable = (f.category === 'VULNERABILITY' || f.category === 'NETWORK') &&
    (sev === 'CRITICAL' || (sev === 'HIGH' && Math.random() > 0.5));
  const epss = f.category === 'VULNERABILITY' ? randRange(...(EPSS_RANGES[sev] ?? [0.01, 0.1])) : 0;
  const status = Math.random() < 0.6 ? 'open' : Math.random() < 0.7 ? 'in_progress' : Math.random() < 0.8 ? 'resolved' : 'suppressed';
  const env = pick(ENVS);
  const autoRem = (f.category === 'MISCONFIGURATION' || f.category === 'NETWORK') && Math.random() > 0.6;
  const mitre = MITRE_BY_CATEGORY[f.category] ?? { tactics: [], techniques: [] };
  const now = new Date('2026-02-27T08:00:00Z');
  const baseDate = f.createdAt ? new Date(f.createdAt) : new Date(now.getTime() - Math.random() * 30 * 24 * 3600 * 1000);
  const lastSeen = f.updatedAt ? new Date(f.updatedAt) : new Date(baseDate.getTime() + Math.random() * 5 * 24 * 3600 * 1000);
  const dueDate = new Date(baseDate.getTime() + (SLA_HOURS[sev] ?? 720) * 3600 * 1000);

  const factors = [];
  if (env === 'production') factors.push('production_environment');
  if (exploitAvailable) factors.push('exploit_available');
  if (epss > 0.5) factors.push('high_epss_score');

  const fw = pickN(FRAMEWORKS, 1 + Math.floor(Math.random() * 2));

  const finding = {
    id,
    source: f.source,
    source_finding_id: f.sourceId,
    type: f.category === 'VULNERABILITY' ? 'vulnerability' : f.category === 'NETWORK' ? 'network_exposure' :
      f.category === 'IDENTITY' ? 'iam_risk' : f.category === 'DATA_EXPOSURE' ? 'data_exposure' :
      f.category === 'COMPLIANCE' ? 'compliance_drift' : 'misconfiguration',
    title: f.title,
    description: f.description,
    resource_type: f.resourceType,
    resource_id: f.resourceId,
    resource_name: f.resourceName,
    resource_arn: f.resourceArn,
    platform: 'cloud',
    cloud_provider: f.provider,
    region: f.region,
    account_id: f.accountId,
    account_name: f.accountName,
    environment_type: env,
    static_severity: sev,
    severity: sev,
    ai_risk_score: aiRiskScore,
    ai_risk_level: sev.toLowerCase(),
    ai_risk_rationale: `${sev} severity finding in ${env}. ${factors.length > 0 ? 'Risk factors: ' + factors.join(', ') + '.' : 'Standard risk assessment.'}`,
    ai_contextual_factors: factors,
    exploit_available: exploitAvailable,
    epss: epss > 0 ? epss : undefined,
    mitre_tactics: pickN(mitre.tactics, Math.min(mitre.tactics.length, 1 + Math.floor(Math.random() * 2))),
    mitre_techniques: pickN(mitre.techniques, Math.min(mitre.techniques.length, 1 + Math.floor(Math.random() * 2))),
    compliance_mappings: fw.map(fId => ({
      framework_id: fId,
      framework_name: FRAMEWORK_NAMES[fId],
      control_id: `${fId === 'nist-csf' ? 'PR' : fId === 'pci-dss' ? 'REQ' : 'A'}.${Math.floor(1 + Math.random() * 12)}.${Math.floor(1 + Math.random() * 6)}`,
      control_title: `Control for ${f.category.toLowerCase().replace('_', ' ')}`,
      section: `${fId === 'nist-csf' ? 'PR' : String(Math.floor(1 + Math.random() * 12))}`,
      severity: sev.toLowerCase(),
    })),
    remediation: autoRem
      ? `Auto-remediation available: Apply configuration fix via ${f.provider.toUpperCase()} API.`
      : `Manual remediation required: ${f.title.includes('CVE') ? 'Apply vendor patch' : 'Review and update configuration'}.`,
    auto_remediatable: autoRem,
    category: f.category,
    status,
    workflow_status: pick(WORKFLOW_STATUSES_BY_STATUS[status] ?? ['new']),
    suppressed: status === 'suppressed',
    service_name: pick(SERVICES),
    line_of_business: pick(LOBS),
    first_found_at: baseDate.toISOString(),
    last_seen_at: lastSeen.toISOString(),
    due_date: dueDate.toISOString(),
    deduplication_key: scrambleHex(id + f.resourceId),
    canonical_rule_id: f.generatorId ?? `${f.category}-${id}`,
  };

  // Clean undefined
  for (const k of Object.keys(finding)) {
    if (finding[k] === undefined) delete finding[k];
  }
  return finding;
}

// ── Load and transform ──

process.stderr.write(`[+] Loading raw findings from ${RAW_DIR}/\n`);

const awsRaw = JSON.parse(readFileSync(`${RAW_DIR}/aws_securityhub_findings.json`, 'utf8'));
const azRaw = JSON.parse(readFileSync(`${RAW_DIR}/azure_defender_assessments.json`, 'utf8'));
const gcpRaw = JSON.parse(readFileSync(`${RAW_DIR}/gcp_scc_findings.json`, 'utf8'));

const awsArr = Array.isArray(awsRaw) ? awsRaw : awsRaw.Findings ?? Object.values(awsRaw)[0];
const azArr = azRaw.value ?? (Array.isArray(azRaw) ? azRaw : Object.values(azRaw)[0]);
const gcpArr = gcpRaw.findings ?? gcpRaw.listFindingsResults ?? (Array.isArray(gcpRaw) ? gcpRaw : Object.values(gcpRaw)[0]);

process.stderr.write(`[+] AWS: ${awsArr.length}, Azure: ${azArr.length}, GCP: ${gcpArr.length}\n`);

const findings = [];
for (const f of awsArr) findings.push(transformAWS(f));
for (const f of azArr) findings.push(transformAzure(f));
for (const f of gcpArr) findings.push(transformGCP(f));

process.stderr.write(`[+] Transformed ${findings.length} findings\n`);

// ── Second pass: impacted_resources + toxic_combo_details ──

const COMBO_TYPES = ['privilege_escalation', 'data_exfiltration', 'lateral_movement', 'network_exposure', 'credential_theft'];
const COMBO_DESCRIPTIONS = {
  privilege_escalation: 'IAM misconfiguration combined with exposed service enables privilege escalation to administrative access.',
  data_exfiltration: 'Unencrypted storage with public access creates a direct data exfiltration path to attacker infrastructure.',
  lateral_movement: 'Permissive security group combined with compromised account enables east-west pivot across subnets.',
  network_exposure: 'Public-facing endpoint without WAF combined with open database port exposes application tier.',
  credential_theft: 'Long-lived access keys combined with overly permissive role provide persistent unauthorized access.',
};

const byAccount = {};
for (const f of findings) {
  if (!byAccount[f.account_id]) byAccount[f.account_id] = [];
  byAccount[f.account_id].push(f);
}

for (const acctFindings of Object.values(byAccount)) {
  const candidates = acctFindings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH');
  for (const finding of candidates) {
    if (Math.random() > 0.20) continue;
    const others = acctFindings.filter(s => s.id !== finding.id);
    if (others.length === 0) continue;
    const count = Math.min(1 + Math.floor(Math.random() * 3), others.length);
    const selected = others.sort(() => Math.random() - 0.5).slice(0, count);
    finding.impacted_resources = selected.map(s => ({
      resource_id: s.resource_id,
      resource_name: s.resource_name,
      resource_type: s.resource_type,
      severity: pick(['HIGH', 'CRITICAL', 'MEDIUM']),
    }));
    if (Math.random() > 0.10) continue;
    const comboType = pick(COMBO_TYPES);
    finding.toxic_combo_details = {
      combo_type: comboType,
      description: COMBO_DESCRIPTIONS[comboType],
      attack_vector: pick(['network', 'local', 'adjacent']),
      blast_radius: pick(['account', 'region', 'vpc']),
      exploit_potential: finding.severity === 'CRITICAL' ? 'active' : 'likely',
      attack_path: ['Internet', finding.resource_name, selected[0].resource_name],
      related_findings: selected.map(s => s.id),
    };
  }
}

const irCount = findings.filter(f => f.impacted_resources?.length > 0).length;
const tcCount = findings.filter(f => f.toxic_combo_details).length;
process.stderr.write(`[+] Enriched: ${irCount} with impacted_resources, ${tcCount} with toxic_combo_details\n`);

// ── Amplify Azure/GCP: normalize regions so canConnect hits more often ──
// Azure and GCP findings have inconsistent/missing regions. Assign each account's
// findings to 2-3 regions so path candidates within the same account can connect.

const AZ_REGIONS_POOL = ['eastus', 'westeurope', 'southeastasia', 'westus2', 'northeurope'];
const GCP_REGIONS_POOL = ['us-central1', 'europe-west1', 'asia-east1', 'us-east4'];

for (const acctFindings of Object.values(byAccount)) {
  if (acctFindings.length === 0) continue;
  const prov = acctFindings[0].cloud_provider;
  if (prov === 'aws') continue; // AWS regions are already correct from the ARN

  const regionPool = prov === 'azure' ? AZ_REGIONS_POOL : GCP_REGIONS_POOL;
  // Assign findings round-robin to 3 regions so same-region pairs form
  for (let i = 0; i < acctFindings.length; i++) {
    acctFindings[i].region = regionPool[i % 3];
  }
}

process.stderr.write(`[+] Region-normalized Azure/GCP findings for path connectivity\n`);

// ── Third pass: pre-compute attack paths from top candidates ──

if (ATTACK_PATHS_FILE) {
  const CANDIDATE_LIMIT = 1500;
  const SEV_SCORE = { CRITICAL: 100, HIGH: 60, MEDIUM: 20, LOW: 5 };
  const TARGET_TYPES = new Set(['storage', 'database', 'encryption', 'secret']);
  const ENTRY_CATS = new Set(['NETWORK', 'VULNERABILITY']);

  const density = {};
  for (const f of findings) density[f.account_id] = (density[f.account_id] ?? 0) + 1;

  const scored = findings.map(f => {
    let s = SEV_SCORE[f.severity] ?? 0;
    if (f.exploit_available) s += 50;
    if (f.environment_type === 'production') s += 30;
    if (ENTRY_CATS.has(f.category)) s += 20;
    if (TARGET_TYPES.has(f.resource_type)) s += 20;
    if ((f.epss ?? 0) > 0.5) s += 15;
    if ((f.mitre_tactics?.length ?? 0) > 0) s += 10;
    if ((f.ai_risk_score ?? 0) > 8) s += 10;
    if ((density[f.account_id] ?? 0) > 100) s += 15;
    if (f.impacted_resources?.length > 0) s += 25;
    return { f, s };
  }).sort((a, b) => b.s - a.s);

  const pool = scored.slice(0, CANDIDATE_LIMIT).map(x => x.f);
  process.stderr.write(`[+] Selected ${pool.length} attack path candidates (top by metadata score)\n`);

  const isEntry = (f) => {
    if (f.category === 'NETWORK') return true;
    if (f.category === 'VULNERABILITY' && f.exploit_available) return true;
    if (f.category === 'IDENTITY' && (SEV_SCORE[f.severity] ?? 0) >= 60) return true;
    const rt = (f.resource_type ?? '').toLowerCase();
    if (['compute', 'container', 'serverless', 'network'].some(t => rt.includes(t)) && (SEV_SCORE[f.severity] ?? 0) >= 20) return true;
    // Broader: any CRITICAL/HIGH misconfiguration on non-target resource is a potential entry
    if (f.category === 'MISCONFIGURATION' && (SEV_SCORE[f.severity] ?? 0) >= 60 && !TARGET_TYPES.has(f.resource_type)) return true;
    return false;
  };
  const isTarget = (f) => TARGET_TYPES.has(f.resource_type) || f.category === 'DATA_EXPOSURE';
  const canConnect = (a, b) => {
    if (a.account_id !== b.account_id || a.resource_id === b.resource_id) return false;
    // Same region or same resource type (original logic)
    if (a.region === b.region || a.resource_type === b.resource_type) return true;
    // Complementary categories — entry types can reach target types in same account
    const entryCats = new Set(['NETWORK', 'VULNERABILITY', 'IDENTITY']);
    const targetCats = new Set(['DATA_EXPOSURE', 'MISCONFIGURATION']);
    if (entryCats.has(a.category) && (targetCats.has(b.category) || TARGET_TYPES.has(b.resource_type))) return true;
    return false;
  };

  const poolByAccount = {};
  for (const f of pool) {
    if (!poolByAccount[f.account_id]) poolByAccount[f.account_id] = [];
    poolByAccount[f.account_id].push(f);
  }

  const toNode = (f) => ({
    id: `node-${f.id}`, finding_id: f.id, resource_id: f.resource_id, resource_name: f.resource_name,
    resource_type: f.resource_type, provider: f.cloud_provider, account_id: f.account_id,
    region: f.region, severity: f.severity, category: f.category,
    label: `${f.resource_name} (${f.resource_type})`,
  });

  const paths = [];
  let pIdx = 0;
  const usedIds = new Set();

  // Per-provider path budget: ~60% AWS, ~25% Azure, ~15% GCP (proportional to real cloud spend)
  const PATH_BUDGET = { aws: 300, azure: 120, gcp: 80 };
  const providerPathCount = { aws: 0, azure: 0, gcp: 0 };

  // Sort accounts: interleave providers so each gets fair share
  const accountEntries = Object.entries(poolByAccount);
  accountEntries.sort((a, b) => {
    const pa = a[1][0]?.cloud_provider ?? '';
    const pb = b[1][0]?.cloud_provider ?? '';
    if (pa !== pb) return pa.localeCompare(pb);
    return b[1].length - a[1].length; // densest accounts first within provider
  });

  for (const [, acctFindings] of accountEntries) {
    if (acctFindings.length < 2) continue;
    const prov = acctFindings[0]?.cloud_provider ?? 'aws';
    const budget = PATH_BUDGET[prov] ?? 100;
    if (providerPathCount[prov] >= budget) continue;

    const entries = acctFindings.filter(isEntry);
    const targets = acctFindings.filter(isTarget);
    const mids = acctFindings.filter(f => !isEntry(f) && !isTarget(f));

    for (const e of entries) {
      if (providerPathCount[prov] >= budget) break;
      for (const t of targets) {
        if (providerPathCount[prov] >= budget) break;
        if (!canConnect(e, t) && mids.length === 0) continue;
        if (canConnect(e, t)) {
          paths.push({
            id: `ap-${String(++pIdx).padStart(5, '0')}`,
            title: `${e.resource_name} → ${t.resource_name}`,
            description: `Attack path from ${e.category.toLowerCase()} on ${e.resource_name} to ${t.resource_type} ${t.resource_name}`,
            severity: (SEV_SCORE[e.severity] ?? 0) >= 100 ? 'CRITICAL' : 'HIGH',
            score: Math.min((SEV_SCORE[e.severity] ?? 0) + (SEV_SCORE[t.severity] ?? 0), 100),
            hop_count: 2, entry_point: toNode(e), target: toNode(t),
            nodes: [toNode(e), toNode(t)],
            edges: [{ id: 'edge-0', source: `node-${e.id}`, target: `node-${t.id}`, label: TARGET_TYPES.has(t.resource_type) ? 'Can access data' : 'Lateral movement', edge_type: 'data_access' }],
            mitre_tactics: e.mitre_tactics ?? [], finding_ids: [e.id, t.id], ai_enriched: false,
          });
          usedIds.add(e.id); usedIds.add(t.id);
          providerPathCount[prov]++;
          continue;
        }
        for (const m of mids) {
          if (canConnect(e, m) && canConnect(m, t)) {
            paths.push({
              id: `ap-${String(++pIdx).padStart(5, '0')}`,
              title: `${e.resource_name} → ${m.resource_name} → ${t.resource_name}`,
              description: `Multi-hop attack from ${e.resource_name} through ${m.resource_name} to ${t.resource_name}`,
              severity: (SEV_SCORE[e.severity] ?? 0) >= 100 ? 'CRITICAL' : 'HIGH',
              score: Math.min((SEV_SCORE[e.severity] ?? 0) + (SEV_SCORE[m.severity] ?? 0) + (SEV_SCORE[t.severity] ?? 0), 100),
              hop_count: 3, entry_point: toNode(e), target: toNode(t),
              nodes: [toNode(e), toNode(m), toNode(t)],
              edges: [
                { id: 'edge-0', source: `node-${e.id}`, target: `node-${m.id}`, label: 'Lateral movement', edge_type: 'lateral_movement' },
                { id: 'edge-1', source: `node-${m.id}`, target: `node-${t.id}`, label: TARGET_TYPES.has(t.resource_type) ? 'Can access data' : 'IAM trust', edge_type: 'data_access' },
              ],
              mitre_tactics: [...new Set([...(e.mitre_tactics ?? []), ...(m.mitre_tactics ?? [])])],
              finding_ids: [e.id, m.id, t.id], ai_enriched: false,
            });
            usedIds.add(e.id); usedIds.add(m.id); usedIds.add(t.id);
            providerPathCount[prov]++;
            break;
          }
        }
      }
    }
  }

  paths.sort((a, b) => {
    const sr = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    return (sr[b.severity] ?? 0) - (sr[a.severity] ?? 0) || b.score - a.score;
  });

  const byProv = {};
  for (const p of paths) { const pr = p.entry_point.provider; byProv[pr] = (byProv[pr] ?? 0) + 1; }

  const apOutput = {
    paths,
    stats: {
      total_findings: findings.length, findings_in_paths: usedIds.size,
      isolated_findings: findings.length - usedIds.size,
      coverage_percent: Math.round((usedIds.size / findings.length) * 100),
      total_paths: paths.length,
      critical_paths: paths.filter(p => p.severity === 'CRITICAL').length,
      high_paths: paths.filter(p => p.severity === 'HIGH').length,
      medium_paths: paths.filter(p => p.severity === 'MEDIUM').length,
      by_provider: byProv,
    },
  };

  writeFileSync(ATTACK_PATHS_FILE, JSON.stringify(apOutput, null, 2));
  process.stderr.write(`[+] ${paths.length} attack paths → ${ATTACK_PATHS_FILE}\n`);
  process.stderr.write(`    CRIT: ${apOutput.stats.critical_paths}, HIGH: ${apOutput.stats.high_paths}\n`);
  process.stderr.write(`    Coverage: ${apOutput.stats.coverage_percent}% of findings in paths\n`);
}

// ── Output findings ──
process.stdout.write(JSON.stringify(findings));
process.stderr.write(`[+] Done. ${findings.length} findings written to stdout\n`);
