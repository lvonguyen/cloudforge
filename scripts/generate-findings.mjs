#!/usr/bin/env node
// Generate 80 mock security findings for CloudForge frontend
// Run: node scripts/generate-findings.mjs > frontend/src/lib/mock/findings.json

const AWS_ACCOUNTS = [
  { id: '123456789012', name: 'acme-payments-prod' },
  { id: '234567890123', name: 'acme-data-lake-dev' },
  { id: '345678901234', name: 'acme-shared-services' },
  { id: '456789012345', name: 'acme-networking-hub' },
  { id: '567890123456', name: 'acme-security-tooling' },
  { id: '678901234567', name: 'acme-catalog-prod' },
  { id: '789012345678', name: 'acme-analytics-staging' },
  { id: '890123456789', name: 'acme-ml-platform' },
  { id: '901234567890', name: 'acme-sandbox-01' },
  { id: '012345678901', name: 'acme-dr-west' },
];
const AZURE_SUBS = [
  { id: 'sub-shared-001', name: 'shared-services-hub' },
  { id: 'sub-identity-001', name: 'corp-identity-prod' },
  { id: 'sub-finance-001', name: 'workload-finance-prod' },
  { id: 'sub-hr-001', name: 'workload-hr-dev' },
  { id: 'sub-monitor-001', name: 'platform-monitoring' },
  { id: 'sub-aks-001', name: 'aks-platform-staging' },
];
const GCP_PROJECTS = [
  { id: 'proj-analytics-001', name: 'analytics-data-warehouse' },
  { id: 'proj-ml-001', name: 'ml-platform-prod' },
  { id: 'proj-bq-001', name: 'bigquery-finance' },
  { id: 'proj-gke-001', name: 'gke-ml-serving' },
];

const AWS_REGIONS = ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1'];
const AZURE_REGIONS = ['eastus', 'westeurope', 'southeastasia'];
const GCP_REGIONS = ['us-central1', 'europe-west1'];
const ENVS = ['production', 'staging', 'development', 'sandbox'];
const ENV_DIST = [32, 24, 16, 8]; // out of 80
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const SEV_DIST = [8, 20, 28, 24];
const STATUSES = ['open', 'in_progress', 'resolved', 'suppressed'];
const STATUS_DIST = [50, 15, 10, 5];
const TYPES = ['vulnerability', 'misconfiguration', 'network_exposure', 'iam_risk', 'data_exposure', 'compliance_drift'];
const CATEGORIES = ['VULNERABILITY', 'MISCONFIGURATION', 'NETWORK', 'IDENTITY', 'COMPLIANCE', 'DATA_EXPOSURE'];
const WORKFLOW_STATUSES = ['new', 'triaged', 'assigned', 'in_progress', 'remediated', 'verified', 'closed'];
const FRAMEWORKS = ['nist-csf', 'pci-dss', 'hipaa', 'iso-27001', 'iso-42001', 'tisax'];
const FRAMEWORK_NAMES = { 'nist-csf': 'NIST CSF', 'pci-dss': 'PCI-DSS v4.0', 'hipaa': 'HIPAA', 'iso-27001': 'ISO 27001:2022', 'iso-42001': 'ISO 42001:2023', 'tisax': 'TISAX' };
const TACTICS = ['TA0001', 'TA0002', 'TA0003', 'TA0004', 'TA0005', 'TA0006', 'TA0008', 'TA0009', 'TA0010', 'TA0040'];
const TECHNIQUES = ['T1190', 'T1059', 'T1098', 'T1068', 'T1562', 'T1552', 'T1021', 'T1005', 'T1567', 'T1499', 'T1078', 'T1530', 'T1548.005', 'T1110', 'T1566'];
const SERVICES = ['payments-service', 'catalog-service', 'auth-service', 'data-pipeline', 'ml-training', 'platform-infra', 'monitoring', 'networking', 'identity', 'analytics'];
const LOBS = ['payments', 'platform', 'data', 'security', 'ml', 'analytics', 'identity', 'catalog'];
const AWS_SOURCES = ['aws-security-hub', 'aws-guardduty'];
const AZURE_SOURCES = ['azure-defender', 'azure-sentinel'];
const GCP_SOURCES = ['gcp-scc', 'gcp-cspm'];

function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
function pickN(arr, n) { const s = [...arr].sort(() => Math.random() - 0.5); return s.slice(0, n); }
function pad(n) { return String(n).padStart(3, '0'); }

// Build distribution arrays
function buildDist(values, counts) {
  const result = [];
  for (let i = 0; i < values.length; i++) {
    for (let j = 0; j < counts[i]; j++) result.push(values[i]);
  }
  return result.sort(() => Math.random() - 0.5);
}

const providerDist = buildDist(['aws', 'azure', 'gcp'], [52, 20, 8]);
const sevDist = buildDist(SEVERITIES, SEV_DIST);
const statusDist = buildDist(STATUSES, STATUS_DIST);
const envDist = buildDist(ENVS, ENV_DIST);

// SLA offsets in hours by severity
const SLA_HOURS = { CRITICAL: 24, HIGH: 168, MEDIUM: 720, LOW: 2160 };

// CVSS ranges by severity
const CVSS_RANGE = { CRITICAL: [9.0, 10.0], HIGH: [7.0, 8.9], MEDIUM: [4.0, 6.9], LOW: [0.1, 3.9] };
const EPSS_RANGE = { CRITICAL: [0.7, 0.98], HIGH: [0.3, 0.7], MEDIUM: [0.05, 0.3], LOW: [0.001, 0.05] };
const RISK_RANGE = { CRITICAL: [8.5, 10.0], HIGH: [6.0, 8.4], MEDIUM: [3.5, 5.9], LOW: [1.0, 3.4] };

function randRange(min, max) { return +(min + Math.random() * (max - min)).toFixed(2); }

// AWS resource templates
const AWS_RESOURCES = [
  { type: 'compute', prefix: 'i-', service: 'EC2', arnType: 'ec2', arnRes: 'instance' },
  { type: 'storage', prefix: 's3-', service: 'S3', arnType: 's3', arnRes: '' },
  { type: 'database', prefix: 'db-', service: 'RDS', arnType: 'rds', arnRes: 'db' },
  { type: 'serverless', prefix: 'fn-', service: 'Lambda', arnType: 'lambda', arnRes: 'function' },
  { type: 'container', prefix: 'eks-', service: 'EKS', arnType: 'eks', arnRes: 'cluster' },
  { type: 'identity', prefix: 'role-', service: 'IAM', arnType: 'iam', arnRes: 'role' },
  { type: 'network', prefix: 'sg-', service: 'VPC', arnType: 'ec2', arnRes: 'security-group' },
  { type: 'logging', prefix: 'trail-', service: 'CloudTrail', arnType: 'cloudtrail', arnRes: 'trail' },
  { type: 'encryption', prefix: 'key-', service: 'KMS', arnType: 'kms', arnRes: 'key' },
  { type: 'network', prefix: 'elb-', service: 'ELB', arnType: 'elasticloadbalancing', arnRes: 'loadbalancer' },
];
const AZURE_RESOURCES = [
  { type: 'compute', prefix: 'vm-', service: 'Virtual Machines', rp: 'Microsoft.Compute/virtualMachines' },
  { type: 'storage', prefix: 'stor-', service: 'Storage', rp: 'Microsoft.Storage/storageAccounts' },
  { type: 'container', prefix: 'aks-', service: 'AKS', rp: 'Microsoft.ContainerService/managedClusters' },
  { type: 'encryption', prefix: 'kv-', service: 'Key Vault', rp: 'Microsoft.KeyVault/vaults' },
  { type: 'network', prefix: 'nsg-', service: 'NSG', rp: 'Microsoft.Network/networkSecurityGroups' },
  { type: 'database', prefix: 'sql-', service: 'SQL Database', rp: 'Microsoft.Sql/servers' },
  { type: 'serverless', prefix: 'app-', service: 'App Service', rp: 'Microsoft.Web/sites' },
  { type: 'identity', prefix: 'ad-', service: 'Azure AD', rp: 'Microsoft.AAD/domainServices' },
];
const GCP_RESOURCES = [
  { type: 'compute', prefix: 'gce-', service: 'GCE' },
  { type: 'storage', prefix: 'gcs-', service: 'GCS' },
  { type: 'container', prefix: 'gke-', service: 'GKE' },
  { type: 'database', prefix: 'csql-', service: 'Cloud SQL' },
  { type: 'database', prefix: 'bq-', service: 'BigQuery' },
  { type: 'identity', prefix: 'iam-', service: 'IAM' },
  { type: 'network', prefix: 'vpc-', service: 'VPC' },
];

// Finding title/description templates
const VULN_TEMPLATES = [
  { title: 'CVE-{cve} — Remote code execution in {res}', desc: 'Remote code execution vulnerability allowing unauthenticated attacker to execute arbitrary code. {extra}' },
  { title: 'CVE-{cve} — SQL injection in {res}', desc: 'SQL injection vulnerability in web application endpoint. Allows data exfiltration. {extra}' },
  { title: 'CVE-{cve} — Privilege escalation via {res}', desc: 'Local privilege escalation through misconfigured permissions. {extra}' },
  { title: 'CVE-{cve} — Buffer overflow in {res}', desc: 'Stack-based buffer overflow in network service. Can lead to denial of service or code execution. {extra}' },
  { title: 'CVE-{cve} — SSRF vulnerability in {res}', desc: 'Server-side request forgery allows internal network scanning and metadata access. {extra}' },
  { title: 'CVE-{cve} — Deserialization flaw in {res}', desc: 'Insecure deserialization allows remote code execution via crafted payload. {extra}' },
];
const MISCONFIG_TEMPLATES = [
  { title: '{service} {res} has public access enabled', desc: '{service} resource is publicly accessible. Should be restricted to VPC/private network.' },
  { title: '{service} {res} missing encryption at rest', desc: 'Data at rest is not encrypted. Violates compliance requirements for data protection.' },
  { title: '{service} {res} has overly permissive security group', desc: 'Security group allows inbound traffic from 0.0.0.0/0 on sensitive ports.' },
  { title: '{service} {res} missing backup configuration', desc: 'No automated backup policy configured. Data loss risk in case of failure.' },
  { title: '{service} {res} logging disabled', desc: 'Audit logging is not enabled. Administrative actions will not be recorded.' },
  { title: '{service} {res} using deprecated TLS version', desc: 'Resource is configured with TLS 1.0/1.1 which has known vulnerabilities.' },
  { title: '{service} {res} missing required tags', desc: 'Resource is missing mandatory tags (owner, cost-center, environment).' },
];
const NETWORK_TEMPLATES = [
  { title: 'Unrestricted SSH access on {res}', desc: 'Port 22 is open to 0.0.0.0/0. SSH should be restricted to bastion hosts.' },
  { title: 'Public-facing RDP on {res}', desc: 'Port 3389 exposed to internet. Remote Desktop should be VPN-only.' },
  { title: 'Unrestricted database port on {res}', desc: 'Database port (3306/5432) open to internet. Must be restricted to application subnets.' },
  { title: 'Missing WAF on public endpoint {res}', desc: 'Public-facing load balancer has no WAF protection. Exposes application to OWASP Top 10 attacks.' },
];
const IAM_TEMPLATES = [
  { title: 'IAM role with wildcard permissions on {res}', desc: 'Role has Action: * or Resource: * in policy. Violates least-privilege principle.' },
  { title: 'Inactive IAM user with console access on {res}', desc: 'User has not logged in for 90+ days but retains console access and active access keys.' },
  { title: 'Cross-account role trust too broad on {res}', desc: 'AssumeRole trust policy allows any principal in trusted account. Should specify exact roles.' },
  { title: 'Service account key not rotated on {res}', desc: 'Service account key is older than 90 days. Key rotation policy requires 90-day maximum.' },
];
const DATA_TEMPLATES = [
  { title: 'Unencrypted data in {service} {res}', desc: 'Sensitive data stored without encryption. Customer PII at risk of exposure.' },
  { title: 'Public dataset in {service} {res}', desc: 'Dataset is publicly queryable. Contains financial records that should be restricted.' },
  { title: 'Missing DLP policy on {res}', desc: 'No Data Loss Prevention policy applied. PCI card data could be exfiltrated.' },
];
const COMPLIANCE_TEMPLATES = [
  { title: 'Missing audit trail for {res}', desc: 'No audit logging configured for administrative actions. Required by SOC2 and PCI-DSS.' },
  { title: 'Non-compliant region deployment for {res}', desc: 'Resource deployed in non-approved region. Violates data residency policy.' },
  { title: 'MFA not enforced for {res}', desc: 'Multi-factor authentication not required for privileged access. Required by NIST CSF PR.AC.' },
];

const TEMPLATES_BY_TYPE = {
  vulnerability: VULN_TEMPLATES,
  misconfiguration: MISCONFIG_TEMPLATES,
  network_exposure: NETWORK_TEMPLATES,
  iam_risk: IAM_TEMPLATES,
  data_exposure: DATA_TEMPLATES,
  compliance_drift: COMPLIANCE_TEMPLATES,
};

function genCVE() {
  const year = Math.random() > 0.5 ? 2024 : 2025;
  const num = Math.floor(1000 + Math.random() * 49000);
  return `CVE-${year}-${num}`;
}

function genHex(len) {
  return [...Array(len)].map(() => Math.floor(Math.random() * 16).toString(16)).join('');
}

function genDate(baseDate, offsetHours) {
  const d = new Date(baseDate);
  d.setHours(d.getHours() + offsetHours);
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

const BASE_DATE = new Date('2026-02-01T00:00:00Z');

const findings = [];
let autoRemCount = 0;
const AUTO_REM_TARGET = 24;

for (let i = 0; i < 80; i++) {
  const idx = i + 1;
  const id = `f-${pad(idx)}`;
  const provider = providerDist[i];
  const severity = sevDist[i];
  const status = statusDist[i];
  const env = envDist[i];

  // Pick type based on distribution
  const typeIdx = i % TYPES.length;
  const type = TYPES[typeIdx];
  const category = CATEGORIES[typeIdx];

  // Pick account/region
  let account, region, source, resource;
  if (provider === 'aws') {
    account = pick(AWS_ACCOUNTS);
    region = pick(AWS_REGIONS);
    source = pick(AWS_SOURCES);
    resource = pick(AWS_RESOURCES);
  } else if (provider === 'azure') {
    account = pick(AZURE_SUBS);
    region = pick(AZURE_REGIONS);
    source = pick(AZURE_SOURCES);
    resource = pick(AZURE_RESOURCES);
  } else {
    account = pick(GCP_PROJECTS);
    region = pick(GCP_REGIONS);
    source = pick(GCP_SOURCES);
    resource = pick(GCP_RESOURCES);
  }

  const resName = `${resource.prefix}${pick(SERVICES).split('-')[0]}-${env.slice(0,4)}-${pad(idx)}`;
  let resId, resArn;
  if (provider === 'aws') {
    resId = resource.prefix === 'i-' ? `i-${genHex(12)}` :
            resource.prefix === 's3-' ? `${resName}-bucket` :
            resource.prefix === 'sg-' ? `sg-${genHex(8)}` :
            `${resource.prefix}${genHex(8)}`;
    resArn = resource.arnRes
      ? `arn:aws:${resource.arnType}:${region}:${account.id}:${resource.arnRes}/${resId}`
      : `arn:aws:${resource.arnType}:::${resId}`;
  } else if (provider === 'azure') {
    const rg = `${env}-rg-${region}`;
    resId = `/subscriptions/${account.id}/resourceGroups/${rg}/providers/${resource.rp}/${resName}`;
    resArn = resId;
  } else {
    resId = `projects/${account.name}/locations/${region}/${resource.service.toLowerCase().replace(/ /g, '-')}/${resName}`;
    resArn = resId;
  }

  // Generate title/description from templates
  const templates = TEMPLATES_BY_TYPE[type];
  const tmpl = pick(templates);
  const cveId = genCVE();
  const title = tmpl.title
    .replace('{cve}', cveId)
    .replace('{res}', resName)
    .replace('{service}', resource.service);
  const desc = tmpl.desc
    .replace('{service}', resource.service)
    .replace('{res}', resName)
    .replace('{extra}', severity === 'CRITICAL' ? 'Public exploit available. CISA KEV listed.' : 'Patch available from vendor.');

  // Scores
  const [cvssMin, cvssMax] = CVSS_RANGE[severity];
  const cvss = randRange(cvssMin, cvssMax);
  const [epssMin, epssMax] = EPSS_RANGE[severity];
  const epss = type === 'vulnerability' ? randRange(epssMin, epssMax) : 0;
  const [riskMin, riskMax] = RISK_RANGE[severity];
  const aiRiskScore = randRange(riskMin, riskMax);
  const aiRiskLevel = severity.toLowerCase();

  const exploitAvailable = type === 'vulnerability' && (severity === 'CRITICAL' || (severity === 'HIGH' && Math.random() > 0.5));

  // CVEs — only for vulnerability type
  const cves = type === 'vulnerability' ? [{
    id: cveId,
    url: `https://nvd.nist.gov/vuln/detail/${cveId}`,
    nvd_url: `https://nvd.nist.gov/vuln/detail/${cveId}`,
    mitre_url: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveId}`,
    description: desc.slice(0, 120),
    cvss,
    cvss_vector: `CVSS:3.1/AV:N/AC:${cvss > 8 ? 'L' : 'H'}/PR:${cvss > 7 ? 'N' : 'L'}/UI:N/S:U/C:H/I:${cvss > 8 ? 'H' : 'L'}/A:${cvss > 9 ? 'H' : 'L'}`,
    cvss_version: '3.1',
    epss,
    cisa_known_exploited: severity === 'CRITICAL' && Math.random() > 0.3,
    published: `${Math.random() > 0.5 ? '2024' : '2025'}-${String(Math.floor(1 + Math.random() * 12)).padStart(2, '0')}-${String(Math.floor(1 + Math.random() * 28)).padStart(2, '0')}T00:00:00Z`,
    modified: '2026-01-15T00:00:00Z',
  }] : [];

  // MITRE
  const mitreTactics = type === 'vulnerability' || type === 'iam_risk' || type === 'network_exposure'
    ? pickN(TACTICS, 1 + Math.floor(Math.random() * 2))
    : [];
  const mitreTechniques = mitreTactics.length > 0
    ? pickN(TECHNIQUES, 1 + Math.floor(Math.random() * 2))
    : [];

  // Compliance mappings
  const numMappings = 1 + Math.floor(Math.random() * 2);
  const compFrameworks = pickN(FRAMEWORKS, numMappings);
  const complianceMappings = compFrameworks.map(fId => ({
    framework_id: fId,
    framework_name: FRAMEWORK_NAMES[fId],
    control_id: `${fId === 'nist-csf' ? 'PR' : fId === 'pci-dss' ? 'REQ' : 'A'}.${Math.floor(1 + Math.random() * 12)}.${Math.floor(1 + Math.random() * 6)}`,
    control_title: `Control for ${type.replace('_', ' ')}`,
    section: `${fId === 'nist-csf' ? 'PR' : fId === 'pci-dss' ? String(Math.floor(1 + Math.random() * 12)) : 'A.' + Math.floor(5 + Math.random() * 4)}`,
    severity: severity.toLowerCase(),
    url: '',
  }));

  // Auto-remediatable
  const autoRem = autoRemCount < AUTO_REM_TARGET &&
    (type === 'misconfiguration' || type === 'network_exposure' || (type === 'compliance_drift' && Math.random() > 0.5));
  if (autoRem) autoRemCount++;

  // Dates
  const foundOffset = Math.floor(Math.random() * 20 * 24); // 0-20 days in hours
  const firstFound = genDate(BASE_DATE, foundOffset);
  const lastSeen = genDate(BASE_DATE, foundOffset + Math.floor(Math.random() * 5 * 24) + 24);
  const slaOffset = SLA_HOURS[severity];
  const dueDate = genDate(new Date(firstFound), slaOffset);

  // SLA breach — only for open findings that are past their SLA
  const now = new Date('2026-02-27T08:00:00Z');
  const dueDateObj = new Date(dueDate);
  const slaBreachDate = (status === 'open' && dueDateObj < now) ? dueDate : undefined;

  const workflowStatus = status === 'open' ? pick(['new', 'triaged', 'assigned']) :
    status === 'in_progress' ? 'in_progress' :
    status === 'resolved' ? pick(['remediated', 'verified']) :
    'closed';

  const factors = [];
  if (env === 'production') factors.push('production_environment');
  if (exploitAvailable) factors.push('exploit_available');
  if (cves.length > 0 && cves[0].cisa_known_exploited) factors.push('cisa_known_exploited');
  if (epss > 0.5) factors.push('high_epss_score');
  if (resource.type === 'storage' || resource.type === 'database') factors.push('data_resource');
  if (resource.type === 'network') factors.push('network_resource');

  const finding = {
    id,
    source,
    source_finding_id: provider === 'aws' ? `arn:aws:securityhub:${region}:${account.id}:finding/${id}` :
      provider === 'azure' ? `azd-${pad(idx)}` : `gcp-${pad(idx)}`,
    type,
    title,
    description: desc,
    resource_type: resource.type,
    resource_id: resId,
    resource_name: resName,
    resource_arn: resArn,
    platform: 'cloud',
    cloud_provider: provider,
    region,
    account_id: account.id,
    account_name: account.name,
    environment_type: env,
    static_severity: severity,
    severity,
    ai_risk_score: aiRiskScore,
    ai_risk_level: aiRiskLevel,
    ai_risk_rationale: `${severity} severity finding in ${env} environment. ${factors.length > 0 ? 'Risk factors: ' + factors.join(', ') + '.' : 'Standard risk assessment.'}`,
    ai_contextual_factors: factors,
    cvss: type === 'vulnerability' ? cvss : undefined,
    cvss_vector: type === 'vulnerability' ? cves[0]?.cvss_vector : undefined,
    epss: type === 'vulnerability' ? epss : undefined,
    exploit_available: exploitAvailable,
    cves,
    mitre_tactics: mitreTactics,
    mitre_techniques: mitreTechniques,
    compliance_mappings: complianceMappings,
    remediation: autoRem
      ? `Auto-remediation available: ${type === 'misconfiguration' ? 'Apply configuration fix via API' : 'Update security group rules'}.`
      : `Manual remediation required: ${title.includes('CVE') ? 'Apply vendor patch' : 'Review and update configuration'}.`,
    auto_remediatable: autoRem,
    category,
    status,
    workflow_status: workflowStatus,
    suppressed: status === 'suppressed',
    service_name: pick(SERVICES),
    line_of_business: pick(LOBS),
    first_found_at: firstFound,
    last_seen_at: lastSeen,
    ...(slaBreachDate ? { sla_breach_date: slaBreachDate } : {}),
    due_date: dueDate,
    deduplication_key: `${genHex(12)}`,
    canonical_rule_id: type === 'vulnerability' ? cveId : `${category}-${pad(idx)}`,
  };

  // Clean undefined values
  Object.keys(finding).forEach(k => { if (finding[k] === undefined) delete finding[k]; });

  findings.push(finding);
}

process.stdout.write(JSON.stringify(findings, null, 2) + '\n');
