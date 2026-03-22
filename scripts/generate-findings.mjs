#!/usr/bin/env node
// Generate mock security findings for CloudForge frontend
// Run: node scripts/generate-findings.mjs [--count N] [--attack-paths attack-paths.json]
// Default: 80 findings to stdout. --count 20000 for production dataset.
// --attack-paths: pre-compute paths from curated <1000 subset and write to file.

// Clustered accounts — 5 total (2 AWS, 2 Azure, 1 GCP) for dense attack paths.
// canConnect() requires same AccountID, so fewer accounts = more findings per account
// = higher probability of BFS chains forming in computeAttackPaths().
const AWS_ACCOUNTS = [
  { id: '123456789012', name: 'acme-workloads-prod' },
  { id: '234567890123', name: 'acme-platform-shared' },
];
const AZURE_SUBS = [
  { id: 'sub-workload-001', name: 'workload-prod-east' },
  { id: 'sub-platform-001', name: 'platform-shared-hub' },
];
const GCP_PROJECTS = [
  { id: 'proj-analytics-001', name: 'analytics-data-platform' },
];

const AWS_REGIONS = ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1'];
const AZURE_REGIONS = ['eastus', 'westeurope', 'southeastasia'];
const GCP_REGIONS = ['us-central1', 'europe-west1'];
const ENVS = ['production', 'staging', 'development', 'sandbox'];
const ENV_DIST = [32, 24, 16, 8]; // out of 80
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const SEV_DIST = [9, 21, 29, 21];
const STATUSES = ['open', 'in_progress', 'resolved', 'suppressed'];
const STATUS_DIST = [47, 17, 11, 5];
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

// CLI args
const cliArgs = process.argv.slice(2);
const getCliArg = (name) => { const i = cliArgs.indexOf(name); return i !== -1 ? cliArgs[i + 1] : undefined };
const TOTAL_COUNT = parseInt(getCliArg('--count') ?? '80', 10);
const ATTACK_PATHS_FILE = getCliArg('--attack-paths');

function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
function pickN(arr, n) { const s = [...arr].sort(() => Math.random() - 0.5); return s.slice(0, n); }
function pad(n) { return String(n).padStart(5, '0'); }

// Build distribution arrays scaled to TOTAL_COUNT with +/- jitter so counts
// look organic rather than perfectly proportional (e.g. 2,137 not 2,000).
function buildDist(values, ratios) {
  const total = ratios.reduce((a, b) => a + b, 0);
  const result = [];
  for (let i = 0; i < values.length; i++) {
    const base = Math.round((ratios[i] / total) * TOTAL_COUNT);
    // Apply +/- 5-8% jitter to avoid perfectly round numbers
    const jitterPct = 0.05 + Math.random() * 0.03;
    const jitter = Math.round(base * jitterPct * (Math.random() < 0.5 ? -1 : 1));
    const count = Math.max(1, base + jitter);
    for (let j = 0; j < count; j++) result.push(values[i]);
  }
  // Pad or trim to exact TOTAL_COUNT
  while (result.length < TOTAL_COUNT) result.push(pick(values));
  return result.slice(0, TOTAL_COUNT).sort(() => Math.random() - 0.5);
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
const AUTO_REM_TARGET = Math.round(TOTAL_COUNT * 0.3);

if (TOTAL_COUNT > 80) process.stderr.write(`[+] Generating ${TOTAL_COUNT} findings...\n`);

for (let i = 0; i < TOTAL_COUNT; i++) {
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

// --- Second pass: populate impacted_resources and toxic_combo_details ---

const COMBO_TYPES = ['privilege_escalation', 'data_exfiltration', 'lateral_movement', 'network_exposure', 'credential_theft'];
const ATTACK_VECTORS = ['network', 'local', 'adjacent'];
const BLAST_RADII = ['account', 'region', 'vpc', 'subnet'];
const EXPLOIT_POTENTIALS = ['active', 'likely', 'possible'];

const COMBO_DESCRIPTIONS = {
  privilege_escalation: [
    'IAM misconfiguration combined with an exposed service allows an attacker to escalate from a low-privilege role to administrative access. The chained exploit bypasses standard permission boundaries.',
    'Overly permissive role trust policy paired with an internet-facing endpoint enables cross-account privilege escalation. An attacker can assume the role without MFA.',
  ],
  data_exfiltration: [
    'Unencrypted storage bucket with public access combined with a permissive egress rule creates a direct data exfiltration path. Sensitive records can be copied to attacker-controlled infrastructure.',
    'Missing DLP controls on an externally accessible service allow bulk export of PII. The absence of egress monitoring means exfiltration could go undetected for days.',
  ],
  lateral_movement: [
    'Overly permissive security group combined with a compromised service account enables east-west movement across VPC subnets. An attacker can pivot from a public-facing workload to internal databases.',
    'Weak network segmentation paired with an unpatched container image allows lateral movement from a developer namespace to production workloads.',
  ],
  network_exposure: [
    'Public-facing load balancer without WAF combined with an open database port exposes the application tier directly to the internet. Exploitation requires no authentication.',
    'Unrestricted ingress on port 22 combined with weak SSH key management creates a persistent backdoor into the private network segment.',
  ],
  credential_theft: [
    'Long-lived access keys stored in a public repository combined with an IAM role without MFA enforcement allow immediate credential takeover. Keys grant broad read/write access.',
    'Service account key not rotated for 90+ days paired with an overly permissive role provides persistent access to sensitive cloud resources even after an initial breach is detected.',
  ],
};

// Group findings by account_id
const byAccount = {};
for (const f of findings) {
  if (!byAccount[f.account_id]) byAccount[f.account_id] = [];
  byAccount[f.account_id].push(f);
}

for (const accountFindings of Object.values(byAccount)) {
  // Identify CRITICAL/HIGH candidates
  const candidates = accountFindings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH');
  const siblings = accountFindings; // all findings in same account

  for (const finding of candidates) {
    // ~20% chance to get impacted_resources
    if (Math.random() > 0.20) continue;

    // Pick 1-3 OTHER findings in the same account as resource references
    const others = siblings.filter(s => s.id !== finding.id);
    if (others.length === 0) continue;
    const count = Math.min(1 + Math.floor(Math.random() * 3), others.length);
    const selected = others.sort(() => Math.random() - 0.5).slice(0, count);

    finding.impacted_resources = selected.map(s => ({
      resource_id: s.resource_id,
      resource_name: s.resource_name,
      resource_type: s.resource_type,
      severity: pick(['HIGH', 'CRITICAL', 'MEDIUM']),
    }));

    // ~10% of findings that have impacted_resources get toxic_combo_details
    if (Math.random() > 0.10) continue;

    const comboType = pick(COMBO_TYPES);
    const descriptions = COMBO_DESCRIPTIONS[comboType];
    const relatedIds = selected.map(s => s.id);
    // Build a plausible attack path using resource names
    const attackPath = ['Internet', finding.resource_name, selected[0].resource_name];

    finding.toxic_combo_details = {
      combo_type: comboType,
      description: pick(descriptions),
      attack_vector: pick(ATTACK_VECTORS),
      blast_radius: pick(BLAST_RADII),
      exploit_potential: pick(EXPLOIT_POTENTIALS),
      attack_path: attackPath,
      related_findings: relatedIds,
    };
  }
}

// --- Third pass: pre-compute attack paths from curated candidate pool ---
import { writeFileSync } from 'fs';

if (ATTACK_PATHS_FILE) {
  const CANDIDATE_LIMIT = 1500;
  const SEVERITY_SCORE = { CRITICAL: 100, HIGH: 60, MEDIUM: 20, LOW: 5 };
  const ENTRY_CATEGORIES = new Set(['NETWORK', 'VULNERABILITY']);
  const TARGET_TYPES = new Set(['storage', 'database', 'encryption', 'secret']);

  // Account density map
  const accountDensity = {};
  for (const f of findings) {
    accountDensity[f.account_id] = (accountDensity[f.account_id] ?? 0) + 1;
  }

  // Score every finding
  const scored = findings.map(f => {
    let score = SEVERITY_SCORE[f.severity] ?? 0;
    if (f.exploit_available) score += 50;
    if (f.environment_type === 'production') score += 30;
    if (ENTRY_CATEGORIES.has(f.category)) score += 20;
    if (TARGET_TYPES.has(f.resource_type)) score += 20;
    if ((f.epss ?? 0) > 0.5) score += 15;
    if ((f.mitre_tactics?.length ?? 0) > 0) score += 10;
    if ((f.ai_risk_score ?? 0) > 8) score += 10;
    if ((accountDensity[f.account_id] ?? 0) > 20) score += 15;
    if (f.impacted_resources?.length > 0) score += 25;
    return { finding: f, score };
  });

  scored.sort((a, b) => b.score - a.score);
  const candidates = scored.slice(0, CANDIDATE_LIMIT).map(s => s.finding);

  process.stderr.write(`[+] Selected ${candidates.length} path candidates from ${findings.length} findings (top by metadata score)\n`);

  // Group candidates by account
  const candByAccount = {};
  for (const f of candidates) {
    if (!candByAccount[f.account_id]) candByAccount[f.account_id] = [];
    candByAccount[f.account_id].push(f);
  }

  // Classification helpers
  const isEntry = (f) => {
    if (f.category === 'NETWORK') return true;
    if (f.category === 'VULNERABILITY' && f.exploit_available) return true;
    const rt = (f.resource_type ?? '').toLowerCase();
    return ['compute', 'container', 'serverless'].some(t => rt.includes(t)) &&
      (SEVERITY_SCORE[f.severity] ?? 0) >= 60;
  };
  const isTarget = (f) => TARGET_TYPES.has(f.resource_type);
  const canConnect = (a, b) => {
    if (a.account_id !== b.account_id) return false;
    if (a.resource_id === b.resource_id) return false;
    return a.region === b.region || a.resource_type === b.resource_type;
  };

  const EDGE_LABELS = {
    storage: 'Can access data', database: 'Can access data', secret: 'Can access data',
    identity: 'IAM trust relationship', network: 'Network reachable',
  };
  const inferEdgeLabel = (from, to) => {
    const toType = (to.resource_type ?? '').toLowerCase();
    for (const [key, label] of Object.entries(EDGE_LABELS)) {
      if (toType.includes(key)) return label;
    }
    return 'Lateral movement';
  };

  const paths = [];
  let pathIdx = 0;

  for (const [, acctFindings] of Object.entries(candByAccount)) {
    if (acctFindings.length < 2) continue;
    const entries = acctFindings.filter(isEntry);
    const targets = acctFindings.filter(isTarget);
    const intermediates = acctFindings.filter(f => !isEntry(f) && !isTarget(f));

    for (const entry of entries) {
      for (const target of targets) {
        // Direct connection
        if (canConnect(entry, target)) {
          paths.push({
            id: `ap-${String(++pathIdx).padStart(5, '0')}`,
            title: `${entry.resource_name} → ${target.resource_name}`,
            description: `Attack path from ${entry.category.toLowerCase()} finding on ${entry.resource_name} to ${target.resource_type} ${target.resource_name}`,
            severity: (SEVERITY_SCORE[entry.severity] ?? 0) >= 100 ? 'CRITICAL' : 'HIGH',
            score: Math.min((SEVERITY_SCORE[entry.severity] ?? 0) + (SEVERITY_SCORE[target.severity] ?? 0), 100),
            hop_count: 2,
            entry_point: { id: `node-${entry.id}`, finding_id: entry.id, resource_id: entry.resource_id, resource_name: entry.resource_name, resource_type: entry.resource_type, provider: entry.cloud_provider, account_id: entry.account_id, region: entry.region, severity: entry.severity, category: entry.category, label: `${entry.resource_name} (${entry.resource_type})` },
            target: { id: `node-${target.id}`, finding_id: target.id, resource_id: target.resource_id, resource_name: target.resource_name, resource_type: target.resource_type, provider: target.cloud_provider, account_id: target.account_id, region: target.region, severity: target.severity, category: target.category, label: `${target.resource_name} (${target.resource_type})` },
            nodes: [
              { id: `node-${entry.id}`, finding_id: entry.id, resource_id: entry.resource_id, resource_name: entry.resource_name, resource_type: entry.resource_type, provider: entry.cloud_provider, account_id: entry.account_id, region: entry.region, severity: entry.severity, category: entry.category, label: `${entry.resource_name} (${entry.resource_type})` },
              { id: `node-${target.id}`, finding_id: target.id, resource_id: target.resource_id, resource_name: target.resource_name, resource_type: target.resource_type, provider: target.cloud_provider, account_id: target.account_id, region: target.region, severity: target.severity, category: target.category, label: `${target.resource_name} (${target.resource_type})` },
            ],
            edges: [{ id: `edge-0`, source: `node-${entry.id}`, target: `node-${target.id}`, label: inferEdgeLabel(entry, target), edge_type: 'lateral_movement' }],
            mitre_tactics: entry.mitre_tactics ?? [],
            finding_ids: [entry.id, target.id],
            ai_enriched: false,
          });
          if (paths.length > 500) break;
          continue;
        }

        // Via intermediate
        for (const mid of intermediates) {
          if (canConnect(entry, mid) && canConnect(mid, target)) {
            const midNode = { id: `node-${mid.id}`, finding_id: mid.id, resource_id: mid.resource_id, resource_name: mid.resource_name, resource_type: mid.resource_type, provider: mid.cloud_provider, account_id: mid.account_id, region: mid.region, severity: mid.severity, category: mid.category, label: `${mid.resource_name} (${mid.resource_type})` };
            paths.push({
              id: `ap-${String(++pathIdx).padStart(5, '0')}`,
              title: `${entry.resource_name} → ${mid.resource_name} → ${target.resource_name}`,
              description: `Multi-hop attack from ${entry.resource_name} through ${mid.resource_name} to ${target.resource_name}`,
              severity: (SEVERITY_SCORE[entry.severity] ?? 0) >= 100 ? 'CRITICAL' : 'HIGH',
              score: Math.min((SEVERITY_SCORE[entry.severity] ?? 0) + (SEVERITY_SCORE[mid.severity] ?? 0) + (SEVERITY_SCORE[target.severity] ?? 0), 100),
              hop_count: 3,
              entry_point: { id: `node-${entry.id}`, finding_id: entry.id, resource_id: entry.resource_id, resource_name: entry.resource_name, resource_type: entry.resource_type, provider: entry.cloud_provider, account_id: entry.account_id, region: entry.region, severity: entry.severity, category: entry.category, label: `${entry.resource_name} (${entry.resource_type})` },
              target: { id: `node-${target.id}`, finding_id: target.id, resource_id: target.resource_id, resource_name: target.resource_name, resource_type: target.resource_type, provider: target.cloud_provider, account_id: target.account_id, region: target.region, severity: target.severity, category: target.category, label: `${target.resource_name} (${target.resource_type})` },
              nodes: [
                { id: `node-${entry.id}`, finding_id: entry.id, resource_id: entry.resource_id, resource_name: entry.resource_name, resource_type: entry.resource_type, provider: entry.cloud_provider, account_id: entry.account_id, region: entry.region, severity: entry.severity, category: entry.category, label: `${entry.resource_name} (${entry.resource_type})` },
                midNode,
                { id: `node-${target.id}`, finding_id: target.id, resource_id: target.resource_id, resource_name: target.resource_name, resource_type: target.resource_type, provider: target.cloud_provider, account_id: target.account_id, region: target.region, severity: target.severity, category: target.category, label: `${target.resource_name} (${target.resource_type})` },
              ],
              edges: [
                { id: `edge-0`, source: `node-${entry.id}`, target: `node-${mid.id}`, label: inferEdgeLabel(entry, mid), edge_type: 'lateral_movement' },
                { id: `edge-1`, source: `node-${mid.id}`, target: `node-${target.id}`, label: inferEdgeLabel(mid, target), edge_type: 'lateral_movement' },
              ],
              mitre_tactics: [...new Set([...(entry.mitre_tactics ?? []), ...(mid.mitre_tactics ?? [])])],
              finding_ids: [entry.id, mid.id, target.id],
              ai_enriched: false,
            });
            break;
          }
        }
        if (paths.length > 500) break;
      }
      if (paths.length > 500) break;
    }
  }

  // Sort by severity desc, score desc
  const sevRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  paths.sort((a, b) => (sevRank[b.severity] ?? 0) - (sevRank[a.severity] ?? 0) || b.score - a.score);

  // Compute stats
  const usedFindings = new Set();
  for (const p of paths) for (const fid of p.finding_ids) usedFindings.add(fid);
  const byProvider = {};
  for (const p of paths) {
    const prov = p.entry_point.provider;
    byProvider[prov] = (byProvider[prov] ?? 0) + 1;
  }

  const output = {
    paths,
    stats: {
      total_findings: findings.length,
      findings_in_paths: usedFindings.size,
      isolated_findings: findings.length - usedFindings.size,
      coverage_percent: findings.length > 0 ? Math.round((usedFindings.size / findings.length) * 100) : 0,
      total_paths: paths.length,
      critical_paths: paths.filter(p => p.severity === 'CRITICAL').length,
      high_paths: paths.filter(p => p.severity === 'HIGH').length,
      medium_paths: paths.filter(p => p.severity === 'MEDIUM').length,
      by_provider: byProvider,
    },
  };

  writeFileSync(ATTACK_PATHS_FILE, JSON.stringify(output, null, 2));
  process.stderr.write(`[+] ${paths.length} attack paths written to ${ATTACK_PATHS_FILE}\n`);
  process.stderr.write(`    CRIT: ${output.stats.critical_paths}, HIGH: ${output.stats.high_paths}, coverage: ${output.stats.coverage_percent}%\n`);
}

process.stdout.write(JSON.stringify(findings) + '\n');
