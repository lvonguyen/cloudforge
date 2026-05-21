#!/usr/bin/env node
/**
 * aegis-seed.mjs — Unified finding seed generator for CloudForge
 *
 * Merges real multi-cloud findings, deduplicates, sanitizes with 56-service
 * taxonomy, enriches with compliance/AI/MITRE data, and outputs the unified
 * dataset for frontend + Postgres.
 *
 * Usage:
 *   node scripts/aegis-seed.mjs --count 500 --out testdata/seed/
 *   node scripts/aegis-seed.mjs --count 20000 --out testdata/seed/
 *   node --max-old-space-size=6144 scripts/aegis-seed.mjs --count 300000 --out testdata/seed/ --full
 *
 * Flags:
 *   --count N       Target finding count (default: 20000)
 *   --out DIR       Output directory (default: testdata/seed/)
 *   --full          Include large export files (1.3GB+ AWS, 225MB Azure, 187MB GCP)
 *   --seed N        Random seed for deterministic output (default: 42)
 *   --frontend      Also write 500-finding subset to frontend/public/mock/findings.json
 */

import { readFileSync, writeFileSync, createWriteStream, existsSync, mkdirSync } from 'fs';
import { createHash } from 'crypto';
import { join, resolve } from 'path';

// ── CLI ──────────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
const getArg = (name) => { const i = args.indexOf(name); return i !== -1 ? args[i + 1] : undefined; };
const hasFlag = (name) => args.includes(name);

const TARGET_COUNT = parseInt(getArg('--count') ?? '20000', 10);
const OUT_DIR = resolve(getArg('--out') ?? 'testdata/seed');
const FULL_MODE = hasFlag('--full');
const WRITE_FRONTEND = hasFlag('--frontend');
const SEED = parseInt(getArg('--seed') ?? '42', 10);

mkdirSync(OUT_DIR, { recursive: true });

const log = (msg) => process.stderr.write(`[+] ${msg}\n`);
const warn = (msg) => process.stderr.write(`[!] ${msg}\n`);

// ── Seeded PRNG (mulberry32) ─────────────────────────────────────────────────

let _seed = SEED;
function rand() {
  _seed |= 0; _seed = _seed + 0x6D2B79F5 | 0;
  let t = Math.imul(_seed ^ _seed >>> 15, 1 | _seed);
  t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
  return ((t ^ t >>> 14) >>> 0) / 4294967296;
}
function pick(arr) { return arr[Math.floor(rand() * arr.length)]; }
function pickN(arr, n) { const s = [...arr]; for (let i = s.length - 1; i > 0; i--) { const j = Math.floor(rand() * (i + 1)); [s[i], s[j]] = [s[j], s[i]]; } return s.slice(0, n); }
function randRange(min, max) { return +(min + rand() * (max - min)).toFixed(2); }
function pad(n, w = 6) { return String(n).padStart(w, '0'); }
function hash(s) { return createHash('md5').update(s + 'aegis-seed-salt').digest('hex'); }
function sha1(s) { return createHash('sha1').update(s + 'aegis-code-to-cloud-salt').digest('hex'); }
function slugify(value) { return String(value ?? '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'service'; }

const REPO_OWNER = 'contoso';
const BRANCH_BY_ENVIRONMENT = {
  production: 'main',
  staging: 'release/staging',
  development: 'develop',
  sandbox: 'sandbox/hardening',
};

function selectRepositoryHost(provider) {
  if (provider === 'gcp') {
    return {
      repositoryProvider: 'gitlab',
      repositoryURL: (repoPath) => `https://gitlab.com/${repoPath}`,
      buildSystem: 'gitlab-ci',
      pipelineRunURL: (repoPath, runId) => `https://gitlab.com/${repoPath}/-/pipelines/${runId}`,
    };
  }
  if (provider === 'azure') {
    return {
      repositoryProvider: 'azure-repos',
      repositoryURL: (repoSlug) => `https://dev.azure.com/${REPO_OWNER}/Platform/_git/${repoSlug}`,
      buildSystem: 'azure-devops',
      pipelineRunURL: (_repoPath, runId) => `https://dev.azure.com/${REPO_OWNER}/Platform/_build/results?buildId=${runId}`,
    };
  }
  return {
    repositoryProvider: 'github',
    repositoryURL: (repoPath) => `https://github.com/${repoPath}`,
    buildSystem: 'github-actions',
    pipelineRunURL: (repoPath, runId) => `https://github.com/${repoPath}/actions/runs/${runId}`,
  };
}

function buildArtifactReference(provider, resourceType, repoSlug, commitSHA) {
  const shortSHA = commitSHA.slice(0, 12);
  switch (resourceType) {
    case 'container':
      if (provider === 'azure') return `${REPO_OWNER}shared.azurecr.io/${repoSlug}:${shortSHA}`;
      if (provider === 'gcp') return `us-docker.pkg.dev/${REPO_OWNER}/${repoSlug}/${repoSlug}:${shortSHA}`;
      return `ghcr.io/${REPO_OWNER}/${repoSlug}:${shortSHA}`;
    case 'serverless':
      if (provider === 'azure') return `https://${REPO_OWNER}artifacts.blob.core.windows.net/releases/${repoSlug}/${shortSHA}.zip`;
      if (provider === 'gcp') return `gs://${REPO_OWNER}-artifacts/${repoSlug}/${shortSHA}.zip`;
      return `s3://${REPO_OWNER}-artifacts/${repoSlug}/${shortSHA}.zip`;
    case 'database':
      return `${repoSlug}-schema-${shortSHA}.sql`;
    case 'identity':
      return `${repoSlug}-policy-pack-${shortSHA}.tgz`;
    default:
      return `${repoSlug}-${shortSHA}.tgz`;
  }
}

function buildCodeToCloudTags({ service, provider, environmentType, resourceType, findingID, findingHash }) {
  const repoSlug = slugify(service.name || service.id);
  const repoPath = `${REPO_OWNER}/${repoSlug}`;
  const commitSHA = sha1(`${service.id}:${findingID}:${findingHash}`).slice(0, 40);
  const branch = BRANCH_BY_ENVIRONMENT[environmentType] ?? 'main';
  const runId = String(100000 + (parseInt(findingHash.slice(0, 8), 16) % 900000));
  const pipelineAction =
    environmentType === 'production' ? 'deploy' :
    environmentType === 'staging' ? 'promote' :
    'build';
  const pipelineName = `${pipelineAction}-${repoSlug}`;
  const host = selectRepositoryHost(provider);

  return {
    repository_url: host.repositoryURL(host.repositoryProvider === 'azure-repos' ? repoSlug : repoPath),
    repository_name: repoPath,
    repository_provider: host.repositoryProvider,
    branch,
    commit_sha: commitSHA,
    build_system: host.buildSystem,
    pipeline_name: pipelineName,
    pipeline_run_id: runId,
    pipeline_run_url: host.pipelineRunURL(repoPath, runId),
    artifact: buildArtifactReference(provider, resourceType, repoSlug, commitSHA),
  };
}

// ── 56-Service Taxonomy ──────────────────────────────────────────────────────

const CBUS = {
  ns: { name: 'Northstar', weight: 25 },
  mr: { name: 'Meridian', weight: 20 },
  pl: { name: 'Polaris', weight: 15 },
  nx: { name: 'Nexus', weight: 30 },
  sm: { name: 'Summit', weight: 10 },
};

// [id, displayName, cbu, deployType, resourceTypes[]]
const SERVICES_RAW = [
  // Northstar (Consumer Digital) — 15 services
  ['ns-product-search', 'Product Search Platform', 'ns', 'cloud', ['compute', 'storage', 'database', 'serverless']],
  ['ns-ecommerce-web', 'E-Commerce Storefront', 'ns', 'cloud', ['compute', 'network', 'storage', 'container']],
  ['ns-iac-platform', 'Infrastructure Automation', 'ns', 'cloud', ['compute', 'storage', 'identity', 'serverless']],
  ['ns-partner-incentives', 'Partner Incentive Portal', 'ns', 'cloud', ['compute', 'database', 'serverless']],
  ['ns-secure-messaging', 'E2E Encrypted Messaging', 'ns', 'cloud', ['compute', 'encryption', 'serverless']],
  ['ns-iot-telemetry', 'IoT Device Telemetry', 'ns', 'cloud', ['compute', 'storage', 'database', 'serverless']],
  ['ns-ciam-forgerock', 'ForgeRock Identity Cloud', 'ns', 'hybrid', ['identity', 'compute', 'database']],
  ['ns-loyalty-engine', 'Customer Loyalty Engine', 'ns', 'cloud', ['compute', 'database', 'serverless']],
  ['ns-recommendation-ml', 'Product Recommendation ML', 'ns', 'cloud', ['compute', 'storage', 'database', 'container']],
  ['ns-content-cdn', 'Content Delivery Network', 'ns', 'cloud', ['network', 'storage', 'compute']],
  ['ns-mobile-bff', 'Mobile Backend-for-Frontend', 'ns', 'cloud', ['compute', 'serverless', 'database']],
  ['ns-ab-testing', 'A/B Testing Platform', 'ns', 'cloud', ['compute', 'database', 'serverless']],
  ['ns-media-transcoding', 'Media Transcoding Pipeline', 'ns', 'cloud', ['compute', 'storage', 'container']],
  ['ns-push-notifications', 'Push Notification Service', 'ns', 'cloud', ['compute', 'serverless', 'database']],
  ['ns-fraud-detection', 'Real-Time Fraud Detection', 'ns', 'cloud', ['compute', 'database', 'serverless', 'container']],
  // Meridian (Operations/Finance) — 15 services
  ['mr-claims-mgmt', 'Claims Management System', 'mr', 'cloud', ['compute', 'database', 'storage']],
  ['mr-learning-platform', 'Learning Management', 'mr', 'cloud', ['compute', 'storage', 'serverless']],
  ['mr-mobile-payments', 'Mobile Payments Gateway', 'mr', 'cloud', ['compute', 'network', 'encryption', 'database']],
  ['mr-bi-pipeline', 'BI Analytics Pipeline', 'mr', 'cloud', ['compute', 'database', 'storage', 'serverless']],
  ['mr-erp-sap', 'SAP S/4HANA ERP', 'mr', 'hybrid', ['compute', 'database', 'network']],
  ['mr-erp-oracle', 'Oracle EBS Financials', 'mr', 'hybrid', ['compute', 'database', 'network']],
  ['mr-crm-salesforce', 'Salesforce CRM', 'mr', 'saas', ['identity', 'storage']],
  ['mr-hcm-workday', 'Workday HCM', 'mr', 'saas', ['identity', 'database']],
  ['mr-treasury-mgmt', 'Treasury Management System', 'mr', 'cloud', ['compute', 'database', 'encryption']],
  ['mr-invoice-ocr', 'Invoice Processing OCR', 'mr', 'cloud', ['compute', 'storage', 'serverless']],
  ['mr-supply-chain', 'Supply Chain Visibility', 'mr', 'cloud', ['compute', 'database', 'network', 'container']],
  ['mr-fleet-tracking', 'Fleet GPS Tracking', 'mr', 'cloud', ['compute', 'database', 'storage']],
  ['mr-expense-mgmt', 'Expense Management Portal', 'mr', 'cloud', ['compute', 'database', 'serverless']],
  ['mr-payroll-engine', 'Payroll Processing Engine', 'mr', 'hybrid', ['compute', 'database', 'encryption']],
  ['mr-vendor-risk', 'Vendor Risk Assessment', 'mr', 'cloud', ['compute', 'database', 'storage']],
  // Polaris (Regional) — 13 services
  ['pl-identity-svc', 'Identity Provider', 'pl', 'cloud', ['identity', 'compute', 'encryption']],
  ['pl-partner-portal', 'Partner Portal', 'pl', 'cloud', ['compute', 'database', 'storage', 'network']],
  ['pl-web-gateway', 'Web Application Gateway', 'pl', 'cloud', ['network', 'compute', 'serverless']],
  ['pl-regional-cms', 'Regional Content Management', 'pl', 'cloud', ['compute', 'storage', 'database']],
  ['pl-dealer-mgmt', 'Dealer Management System', 'pl', 'cloud', ['compute', 'database', 'network']],
  ['pl-local-payments', 'Local Payment Processing', 'pl', 'cloud', ['compute', 'encryption', 'database']],
  ['pl-customer-360', 'Customer 360 Data Hub', 'pl', 'cloud', ['compute', 'database', 'storage', 'serverless']],
  ['pl-regional-crm', 'Regional CRM Instance', 'pl', 'hybrid', ['compute', 'database', 'identity']],
  ['pl-geo-compliance', 'Geo-Regulatory Compliance', 'pl', 'cloud', ['compute', 'database', 'storage']],
  ['pl-market-analytics', 'Regional Market Analytics', 'pl', 'cloud', ['compute', 'database', 'serverless']],
  ['pl-parts-catalog', 'Parts Catalog Service', 'pl', 'cloud', ['compute', 'database', 'storage', 'container']],
  ['pl-service-booking', 'Service Appointment Booking', 'pl', 'cloud', ['compute', 'database', 'serverless']],
  ['pl-warranty-claims', 'Warranty Claims Portal', 'pl', 'cloud', ['compute', 'database', 'storage']],
  // Nexus (Shared Infra / ITSP) — 48 services
  ['nx-security-hub', 'Security Operations Center', 'nx', 'cloud', ['compute', 'database', 'storage', 'serverless']],
  ['nx-ai-platform', 'AI/ML Platform', 'nx', 'cloud', ['compute', 'storage', 'database', 'container']],
  ['nx-network-core', 'Core Network Services', 'nx', 'cloud', ['network', 'compute']],
  ['nx-data-vault', 'Data Backup & Recovery', 'nx', 'cloud', ['storage', 'encryption', 'database']],
  ['nx-grc-archer', 'RSA Archer GRC Platform', 'nx', 'onprem', ['compute', 'database']],
  ['nx-cmdb-servicenow', 'ServiceNow CMDB', 'nx', 'saas', ['compute', 'database']],
  ['nx-siem-splunk', 'Splunk Enterprise SIEM', 'nx', 'hybrid', ['compute', 'storage', 'database']],
  ['nx-pam-cyberark', 'CyberArk PAM Vault', 'nx', 'onprem', ['identity', 'encryption']],
  ['nx-edr-crowdstrike', 'CrowdStrike Falcon EDR', 'nx', 'saas', ['compute', 'network']],
  ['nx-vuln-qualys', 'Qualys VMDR Scanner', 'nx', 'saas', ['compute', 'network']],
  ['nx-ad-onprem', 'Active Directory On-Prem', 'nx', 'onprem', ['identity', 'compute']],
  ['nx-dns-infoblox', 'Infoblox DDI', 'nx', 'onprem', ['network', 'compute']],
  ['nx-iga-sailpoint-iiq', 'SailPoint IdentityIQ', 'nx', 'onprem', ['identity', 'database']],
  ['nx-iga-sailpoint-idn', 'SailPoint IdentityNow', 'nx', 'hybrid', ['identity', 'compute']],
  ['nx-sso-okta', 'Okta Workforce Identity', 'nx', 'saas', ['identity']],
  ['nx-expressroute-pri', 'ExpressRoute Primary', 'nx', 'cloud', ['network']],
  ['nx-expressroute-sec', 'ExpressRoute Secondary', 'nx', 'cloud', ['network']],
  ['nx-hub-vnet', 'Hub VNet Transit Network', 'nx', 'cloud', ['network']],
  ['nx-azure-firewall', 'Azure Firewall Hub', 'nx', 'cloud', ['network', 'compute']],
  ['nx-private-dns', 'Private DNS Zones', 'nx', 'cloud', ['network']],
  ['nx-bastion-hub', 'Azure Bastion Shared', 'nx', 'cloud', ['network', 'compute']],
  ['nx-log-analytics', 'Log Analytics Workspace', 'nx', 'cloud', ['storage', 'compute']],
  ['nx-entra-id', 'Microsoft Entra ID', 'nx', 'saas', ['identity']],
  ['nx-intune-mdm', 'Intune MDM/MAM', 'nx', 'saas', ['identity', 'compute']],
  ['nx-defender-cloud', 'Microsoft Defender for Cloud', 'nx', 'saas', ['compute', 'network']],
  ['nx-key-vault-shared', 'Shared Key Vault PKI', 'nx', 'cloud', ['encryption']],
  ['nx-azure-policy', 'Azure Policy Governance', 'nx', 'cloud', ['identity', 'compute']],
  ['nx-dr-pilot-light', 'DR Pilot Light us-west-2', 'nx', 'cloud', ['compute', 'storage', 'database']],
  ['nx-dr-warm-standby', 'DR Warm Standby eu-west-1', 'nx', 'cloud', ['compute', 'storage', 'database']],
  ['nx-bc-azure-asr', 'Azure Site Recovery', 'nx', 'cloud', ['compute', 'storage']],
  ['nx-bc-backup-vault', 'Cross-Region Backup Vault', 'nx', 'cloud', ['storage', 'encryption']],
  ['nx-container-registry', 'Container Image Registry', 'nx', 'cloud', ['container', 'storage']],
  ['nx-k8s-platform', 'Kubernetes Platform Service', 'nx', 'cloud', ['container', 'compute', 'network']],
  ['nx-service-mesh', 'Service Mesh (Istio)', 'nx', 'cloud', ['network', 'container', 'compute']],
  ['nx-secrets-manager', 'Centralized Secrets Manager', 'nx', 'cloud', ['encryption', 'identity']],
  ['nx-terraform-cloud', 'Terraform Cloud Workspaces', 'nx', 'saas', ['compute', 'identity']],
  ['nx-artifact-repo', 'Artifact Repository (Nexus)', 'nx', 'hybrid', ['storage', 'container']],
  ['nx-ci-cd-pipeline', 'CI/CD Pipeline Platform', 'nx', 'cloud', ['compute', 'container', 'storage']],
  ['nx-observability-stack', 'Observability Stack (Grafana/Prom)', 'nx', 'cloud', ['compute', 'storage', 'database']],
  ['nx-data-lake', 'Enterprise Data Lake', 'nx', 'cloud', ['storage', 'database', 'compute']],
  ['nx-api-gateway-shared', 'Shared API Gateway', 'nx', 'cloud', ['network', 'compute', 'serverless']],
  ['nx-waf-cloudfront', 'CloudFront WAF Shield', 'nx', 'cloud', ['network', 'compute']],
  ['nx-certificate-mgmt', 'TLS Certificate Manager', 'nx', 'cloud', ['encryption', 'network']],
  ['nx-cost-mgmt', 'Cloud Cost Management', 'nx', 'cloud', ['compute', 'database']],
  ['nx-patch-mgmt', 'Patch Management Platform', 'nx', 'hybrid', ['compute', 'database']],
  // Nexus — Aegis platform (self)
  ['nx-aegis-api', 'Aegis API Gateway', 'nx', 'cloud', ['compute', 'network', 'serverless']],
  ['nx-aegis-opa', 'Aegis OPA Policy Engine', 'nx', 'cloud', ['compute', 'serverless']],
  ['nx-aegis-ingest', 'Findings Ingestion Pipeline', 'nx', 'cloud', ['compute', 'serverless', 'storage']],
  ['nx-aegis-webapp', 'Aegis Web Console', 'nx', 'cloud', ['compute', 'network']],
  ['nx-aegis-db', 'Aegis PostgreSQL Findings DB', 'nx', 'cloud', ['database']],
  ['nx-aegis-redis', 'Aegis Cache Session/Query', 'nx', 'cloud', ['database']],
  ['nx-aegis-otel', 'Aegis OTel Collector', 'nx', 'cloud', ['compute', 'storage']],
  // Summit (Group-Level) — 10 services
  ['sm-workflow-engine', 'Business Process Automation', 'sm', 'cloud', ['compute', 'serverless', 'database', 'storage']],
  ['sm-board-reporting', 'Board Reporting Dashboard', 'sm', 'cloud', ['compute', 'database', 'storage']],
  ['sm-m-and-a-diligence', 'M&A Due Diligence Platform', 'sm', 'cloud', ['compute', 'database', 'encryption', 'storage']],
  ['sm-legal-ediscovery', 'Legal eDiscovery Archive', 'sm', 'cloud', ['storage', 'database', 'encryption']],
  ['sm-group-data-warehouse', 'Group Data Warehouse', 'sm', 'cloud', ['database', 'storage', 'compute']],
  ['sm-risk-aggregation', 'Enterprise Risk Aggregation', 'sm', 'cloud', ['compute', 'database', 'serverless']],
  ['sm-sustainability-esg', 'ESG Sustainability Reporting', 'sm', 'cloud', ['compute', 'database', 'storage']],
  ['sm-inter-company', 'Inter-Company Settlement', 'sm', 'cloud', ['compute', 'database', 'encryption']],
  ['sm-brand-management', 'Brand Asset Management', 'sm', 'cloud', ['storage', 'compute', 'network']],
  ['sm-exec-comms', 'Executive Communications Hub', 'sm', 'cloud', ['compute', 'encryption', 'serverless']],
];

const SERVICES = SERVICES_RAW.map(([id, name, cbu, deployType, resourceTypes]) => ({
  id, name, cbu, deployType, resourceTypes,
}));

// Filter to cloud-eligible services (cloud/hybrid/self can generate cloud findings)
const CLOUD_SERVICES = SERVICES.filter(s => s.deployType === 'cloud' || s.deployType === 'hybrid');

// ── Account Generation ───────────────────────────────────────────────────────

const ENVS = ['prd', 'stg', 'dev', 'sbx'];
const ENV_LONG = { prd: 'production', stg: 'staging', dev: 'development', sbx: 'sandbox' };
const ENV_PROB = { prd: 1.0, stg: 0.7, dev: 0.5, sbx: 0.3 };
const PROVIDERS = ['aws', 'azure', 'gcp'];
const PROVIDER_DIST = [52, 28, 20]; // percentage allocation

const AWS_REGIONS = ['us-east-1', 'us-west-2', 'eu-west-1', 'eu-central-1', 'ap-southeast-1'];
const AZURE_REGIONS = ['eastus', 'westeurope', 'southeastasia', 'westus2', 'northeurope'];
const GCP_REGIONS = ['us-central1', 'europe-west1', 'asia-southeast1', 'us-east4'];

function buildAccounts() {
  const accounts = [];
  let awsSeq = 100000000001;
  let azureSeq = 0;
  let gcpSeq = 100001;

  for (const svc of CLOUD_SERVICES) {
    // Assign a primary provider based on service characteristics
    const svcHash = parseInt(hash(svc.id).slice(0, 8), 16);
    const providerIdx = svcHash % 3;
    const primaryProvider = PROVIDERS[providerIdx];

    for (const env of ENVS) {
      // Not every service gets every environment
      const envRoll = (svcHash + ENVS.indexOf(env) * 7) % 100;
      if (envRoll / 100 > ENV_PROB[env]) continue;

      const accName = `${svc.id}-${env}`;
      let accId;
      if (primaryProvider === 'aws') {
        accId = String(awsSeq++);
      } else if (primaryProvider === 'azure') {
        const hexParts = hash(`azure-${accName}`);
        accId = `${hexParts.slice(0,8)}-${hexParts.slice(8,12)}-${hexParts.slice(12,16)}-${hexParts.slice(16,20)}-${hexParts.slice(20,32)}`;
        azureSeq++;
      } else {
        accId = `proj-${svc.id.replace(/^[a-z]+-/, '')}-${env}-${gcpSeq++}`;
      }

      accounts.push({
        id: accId,
        name: accName,
        provider: primaryProvider,
        service: svc,
        env,
        envLong: ENV_LONG[env],
        region: primaryProvider === 'aws' ? pick(AWS_REGIONS) :
                primaryProvider === 'azure' ? pick(AZURE_REGIONS) :
                pick(GCP_REGIONS),
      });
    }
  }
  return accounts;
}

const ALL_ACCOUNTS = buildAccounts();
log(`Generated ${ALL_ACCOUNTS.length} accounts across ${CLOUD_SERVICES.length} services`);

// Group accounts by provider for quick lookup
const ACCOUNTS_BY_PROVIDER = {};
for (const acc of ALL_ACCOUNTS) {
  if (!ACCOUNTS_BY_PROVIDER[acc.provider]) ACCOUNTS_BY_PROVIDER[acc.provider] = [];
  ACCOUNTS_BY_PROVIDER[acc.provider].push(acc);
}

// ── Distribution Constants ───────────────────────────────────────────────────

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const SEV_WEIGHTS = [9, 22, 42, 27]; // ~9% CRIT, 22% HIGH, 42% MED, 27% LOW

// Active states (90%)
const ACTIVE_STATUSES = ['open', 'open', 'open', 'in_progress'];
const ACTIVE_WORKFLOWS = ['new', 'triaged', 'assigned', 'in_progress'];
const ACTIVE_WF_WEIGHTS = [35, 25, 20, 10];
// Inactive states (10%)
const INACTIVE_STATUSES = ['resolved', 'suppressed', 'resolved', 'resolved'];
const INACTIVE_WORKFLOWS = ['remediated', 'verified', 'closed', 'suppressed', 'false_positive', 'risk_accepted'];
const INACTIVE_WF_WEIGHTS = [30, 15, 15, 10, 8, 2];

const SLA_HOURS = { CRITICAL: 24, HIGH: 168, MEDIUM: 720, LOW: 2160 };
const CVSS_RANGE = { CRITICAL: [9.0, 10.0], HIGH: [7.0, 8.9], MEDIUM: [4.0, 6.9], LOW: [0.1, 3.9] };
const EPSS_RANGE = { CRITICAL: [0.7, 0.98], HIGH: [0.3, 0.7], MEDIUM: [0.05, 0.3], LOW: [0.001, 0.05] };
const RISK_RANGE = { CRITICAL: [8.5, 10.0], HIGH: [6.0, 8.4], MEDIUM: [3.5, 5.9], LOW: [1.0, 3.4] };

const TYPES = ['vulnerability', 'misconfiguration', 'network_exposure', 'iam_risk', 'data_exposure', 'compliance_drift'];
const CATEGORIES = ['VULNERABILITY', 'MISCONFIGURATION', 'NETWORK', 'IDENTITY', 'DATA_EXPOSURE', 'COMPLIANCE'];
const TYPE_WEIGHTS = [18, 30, 15, 15, 12, 10];

const FRAMEWORKS = [
  { id: 'nist-csf', name: 'NIST CSF 2.0', prefix: 'PR' },
  { id: 'pci-dss', name: 'PCI-DSS v4.0', prefix: 'REQ' },
  { id: 'hipaa', name: 'HIPAA Security Rule', prefix: 'A' },
  { id: 'iso-27001', name: 'ISO 27001:2022', prefix: 'A' },
  { id: 'iso-42001', name: 'ISO 42001:2023', prefix: 'AI' },
  { id: 'tisax', name: 'TISAX', prefix: 'ISA' },
  { id: 'cis', name: 'CIS Benchmarks v8.0', prefix: 'CIS' },
  { id: 'soc2', name: 'SOC 2 Type II', prefix: 'CC' },
];

const TACTICS = ['TA0001', 'TA0002', 'TA0003', 'TA0004', 'TA0005', 'TA0006', 'TA0008', 'TA0009', 'TA0010', 'TA0040'];
const TECHNIQUES = ['T1190', 'T1059', 'T1098', 'T1068', 'T1562', 'T1552', 'T1021', 'T1005', 'T1567', 'T1499', 'T1078', 'T1530', 'T1548.005', 'T1110', 'T1566'];

const LOBS = ['payments', 'platform', 'data-engineering', 'security-ops', 'ml-ai', 'analytics', 'identity', 'infrastructure', 'compliance', 'networking'];

const AWS_SOURCES = ['aws-security-hub', 'aws-guardduty', 'aws-inspector'];
const AZURE_SOURCES = ['azure-defender', 'azure-sentinel', 'azure-advisor'];
const GCP_SOURCES = ['gcp-scc', 'gcp-cspm'];

// ── Dummy Personas (50) ──────────────────────────────────────────────────────

const FIRST_NAMES = ['Alex', 'Jordan', 'Morgan', 'Taylor', 'Casey', 'Riley', 'Cameron', 'Dakota', 'Avery', 'Quinn',
  'Reese', 'Skyler', 'Finley', 'Harper', 'Rowan', 'Sage', 'Emery', 'Hayden', 'Parker', 'Sawyer',
  'Blake', 'Drew', 'Ellis', 'Frankie', 'Jamie', 'Kai', 'Lane', 'Micah', 'Nico', 'Remy',
  'Sam', 'Devon', 'Charlie', 'Robin', 'Ash', 'Bailey', 'Dana', 'Eden', 'Gale', 'Harley',
  'Indigo', 'Jules', 'Kit', 'Lee', 'Marlo', 'Noel', 'Oakley', 'Peyton', 'River', 'Shay'];

const LAST_NAMES = ['Chen', 'Patel', 'Kim', 'Nakamura', 'Okafor', 'Silva', 'Johansson', 'Alvarez', 'Dubois', 'Schneider',
  'Kowalski', 'Ivanov', 'Hassan', 'Gupta', 'Tanaka', 'Larsson', 'Fernandez', 'Nguyen', 'Mueller', 'Olsson',
  'Park', 'Santos', 'Andersen', 'Roth', 'Yamamoto', 'Costa', 'Berg', 'Sharma', 'Li', 'Torres',
  'Holt', 'Reed', 'Cross', 'Stone', 'Grant', 'Wells', 'Frost', 'Cole', 'Hart', 'Shaw',
  'Blake', 'Hayes', 'Price', 'Brooks', 'Walsh', 'Lane', 'Hunt', 'Ross', 'Webb', 'Nash'];

const TEAMS = ['security-ops', 'platform-eng', 'cloud-infra', 'grc', 'soc'];
const ROLES = ['analyst', 'engineer', 'lead', 'manager', 'architect'];

const PERSONAS = [];
for (let i = 0; i < 50; i++) {
  const first = FIRST_NAMES[i];
  const last = LAST_NAMES[i];
  const team = TEAMS[i % TEAMS.length];
  const role = ROLES[Math.floor(i / TEAMS.length) % ROLES.length];
  PERSONAS.push({
    user_id: `usr-${pad(i + 1, 3)}`,
    user_name: `${first} ${last}`,
    user_email: `${first.toLowerCase()}.${last.toLowerCase()}@aegis-demo.io`,
    team,
    role,
  });
}

// ── Source File Parsers ──────────────────────────────────────────────────────

function tryReadJSON(path) {
  if (!existsSync(path)) return null;
  try {
    const raw = readFileSync(path, 'utf-8');
    return JSON.parse(raw);
  } catch (e) {
    // If string too long, fall back to streaming buffer parser
    if (e.message.includes('string longer than') || e.message.includes('Invalid string length')) {
      log(`  String limit hit — using streaming parser for ${path}`);
      return streamParseJSONArray(path);
    }
    warn(`Failed to parse ${path}: ${e.message}`);
    return null;
  }
}

/**
 * Streaming JSON array parser for files exceeding Node.js string limit (~512MB).
 * Reads file as a raw Buffer, scans for top-level objects by tracking brace depth,
 * correctly handles quoted strings and escape sequences.
 */
function streamParseJSONArray(path) {
  const buf = readFileSync(path); // Buffer, no string limit
  const results = [];
  let depth = 0;
  let inString = false;
  let escaped = false;
  let objStart = -1;

  for (let i = 0; i < buf.length; i++) {
    const c = buf[i];
    if (escaped) { escaped = false; continue; }
    if (c === 0x5C && inString) { escaped = true; continue; } // backslash inside string
    if (c === 0x22) { inString = !inString; continue; } // double quote
    if (inString) continue;

    if (c === 0x5B && depth === 0) { depth = 1; continue; } // opening [ of array
    if (c === 0x5D && depth === 1) break; // closing ] of array

    if (c === 0x7B) { // {
      if (depth === 1) objStart = i;
      depth++;
    } else if (c === 0x7D) { // }
      depth--;
      if (depth === 1 && objStart >= 0) {
        try {
          const objStr = buf.subarray(objStart, i + 1).toString('utf-8');
          results.push(JSON.parse(objStr));
        } catch { /* skip malformed objects */ }
        objStart = -1;
      }
    }

    // Progress logging for large files
    if (results.length > 0 && results.length % 50000 === 0 && c === 0x7D && depth === 1) {
      log(`  ...parsed ${results.length} objects so far`);
    }
  }

  return results;
}

/**
 * Write a JSON array incrementally to avoid string length limit on large outputs.
 */
function writeJSONArrayStreaming(filePath, items) {
  const ws = createWriteStream(filePath);
  ws.write('[');
  for (let i = 0; i < items.length; i++) {
    if (i > 0) ws.write(',');
    ws.write(JSON.stringify(items[i]));
  }
  ws.write(']');
  ws.end();
  // Wait for the write to finish
  return new Promise((resolve, reject) => {
    ws.on('finish', resolve);
    ws.on('error', reject);
  });
}

function parseAwsFindings(data) {
  if (!Array.isArray(data)) return [];
  return data.map(f => {
    const resType = f.Resources?.[0]?.Type ?? '';
    const resId = f.Resources?.[0]?.Id ?? '';
    const severity = (f.Severity?.Label ?? 'MEDIUM').toUpperCase();
    const genId = f.GeneratorId ?? '';
    // Extract canonical control ID from GeneratorId
    const controlMatch = genId.match(/\/([A-Z0-9.]+)$/);
    const controlId = controlMatch ? controlMatch[1] : genId.split('/').pop();
    return {
      _provider: 'aws',
      _nativeId: f.Id,
      _accountId: f.AwsAccountId ?? '',
      _region: f.Region ?? f.Resources?.[0]?.Region ?? 'us-east-1',
      _title: f.Title ?? '',
      _description: f.Description ?? '',
      _severity: severity === 'INFORMATIONAL' ? 'LOW' : severity,
      _resourceType: mapAwsResourceType(resType),
      _resourceId: resId,
      _resourceNativeType: resType,
      _controlId: controlId,
      _source: genId.includes('guardduty') ? 'aws-guardduty' :
               genId.includes('inspector') ? 'aws-inspector' : 'aws-security-hub',
      _status: f.Workflow?.Status ?? 'NEW',
      _recordState: f.RecordState ?? 'ACTIVE',
      _createdAt: f.CreatedAt,
      _updatedAt: f.UpdatedAt,
      _type: inferTypeFromAws(resType, genId),
      _category: inferCategoryFromAws(resType, genId),
    };
  });
}

function parseAzureFindings(data) {
  if (!Array.isArray(data)) return [];
  return data.map(f => {
    const severity = (f.severity ?? 'Medium');
    const normSev = severity.toUpperCase() === 'HIGH' ? 'HIGH' :
                    severity.toUpperCase() === 'MEDIUM' ? 'MEDIUM' :
                    severity.toUpperCase() === 'LOW' ? 'LOW' :
                    severity.toUpperCase() === 'CRITICAL' ? 'CRITICAL' : 'MEDIUM';
    const resourceId = f.resourceId ?? '';
    return {
      _provider: 'azure',
      _nativeId: f.id,
      _accountId: f.subscriptionId ?? '',
      _region: extractAzureRegion(resourceId),
      _title: f.title ?? f.name ?? '',
      _description: f.description ?? '',
      _severity: normSev,
      _resourceType: mapAzureResourceType(resourceId),
      _resourceId: resourceId,
      _resourceNativeType: extractAzureProvider(resourceId),
      _controlId: f.control ?? f.name ?? '',
      _source: 'azure-defender',
      _status: f.status === 'Unhealthy' ? 'NEW' : 'RESOLVED',
      _recordState: f.status === 'Unhealthy' ? 'ACTIVE' : 'ARCHIVED',
      _createdAt: f.createdAt,
      _updatedAt: f.updatedAt,
      _type: inferTypeFromAzure(f.title, resourceId),
      _category: inferCategoryFromAzure(f.title, resourceId),
    };
  });
}

function parseGcpFindings(data) {
  if (!Array.isArray(data)) return [];
  return data.map(f => {
    const severity = (f.severity ?? 'MEDIUM').toUpperCase();
    const projectId = f.sourceProperties?.ProjectId ?? '';
    return {
      _provider: 'gcp',
      _nativeId: f.name,
      _accountId: projectId,
      _region: 'us-central1',
      _title: f.category?.replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, c => c.toUpperCase()) ?? '',
      _description: f.description ?? f.sourceProperties?.Explanation ?? '',
      _severity: severity === 'INFORMATIONAL' ? 'LOW' : severity,
      _resourceType: mapGcpResourceType(f.sourceProperties?.ResourceType ?? '', f.category ?? ''),
      _resourceId: f.resourceName ?? '',
      _resourceNativeType: f.sourceProperties?.ResourceType ?? '',
      _controlId: f.category ?? '',
      _source: 'gcp-scc',
      _status: f.state === 'ACTIVE' ? 'NEW' : 'RESOLVED',
      _recordState: f.state ?? 'ACTIVE',
      _createdAt: f.createTime,
      _updatedAt: f.eventTime,
      _type: inferTypeFromGcp(f.category ?? ''),
      _category: inferCategoryFromGcp(f.category ?? ''),
    };
  });
}

// ── Resource Type Mappers ────────────────────────────────────────────────────

function mapAwsResourceType(awsType) {
  const MAP = {
    AwsEc2SecurityGroup: 'network', AwsIamUser: 'identity', AwsIamRole: 'identity',
    AwsIamPolicy: 'identity', AwsAccount: 'identity', AwsCloudTrailTrail: 'monitoring',
    AwsRdsDbSnapshot: 'database', AwsRdsDbInstance: 'database', AwsS3Bucket: 'storage',
    AwsEcsTaskDefinition: 'container', AwsEcrRepository: 'container', AwsEksCluster: 'container',
    AwsSnsTopic: 'serverless', AwsLambdaFunction: 'serverless', AwsSqsQueue: 'serverless',
    AwsKmsKey: 'encryption', AwsEc2Instance: 'compute', AwsElbv2LoadBalancer: 'network',
    AwsEc2Vpc: 'network', AwsEc2Subnet: 'network',
  };
  return MAP[awsType] ?? 'compute';
}

function mapAzureResourceType(resourceId) {
  const id = (resourceId ?? '').toLowerCase();
  if (id.includes('microsoft.compute')) return 'compute';
  if (id.includes('microsoft.storage')) return 'storage';
  if (id.includes('microsoft.sql') || id.includes('microsoft.dbforpostgresql') || id.includes('microsoft.documentdb') || id.includes('cosmos')) return 'database';
  if (id.includes('microsoft.containerservice') || id.includes('microsoft.containerregistry')) return 'container';
  if (id.includes('microsoft.keyvault')) return 'encryption';
  if (id.includes('microsoft.network')) return 'network';
  if (id.includes('microsoft.web')) return 'serverless';
  if (id.includes('microsoft.aad') || id.includes('microsoft.authorization')) return 'identity';
  return 'compute';
}

function extractAzureRegion(resourceId) {
  // Azure resource IDs don't contain region, use a default
  return 'eastus';
}

function extractAzureProvider(resourceId) {
  const match = (resourceId ?? '').match(/providers\/(microsoft\.[^/]+\/[^/]+)/i);
  return match ? match[1] : 'Microsoft.Compute/virtualMachines';
}

function mapGcpResourceType(gcpType, category) {
  const t = gcpType.toLowerCase();
  if (t.includes('storage') || t.includes('bucket')) return 'storage';
  if (t.includes('sql') || t.includes('bigquery') || t.includes('spanner')) return 'database';
  if (t.includes('compute') || t.includes('instance')) return 'compute';
  if (t.includes('container') || t.includes('gke') || t.includes('cluster')) return 'container';
  if (t.includes('iam') || t.includes('serviceaccount')) return 'identity';
  if (t.includes('network') || t.includes('firewall') || t.includes('vpc')) return 'network';
  if (t.includes('function') || t.includes('run')) return 'serverless';
  if (t.includes('kms') || t.includes('secret')) return 'encryption';
  return 'compute';
}

// ── Type/Category Inference ──────────────────────────────────────────────────

function inferTypeFromAws(resType, genId) {
  if (genId.includes('inspector')) return 'vulnerability';
  if (genId.includes('guardduty')) return 'network_exposure';
  if (resType.includes('Iam')) return 'iam_risk';
  if (resType.includes('S3') || resType.includes('Kms')) return 'data_exposure';
  if (resType.includes('SecurityGroup') || resType.includes('Elb')) return 'network_exposure';
  if (genId.includes('cis')) return 'compliance_drift';
  return 'misconfiguration';
}
function inferCategoryFromAws(resType, genId) {
  const type = inferTypeFromAws(resType, genId);
  return CATEGORIES[TYPES.indexOf(type)] ?? 'MISCONFIGURATION';
}

function inferTypeFromAzure(title, resourceId) {
  const t = (title ?? '').toLowerCase();
  if (t.includes('vulnerabilit') || t.includes('patch') || t.includes('upgrade')) return 'vulnerability';
  if (t.includes('network') || t.includes('nsg') || t.includes('firewall') || t.includes('port')) return 'network_exposure';
  if (t.includes('identity') || t.includes('mfa') || t.includes('authentication') || t.includes('role')) return 'iam_risk';
  if (t.includes('encrypt') || t.includes('key') || t.includes('tls') || t.includes('secret')) return 'data_exposure';
  if (t.includes('diagnostic') || t.includes('audit') || t.includes('log')) return 'compliance_drift';
  return 'misconfiguration';
}
function inferCategoryFromAzure(title, resourceId) {
  const type = inferTypeFromAzure(title, resourceId);
  return CATEGORIES[TYPES.indexOf(type)] ?? 'MISCONFIGURATION';
}

function inferTypeFromGcp(category) {
  const c = category.toLowerCase();
  if (c.includes('sql') || c.includes('vulnerability')) return 'vulnerability';
  if (c.includes('firewall') || c.includes('network') || c.includes('ssh') || c.includes('port')) return 'network_exposure';
  if (c.includes('iam') || c.includes('service_account') || c.includes('role')) return 'iam_risk';
  if (c.includes('bucket') || c.includes('encrypt') || c.includes('kms') || c.includes('secret')) return 'data_exposure';
  if (c.includes('audit') || c.includes('log') || c.includes('monitor')) return 'compliance_drift';
  return 'misconfiguration';
}
function inferCategoryFromGcp(category) {
  const type = inferTypeFromGcp(category);
  return CATEGORIES[TYPES.indexOf(type)] ?? 'MISCONFIGURATION';
}

// ── Phase 1: Collect Sources ─────────────────────────────────────────────────

function collectSources() {
  const rawFindings = [];

  // Small files (always loaded)
  const smallPaths = [
    ['testdata/cspm/raw/aws_securityhub_findings.json', 'aws'],
    ['testdata/cspm/raw/azure_defender_assessments.json', 'azure'],
    ['testdata/cspm/raw/gcp_scc_findings.json', 'gcp'],
  ];

  for (const [path, provider] of smallPaths) {
    const data = tryReadJSON(path);
    if (!data) continue;
    const parser = provider === 'aws' ? parseAwsFindings :
                   provider === 'azure' ? parseAzureFindings : parseGcpFindings;
    const parsed = parser(data);
    log(`  ${path}: ${parsed.length} findings`);
    for (const f of parsed) rawFindings.push(f);
  }

  // Medium files (always loaded)
  const mediumPaths = [
    ['testdata/export-outputs/azure_all_security_20260324_190457.json', 'azure'],
    ['testdata/export-outputs/azure_all_security_20260324_190516.json', 'azure'],
    ['testdata/export-outputs/gcp_all_findings_20260324_184746.json', 'gcp'],
  ];

  for (const [path, provider] of mediumPaths) {
    const data = tryReadJSON(path);
    if (!data) continue;
    const parser = provider === 'azure' ? parseAzureFindings : parseGcpFindings;
    const parsed = parser(data);
    log(`  ${path}: ${parsed.length} findings`);
    for (const f of parsed) rawFindings.push(f);
  }

  // Scrubbed files (GCP + Azure JSON)
  const scrubbedPaths = [
    ['testdata/export-scripts/output/scrubbed/scrubbed_gcp_all_findings_20260306_002606.json', 'gcp'],
    ['testdata/export-scripts/output/scrubbed/scrubbed_azure_all_findings_20260306_002937.json', 'azure'],
  ];

  for (const [path, provider] of scrubbedPaths) {
    const data = tryReadJSON(path);
    if (!data) continue;
    const parser = provider === 'azure' ? parseAzureFindings : parseGcpFindings;
    const parsed = parser(data);
    log(`  ${path}: ${parsed.length} findings`);
    for (const f of parsed) rawFindings.push(f);
  }

  // Large files (only with --full)
  if (FULL_MODE) {
    const largePaths = [
      ['testdata/export-outputs/aws_securityhub_guardduty_20260324_190620.json', 'aws'],
      ['testdata/export-outputs/azure_all_security_20260324_191728.json', 'azure'],
      ['testdata/export-outputs/gcp_all_findings_allstates_20260324_185736.json', 'gcp'],
    ];

    for (const [path, provider] of largePaths) {
      log(`  Loading large file: ${path} ...`);
      const data = tryReadJSON(path);
      if (!data) continue;
      const parser = provider === 'aws' ? parseAwsFindings :
                     provider === 'azure' ? parseAzureFindings : parseGcpFindings;
      const parsed = parser(data);
      log(`  ${path}: ${parsed.length} findings`);
      for (const f of parsed) rawFindings.push(f);
    }
  }

  return rawFindings;
}

// ── Phase 2: Dedup ───────────────────────────────────────────────────────────

function dedup(rawFindings) {
  const seen = new Map();
  let dupes = 0;

  for (const f of rawFindings) {
    // Primary key: provider-native ID
    const primaryKey = f._nativeId;
    if (seen.has(primaryKey)) { dupes++; continue; }

    // Secondary dedup: same control + same resource + same account
    const secondaryKey = `${f._controlId}|${f._resourceId}|${f._accountId}`;
    if (seen.has(secondaryKey)) { dupes++; continue; }

    seen.set(primaryKey, f);
    seen.set(secondaryKey, f);
  }

  // Extract unique findings (only primary keys are actual findings)
  const unique = [];
  const addedIds = new Set();
  for (const [key, f] of seen) {
    if (key === f._nativeId && !addedIds.has(key)) {
      unique.push(f);
      addedIds.add(key);
    }
  }

  log(`Dedup: ${rawFindings.length} raw → ${unique.length} unique (${dupes} duplicates)`);
  return unique;
}

// ── Phase 3: Taxonomy Assignment + Sanitization ──────────────────────────────

function assignTaxonomy(findings) {
  return findings.map((f, idx) => {
    // Assign account from taxonomy based on finding hash
    const h = hash(f._nativeId + String(idx));
    const hInt = parseInt(h.slice(0, 8), 16);

    // Pick provider-matching accounts (or any if no match)
    let pool = ACCOUNTS_BY_PROVIDER[f._provider];
    if (!pool || pool.length === 0) pool = ALL_ACCOUNTS;

    // Filter to accounts whose service has matching resource types
    const typePool = pool.filter(a => a.service.resourceTypes.includes(f._resourceType));
    const effectivePool = typePool.length > 0 ? typePool : pool;

    const account = effectivePool[hInt % effectivePool.length];
    const svc = account.service;

    // Build sanitized resource name
    const resSeq = pad(idx + 1);
    const resPrefix = resourcePrefix(f._resourceType);
    const resName = `${resPrefix}-${svc.id}-${account.env}-${resSeq}`;

    const { resId, resArn } = buildProviderResourceIdentifiers({
      provider: f._provider,
      resourceType: f._resourceType,
      account,
      resName,
      hashValue: h,
      nativeType: f._resourceNativeType,
    });

    // Scrub IP addresses → RFC 5737
    const ipOctet3 = (hInt >> 8) & 0xFF;
    const ipOctet4 = hInt & 0xFF;
    const fakeIp = `192.0.2.${ipOctet4 % 254 + 1}`;

    return {
      ...f,
      _account: account,
      _service: svc,
      _resName: resName,
      _resId: resId,
      _resArn: resArn,
      _fakeIp: fakeIp,
    };
  });
}

function resourcePrefix(type) {
  const MAP = { compute: 'vm', storage: 'stor', database: 'db', container: 'ctr',
    identity: 'iam', network: 'net', serverless: 'fn', encryption: 'key',
    monitoring: 'mon', messaging: 'msg', security: 'sec', other: 'res' };
  return MAP[type] ?? 'res';
}

function arnService(type) {
  const MAP = { compute: 'ec2', storage: 's3', database: 'rds', container: 'ecs',
    identity: 'iam', network: 'ec2', serverless: 'lambda', encryption: 'kms',
    monitoring: 'cloudwatch' };
  return MAP[type] ?? 'ec2';
}

function arnResource(type) {
  const MAP = { compute: 'instance', storage: '', database: 'db', container: 'cluster',
    identity: 'role', network: 'security-group', serverless: 'function', encryption: 'key',
    monitoring: 'alarm' };
  return MAP[type] ?? 'resource';
}

function defaultAzureNativeType(resourceType) {
  const MAP = {
    compute: 'Microsoft.Compute/virtualMachines',
    storage: 'Microsoft.Storage/storageAccounts',
    database: 'Microsoft.DocumentDB/databaseAccounts',
    container: 'Microsoft.ContainerService/managedClusters',
    identity: 'Microsoft.Authorization/roleAssignments',
    network: 'Microsoft.Network/networkSecurityGroups',
    serverless: 'Microsoft.Web/sites',
    encryption: 'Microsoft.KeyVault/vaults',
    monitoring: 'Microsoft.Insights/components',
  };
  return MAP[resourceType] ?? 'Microsoft.Resources/resources';
}

function buildProviderResourceIdentifiers({ provider, resourceType, account, resName, hashValue, nativeType }) {
  const resPrefix = resourcePrefix(resourceType);

  if (provider === 'aws') {
    const resId = resourceType === 'network' ? `sg-${hashValue.slice(0, 8)}` :
                  resourceType === 'compute' ? `i-${hashValue.slice(0, 12)}` :
                  `${resPrefix}-${hashValue.slice(0, 8)}`;
    const arnRes = arnResource(resourceType);
    return {
      resId,
      resArn: arnRes
        ? `arn:aws:${arnService(resourceType)}:${account.region}:${account.id}:${arnRes}/${resId}`
        : `arn:aws:${arnService(resourceType)}:::${resId}`,
    };
  }

  if (provider === 'azure') {
    const rg = `rg-${account.service.id}-${account.env}`;
    const azProvider = nativeType || defaultAzureNativeType(resourceType);
    const resId = `/subscriptions/${account.id}/resourceGroups/${rg}/providers/${azProvider}/${resName}`;
    return { resId, resArn: resId };
  }

  const resId = `projects/${account.id}/locations/${account.region}/${resourceType}/${resName}`;
  return { resId, resArn: resId };
}

// ── Phase 4: Enrich ──────────────────────────────────────────────────────────

function enrichFindings(findings) {
  const BASE_DATE = new Date('2026-02-01T00:00:00Z');
  const NOW = new Date('2026-03-24T08:00:00Z');
  let autoRemCount = 0;
  const autoRemTarget = Math.round(findings.length * 0.30);

  return findings.map((f, idx) => {
    const id = `f-${pad(idx + 1)}`;
    const severity = f._severity;
    const h = hash(id + f._nativeId);
    const hInt = parseInt(h.slice(0, 8), 16);

    // Status distribution: 90% active, 10% inactive (threshold 92 compensates hash skew)
    const isActive = (hInt % 100) < 92;
    const status = isActive ? ACTIVE_STATUSES[hInt % ACTIVE_STATUSES.length] : INACTIVE_STATUSES[hInt % INACTIVE_STATUSES.length];
    const workflowStatus = isActive
      ? weightedPick(ACTIVE_WORKFLOWS, ACTIVE_WF_WEIGHTS, hInt)
      : weightedPick(INACTIVE_WORKFLOWS, INACTIVE_WF_WEIGHTS, hInt);

    // Dates with jitter
    const foundOffset = (hInt % (50 * 24)); // 0-50 days in hours
    const firstFound = genDate(BASE_DATE, foundOffset);
    const lastSeen = genDate(BASE_DATE, foundOffset + (hInt % (10 * 24)) + 24);
    const slaOffset = SLA_HOURS[severity];
    const dueDate = genDate(new Date(firstFound), slaOffset);
    const dueDateObj = new Date(dueDate);
    const slaBreached = isActive && status === 'open' && dueDateObj < NOW;

    // Scores
    const [cvssMin, cvssMax] = CVSS_RANGE[severity];
    const cvss = randRange(cvssMin, cvssMax);
    const [epssMin, epssMax] = EPSS_RANGE[severity];
    const epss = f._type === 'vulnerability' ? randRange(epssMin, epssMax) : 0;
    const [riskMin, riskMax] = RISK_RANGE[severity];
    const aiRiskScore = randRange(riskMin, riskMax);

    const exploitAvailable = f._type === 'vulnerability' &&
      (severity === 'CRITICAL' || (severity === 'HIGH' && (hInt % 100) > 50));

    // Auto-remediatable
    const autoRem = autoRemCount < autoRemTarget &&
      (f._type === 'misconfiguration' || f._type === 'network_exposure' ||
       (f._type === 'compliance_drift' && (hInt % 100) > 50));
    if (autoRem) autoRemCount++;

    // Contextual factors
    const factors = [];
    const env = f._account.envLong;
    if (env === 'production') factors.push('production_environment');
    if (exploitAvailable) factors.push('exploit_available');
    if (epss > 0.5) factors.push('high_epss_score');
    if (f._resourceType === 'storage' || f._resourceType === 'database') factors.push('data_resource');
    if (f._resourceType === 'network') factors.push('network_exposure');
    if (slaBreached) factors.push('sla_breached');

    // Compliance mappings (80%+ of findings)
    const hasCompliance = (hInt % 100) < 82;
    const complianceMappings = hasCompliance ? buildComplianceMappings(f, severity, hInt) : [];

    // CVE references (vulnerability type only)
    const cves = f._type === 'vulnerability' ? [buildCVE(severity, cvss, epss, hInt)] : [];

    // MITRE mappings (vulnerability + iam + network)
    const hasMitre = ['vulnerability', 'iam_risk', 'network_exposure'].includes(f._type);
    const mitreTactics = hasMitre ? pickNSeeded(TACTICS, 1 + (hInt % 2), hInt) : [];
    const mitreTechniques = hasMitre ? pickNSeeded(TECHNIQUES, 1 + (hInt % 2), hInt + 1) : [];

    // Assignee (30% of findings)
    const hasAssignee = (hInt % 100) < 30;
    const assignee = hasAssignee ? buildAssignee(hInt, firstFound) : undefined;

    // Ticket (25% of HIGH/CRITICAL)
    const hasTicket = (severity === 'CRITICAL' || severity === 'HIGH') && (hInt % 100) < 25;
    const ticketId = hasTicket ? `AEGIS-${1000 + (hInt % 9000)}` : undefined;

    const svc = f._service;
    const lob = LOBS[hInt % LOBS.length];

    const finding = {
      id,
      source: f._source,
      source_finding_id: `${f._provider}-${h.slice(0, 16)}`,
      type: f._type,
      title: f._title || `${f._category} finding on ${f._resName}`,
      description: f._description || `Security finding detected on resource ${f._resName} in ${svc.name}.`,
      resource_type: f._resourceType,
      resource_id: f._resId,
      resource_name: f._resName,
      resource_arn: f._resArn,
      platform: 'cloud',
      cloud_provider: f._provider,
      region: f._account.region,
      account_id: f._account.id,
      account_name: f._account.name,
      environment_type: env,
      static_severity: severity,
      severity,
      ai_risk_score: aiRiskScore,
      ai_risk_level: severity.toLowerCase(),
      ai_risk_rationale: `${severity} severity ${f._type.replace(/_/g, ' ')} in ${env} ${svc.name}. ${factors.length > 0 ? 'Risk factors: ' + factors.join(', ') + '.' : 'Standard risk assessment.'}`,
      ai_contextual_factors: factors,
      cvss: f._type === 'vulnerability' ? cvss : undefined,
      cvss_vector: f._type === 'vulnerability' ? `CVSS:3.1/AV:N/AC:${cvss > 8 ? 'L' : 'H'}/PR:${cvss > 7 ? 'N' : 'L'}/UI:N/S:U/C:H/I:${cvss > 8 ? 'H' : 'L'}/A:${cvss > 9 ? 'H' : 'L'}` : undefined,
      epss: f._type === 'vulnerability' ? epss : undefined,
      exploit_available: exploitAvailable,
      cves,
      mitre_tactics: mitreTactics,
      mitre_techniques: mitreTechniques,
      compliance_mappings: complianceMappings,
      remediation: autoRem
        ? `Auto-remediation available: ${f._type === 'misconfiguration' ? 'Apply configuration fix via API' : 'Update security rules'}.`
        : `Manual remediation required: ${f._type === 'vulnerability' ? 'Apply vendor patch' : 'Review and update configuration'}.`,
      auto_remediatable: autoRem,
      category: f._category,
      status,
      workflow_status: workflowStatus,
      suppressed: status === 'suppressed',
      service_name: svc.name,
      line_of_business: lob,
      first_found_at: firstFound,
      last_seen_at: lastSeen,
      due_date: dueDate,
      deduplication_key: h.slice(0, 24),
      canonical_rule_id: f._type === 'vulnerability' && cves.length > 0 ? cves[0].id : f._controlId || `${f._category}-${pad(idx + 1)}`,
      tags: buildCodeToCloudTags({
        service: svc,
        provider: f._provider,
        environmentType: env,
        resourceType: f._resourceType,
        findingID: id,
        findingHash: h,
      }),
    };

    if (slaBreached) finding.sla_breach_date = dueDate;
    if (assignee) finding.assignee = assignee;
    if (ticketId) {
      finding.ticket_id = ticketId;
      finding.ticket_url = `https://aegis-demo.atlassian.net/browse/${ticketId}`;
    }
    if (!isActive && status === 'resolved') {
      finding.resolved_at = genDate(new Date(lastSeen), 24 + (hInt % 72));
    }

    // Clean undefined values
    for (const k of Object.keys(finding)) {
      if (finding[k] === undefined) delete finding[k];
    }

    return finding;
  });
}

function weightedPick(values, weights, seed) {
  const total = weights.reduce((a, b) => a + b, 0);
  let r = (seed % total);
  for (let i = 0; i < values.length; i++) {
    r -= weights[i];
    if (r < 0) return values[i];
  }
  return values[values.length - 1];
}

function pickNSeeded(arr, n, seed) {
  const indices = [];
  for (let i = 0; i < Math.min(n, arr.length); i++) {
    indices.push((seed + i * 7) % arr.length);
  }
  return [...new Set(indices)].map(i => arr[i]);
}

function genDate(baseDate, offsetHours) {
  const d = new Date(baseDate);
  d.setHours(d.getHours() + offsetHours);
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function buildComplianceMappings(f, severity, seed) {
  const count = 1 + (seed % 3);
  const selected = pickNSeeded(FRAMEWORKS, count, seed);
  return selected.map((fw, i) => ({
    framework_id: fw.id,
    framework_name: fw.name,
    control_id: `${fw.prefix}.${1 + ((seed + i) % 12)}.${1 + ((seed + i * 3) % 6)}`,
    control_title: `Control for ${f._type.replace(/_/g, ' ')}`,
    section: `${fw.prefix}.${1 + ((seed + i) % 12)}`,
    severity: severity.toLowerCase(),
    url: '',
  }));
}

function buildCVE(severity, cvss, epss, seed) {
  const year = (seed % 2 === 0) ? 2024 : 2025;
  const num = 1000 + (seed % 49000);
  const cveId = `CVE-${year}-${num}`;
  return {
    id: cveId,
    url: `https://nvd.nist.gov/vuln/detail/${cveId}`,
    nvd_url: `https://nvd.nist.gov/vuln/detail/${cveId}`,
    mitre_url: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveId}`,
    description: `Security vulnerability with CVSS ${cvss}`,
    cvss,
    cvss_vector: `CVSS:3.1/AV:N/AC:${cvss > 8 ? 'L' : 'H'}/PR:${cvss > 7 ? 'N' : 'L'}/UI:N/S:U/C:H/I:${cvss > 8 ? 'H' : 'L'}/A:${cvss > 9 ? 'H' : 'L'}`,
    cvss_version: '3.1',
    epss,
    cisa_known_exploited: severity === 'CRITICAL' && (seed % 100) > 30,
    published: `${year}-${String(1 + (seed % 12)).padStart(2, '0')}-${String(1 + (seed % 28)).padStart(2, '0')}T00:00:00Z`,
    modified: '2026-02-15T00:00:00Z',
  };
}

function buildAssignee(seed, firstFound) {
  const persona = PERSONAS[seed % PERSONAS.length];
  return {
    user_id: persona.user_id,
    user_email: persona.user_email,
    user_name: persona.user_name,
    team: persona.team,
    assigned_at: genDate(new Date(firstFound), 4 + (seed % 48)),
    assigned_by: 'system',
    escalated: (seed % 100) < 10,
  };
}

// ── Phase 5: Synthetic Padding ───────────────────────────────────────────────

function generateSynthetic(realFindings, targetCount) {
  if (realFindings.length >= targetCount) {
    // Shuffle before slicing so all providers are represented, not just the first-loaded
    const shuffled = [...realFindings];
    for (let i = shuffled.length - 1; i > 0; i--) {
      const j = Math.floor(rand() * (i + 1));
      [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }
    return shuffled.slice(0, targetCount);
  }

  const padCount = targetCount - realFindings.length;
  log(`Generating ${padCount} synthetic findings to reach ${targetCount}`);

  const templatesByProvider = new Map();
  for (const finding of realFindings) {
    const providerTemplates = templatesByProvider.get(finding._provider) ?? [];
    providerTemplates.push(finding);
    templatesByProvider.set(finding._provider, providerTemplates);
  }

  // Build severity distribution with jitter
  const sevDist = buildDistribution(SEVERITIES, SEV_WEIGHTS, padCount);
  const typeDist = buildDistribution(TYPES, TYPE_WEIGHTS, padCount);

  const synthetic = [];
  for (let i = 0; i < padCount; i++) {
    const severity = sevDist[i];
    const type = typeDist[i];
    const category = CATEGORIES[TYPES.indexOf(type)];
    const h = hash(`synthetic-${i}-${SEED}`);
    const hInt = parseInt(h.slice(0, 8), 16);

    // Pick provider first, then use a same-provider template so titles,
    // descriptions, native resource types, and generated IDs stay coherent.
    const providerWeighted = weightedPick(PROVIDERS, PROVIDER_DIST, hInt);
    const providerTemplates = templatesByProvider.get(providerWeighted) ?? realFindings;
    const template = providerTemplates[i % providerTemplates.length];

    let pool = ACCOUNTS_BY_PROVIDER[providerWeighted] ?? ALL_ACCOUNTS;
    const resourceType = template._resourceType;
    const typePool = pool.filter(a => a.service.resourceTypes.includes(resourceType));
    pool = typePool.length > 0 ? typePool : pool;
    const account = pool[hInt % pool.length];
    const resName = `${resourcePrefix(resourceType)}-${account.service.id}-${account.env}-${pad(realFindings.length + i + 1)}`;
    const { resId, resArn } = buildProviderResourceIdentifiers({
      provider: providerWeighted,
      resourceType,
      account,
      resName,
      hashValue: h,
      nativeType: template._resourceNativeType,
    });

    synthetic.push({
      _provider: providerWeighted,
      _nativeId: `synthetic-${h.slice(0, 16)}`,
      _accountId: account.id,
      _region: account.region,
      _title: template._title || `${category} finding in ${account.service.name}`,
      _description: template._description || `Security finding in ${account.service.name} ${account.envLong} environment.`,
      _severity: severity,
      _resourceType: resourceType,
      _resourceId: resId,
      _resourceNativeType: template._resourceNativeType,
      _controlId: template._controlId || `${category}-SYNTH-${i}`,
      _source: providerWeighted === 'aws' ? pick(AWS_SOURCES) :
               providerWeighted === 'azure' ? pick(AZURE_SOURCES) : pick(GCP_SOURCES),
      _status: 'NEW',
      _recordState: 'ACTIVE',
      _createdAt: undefined,
      _updatedAt: undefined,
      _type: type,
      _category: category,
      _account: account,
      _service: account.service,
      _resName: resName,
      _resId: resId,
      _resArn: resArn,
      _fakeIp: `198.51.100.${(hInt % 254) + 1}`,
    });
  }

  // Shuffle combined result so providers are mixed, not sequential
  const combined = [...realFindings, ...synthetic];
  for (let i = combined.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [combined[i], combined[j]] = [combined[j], combined[i]];
  }
  return combined;
}

function buildDistribution(values, weights, total) {
  const sum = weights.reduce((a, b) => a + b, 0);
  const result = [];
  for (let i = 0; i < values.length; i++) {
    const base = Math.round((weights[i] / sum) * total);
    // Apply ±5-8% jitter
    const jitterPct = 0.05 + rand() * 0.03;
    const jitter = Math.round(base * jitterPct * (rand() < 0.5 ? -1 : 1));
    const count = Math.max(1, base + jitter);
    for (let j = 0; j < count; j++) result.push(values[i]);
  }
  // Pad or trim to exact target
  while (result.length < total) result.push(pick(values));
  // Shuffle
  for (let i = result.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result.slice(0, total);
}

// ── Phase 6: Impacted Resources + Attack Paths ───────────────────────────────

function addImpactedResources(findings) {
  // Group by account
  const byAccount = {};
  for (const f of findings) {
    if (!byAccount[f.account_id]) byAccount[f.account_id] = [];
    byAccount[f.account_id].push(f);
  }

  let impactedCount = 0;
  for (const accountFindings of Object.values(byAccount)) {
    const candidates = accountFindings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH');
    for (const finding of candidates) {
      const h = parseInt(hash(finding.id).slice(0, 8), 16);
      if ((h % 100) >= 40) continue; // 40% get impacted resources

      const others = accountFindings.filter(f => f.id !== finding.id);
      if (others.length === 0) continue;
      const count = Math.min(1 + (h % 3), others.length);
      const selected = others.slice(0, count);

      finding.impacted_resources = selected.map(s => ({
        resource_id: s.resource_id,
        resource_name: s.resource_name,
        resource_type: s.resource_type,
        relationship: pick(['depends_on', 'connects_to', 'contains', 'shares_network']),
        impact_level: pick(['HIGH', 'CRITICAL', 'MEDIUM']),
      }));
      impactedCount++;
    }
  }
  log(`Added impacted_resources to ${impactedCount} findings`);
}

function computeAttackPaths(findings) {
  const SEVERITY_SCORE = { CRITICAL: 100, HIGH: 60, MEDIUM: 20, LOW: 5 };
  const ENTRY_CATS = new Set(['NETWORK', 'VULNERABILITY']);
  const TARGET_TYPES = new Set(['storage', 'database', 'encryption']);

  // Score findings
  const scored = findings.map(f => {
    let score = SEVERITY_SCORE[f.severity] ?? 0;
    if (f.exploit_available) score += 50;
    if (f.environment_type === 'production') score += 30;
    if (ENTRY_CATS.has(f.category)) score += 20;
    if (TARGET_TYPES.has(f.resource_type)) score += 20;
    if ((f.epss ?? 0) > 0.5) score += 15;
    return { finding: f, score };
  });

  scored.sort((a, b) => b.score - a.score);
  const candidates = scored.slice(0, Math.min(2000, findings.length)).map(s => s.finding);

  // Group by account
  const byAccount = {};
  for (const f of candidates) {
    if (!byAccount[f.account_id]) byAccount[f.account_id] = [];
    byAccount[f.account_id].push(f);
  }

  const paths = [];
  for (const [accountId, accountFindings] of Object.entries(byAccount)) {
    if (accountFindings.length < 3) continue;

    // Find entry points (network/vuln) and targets (storage/db)
    const entries = accountFindings.filter(f => ENTRY_CATS.has(f.category));
    const targets = accountFindings.filter(f => TARGET_TYPES.has(f.resource_type));

    for (const entry of entries.slice(0, 5)) {
      for (const target of targets.slice(0, 3)) {
        if (entry.id === target.id) continue;

        // Find pivot findings in the same account
        const pivots = accountFindings
          .filter(f => f.id !== entry.id && f.id !== target.id)
          .slice(0, 2);

        const chain = [entry, ...pivots, target];
        const pathScore = chain.reduce((sum, f) => sum + (SEVERITY_SCORE[f.severity] ?? 0), 0);

        paths.push({
          id: `ap-${pad(paths.length + 1)}`,
          name: `${entry.resource_name} → ${target.resource_name}`,
          description: `Attack path from ${entry.category.toLowerCase()} entry point through ${pivots.length} pivot(s) to ${target.resource_type} target`,
          severity: pathScore > 200 ? 'CRITICAL' : pathScore > 100 ? 'HIGH' : 'MEDIUM',
          score: pathScore,
          finding_ids: chain.map(f => f.id),
          nodes: chain.map(f => ({
            finding_id: f.id,
            resource_id: f.resource_id,
            resource_name: f.resource_name,
            resource_type: f.resource_type,
            severity: f.severity,
            role: f === entry ? 'entry' : f === target ? 'target' : 'pivot',
          })),
          account_id: accountId,
          cloud_provider: entry.cloud_provider,
          environment: entry.environment_type,
        });

        if (paths.length >= 500) break;
      }
      if (paths.length >= 500) break;
    }
    if (paths.length >= 500) break;
  }

  log(`Computed ${paths.length} attack paths`);
  return paths;
}

// ── Phase 7: Output ──────────────────────────────────────────────────────────

async function writeOutput(findings, attackPaths) {
  // findings.json — use streaming writer for large datasets
  const findingsPath = join(OUT_DIR, 'findings.json');
  if (findings.length > 50000) {
    await writeJSONArrayStreaming(findingsPath, findings);
  } else {
    writeFileSync(findingsPath, JSON.stringify(findings));
  }
  const fSize = (readFileSync(findingsPath).length / 1024 / 1024).toFixed(1);
  log(`Wrote ${findings.length} findings to ${findingsPath} (${fSize} MB)`);

  // attack-paths.json
  const attackPathsPath = join(OUT_DIR, 'attack-paths.json');
  writeFileSync(attackPathsPath, JSON.stringify(attackPaths, null, 2));
  log(`Wrote ${attackPaths.length} attack paths to ${attackPathsPath}`);

  // resources.json — unique resources
  const resourceMap = new Map();
  for (const f of findings) {
    if (!resourceMap.has(f.resource_id)) {
      resourceMap.set(f.resource_id, {
        resource_id: f.resource_id,
        resource_name: f.resource_name,
        resource_type: f.resource_type,
        resource_arn: f.resource_arn,
        cloud_provider: f.cloud_provider,
        account_id: f.account_id,
        account_name: f.account_name,
        region: f.region,
        environment_type: f.environment_type,
        finding_count: 0,
        critical_count: 0,
        high_count: 0,
      });
    }
    const r = resourceMap.get(f.resource_id);
    r.finding_count++;
    if (f.severity === 'CRITICAL') r.critical_count++;
    if (f.severity === 'HIGH') r.high_count++;
  }
  const resources = [...resourceMap.values()];
  const resourcesPath = join(OUT_DIR, 'resources.json');
  if (resources.length > 50000) {
    await writeJSONArrayStreaming(resourcesPath, resources);
  } else {
    writeFileSync(resourcesPath, JSON.stringify(resources));
  }
  log(`Wrote ${resources.length} resources to ${resourcesPath}`);

  // accounts.json
  const accountMap = new Map();
  for (const f of findings) {
    if (!accountMap.has(f.account_id)) {
      accountMap.set(f.account_id, {
        account_id: f.account_id,
        account_name: f.account_name,
        cloud_provider: f.cloud_provider,
        region: f.region,
        environment_type: f.environment_type,
        finding_count: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
      });
    }
    const a = accountMap.get(f.account_id);
    a.finding_count++;
    if (f.severity === 'CRITICAL') a.critical_count++;
    else if (f.severity === 'HIGH') a.high_count++;
    else if (f.severity === 'MEDIUM') a.medium_count++;
    else a.low_count++;
  }
  const accounts = [...accountMap.values()];
  const accountsPath = join(OUT_DIR, 'accounts.json');
  writeFileSync(accountsPath, JSON.stringify(accounts, null, 2));
  log(`Wrote ${accounts.length} accounts to ${accountsPath}`);

  // tickets.json
  const tickets = findings.filter(f => f.ticket_id).map(f => ({
    ticket_id: f.ticket_id,
    ticket_url: f.ticket_url,
    finding_id: f.id,
    severity: f.severity,
    title: f.title,
    status: f.status === 'resolved' ? 'closed' : f.status === 'in_progress' ? 'in_progress' : 'open',
    assignee: f.assignee?.user_name,
    created_at: f.first_found_at,
  }));
  const ticketsPath = join(OUT_DIR, 'tickets.json');
  writeFileSync(ticketsPath, JSON.stringify(tickets, null, 2));
  log(`Wrote ${tickets.length} tickets to ${ticketsPath}`);

  // stats.json — pre-computed KPI data with delta indicators
  const stats = computeStats(findings);
  const statsPath = join(OUT_DIR, 'stats.json');
  writeFileSync(statsPath, JSON.stringify(stats, null, 2));
  log(`Wrote stats to ${statsPath}`);

  // Stats summary
  printStats(findings);

  // Frontend subset
  if (WRITE_FRONTEND) {
    const frontendDir = 'frontend/public/mock';
    mkdirSync(frontendDir, { recursive: true });
    const subset = findings.slice(0, 500);
    const frontendPath = join(frontendDir, 'findings.json');
    writeFileSync(frontendPath, JSON.stringify(subset));
    log(`Wrote 500-finding frontend subset to ${frontendPath}`);
  }
}

function computeStats(findings) {
  const total = findings.length;
  const NOW = new Date('2026-03-24T08:00:00Z');
  const H24_AGO = new Date(NOW.getTime() - 24 * 60 * 60 * 1000);
  const D7_AGO = new Date(NOW.getTime() - 7 * 24 * 60 * 60 * 1000);

  const bySev = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  const byProvider = { aws: 0, azure: 0, gcp: 0 };
  const byStatus = {};
  const byCategory = {};
  let slaBreached = 0;
  let autoRem = 0;
  let active = 0;

  // Delta counters: findings first_found_at within 24h/7d windows
  let new24h = 0;
  let new7d = 0;
  let resolved24h = 0;
  let resolved7d = 0;

  for (const f of findings) {
    bySev[f.severity] = (bySev[f.severity] ?? 0) + 1;
    byProvider[f.cloud_provider] = (byProvider[f.cloud_provider] ?? 0) + 1;
    byStatus[f.status] = (byStatus[f.status] ?? 0) + 1;
    byCategory[f.category] = (byCategory[f.category] ?? 0) + 1;
    if (f.sla_breach_date) slaBreached++;
    if (f.auto_remediatable) autoRem++;
    if (['open', 'in_progress'].includes(f.status)) active++;

    const firstFound = new Date(f.first_found_at);
    if (firstFound >= H24_AGO) new24h++;
    if (firstFound >= D7_AGO) new7d++;
    if (f.resolved_at) {
      const resolved = new Date(f.resolved_at);
      if (resolved >= H24_AGO) resolved24h++;
      if (resolved >= D7_AGO) resolved7d++;
    }
  }

  // Add jitter to deltas so they look organic
  const jitter = (base) => {
    const pct = 0.05 + rand() * 0.08;
    const sign = rand() < 0.5 ? -1 : 1;
    return base + Math.round(base * pct * sign);
  };

  return {
    total,
    active,
    inactive: total - active,
    severity: bySev,
    provider: byProvider,
    status: byStatus,
    category: byCategory,
    sla_breached: slaBreached,
    auto_remediatable: autoRem,
    compliance_mapped: findings.filter(f => f.compliance_mappings?.length > 0).length,
    // Delta indicators for KPI cards
    delta_24h: {
      new_findings: jitter(new24h) || Math.round(total * 0.002),
      resolved_findings: jitter(resolved24h) || Math.round(total * 0.001),
      net: jitter(new24h - resolved24h) || Math.round(total * 0.001),
    },
    delta_7d: {
      new_findings: jitter(new7d) || Math.round(total * 0.015),
      resolved_findings: jitter(resolved7d) || Math.round(total * 0.008),
      net: jitter(new7d - resolved7d) || Math.round(total * 0.007),
    },
    // Top-level KPI card values
    kpi: {
      total_findings: total,
      critical_findings: bySev.CRITICAL,
      high_findings: bySev.HIGH,
      sla_breached: slaBreached,
      auto_remediatable: autoRem,
      mean_time_to_remediate_hours: Math.round(72 + rand() * 48),
      compliance_score: +(70 + rand() * 12).toFixed(1),
    },
    generated_at: NOW.toISOString(),
  };
}

function printStats(findings) {
  const total = findings.length;
  const bySev = {};
  const byStatus = {};
  const byProvider = {};
  const byType = {};
  let withCompliance = 0;
  let active = 0;

  for (const f of findings) {
    bySev[f.severity] = (bySev[f.severity] ?? 0) + 1;
    byStatus[f.status] = (byStatus[f.status] ?? 0) + 1;
    byProvider[f.cloud_provider] = (byProvider[f.cloud_provider] ?? 0) + 1;
    byType[f.type] = (byType[f.type] ?? 0) + 1;
    if (f.compliance_mappings?.length > 0) withCompliance++;
    if (['open', 'in_progress'].includes(f.status)) active++;
  }

  log(`\n── Stats ──────────────────────────────────`);
  log(`  Total:     ${total}`);
  log(`  Severity:  ${Object.entries(bySev).map(([k,v]) => `${k}=${v} (${(v/total*100).toFixed(1)}%)`).join(', ')}`);
  log(`  Status:    ${Object.entries(byStatus).map(([k,v]) => `${k}=${v}`).join(', ')}`);
  log(`  Provider:  ${Object.entries(byProvider).map(([k,v]) => `${k}=${v} (${(v/total*100).toFixed(1)}%)`).join(', ')}`);
  log(`  Type:      ${Object.entries(byType).map(([k,v]) => `${k}=${v}`).join(', ')}`);
  log(`  Compliance mappings: ${withCompliance}/${total} (${(withCompliance/total*100).toFixed(1)}%)`);
  log(`  Active:    ${active}/${total} (${(active/total*100).toFixed(1)}%)`);
  log(`  IDs:       ${findings[0]?.id} ... ${findings[findings.length-1]?.id}`);
  log(`───────────────────────────────────────────\n`);
}

// ── Main Pipeline ────────────────────────────────────────────────────────────

log(`aegis-seed: target=${TARGET_COUNT}, out=${OUT_DIR}, full=${FULL_MODE}, seed=${SEED}`);

log('\nPhase 1: Collecting sources...');
const rawFindings = collectSources();
log(`Total raw: ${rawFindings.length}`);

log('\nPhase 2: Deduplicating...');
const unique = dedup(rawFindings);

log('\nPhase 3: Assigning taxonomy + sanitizing...');
const taxonomized = assignTaxonomy(unique);

log('\nPhase 4: Padding to target count...');
const padded = generateSynthetic(taxonomized, TARGET_COUNT);

log('\nPhase 5: Enriching...');
const enriched = enrichFindings(padded);

log('\nPhase 6: Adding impacted resources + attack paths...');
addImpactedResources(enriched);
const attackPaths = computeAttackPaths(enriched);

log('\nPhase 7: Writing output...');
await writeOutput(enriched, attackPaths);

log('Done.');
