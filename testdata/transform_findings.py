#!/usr/bin/env python3
"""Transform scrubbed multi-cloud findings exports into CloudForge Finding schema.

Reads:
  - AWS:   testdata/export-scripts/output/scrubbed/scrubbed_aws_all_findings_*.csv
  - Azure: testdata/export-scripts/output/scrubbed/scrubbed_azure_all_findings_*.json
  - GCP:   testdata/export-scripts/output/gcp_all_findings_*.json (raw — scrubbed here)

Outputs:
  - frontend/src/lib/mock/findings.json

Usage:
    python testdata/transform_findings.py --dry-run
    python testdata/transform_findings.py --execute
"""

import argparse
import csv
import hashlib
import json
import random
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
INPUT_DIR = SCRIPT_DIR / "export-scripts" / "output"
SCRUBBED_DIR = INPUT_DIR / "scrubbed"
OUTPUT_PATH = PROJECT_ROOT / "frontend" / "src" / "lib" / "mock" / "findings.json"

# Sampling targets
AWS_SAMPLE = 120
GCP_SAMPLE = 80

# Seed for reproducible sampling
SEED = 42

# --- Resource type mapping ---

AWS_RESOURCE_TYPE_MAP = {
    "EC2": "compute", "ECS": "container", "EKS": "container",
    "Lambda": "serverless", "S3": "storage", "RDS": "database",
    "DynamoDB": "database", "Redshift": "database", "Neptune": "database",
    "ElastiCache": "database", "IAM": "identity", "KMS": "encryption",
    "SecretsManager": "secret", "SSM": "compute", "VPC": "network",
    "SecurityGroup": "network", "CloudFront": "network", "ELB": "network",
    "ALB": "network", "WAF": "network", "GuardDuty": "compute",
    "Config": "compute", "CloudTrail": "logging", "SageMaker": "compute",
    "APIGateway": "network", "SNS": "messaging", "SQS": "messaging",
    "EFS": "storage", "Backup": "storage", "DMS": "database",
    "Opensearch": "database", "ES": "database", "CloudFormation": "compute",
    "AutoScaling": "compute", "CodeBuild": "compute",
}

AZURE_RESOURCE_TYPE_MAP = {
    "microsoft.compute/virtualmachines": "compute",
    "microsoft.storage/storageaccounts": "storage",
    "acr.containerimage": "container",
    "microsoft.containerregistry/registries": "container",
    "microsoft.cognitiveservices/accounts": "compute",
    "microsoft.keyvault/vaults": "secret",
    "microsoft.search/searchservices": "database",
    "microsoft.security/azureiamuser": "identity",
    "microsoft.security/azureiamserviceprincipal": "identity",
    "microsoft.network/virtualnetworks": "network",
    "microsoft.network/applicationgateways": "network",
    "subscription": "identity",
}

GCP_RESOURCE_TYPE_MAP = {
    "COMPUTE": "compute", "STORAGE": "storage", "DATABASE": "database",
    "NETWORK": "network", "IAM": "identity", "KMS": "encryption",
    "CONTAINER": "container", "SERVERLESS": "serverless",
}

# --- Category mapping ---

AWS_CATEGORY_MAP = {
    "Software and Configuration Checks": "MISCONFIGURATION",
    "TTPs": "VULNERABILITY",
    "Effects": "VULNERABILITY",
    "Unusual Behaviors": "IDENTITY",
    "Sensitive Data Identifications": "DATA_SECURITY",
}

AZURE_CATEGORY_MAP = {
    '["Compute"]': "MISCONFIGURATION",
    '["Data"]': "DATA_SECURITY",
    '["IdentityAndAccess"]': "IDENTITY",
    '["Networking"]': "NETWORK",
    '["Container"]': "MISCONFIGURATION",
}

GCP_FINDING_CLASS_MAP = {
    "MISCONFIGURATION": "MISCONFIGURATION",
    "THREAT": "VULNERABILITY",
    "VULNERABILITY": "VULNERABILITY",
    "TOXIC_COMBINATION": "VULNERABILITY",
    "OBSERVATION": "MISCONFIGURATION",
    "CHOKEPOINT": "NETWORK",
}

# --- MITRE mapping for common finding types ---

MITRE_TACTIC_MAP = {
    "NETWORK": ["TA0001"],  # Initial Access
    "VULNERABILITY": ["TA0002", "TA0008"],  # Execution, Lateral Movement
    "IDENTITY": ["TA0003", "TA0004"],  # Persistence, Privilege Escalation
    "MISCONFIGURATION": ["TA0005"],  # Defense Evasion
    "DATA_SECURITY": ["TA0009", "TA0010"],  # Collection, Exfiltration
}

MITRE_TECHNIQUE_MAP = {
    "NETWORK": ["T1190"],  # Exploit Public-Facing Application
    "VULNERABILITY": ["T1203", "T1210"],  # Exploitation for Client/Remote
    "IDENTITY": ["T1078", "T1098"],  # Valid Accounts, Account Manipulation
    "MISCONFIGURATION": ["T1562"],  # Impair Defenses
    "DATA_SECURITY": ["T1530"],  # Data from Cloud Storage
}

# --- Compliance framework templates ---

COMPLIANCE_FRAMEWORKS = [
    {"framework_id": "cis-aws", "framework_name": "CIS AWS Foundations", "section": ""},
    {"framework_id": "cis-azure", "framework_name": "CIS Azure Foundations", "section": ""},
    {"framework_id": "cis-gcp", "framework_name": "CIS GCP Foundations", "section": ""},
    {"framework_id": "nist-800-53", "framework_name": "NIST 800-53 Rev 5", "section": ""},
    {"framework_id": "soc2", "framework_name": "SOC 2 Type II", "section": ""},
    {"framework_id": "hipaa", "framework_name": "HIPAA", "section": ""},
    {"framework_id": "pci-dss", "framework_name": "PCI DSS 4.0", "section": ""},
]

# --- GCP PII scrub patterns ---

GCP_PROJECT_SCRUB: dict[str, str] = {}
GCP_PROJECT_COUNTER = 0


def _pick_env_type(rng: random.Random) -> str:
    """Weighted random environment type."""
    r = rng.random()
    cumulative = 0.0
    for env, weight in ENV_TYPE_WEIGHTS.items():
        cumulative += weight
        if r < cumulative:
            return env
    return "production"


def scrub_gcp_value(val: str) -> str:
    """Replace GCP project names/IDs with contoso equivalents."""
    global GCP_PROJECT_COUNTER
    # Replace project IDs (numeric)
    def replace_project_id(m: re.Match) -> str:
        global GCP_PROJECT_COUNTER
        original = m.group(0)
        if original not in GCP_PROJECT_SCRUB:
            GCP_PROJECT_COUNTER += 1
            GCP_PROJECT_SCRUB[original] = f"contoso-gcp-project-{GCP_PROJECT_COUNTER:03d}"
        return GCP_PROJECT_SCRUB[original]

    val = re.sub(r"projects/(\d{12,})", lambda m: f"projects/{replace_project_id(m)}", val)
    val = re.sub(r"organizations/\d+", "organizations/000000000000", val)
    # Replace docker registry paths
    val = re.sub(r"[\w.-]+-docker\.pkg\.dev/[\w.-]+", "contoso-docker.pkg.dev/contoso-project", val)
    # Replace GKE cluster references
    val = re.sub(r"gk[es][\w-]+", "contoso-gke-cluster", val)
    return val


# --- Enrichment helpers ---

def ai_risk_score(severity: str, env_type: str, category: str) -> float:
    """Deterministic AI risk score from severity + environment + category."""
    base = {"CRITICAL": 9.0, "HIGH": 7.0, "MEDIUM": 4.5, "LOW": 2.0, "INFORMATIONAL": 1.0}
    score = base.get(severity, 3.0)
    if "prod" in env_type.lower():
        score += 1.0
    if category in ("VULNERABILITY", "NETWORK"):
        score += 0.5
    return round(min(score + random.uniform(-0.5, 0.5), 10.0), 2)


def ai_risk_level(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def make_dedup_key(source: str, source_id: str) -> str:
    return hashlib.sha256(f"{source}:{source_id}".encode()).hexdigest()[:12]


def make_due_date(severity: str, first_found: str) -> str:
    """SLA-based due date from severity."""
    sla_days = {"CRITICAL": 7, "HIGH": 30, "MEDIUM": 90, "LOW": 180, "INFORMATIONAL": 365}
    try:
        dt = datetime.fromisoformat(first_found.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        dt = datetime.now()
    delta = timedelta(days=sla_days.get(severity, 90))
    return (dt + delta).strftime("%Y-%m-%dT%H:%M:%SZ")


def pick_status(rng: random.Random) -> tuple[str, str]:
    """Weighted random status + workflow_status."""
    r = rng.random()
    if r < 0.55:
        return "open", rng.choice(["new", "triaged"])
    if r < 0.80:
        return "in_progress", "assigned"
    if r < 0.95:
        return "resolved", "resolved"
    return "suppressed", "suppressed"


def pick_workload_context(resource_type: str, rng: random.Random) -> tuple[str, str]:
    """Pick a service name and LOB based on resource type for realistic context."""
    # Map resource types to likely workload groups
    type_affinity = {
        "compute": ["external", "internal", "data"],
        "container": ["external", "data", "payment"],
        "serverless": ["external", "messaging", "data"],
        "storage": ["storage", "data"],
        "database": ["database", "data", "payment"],
        "network": ["external", "internal"],
        "identity": ["internal"],
        "encryption": ["internal", "payment"],
        "secret": ["internal", "payment"],
        "logging": ["internal"],
        "messaging": ["messaging"],
    }
    groups = type_affinity.get(resource_type, ["internal", "external"])
    group = rng.choice(groups)
    service = rng.choice(WORKLOADS.get(group, WORKLOADS["internal"]))
    lob = rng.choice(LOB_NAMES)
    return service, lob


def pick_resource_name(resource_type: str, service: str, env: str, idx: int, rng: random.Random) -> str:
    """Generate realistic resource names reflecting workload patterns."""
    env_short = {"production": "prd", "staging": "stg", "development": "dev", "infrastructure": "infra"}.get(env, "dev")
    region_short = rng.choice(["ue1", "uw2", "ew1", "ec1", "ase1"])
    svc_short = service.split("-")[0][:6]
    patterns = [
        f"{svc_short}-{env_short}-{region_short}-{idx:03d}",
        f"{svc_short}-{env_short}-{idx:03d}",
        f"contoso-{resource_type}-{env_short}-{rng.randint(1, 999):03d}",
        f"{svc_short}-{rng.choice(['blue', 'green', 'canary'])}-{env_short}",
    ]
    return rng.choice(patterns)


def make_compliance_mappings(
    category: str, provider: str, control_id: str, rng: random.Random
) -> list[dict[str, str]]:
    """Generate 1-3 compliance mappings based on finding context."""
    provider_fw = {"aws": "cis-aws", "azure": "cis-azure", "gcp": "cis-gcp"}
    mappings = []
    fw = next((f for f in COMPLIANCE_FRAMEWORKS if f["framework_id"] == provider_fw.get(provider)), None)
    if fw:
        mappings.append({
            "framework_id": fw["framework_id"],
            "framework_name": fw["framework_name"],
            "control_id": control_id or f"{fw['framework_id']}.{rng.randint(1, 9)}.{rng.randint(1, 12)}",
            "control_title": f"Control for {category.lower().replace('_', ' ')}",
            "section": f"Section {rng.randint(1, 8)}",
            "severity": category.lower(),
            "url": "",
        })
    # Add 1-2 cross-framework mappings
    extras = rng.sample(
        [f for f in COMPLIANCE_FRAMEWORKS if f["framework_id"] not in provider_fw.values()],
        k=min(rng.randint(1, 2), 4),
    )
    for ef in extras:
        mappings.append({
            "framework_id": ef["framework_id"],
            "framework_name": ef["framework_name"],
            "control_id": f"{ef['framework_id'].split('-')[0].upper()}.{rng.randint(1, 9)}.{rng.randint(1, 20)}",
            "control_title": f"Control for {category.lower().replace('_', ' ')}",
            "section": f"Section {rng.randint(1, 10)}",
            "severity": "medium",
            "url": "",
        })
    return mappings


# Workload taxonomy — modeled after FPFN sector patterns
# (automotive, education, energy, financial, healthcare, retail, saas, government)
WORKLOADS = {
    # Internal-facing
    "internal": [
        "identity-broker", "config-manager", "audit-logger", "vault-proxy",
        "secrets-rotator", "policy-engine", "compliance-scanner", "cert-manager",
        "ldap-sync", "sso-gateway", "internal-wiki", "hr-portal",
    ],
    # External-facing web/API
    "external": [
        "web-frontend", "api-gateway", "cdn-edge", "customer-portal",
        "mobile-bff", "public-api", "webhook-receiver", "oauth-server",
        "graphql-gateway", "partner-api",
    ],
    # Data platforms
    "data": [
        "data-pipeline", "etl-worker", "data-lake-ingestion", "analytics-engine",
        "ml-inference", "ml-training", "feature-store", "data-catalog",
        "stream-processor", "batch-aggregator", "dbt-runner",
    ],
    # Payment / financial
    "payment": [
        "payment-gateway", "billing-service", "invoice-processor",
        "fraud-detector", "ledger-service", "reconciliation-engine",
        "payout-service", "subscription-manager",
    ],
    # Storage / media
    "storage": [
        "file-storage", "video-transcoder", "media-cdn", "backup-agent",
        "archive-mover", "document-service", "image-optimizer",
        "asset-pipeline", "object-replicator",
    ],
    # Database / search
    "database": [
        "search-service", "cache-cluster", "db-proxy", "read-replica-mgr",
        "migration-runner", "index-builder", "graph-db-service",
    ],
    # Messaging / eventing
    "messaging": [
        "notification-service", "event-bus", "queue-worker",
        "email-sender", "sms-gateway", "push-service",
    ],
}

# Flat service names derived from workloads
SERVICE_NAMES = [svc for group in WORKLOADS.values() for svc in group]

LOB_NAMES = [
    "platform", "data-engineering", "ml-ops", "security",
    "devops", "product", "finops", "compliance",
    "infrastructure", "commerce", "media", "analytics",
]

# Identity patterns — human vs non-human (service accounts)
IDENTITY_TYPES = {
    "human": {
        "weight": 0.25,
        "patterns": [
            "admin1@contoso.dev", "operator1@contoso.dev", "operator2@contoso.dev",
            "user1@contoso.dev", "user2@contoso.dev", "sre-lead@contoso.dev",
            "platform-eng@contoso.dev", "security-analyst@contoso.dev",
        ],
    },
    "service_account": {
        "weight": 0.50,
        "patterns": [
            "svc-deploy@contoso.dev", "svc-monitoring@contoso.dev",
            "svc-backup@contoso.dev", "svc-cicd@contoso.dev",
            "svc-data-pipeline@contoso.dev", "svc-terraform@contoso.dev",
            "svc-vault@contoso.dev", "svc-k8s-operator@contoso.dev",
        ],
    },
    "machine_identity": {
        "weight": 0.25,
        "patterns": [
            "arn:aws:iam::123456789012:role/deploy-role",
            "arn:aws:iam::123456789012:role/lambda-exec",
            "arn:aws:iam::123456789012:role/ecs-task-role",
            "system:serviceaccount:kube-system:default",
            "projects/contoso/serviceAccounts/compute@developer.gserviceaccount.com",
        ],
    },
}

# Realistic multi-region distribution
AWS_REGIONS = [
    "us-east-1", "us-west-2", "eu-west-1", "eu-central-1",
    "ap-southeast-1", "ap-northeast-1", "ca-central-1", "sa-east-1",
]
AZURE_REGIONS = [
    "eastus", "westus2", "westeurope", "northeurope",
    "southeastasia", "japaneast", "canadacentral", "brazilsouth",
]
GCP_REGIONS = [
    "us-central1", "us-east1", "europe-west1", "europe-west4",
    "asia-southeast1", "asia-northeast1", "northamerica-northeast1",
]

# Account name templates for realistic enterprise patterns
ACCOUNT_TEMPLATES = {
    "aws": {
        "prod": [
            "contoso-{lob}-prd", "contoso-{lob}-prod-{region_short}",
            "contoso-shared-services", "contoso-network-hub",
        ],
        "staging": ["contoso-{lob}-stg", "contoso-{lob}-uat"],
        "dev": ["contoso-{lob}-dev", "contoso-{lob}-sandbox"],
        "infra": ["contoso-iac", "contoso-logging", "contoso-security-tooling"],
    },
    "azure": {
        "prod": ["contoso-web", "contoso-ai-prod", "contoso-data-prod"],
        "dev": ["contoso-web-dev", "contoso-ai-dev", "contoso-data-dev"],
    },
    "gcp": {
        "prod": [
            "contoso-analytics-prod", "contoso-ml-prod", "contoso-data-prod",
        ],
        "dev": [
            "contoso-analytics-dev", "contoso-ml-dev", "contoso-data-dev",
            "contoso-sandbox-{n}",
        ],
    },
}

REGION_SHORT = {
    "us-east-1": "ue1", "us-west-2": "uw2", "eu-west-1": "ew1",
    "eu-central-1": "ec1", "ap-southeast-1": "ase1", "ap-northeast-1": "ane1",
}

ENV_TYPE_WEIGHTS = {
    "production": 0.45, "staging": 0.20, "development": 0.25, "infrastructure": 0.10,
}


# --- Provider parsers ---

def extract_aws_resource_type(title: str) -> str:
    """Derive resource_type from AWS finding title prefix."""
    for prefix, rtype in AWS_RESOURCE_TYPE_MAP.items():
        if title.startswith(prefix) or f" {prefix}" in title[:30]:
            return rtype
    t = title.lower()
    if any(k in t for k in ["instance", "ec2", "ssm"]):
        return "compute"
    if any(k in t for k in ["bucket", "s3"]):
        return "storage"
    if any(k in t for k in ["security group", "vpc", "network"]):
        return "network"
    if any(k in t for k in ["rds", "database", "db"]):
        return "database"
    if any(k in t for k in ["iam", "role", "user", "access"]):
        return "identity"
    return "compute"


def parse_aws_csv(path: Path, sample_n: int, rng: random.Random) -> list[dict[str, Any]]:
    """Parse scrubbed AWS SecurityHub CSV and sample findings."""
    findings: list[dict[str, Any]] = []
    rows_by_severity: dict[str, list[dict]] = {
        "CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFORMATIONAL": [],
    }

    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            sev = row.get("Severity.Label", "").upper()
            if sev in rows_by_severity:
                rows_by_severity[sev].append(row)

    # Stratified sampling
    targets = {"CRITICAL": 8, "HIGH": 40, "MEDIUM": 40, "LOW": 20, "INFORMATIONAL": 12}
    sampled: list[dict] = []
    for sev, target in targets.items():
        pool = rows_by_severity[sev]
        n = min(target, len(pool))
        sampled.extend(rng.sample(pool, n))

    for idx, row in enumerate(sampled):
        severity = row.get("Severity.Label", "MEDIUM").upper()
        title = row.get("Title", "Unknown Finding")
        resource_type = extract_aws_resource_type(title)
        acct_id = row.get("AwsAccountId", "100000000000")
        acct_name = row.get("_AccountName", f"contoso-aws-{acct_id[-3:]}")
        acct_env = row.get("_AccountEnvironment", "Production")
        region = row.get("Region", "us-east-1")
        control_id = row.get("Compliance.SecurityControlId", "")
        category = "MISCONFIGURATION"
        types_str = row.get("Types", "")
        for pattern, cat in AWS_CATEGORY_MAP.items():
            if pattern in types_str:
                category = cat
                break

        first_found = row.get("FirstObservedAt", row.get("CreatedAt", ""))
        last_seen = row.get("LastObservedAt", row.get("UpdatedAt", ""))

        # Enrich with realistic region/env diversity
        region = rng.choice(AWS_REGIONS) if rng.random() < 0.6 else region
        # Normalize environment — map HAEA-specific values to standard types
        raw_env = (acct_env or "").lower()
        env_map = {
            "production": "production", "staging": "staging", "development": "development",
            "infrastructure": "infrastructure", "shared services": "production",
            "dr": "production", "discovered": "development", "qa": "staging",
        }
        env_type = env_map.get(raw_env, _pick_env_type(rng))
        # Generate realistic account name from template
        lob = rng.choice(LOB_NAMES)
        env_bucket = "prod" if "prod" in env_type else ("staging" if "stag" in env_type else "dev")
        templates = ACCOUNT_TEMPLATES["aws"].get(env_bucket, ACCOUNT_TEMPLATES["aws"]["dev"])
        acct_name_enriched = rng.choice(templates).format(
            lob=lob, region_short=REGION_SHORT.get(region, "ue1"), n=rng.randint(1, 5),
        )

        service, lob = pick_workload_context(resource_type, rng)
        res_name = pick_resource_name(resource_type, service, env_type, idx + 1, rng)

        score = ai_risk_score(severity, env_type, category)
        status, wf_status = pick_status(rng)

        finding_id = f"f-aws-{idx + 1:04d}"
        source_id = row.get("Id", finding_id)
        # Sanitize source_id — replace any remaining real account IDs
        source_id = re.sub(r"\d{12}", acct_id, source_id)

        findings.append({
            "id": finding_id,
            "source": "aws-security-hub",
            "source_finding_id": source_id,
            "type": "vulnerability" if category == "VULNERABILITY" else "misconfiguration",
            "title": title,
            "description": row.get("Description", "")[:500],
            "resource_type": resource_type,
            "resource_id": f"{resource_type}-{make_dedup_key('aws', source_id)[:8]}",
            "resource_name": res_name,
            "resource_arn": f"arn:aws::::{acct_id}:{resource_type}/{res_name}",
            "platform": "cloud",
            "cloud_provider": "aws",
            "region": region,
            "account_id": acct_id,
            "account_name": acct_name_enriched,
            "environment_type": env_type,
            "static_severity": severity,
            "severity": severity,
            "ai_risk_score": score,
            "ai_risk_level": ai_risk_level(score),
            "ai_risk_rationale": f"{severity} finding in {acct_env.lower()} environment. Category: {category}.",
            "ai_contextual_factors": [resource_type, acct_env.lower()],
            "cvss": None,
            "cvss_vector": "",
            "epss": None,
            "exploit_available": category == "VULNERABILITY" and rng.random() < 0.3,
            "cves": [],
            "mitre_tactics": MITRE_TACTIC_MAP.get(category, ["TA0005"]),
            "mitre_techniques": MITRE_TECHNIQUE_MAP.get(category, ["T1562"]),
            "compliance_mappings": make_compliance_mappings(category, "aws", control_id, rng),
            "remediation": row.get("Remediation.Recommendation.Text", "Consult provider documentation."),
            "auto_remediatable": rng.random() < 0.3,
            "category": category,
            "status": status,
            "workflow_status": wf_status,
            "suppressed": status == "suppressed",
            "service_name": service,
            "line_of_business": lob,
            "first_found_at": first_found,
            "last_seen_at": last_seen,
            "due_date": make_due_date(severity, first_found),
            "deduplication_key": make_dedup_key("aws", source_id),
            "canonical_rule_id": control_id or title.split(" ")[0],
        })

    return findings


def parse_azure_json(path: Path, rng: random.Random) -> list[dict[str, Any]]:
    """Parse scrubbed Azure Defender JSON (all records)."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings: list[dict[str, Any]] = []
    for idx, item in enumerate(data):
        severity = (item.get("severity", "Medium")).upper()
        title = item.get("displayName", "Unknown Assessment")
        raw_rt = item.get("resourceType", "subscription")
        resource_type = AZURE_RESOURCE_TYPE_MAP.get(raw_rt, "compute")
        sub_id = item.get("subscriptionId", "a0000000-0000-4000-8000-000000000000")
        sub_name = item.get("subscriptionName", "contoso-default")
        resource_name = item.get("resourceName", f"azure-resource-{idx}")
        resource_group = item.get("resourceGroup", "contoso-rg")
        categories = item.get("categories", "")
        category = AZURE_CATEGORY_MAP.get(categories, "MISCONFIGURATION")

        first_found = item.get("firstEvaluationDate", "")
        last_seen = item.get("statusChangeDate", "")

        # Strip HTML from remediation
        remediation = re.sub(r"<[^>]+>", " ", item.get("remediationDescription", ""))
        remediation = re.sub(r"\s+", " ", remediation).strip()[:500]

        service, lob = pick_workload_context(resource_type, rng)
        env_type = "development" if "dev" in sub_name.lower() else "production"
        res_name = pick_resource_name(resource_type, service, env_type, idx + 1, rng)

        score = ai_risk_score(severity, sub_name, category)
        status, wf_status = pick_status(rng)

        finding_id = f"f-az-{idx + 1:04d}"
        source_id = item.get("id", finding_id)

        findings.append({
            "id": finding_id,
            "source": "azure-defender",
            "source_finding_id": source_id,
            "type": "vulnerability" if category == "VULNERABILITY" else "misconfiguration",
            "title": title,
            "description": item.get("description", "")[:500],
            "resource_type": resource_type,
            "resource_id": f"{resource_group}/{res_name}",
            "resource_name": res_name,
            "platform": "cloud",
            "cloud_provider": "azure",
            "region": rng.choice(AZURE_REGIONS),
            "account_id": sub_id,
            "account_name": sub_name,
            "environment_type": env_type,
            "static_severity": severity,
            "severity": severity,
            "ai_risk_score": score,
            "ai_risk_level": ai_risk_level(score),
            "ai_risk_rationale": f"{severity} finding in Azure subscription {sub_name}. Category: {category}.",
            "ai_contextual_factors": [resource_type, categories],
            "cvss": None,
            "cvss_vector": "",
            "epss": None,
            "exploit_available": False,
            "cves": [],
            "mitre_tactics": MITRE_TACTIC_MAP.get(category, ["TA0005"]),
            "mitre_techniques": MITRE_TECHNIQUE_MAP.get(category, ["T1562"]),
            "compliance_mappings": make_compliance_mappings(category, "azure", "", rng),
            "remediation": remediation or "Consult Azure Defender recommendations.",
            "auto_remediatable": rng.random() < 0.2,
            "category": category,
            "status": status,
            "workflow_status": wf_status,
            "suppressed": status == "suppressed",
            "service_name": service,
            "line_of_business": lob,
            "first_found_at": first_found,
            "last_seen_at": last_seen,
            "due_date": make_due_date(severity, first_found),
            "deduplication_key": make_dedup_key("azure", source_id),
            "canonical_rule_id": item.get("assessmentKey", ""),
        })

    return findings


def parse_gcp_json(path: Path, sample_n: int, rng: random.Random) -> list[dict[str, Any]]:
    """Parse raw GCP SCC JSON, apply PII scrub, sample findings."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Stratified sampling by severity
    by_severity: dict[str, list[dict]] = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for item in data:
        sev = item.get("severity", "LOW").upper()
        if sev in by_severity:
            by_severity[sev].append(item)

    targets = {"CRITICAL": 8, "HIGH": 30, "MEDIUM": 25, "LOW": 17}
    sampled: list[dict] = []
    for sev, target in targets.items():
        pool = by_severity[sev]
        n = min(target, len(pool))
        sampled.extend(rng.sample(pool, n))

    findings: list[dict[str, Any]] = []
    for idx, item in enumerate(sampled):
        severity = item.get("severity", "LOW").upper()
        category_raw = item.get("finding.category", item.get("category", "UNKNOWN"))
        finding_class = item.get("finding.findingClass", "MISCONFIGURATION")
        category = GCP_FINDING_CLASS_MAP.get(finding_class, "MISCONFIGURATION")

        description = item.get("finding.description", category_raw)
        title = category_raw
        if len(title) > 80:
            title = title[:77] + "..."

        # Scrub project/org references
        project_name = item.get("resource.projectDisplayName",
                                item.get("projectDisplayName", f"contoso-gcp-{idx:03d}"))
        project_name = scrub_gcp_value(project_name)

        project_id = item.get("resource.projectName", item.get("resource.project", ""))
        if project_id:
            project_id = scrub_gcp_value(project_id)

        first_found = item.get("finding.createTime", "")
        last_seen = item.get("finding.eventTime", first_found)

        # Extract MITRE from finding if present
        mitre = item.get("finding.mitreAttack", {})
        mitre_tactics_raw = []
        mitre_techniques_raw = []
        if isinstance(mitre, dict):
            if mitre.get("primaryTactic"):
                mitre_tactics_raw.append(mitre["primaryTactic"])
            mitre_tactics_raw.extend(mitre.get("additionalTactics", []))
            if mitre.get("primaryTechniques"):
                mitre_techniques_raw.extend(mitre["primaryTechniques"])
            mitre_techniques_raw.extend(mitre.get("additionalTechniques", []))

        # Map GCP MITRE names to ATT&CK IDs
        gcp_tactic_to_id = {
            "INITIAL_ACCESS": "TA0001", "EXECUTION": "TA0002",
            "PERSISTENCE": "TA0003", "PRIVILEGE_ESCALATION": "TA0004",
            "DEFENSE_EVASION": "TA0005", "CREDENTIAL_ACCESS": "TA0006",
            "DISCOVERY": "TA0007", "LATERAL_MOVEMENT": "TA0008",
            "COLLECTION": "TA0009", "EXFILTRATION": "TA0010",
            "COMMAND_AND_CONTROL": "TA0011", "IMPACT": "TA0040",
        }
        gcp_technique_to_id = {
            "INGRESS_TOOL_TRANSFER": "T1105", "SHARED_MODULES": "T1129",
            "EXPLOIT_PUBLIC_FACING_APPLICATION": "T1190",
            "VALID_ACCOUNTS": "T1078", "MODIFY_CLOUD_COMPUTE_INFRASTRUCTURE": "T1578",
        }
        mitre_tactics = [gcp_tactic_to_id.get(t, t) for t in mitre_tactics_raw] or MITRE_TACTIC_MAP.get(category, [])
        mitre_techniques = [gcp_technique_to_id.get(t, t) for t in mitre_techniques_raw] or MITRE_TECHNIQUE_MAP.get(category, [])

        # Compliance from GCP finding
        compliances = item.get("finding.compliances", [])
        compliance_mappings = []
        if isinstance(compliances, list):
            for c in compliances[:3]:
                if isinstance(c, dict):
                    std = c.get("standard", "")
                    ids = c.get("ids", [])
                    if std and ids:
                        compliance_mappings.append({
                            "framework_id": std.lower().replace(" ", "-"),
                            "framework_name": std,
                            "control_id": ids[0] if ids else "",
                            "control_title": f"{std} control",
                            "section": "",
                            "severity": severity.lower(),
                            "url": "",
                        })
        if not compliance_mappings:
            compliance_mappings = make_compliance_mappings(category, "gcp", "", rng)

        # Determine resource type from finding class + category
        resource_type = "compute"
        cat_lower = category_raw.lower()
        if any(k in cat_lower for k in ["storage", "bucket", "gcs"]):
            resource_type = "storage"
        elif any(k in cat_lower for k in ["sql", "database", "spanner", "bigtable"]):
            resource_type = "database"
        elif any(k in cat_lower for k in ["firewall", "vpc", "network", "port", "flow"]):
            resource_type = "network"
        elif any(k in cat_lower for k in ["iam", "service_account", "role", "key"]):
            resource_type = "identity"
        elif any(k in cat_lower for k in ["kms", "encrypt"]):
            resource_type = "encryption"
        elif any(k in cat_lower for k in ["container", "gke", "kubernetes"]):
            resource_type = "container"
        elif any(k in cat_lower for k in ["function", "run"]):
            resource_type = "serverless"

        service, lob = pick_workload_context(resource_type, rng)
        env_type = _pick_env_type(rng)
        res_name = pick_resource_name(resource_type, service, env_type, idx + 1, rng)

        score = ai_risk_score(severity, project_name, category)
        status, wf_status = pick_status(rng)

        finding_id = f"f-gcp-{idx + 1:04d}"
        source_id = item.get("finding.canonicalName", item.get("finding.name", finding_id))
        source_id = scrub_gcp_value(source_id)

        findings.append({
            "id": finding_id,
            "source": "gcp-scc",
            "source_finding_id": source_id,
            "type": "vulnerability" if finding_class in ("THREAT", "VULNERABILITY") else "misconfiguration",
            "title": title,
            "description": scrub_gcp_value(description)[:500],
            "resource_type": resource_type,
            "resource_id": f"gcp-{make_dedup_key('gcp', source_id)[:8]}",
            "resource_name": res_name,
            "platform": "cloud",
            "cloud_provider": "gcp",
            "region": item.get("resource.location", None) or rng.choice(GCP_REGIONS),
            "account_id": project_id.split("/")[-1] if project_id else f"contoso-gcp-{idx:03d}",
            "account_name": project_name,
            "environment_type": env_type,
            "static_severity": severity,
            "severity": severity,
            "ai_risk_score": score,
            "ai_risk_level": ai_risk_level(score),
            "ai_risk_rationale": f"{severity} {finding_class.lower()} in GCP project {project_name}.",
            "ai_contextual_factors": [resource_type, finding_class.lower()],
            "cvss": None,
            "cvss_vector": "",
            "epss": None,
            "exploit_available": finding_class == "THREAT" and rng.random() < 0.4,
            "cves": [],
            "mitre_tactics": mitre_tactics,
            "mitre_techniques": mitre_techniques,
            "compliance_mappings": compliance_mappings,
            "remediation": scrub_gcp_value(item.get("finding.description", "Consult GCP SCC."))[:300],
            "auto_remediatable": rng.random() < 0.15,
            "category": category,
            "status": status,
            "workflow_status": wf_status,
            "suppressed": status == "suppressed",
            "service_name": service,
            "line_of_business": lob,
            "first_found_at": first_found,
            "last_seen_at": last_seen,
            "due_date": make_due_date(severity, first_found),
            "deduplication_key": make_dedup_key("gcp", source_id),
            "canonical_rule_id": category_raw,
        })

    return findings


# --- File discovery ---

def find_file(directory: Path, pattern: str) -> Path | None:
    """Find most recent file matching glob pattern."""
    matches = sorted(directory.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
    return matches[0] if matches else None


# --- Main ---

def main() -> int:
    parser = argparse.ArgumentParser(description="Transform cloud findings to CloudForge schema")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--dry-run", action="store_true", help="Preview without writing")
    group.add_argument("--execute", action="store_true", help="Write output file")
    args = parser.parse_args()

    rng = random.Random(SEED)

    print("=" * 70)
    print("CloudForge Findings Transformer")
    print("=" * 70)

    # Discover input files
    aws_csv = find_file(SCRUBBED_DIR, "scrubbed_aws_all_findings_*.csv")
    azure_json = find_file(SCRUBBED_DIR, "scrubbed_azure_all_findings_*.json")
    gcp_json = find_file(INPUT_DIR, "gcp_all_findings_*.json")

    print(f"\n[*] Input files:")
    print(f"    AWS CSV:    {aws_csv.name if aws_csv else 'NOT FOUND'}")
    print(f"    Azure JSON: {azure_json.name if azure_json else 'NOT FOUND'}")
    print(f"    GCP JSON:   {gcp_json.name if gcp_json else 'NOT FOUND'}")

    all_findings: list[dict[str, Any]] = []

    # Parse each provider
    if aws_csv:
        print(f"\n[*] Parsing AWS (sampling {AWS_SAMPLE} from ~109K)...")
        aws_findings = parse_aws_csv(aws_csv, AWS_SAMPLE, rng)
        print(f"    [+] AWS: {len(aws_findings)} findings")
        all_findings.extend(aws_findings)
    else:
        print("\n[!] AWS CSV not found — skipping")

    if azure_json:
        print(f"\n[*] Parsing Azure (all records)...")
        azure_findings = parse_azure_json(azure_json, rng)
        print(f"    [+] Azure: {len(azure_findings)} findings")
        all_findings.extend(azure_findings)
    else:
        print("\n[!] Azure JSON not found — skipping")

    if gcp_json:
        print(f"\n[*] Parsing GCP (sampling {GCP_SAMPLE} from ~8.2K, applying PII scrub)...")
        gcp_findings = parse_gcp_json(gcp_json, GCP_SAMPLE, rng)
        print(f"    [+] GCP: {len(gcp_findings)} findings")
        all_findings.extend(gcp_findings)
    else:
        print("\n[!] GCP JSON not found — skipping")

    # Summary
    print(f"\n{'=' * 70}")
    print(f"[+] Total findings: {len(all_findings)}")
    from collections import Counter
    sev_counts = Counter(f["severity"] for f in all_findings)
    provider_counts = Counter(f["cloud_provider"] for f in all_findings)
    cat_counts = Counter(f["category"] for f in all_findings)
    rt_counts = Counter(f["resource_type"] for f in all_findings)
    status_counts = Counter(f["status"] for f in all_findings)

    print("\n    By provider:")
    for k, v in provider_counts.most_common():
        print(f"      {k}: {v}")
    print("\n    By severity:")
    for k, v in sev_counts.most_common():
        print(f"      {k}: {v}")
    print("\n    By category:")
    for k, v in cat_counts.most_common():
        print(f"      {k}: {v}")
    print("\n    By resource type:")
    for k, v in rt_counts.most_common():
        print(f"      {k}: {v}")
    print("\n    By status:")
    for k, v in status_counts.most_common():
        print(f"      {k}: {v}")

    env_counts = Counter(f["environment_type"] for f in all_findings)
    print("\n    By environment:")
    for k, v in env_counts.most_common():
        print(f"      {k}: {v}")

    lob_counts = Counter(f["line_of_business"] for f in all_findings)
    print("\n    By LOB:")
    for k, v in lob_counts.most_common():
        print(f"      {k}: {v}")

    region_counts = Counter(f["region"] for f in all_findings)
    print(f"\n    By region ({len(region_counts)} unique):")
    for k, v in region_counts.most_common(10):
        print(f"      {k}: {v}")
    if len(region_counts) > 10:
        print(f"      ... and {len(region_counts) - 10} more")

    svc_counts = Counter(f["service_name"] for f in all_findings)
    print(f"\n    By service ({len(svc_counts)} unique):")
    for k, v in svc_counts.most_common(10):
        print(f"      {k}: {v}")
    if len(svc_counts) > 10:
        print(f"      ... and {len(svc_counts) - 10} more")

    # Verify attack path viability
    by_account = Counter(f["account_id"] for f in all_findings)
    multi_acct = sum(1 for c in by_account.values() if c >= 2)
    entry_points = sum(1 for f in all_findings
                       if f["category"] in ("NETWORK", "VULNERABILITY") or f["exploit_available"])
    targets = sum(1 for f in all_findings
                  if f["resource_type"] in ("storage", "database", "secret", "encryption"))
    print(f"\n    Attack path viability:")
    print(f"      Accounts with 2+ findings: {multi_acct}")
    print(f"      Entry points (NETWORK/VULN/exploit): {entry_points}")
    print(f"      Targets (storage/db/secret): {targets}")

    if args.dry_run:
        print(f"\n[*] DRY RUN — no output written")
        print(f"    Would write to: {OUTPUT_PATH}")
        return 0

    # Write output
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(all_findings, f, indent=2, default=str)

    size_kb = OUTPUT_PATH.stat().st_size / 1024
    print(f"\n[+] Written: {OUTPUT_PATH}")
    print(f"    Size: {size_kb:.1f} KB ({len(all_findings)} findings)")
    print(f"{'=' * 70}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Cancelled")
        sys.exit(130)
