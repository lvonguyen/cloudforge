#!/usr/bin/env python3
"""Amplify 270 template findings to ~5000 with realistic resource names.

Reads:  frontend/src/lib/mock/findings.json (270 templates)
Writes: frontend/src/lib/mock/findings.json (5000+ findings)

Usage:
    python testdata/amplify_findings.py --dry-run
    python testdata/amplify_findings.py --execute
"""

import argparse
import hashlib
import json
import random
import sys
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).parent.parent
FINDINGS_PATH = PROJECT_ROOT / "frontend" / "public" / "mock" / "findings.json"

TARGET_COUNT = 5000
SEED = 42

# --- Short, cloud-realistic resource name patterns per type ---

RESOURCE_NAMES: dict[str, list[str]] = {
    "compute": [
        "vm-{env}-{n:02d}", "web-srv-{n:02d}", "app-{reg}-{n:02d}",
        "k8s-node-{n:02d}", "ec2-{svc}-{n:02d}", "worker-{env}-{n:02d}",
        "bastion-{env}", "jump-{reg}-{n:02d}", "batch-{svc}-{n:02d}",
    ],
    "container": [
        "aks-{env}-{n:02d}", "ecs-{svc}-{n:02d}", "gke-{env}-{n:02d}",
        "pod-{svc}-{n:02d}", "fargate-{svc}-{n:02d}", "k8s-{env}-{n:02d}",
    ],
    "database": [
        "rds-{svc}-{n:02d}", "db-{env}-{n:02d}", "sql-{env}-{n:02d}",
        "cosmos-{env}-{n:02d}", "pg-{svc}-{n:02d}", "redis-{env}-{n:02d}",
        "dynamo-{svc}", "es-{env}-{n:02d}",
    ],
    "identity": [
        "sa-{svc}", "iam-{env}-{n:02d}", "msi-{svc}-{n:02d}",
        "sp-deploy-{n:02d}", "role-{svc}", "svc-acct-{n:02d}",
    ],
    "network": [
        "vnet-{env}-{n:02d}", "fw-{env}-{n:02d}", "nsg-{env}-{n:02d}",
        "lb-{svc}-{n:02d}", "agw-{env}-{n:02d}", "vpn-{reg}",
        "nat-{env}-{n:02d}", "cdn-{svc}",
    ],
    "secret": [
        "kv-{env}-{n:02d}", "sm-{svc}", "vault-{env}-{n:02d}",
        "cert-{svc}-{n:02d}",
    ],
    "storage": [
        "st{env}{n:02d}", "s3-{svc}-{n:02d}", "gcs-{env}-{n:02d}",
        "blob-{svc}-{n:02d}", "efs-{env}-{n:02d}", "disk-{svc}-{n:02d}",
    ],
    "serverless": [
        "fn-{svc}-{n:02d}", "lambda-{svc}-{n:02d}", "cf-{env}-{n:02d}",
    ],
    "encryption": [
        "kms-{env}-{n:02d}", "cmk-{svc}", "key-{env}-{n:02d}",
    ],
    "logging": [
        "logs-{env}-{n:02d}", "trail-{env}", "sink-{svc}-{n:02d}",
    ],
    "messaging": [
        "sqs-{svc}-{n:02d}", "sns-{env}-{n:02d}", "bus-{svc}-{n:02d}",
        "topic-{svc}", "queue-{env}-{n:02d}",
    ],
}

ENVS = ["prod", "stg", "dev", "qa", "sbx"]
ENV_FULL = {"prod": "production", "stg": "staging", "dev": "development", "qa": "qa", "sbx": "sandbox"}
REGIONS_SHORT = ["ue1", "uw2", "ew1", "ec1", "ase1", "apn1", "sae1", "cac1"]

SVCS = [
    "web", "api", "auth", "pay", "bill", "etl", "ml", "cdn",
    "log", "mon", "ci", "deploy", "vault", "search", "cache",
    "msg", "mail", "media", "sync", "ingest", "pipe", "sched",
]

# Additional regions per provider for variety
AWS_REGIONS = [
    "us-east-1", "us-east-2", "us-west-2", "eu-west-1", "eu-central-1",
    "ap-southeast-1", "ap-northeast-1", "ca-central-1", "sa-east-1",
    "ap-south-1", "eu-west-2", "eu-north-1",
]
AZURE_REGIONS = [
    "eastus", "eastus2", "westus2", "westeurope", "northeurope",
    "southeastasia", "japaneast", "canadacentral", "australiaeast",
    "uksouth", "centralus", "westus3",
]
GCP_REGIONS = [
    "us-central1", "us-east1", "us-west1", "europe-west1", "europe-west4",
    "asia-east1", "asia-southeast1", "northamerica-northeast1",
    "southamerica-east1", "australia-southeast1",
]

PROVIDER_REGIONS = {"aws": AWS_REGIONS, "azure": AZURE_REGIONS, "gcp": GCP_REGIONS}

# Account pools per provider
AWS_ACCOUNTS = [
    ("100000000010", "contoso-core-prod"), ("100000000053", "contoso-web-prod"),
    ("100000000098", "contoso-data-prod"), ("100000000122", "contoso-ml-prod"),
    ("100000000150", "contoso-pay-prod"), ("100000000175", "contoso-sec-prod"),
    ("100000000198", "contoso-infra-dev"), ("100000000210", "contoso-media-sandbox"),
    ("100000000225", "contoso-core-stg"), ("100000000240", "contoso-web-stg"),
    ("100000000260", "contoso-data-dev"), ("100000000280", "contoso-finops"),
    ("100000000300", "contoso-dr-west"), ("100000000315", "contoso-edge-prod"),
    ("100000000330", "contoso-analytics"), ("100000000345", "contoso-iot-prod"),
]
AZURE_SUBS = [
    ("sub-001", "contoso-hub-prod"), ("sub-002", "contoso-spoke-prod"),
    ("sub-003", "contoso-spoke-dev"), ("sub-004", "contoso-data-prod"),
    ("sub-005", "contoso-k8s-prod"), ("sub-006", "contoso-mgmt"),
    ("sub-007", "contoso-dmz"), ("sub-008", "contoso-dr"),
]
GCP_PROJECTS = [
    ("prj-001", "contoso-platform-prod"), ("prj-002", "contoso-data-prod"),
    ("prj-003", "contoso-ml-prod"), ("prj-004", "contoso-web-prod"),
    ("prj-005", "contoso-infra-dev"), ("prj-006", "contoso-sec-ops"),
]


def gen_resource_name(
    resource_type: str, rng: random.Random, counter: int
) -> str:
    patterns = RESOURCE_NAMES.get(resource_type, RESOURCE_NAMES["compute"])
    pattern = rng.choice(patterns)
    return pattern.format(
        env=rng.choice(ENVS),
        n=counter % 100,
        reg=rng.choice(REGIONS_SHORT),
        svc=rng.choice(SVCS),
    )


def amplify(templates: list[dict[str, Any]], target: int, rng: random.Random) -> list[dict[str, Any]]:
    """Amplify template findings to target count with varied attributes."""
    results: list[dict[str, Any]] = []
    provider_counts = {"aws": 0, "azure": 0, "gcp": 0}

    # Target distribution: 55% AWS, 20% Azure, 25% GCP
    provider_weights = {"aws": 0.55, "azure": 0.20, "gcp": 0.25}

    # Group templates by provider
    by_provider: dict[str, list[dict]] = {"aws": [], "azure": [], "gcp": []}
    for t in templates:
        p = t.get("cloud_provider", "aws")
        if p in by_provider:
            by_provider[p].append(t)

    for i in range(target):
        # Pick provider based on weights
        r = rng.random()
        if r < provider_weights["aws"]:
            provider = "aws"
        elif r < provider_weights["aws"] + provider_weights["azure"]:
            provider = "azure"
        else:
            provider = "gcp"

        pool = by_provider[provider]
        template = rng.choice(pool)
        provider_counts[provider] += 1
        counter = provider_counts[provider]

        finding = deepcopy(template)
        finding["id"] = f"f-{provider}-{counter:04d}"

        # New resource name
        rt = finding.get("resource_type", "compute")
        finding["resource_name"] = gen_resource_name(rt, rng, counter)
        finding["resource_id"] = f"{rt}-{hashlib.md5(finding['resource_name'].encode()).hexdigest()[:8]}"

        # Vary region
        regions = PROVIDER_REGIONS.get(provider, AWS_REGIONS)
        finding["region"] = rng.choice(regions)

        # Vary account
        if provider == "aws":
            acct_id, acct_name = rng.choice(AWS_ACCOUNTS)
        elif provider == "azure":
            acct_id, acct_name = rng.choice(AZURE_SUBS)
        else:
            acct_id, acct_name = rng.choice(GCP_PROJECTS)
        finding["account_id"] = acct_id
        finding["account_name"] = acct_name

        # Vary environment
        env = rng.choice(list(ENV_FULL.keys()))
        finding["environment_type"] = ENV_FULL[env]

        # Vary dates (within last 6 months)
        days_ago = rng.randint(1, 180)
        first_found = datetime.now() - timedelta(days=days_ago)
        finding["first_found_at"] = first_found.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        last_seen = first_found + timedelta(days=rng.randint(0, min(days_ago, 30)))
        finding["last_seen_at"] = last_seen.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        # Recalculate SLA due date
        sla_days = {"CRITICAL": 7, "HIGH": 30, "MEDIUM": 90, "LOW": 180}
        sla = sla_days.get(finding["severity"], 90)
        due = first_found + timedelta(days=sla)
        finding["due_date"] = due.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Vary status
        sr = rng.random()
        if sr < 0.53:
            finding["status"], finding["workflow_status"] = "open", rng.choice(["new", "triaged"])
        elif sr < 0.78:
            finding["status"], finding["workflow_status"] = "in_progress", "assigned"
        elif sr < 0.93:
            finding["status"], finding["workflow_status"] = "resolved", "resolved"
        else:
            finding["status"], finding["workflow_status"] = "suppressed", "suppressed"

        # Unique dedup key
        finding["deduplication_key"] = hashlib.sha256(
            f"{finding['source']}:{finding['id']}:{finding['resource_name']}".encode()
        ).hexdigest()[:12]

        # ARN / resource path
        if provider == "aws":
            finding["resource_arn"] = f"arn:aws::::{acct_id}:{rt}/{finding['resource_name']}"
        elif provider == "azure":
            finding["resource_arn"] = f"/subscriptions/{acct_id}/resourceGroups/rg-{env}/providers/{rt}/{finding['resource_name']}"
        else:
            finding["resource_arn"] = f"//cloudresourcemanager.googleapis.com/projects/{acct_id}/{rt}/{finding['resource_name']}"

        # Source finding ID uniqueness
        finding["source_finding_id"] = f"{finding['source']}:{hashlib.md5(finding['id'].encode()).hexdigest()[:16]}"

        results.append(finding)

    # Sort by severity order then ID
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
    results.sort(key=lambda f: (sev_order.get(f["severity"], 9), f["id"]))

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Amplify findings to production scale")
    parser.add_argument("--dry-run", action="store_true", help="Preview without writing")
    parser.add_argument("--execute", action="store_true", help="Write output file")
    parser.add_argument("--target", type=int, default=TARGET_COUNT, help="Target finding count")
    args = parser.parse_args()

    if not args.dry_run and not args.execute:
        print("[!] Specify --dry-run or --execute")
        sys.exit(1)

    if not FINDINGS_PATH.exists():
        print(f"[!] Input not found: {FINDINGS_PATH}")
        sys.exit(1)

    templates = json.loads(FINDINGS_PATH.read_text())
    print(f"[*] Loaded {len(templates)} template findings")

    rng = random.Random(SEED)
    amplified = amplify(templates, args.target, rng)

    # Stats
    from collections import Counter
    providers = Counter(f["cloud_provider"] for f in amplified)
    severities = Counter(f["severity"] for f in amplified)
    types = Counter(f["resource_type"] for f in amplified)
    statuses = Counter(f["status"] for f in amplified)
    regions = len({f["region"] for f in amplified})
    accounts = len({f["account_id"] for f in amplified})
    unique_names = len({f["resource_name"] for f in amplified})

    print(f"[+] Generated {len(amplified)} findings")
    print(f"    Providers:  {dict(providers)}")
    print(f"    Severities: {dict(severities)}")
    print(f"    Types:      {dict(types)}")
    print(f"    Statuses:   {dict(statuses)}")
    print(f"    Regions:    {regions} unique")
    print(f"    Accounts:   {accounts} unique")
    print(f"    Resources:  {unique_names} unique names")

    # Sample names per type
    print("\n[*] Sample resource names:")
    for rt in sorted(types.keys()):
        names = [f["resource_name"] for f in amplified if f["resource_type"] == rt][:5]
        print(f"    {rt:12s}: {', '.join(names)}")

    if args.execute:
        FINDINGS_PATH.write_text(json.dumps(amplified, indent=2) + "\n")
        size_mb = FINDINGS_PATH.stat().st_size / (1024 * 1024)
        print(f"\n[+] Written to {FINDINGS_PATH} ({size_mb:.1f} MB)")
    else:
        print("\n[*] Dry run — no files written. Use --execute to write.")


if __name__ == "__main__":
    main()
