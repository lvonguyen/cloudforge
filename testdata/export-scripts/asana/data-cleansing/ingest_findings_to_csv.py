#!/usr/bin/env python3
"""
ingest_findings_to_csv.py - Multi-cloud findings ingestion and normalization

Ingests JSON exports from AWS Security Hub, Azure Defender, and GCP SCC.
Produces a single standardized CSV file for Asana import.

Usage:
    python ingest_findings_to_csv.py --dry-run
    python ingest_findings_to_csv.py --execute

Author: HAEA Security TFT
Date: 2025-12-11
"""

import argparse
import csv
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


# Path configuration
SCRIPT_DIR = Path(__file__).parent
INPUT_DIR = SCRIPT_DIR.parent.parent / "1.1finding-export-utils" / "finding-outputs" / "json"
OUTPUT_DIR = SCRIPT_DIR / "cleansed-imports"

# Execution team mappings
EXECUTION_TEAM_MAP = {
    "aws": {
        "default": "AWS Platform Ops",
        "ccoe_controls": ["IAM", "CloudTrail", "Config", "Organizations"],
    },
    "azure": {
        "default": "Az Platform",
        "ccoe_controls": ["Defender", "Policy", "KeyVault"],
    },
    "gcp": {
        "default": "GCP Platform Ops",
        "ccoe_controls": ["IAM", "UNUSED_IAM", "SERVICE_AGENT"],
    },
}

# Effort estimation based on category patterns
EFFORT_ESTIMATES = {
    # AWS patterns
    r"CloudFront": 0.5,
    r"S3\.\d+": 0.5,
    r"EC2\.\d+": 1.0,
    r"IAM\.\d+": 1.5,
    r"RDS\.\d+": 1.0,
    r"Lambda": 0.5,
    r"VPC|SecurityGroup": 1.0,
    # Azure patterns
    r"Defender": 2.0,
    r"Storage": 0.5,
    r"AI Services": 1.0,
    r"Cosmos DB": 1.5,
    r"Identity|Access": 1.5,
    # GCP patterns
    r"OPEN_.*_PORT": 0.5,
    r"OPEN_FIREWALL": 1.0,
    r"UNUSED_IAM": 0.5,
    r"SERVICE_AGENT": 1.0,
    r"VULNERABILITY": 2.0,
    r"SSL_NOT_ENFORCED": 0.5,
    # Default
    r".*": 1.0,
}


def extract_finding_id_short(full_id: str, csp: str) -> str:
    """Extract normalized short ID from full ARN/path while retaining queryability."""
    if csp == "aws":
        # AWS ARNs: extract the finding UUID from end
        # e.g., arn:aws:securityhub:...finding/abc123-def456
        match = re.search(r"finding/([a-f0-9-]+)(?:/[a-f0-9-]+)?$", full_id)
        if match:
            return match.group(1)[:12]  # First 12 chars for brevity
        # Fallback: last segment
        return full_id.split("/")[-1][:12]

    elif csp == "azure":
        # Azure assessment IDs: extract the assessment UUID
        # e.g., /subscriptions/.../assessments/13b10b36-aa99-4db6-b00c-dcf87c4761e6
        match = re.search(r"assessments/([a-f0-9-]+)$", full_id)
        if match:
            return match.group(1)[:12]
        return full_id.split("/")[-1][:12]

    elif csp == "gcp":
        # GCP findings: extract finding ID
        # e.g., organizations/.../findings/01bbbffc1607c7d715a72af6ca7ee74e
        match = re.search(r"findings/([a-f0-9]+)$", full_id)
        if match:
            return match.group(1)[:12]
        return full_id.split("/")[-1][:12]

    return full_id[:12]


def estimate_effort(finding_name: str, severity: str) -> float:
    """Estimate remediation effort in hours based on finding type and severity."""
    base_effort = 1.0
    for pattern, effort in EFFORT_ESTIMATES.items():
        if re.search(pattern, finding_name, re.IGNORECASE):
            base_effort = effort
            break

    # Severity multiplier
    severity_multiplier = {
        "CRITICAL": 1.5,
        "HIGH": 1.0,
        "MEDIUM": 0.75,
        "LOW": 0.5,
    }.get(severity.upper(), 1.0)

    return round(base_effort * severity_multiplier, 1)


def determine_execution_team(finding_name: str, csp: str) -> str:
    """Determine which team should handle the remediation."""
    csp_config = EXECUTION_TEAM_MAP.get(csp.lower(), {"default": "HAEA Security TFT"})

    # Check if it's a CCoE-owned control
    for ccoe_pattern in csp_config.get("ccoe_controls", []):
        if ccoe_pattern.lower() in finding_name.lower():
            return "CCoE"

    return csp_config.get("default", "HAEA Security TFT")


def normalize_severity(severity: str) -> str:
    """Normalize severity to standard values."""
    severity_upper = severity.upper() if severity else "UNKNOWN"
    mapping = {
        "CRITICAL": "Critical",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
        "INFORMATIONAL": "Info",
    }
    return mapping.get(severity_upper, severity_upper.title())


def determine_tier(severity: str, environment: str) -> str:
    """Determine priority tier based on severity and environment."""
    sev = severity.upper() if severity else ""
    env = environment.lower() if environment else ""

    if sev == "CRITICAL" or (sev == "HIGH" and "prod" in env):
        return "Tier 1"
    elif sev == "HIGH" or (sev == "MEDIUM" and "prod" in env):
        return "Tier 2"
    else:
        return "Tier 3"


def determine_env_type(env_friendly_name: str) -> str:
    """Determine environment type (Prod or Non-Prod) from environment name.

    Logic:
    - Non-Prod keywords: dev, stg, stage, qa, nprd, nonprod, non-prod, sandbox, test
    - Prod keywords: prd, prod (when not preceded by 'non' or 'n')
    - Default: If no clear indicator, assume Prod (safer assumption)
    """
    name_lower = env_friendly_name.lower() if env_friendly_name else ""

    # Check for Non-Prod indicators first (more specific)
    non_prod_keywords = ['dev', 'stg', 'stage', 'qa', 'nprd', 'nonprod', 'non-prod', 'sandbox', 'test']
    for keyword in non_prod_keywords:
        if keyword in name_lower:
            return "Non-Prod"

    # Check for Prod indicators
    prod_keywords = ['prd', 'prod']
    for keyword in prod_keywords:
        if keyword in name_lower:
            # Make sure it's not "nonprod" or "non-prod" (already handled above)
            return "Prod"

    # Default: If no clear indicator, treat as Prod (conservative assumption)
    return "Prod"


def parse_aws_findings(json_path: Path) -> list[dict[str, Any]]:
    """Parse AWS Security Hub JSON export."""
    findings = []
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    for item in data.get("findings", []):
        finding_id = item.get("Id", "")
        created_time = item.get("CreatedAt", "")
        if created_time:
            try:
                created_time = datetime.fromisoformat(created_time.replace("Z", "+00:00")).strftime("%Y-%m-%d")
            except (ValueError, AttributeError):
                pass

        severity = item.get("Severity", {}).get("Label", "UNKNOWN")
        env = item.get("AccountEnvironment", "Unknown")
        finding_name = item.get("Title", "Unknown Finding")
        region = item.get("Region", item.get("QueryRegion", "unknown"))

        # Extract control ID from generator or title
        generator = item.get("GeneratorId", "")
        control_match = re.search(r"([\w.-]+)/v/[\d.]+/([\w.]+)/", finding_id)
        control_id = control_match.group(2) if control_match else generator.split("/")[-1]

        # Build tags from Types field
        tags = item.get("Types", [])
        tags_str = "; ".join(tags) if tags else ""

        env_friendly_name = item.get("AwsAccountName", item.get("AccountName", ""))
        findings.append({
            "Finding": finding_name,
            "Assignee": "",  # To be assigned via Asana
            "Status": "not started",
            "CSP": "AWS",
            "Severity": normalize_severity(severity),
            "Tier": determine_tier(severity, env),
            "EnvType": determine_env_type(env_friendly_name),
            "EnvFriendlyName": env_friendly_name,
            "EnvId": item.get("AwsAccountId", ""),
            "CreatedTime": created_time,
            "FindingId": finding_id,
            "FindingIdShort": extract_finding_id_short(finding_id, "aws"),
            "Region": region,
            "ExecutionTeam": determine_execution_team(finding_name, "aws"),
            "EstEffort": estimate_effort(finding_name, severity),
            "Tags": tags_str,
        })

    return findings


def parse_azure_findings(json_path: Path) -> list[dict[str, Any]]:
    """Parse Azure Defender JSON export."""
    findings = []
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    for item in data.get("detailed_findings", []):
        finding_id = item.get("assessment_id", "")
        severity = item.get("severity", "UNKNOWN")
        env = item.get("environment", "Unknown")
        finding_name = item.get("recommendation_name", "Unknown Finding")

        # Azure doesn't have a direct region field - extract from resource if possible
        resource = item.get("impacted_resource", "")
        region_match = re.search(r"resourcegroups/[^/]+/providers", resource.lower())
        region = "global"  # Azure assessments are typically subscription-level

        # Get creation time from metadata if available
        created_time = data.get("validation_metadata", {}).get("date", "")
        if created_time:
            try:
                created_time = datetime.fromisoformat(created_time).strftime("%Y-%m-%d")
            except (ValueError, AttributeError):
                pass

        # Build control ID from assessment
        control_match = re.search(r"assessments/([a-f0-9-]+)$", finding_id)
        control_id = control_match.group(1)[:8] if control_match else "unknown"

        # Determine category for tags
        category = data.get("breakdown", {}).get("by_category", {})
        tags = f"category:{finding_name[:30]}"

        env_friendly_name = item.get("subscription_name", "")
        findings.append({
            "Finding": finding_name,
            "Assignee": "",
            "Status": "not started",
            "CSP": "AZ",
            "Severity": normalize_severity(severity),
            "Tier": determine_tier(severity, env),
            "EnvType": determine_env_type(env_friendly_name),
            "EnvFriendlyName": env_friendly_name,
            "EnvId": item.get("subscription_id", ""),
            "CreatedTime": created_time,
            "FindingId": finding_id,
            "FindingIdShort": extract_finding_id_short(finding_id, "azure"),
            "Region": region,
            "ExecutionTeam": determine_execution_team(finding_name, "azure"),
            "EstEffort": estimate_effort(finding_name, severity),
            "Tags": tags,
        })

    return findings


def parse_gcp_findings(json_path: Path) -> list[dict[str, Any]]:
    """Parse GCP SCC JSON export."""
    findings = []
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    for item in data.get("findings", []):
        finding_data = item.get("finding", {})
        resource_data = item.get("resource", {})

        finding_id = finding_data.get("name", finding_data.get("canonicalName", ""))
        category = finding_data.get("category", "Unknown")
        severity = finding_data.get("severity", "UNKNOWN")
        description = finding_data.get("description", category)
        finding_name = f"{category}: {description[:80]}" if description != category else category

        # Get environment from item-level enrichment
        env = item.get("projectEnvironment", "Unknown")
        project_name = resource_data.get("projectDisplayName", resource_data.get("parentDisplayName", ""))

        # Get region/location
        region = resource_data.get("location", "global")

        # Parse creation time
        created_time = finding_data.get("createTime", "")
        if created_time:
            try:
                created_time = datetime.fromisoformat(created_time.replace("Z", "+00:00")).strftime("%Y-%m-%d")
            except (ValueError, AttributeError):
                pass

        # Build tags from compliances
        compliances = finding_data.get("compliances", [])
        tags_list = []
        for c in compliances:
            std = c.get("standard", "")
            ids = c.get("ids", [])
            if std and ids:
                tags_list.append(f"{std}:{','.join(ids)}")
        tags = "; ".join(tags_list) if tags_list else f"category:{category}"

        findings.append({
            "Finding": finding_name,
            "Assignee": "",
            "Status": "not started",
            "CSP": "GCP",
            "Severity": normalize_severity(severity),
            "Tier": determine_tier(severity, env),
            "EnvType": determine_env_type(project_name),
            "EnvFriendlyName": project_name,
            "EnvId": resource_data.get("projectName", "").split("/")[-1] if resource_data.get("projectName") else "",
            "CreatedTime": created_time,
            "FindingId": finding_id,
            "FindingIdShort": extract_finding_id_short(finding_id, "gcp"),
            "Region": region,
            "ExecutionTeam": determine_execution_team(category, "gcp"),
            "EstEffort": estimate_effort(category, severity),
            "Tags": tags,
        })

    return findings


def find_latest_json_files(input_dir: Path) -> dict[str, Path | None]:
    """Find the most recent JSON file for each CSP."""
    files = {"aws": None, "azure": None, "gcp": None}

    for f in input_dir.glob("*.json"):
        name = f.name.lower()
        if "aws_securityhub" in name:
            if files["aws"] is None or f.stat().st_mtime > files["aws"].stat().st_mtime:
                files["aws"] = f
        elif "az_defender" in name:
            if files["azure"] is None or f.stat().st_mtime > files["azure"].stat().st_mtime:
                files["azure"] = f
        elif "gcp_scc" in name:
            if files["gcp"] is None or f.stat().st_mtime > files["gcp"].stat().st_mtime:
                files["gcp"] = f

    return files


def main():
    parser = argparse.ArgumentParser(
        description="Ingest multi-cloud findings JSON and produce standardized CSV"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview what would be processed without writing output",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Execute the ingestion and write output CSV",
    )
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=INPUT_DIR,
        help=f"Directory containing JSON inputs (default: {INPUT_DIR})",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=OUTPUT_DIR,
        help=f"Directory for output CSV (default: {OUTPUT_DIR})",
    )
    args = parser.parse_args()

    if not args.dry_run and not args.execute:
        print("ERROR: Must specify either --dry-run or --execute")
        sys.exit(1)

    # Find input files
    print(f"\n=== Finding Input Files ===")
    print(f"Input directory: {args.input_dir}")

    json_files = find_latest_json_files(args.input_dir)

    for csp, path in json_files.items():
        if path:
            print(f"  {csp.upper()}: {path.name}")
        else:
            print(f"  {csp.upper()}: NOT FOUND")

    # Parse all findings
    print(f"\n=== Parsing Findings ===")
    all_findings = []

    if json_files["aws"]:
        aws_findings = parse_aws_findings(json_files["aws"])
        print(f"  AWS: {len(aws_findings)} findings")
        all_findings.extend(aws_findings)

    if json_files["azure"]:
        azure_findings = parse_azure_findings(json_files["azure"])
        print(f"  Azure: {len(azure_findings)} findings")
        all_findings.extend(azure_findings)

    if json_files["gcp"]:
        gcp_findings = parse_gcp_findings(json_files["gcp"])
        print(f"  GCP: {len(gcp_findings)} findings")
        all_findings.extend(gcp_findings)

    print(f"\n  TOTAL: {len(all_findings)} findings")

    # Summary by CSP and severity
    print(f"\n=== Summary ===")
    by_csp = {}
    by_severity = {}
    by_tier = {}
    by_env_type = {}
    by_team = {}

    for f in all_findings:
        csp = f["CSP"]
        sev = f["Severity"]
        tier = f["Tier"]
        env_type = f["EnvType"]
        team = f["ExecutionTeam"]

        by_csp[csp] = by_csp.get(csp, 0) + 1
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_tier[tier] = by_tier.get(tier, 0) + 1
        by_env_type[env_type] = by_env_type.get(env_type, 0) + 1
        by_team[team] = by_team.get(team, 0) + 1

    print("  By CSP:")
    for csp, count in sorted(by_csp.items()):
        print(f"    {csp}: {count}")

    print("  By Severity:")
    for sev, count in sorted(by_severity.items()):
        print(f"    {sev}: {count}")

    print("  By Tier:")
    for tier, count in sorted(by_tier.items()):
        print(f"    {tier}: {count}")

    print("  By EnvType:")
    for env_type, count in sorted(by_env_type.items()):
        print(f"    {env_type}: {count}")

    print("  By Execution Team:")
    for team, count in sorted(by_team.items()):
        print(f"    {team}: {count}")

    # Output
    if args.dry_run:
        print(f"\n=== DRY RUN - No output written ===")
        print("Run with --execute to write output CSV")
    else:
        # Ensure output directory exists
        args.output_dir.mkdir(parents=True, exist_ok=True)

        # Generate output filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = args.output_dir / f"unified_findings_{timestamp}.csv"

        # CSV headers per spec
        headers = [
            "Finding",
            "Assignee",
            "Status",
            "CSP",
            "Severity",
            "Tier",
            "EnvType",
            "EnvFriendlyName",
            "EnvId",
            "CreatedTime",
            "FindingId",
            "FindingIdShort",
            "Region",
            "ExecutionTeam",
            "EstEffort",
            "Tags",
        ]

        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(all_findings)

        print(f"\n=== Output Written ===")
        print(f"  File: {output_file}")
        print(f"  Records: {len(all_findings)}")


if __name__ == "__main__":
    main()
