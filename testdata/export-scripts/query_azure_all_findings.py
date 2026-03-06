#!/usr/bin/env python3
"""
Azure Defender — All CBU Findings Export
All subscriptions, all severities, all fields. CSV + JSON.

Usage:
    python query_azure_all_findings.py
    python query_azure_all_findings.py --output-dir ./my-outputs
"""

import argparse
import json
import sys
import tempfile
from collections import Counter
from datetime import datetime
from pathlib import Path

from findings_export_utils import (
    DEFAULT_OUTPUT_DIR,
    print_severity_breakdown,
    run_cmd,
    timestamp,
    write_outputs,
)


def export_azure(output_dir: Path) -> Path | None:
    print("=" * 80)
    print("Azure Defender / Microsoft Defender for Cloud")
    print("All subscriptions, all severities, unhealthy only")
    print(f"Started: {datetime.now().isoformat()}")
    print("=" * 80)

    # Get all enabled subscriptions
    raw = run_cmd(["az", "account", "list", "--output", "json", "--all"])
    if not raw:
        print("[!] Failed to list Azure subscriptions")
        return None

    try:
        subs = json.loads(raw)
    except json.JSONDecodeError:
        print(f"[!] Failed to parse subscription list: {raw[:200]}")
        return None

    enabled_subs = [s for s in subs if s.get("state") == "Enabled"]
    sub_ids = [s["id"] for s in enabled_subs]
    sub_map = {s["id"]: s["name"] for s in enabled_subs}

    print(f"[*] {len(enabled_subs)} enabled subscriptions")
    for s in enabled_subs:
        print(f"    {s['name']} ({s['id'][:8]}...)")

    # Resource Graph — all severities, unhealthy, all fields
    kusto = """
securityresources
| where type =~ "microsoft.security/assessments"
| extend statusCode = tostring(properties.status.code)
| where statusCode == "Unhealthy"
| extend assessmentKey = name
| extend displayName = tostring(properties.displayName)
| extend severity = tostring(properties.metadata.severity)
| extend description = tostring(properties.metadata.description)
| extend remediationDescription = tostring(properties.metadata.remediationDescription)
| extend categories = tostring(properties.metadata.categories)
| extend threats = tostring(properties.metadata.threats)
| extend isPreview = tobool(properties.metadata.preview)
| extend assessmentType = tostring(properties.metadata.assessmentType)
| extend implementationEffort = tostring(properties.metadata.implementationEffort)
| extend userImpact = tostring(properties.metadata.userImpact)
| extend policyDefinitionId = tostring(properties.metadata.policyDefinitionId)
| extend statusChangeDate = tostring(properties.status.statusChangeDate)
| extend firstEvaluationDate = tostring(properties.status.firstEvaluationDate)
| extend statusCause = tostring(properties.status.cause)
| extend statusDescription = tostring(properties.status.description)
| extend resourceSource = tostring(properties.resourceDetails.Source)
| extend resourceDetailId = tostring(properties.resourceDetails.Id)
| extend resourceName = tostring(coalesce(
    properties.resourceDetails.ResourceName,
    properties.resourceDetails.resourceName,
    split(id, '/')[-3]
))
| extend resourceType = tostring(coalesce(
    properties.resourceDetails.ResourceType,
    properties.resourceDetails.resourceType
))
| extend resourceGroup = tostring(extract("resourceGroups/([^/]+)", 1, id))
| extend partnerName = tostring(properties.metadata.partnerName)
| extend nativeCloudAccountId = tostring(properties.resourceDetails.NativeCloudAccountId)
| project
    subscriptionId,
    assessmentKey,
    displayName,
    severity,
    statusCode,
    categories,
    threats,
    description,
    remediationDescription,
    isPreview,
    assessmentType,
    implementationEffort,
    userImpact,
    policyDefinitionId,
    statusChangeDate,
    firstEvaluationDate,
    statusCause,
    statusDescription,
    resourceSource,
    resourceDetailId,
    resourceName,
    resourceType,
    resourceGroup,
    partnerName,
    nativeCloudAccountId,
    id
| order by severity asc, subscriptionId asc, displayName asc
""".strip()

    all_findings: list[dict] = []
    skip = 0
    page_size = 1000

    print(f"\n[*] Querying Azure Resource Graph...")

    # Write Kusto query to temp file to avoid shell quoting issues
    kusto_file = tempfile.NamedTemporaryFile(
        mode="w", suffix=".kql", delete=False, encoding="utf-8"
    )
    kusto_file.write(kusto)
    kusto_file.close()
    kusto_path = kusto_file.name

    try:
        while True:
            cmd = [
                "az", "graph", "query",
                "-q", f"@{kusto_path}",
                "--first", str(page_size),
                "--skip", str(skip),
                "--output", "json",
            ]
            for sid in sub_ids:
                cmd += ["--subscriptions", sid]

            raw = run_cmd(cmd, timeout=120)
            if not raw:
                print(f"[!] Resource Graph query failed at skip={skip}")
                break

            try:
                result = json.loads(raw)
            except json.JSONDecodeError:
                print(f"[!] Failed to parse Resource Graph response: {raw[:200]}")
                break

            data = result.get("data", [])
            total = result.get("totalRecords", result.get("total_records", None))

            if not data:
                break

            for row in data:
                row["subscriptionName"] = sub_map.get(row.get("subscriptionId", ""), "Unknown")

            all_findings.extend(data)
            if total is not None:
                print(f"    Progress: {len(all_findings)}/{total}")
            else:
                print(f"    Progress: {len(all_findings)} (total unknown)")

            if total is not None and len(all_findings) >= total:
                break
            if len(data) < page_size:
                break
            skip += page_size
    finally:
        Path(kusto_path).unlink(missing_ok=True)

    print(f"\n[+] Total Azure findings: {len(all_findings)}")
    print_severity_breakdown(all_findings)

    sub_counts = Counter(f.get("subscriptionName", "Unknown") for f in all_findings)
    print("\n    By subscription:")
    for sub, cnt in sorted(sub_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"      {sub}: {cnt}")

    ts = timestamp()
    csv_path = output_dir / f"azure_all_findings_{ts}.csv"
    json_path = output_dir / f"azure_all_findings_{ts}.json"
    write_outputs(all_findings, csv_path, json_path)

    print(f"\n[*] Finished: {datetime.now().isoformat()}")
    return csv_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Azure — All CBU Findings Export")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    result = export_azure(output_dir)
    return 0 if result else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Cancelled")
        sys.exit(130)
