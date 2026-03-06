#!/usr/bin/env python3
"""
GCP Security Command Center — All CBU Findings Export
Org-level, all projects, all severities, all fields. CSV + JSON.

Usage:
    python query_gcp_all_findings.py
    python query_gcp_all_findings.py --org-id 654662756615
    python query_gcp_all_findings.py --output-dir ./my-outputs
"""

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from findings_export_utils import (
    DEFAULT_OUTPUT_DIR,
    print_severity_breakdown,
    run_cmd,
    timestamp,
    write_outputs,
)


def export_gcp(output_dir: Path, org_id: str) -> Path | None:
    print("=" * 80)
    print("GCP Security Command Center")
    print(f"Organization: {org_id} — all projects, all severities")
    print(f"Started: {datetime.now().isoformat()}")
    print("=" * 80)

    print("[*] Querying SCC for ACTIVE, non-muted findings (all severities)...")
    print("    This may take a few minutes for large orgs.\n")

    cmd = [
        "gcloud", "scc", "findings", "list",
        f"organizations/{org_id}/sources/-",
        "--filter=state=\"ACTIVE\" AND NOT mute=\"MUTED\"",
        "--format=json",
        "--page-size=1000",
    ]

    raw = run_cmd(cmd, timeout=600)
    if not raw:
        print("[!] GCP SCC query failed")
        print("    Verify: gcloud auth login + org-level SCC access")
        return None

    try:
        findings_raw = json.loads(raw)
    except json.JSONDecodeError:
        print(f"[!] Failed to parse SCC response: {raw[:200]}")
        return None

    if not isinstance(findings_raw, list):
        print(f"[!] Unexpected SCC response type: {type(findings_raw).__name__}")
        return None
    print(f"[+] Raw SCC results: {len(findings_raw)}")

    # Merge finding + resource into single flat records
    findings: list[dict] = []
    for item in findings_raw:
        record: dict[str, Any] = {}
        if "finding" in item:
            for k, v in item["finding"].items():
                record[f"finding.{k}"] = v
        if "resource" in item:
            for k, v in item["resource"].items():
                record[f"resource.{k}"] = v
        # Promote key fields to top level for easy filtering
        record["severity"] = item.get("finding", {}).get("severity", "UNSPECIFIED")
        record["category"] = item.get("finding", {}).get("category", "")
        record["state"] = item.get("finding", {}).get("state", "")
        record["projectDisplayName"] = item.get("resource", {}).get("projectDisplayName", "")
        findings.append(record)

    print(f"[+] Total GCP findings: {len(findings)}")
    print_severity_breakdown(findings)

    # Project breakdown
    proj_counts = Counter(f.get("projectDisplayName", "Unknown") for f in findings)
    print(f"\n    Across {len(proj_counts)} projects:")
    for proj, cnt in sorted(proj_counts.items(), key=lambda x: x[1], reverse=True)[:20]:
        print(f"      {proj}: {cnt}")
    if len(proj_counts) > 20:
        print(f"      ... and {len(proj_counts) - 20} more")

    ts = timestamp()
    csv_path = output_dir / f"gcp_all_findings_{ts}.csv"
    json_path = output_dir / f"gcp_all_findings_{ts}.json"
    write_outputs(findings, csv_path, json_path)

    print(f"\n[*] Finished: {datetime.now().isoformat()}")
    return csv_path


def main() -> int:
    parser = argparse.ArgumentParser(description="GCP SCC — All CBU Findings Export")
    parser.add_argument("--org-id", default=os.environ.get("GCP_ORG_ID", "654662756615"))
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    result = export_gcp(output_dir, org_id=args.org_id)
    return 0 if result else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Cancelled")
        sys.exit(130)
