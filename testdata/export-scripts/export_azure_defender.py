#!/usr/bin/env python3
"""
Azure Security — Multi-Source Per-Subscription Export (HAEA tenant)
Pulls from all available security APIs, not just Defender assessments.

Sources:
  1. Security Assessments (Defender for Cloud) — all statuses
  2. Advisor Recommendations (free, all subs) — security + reliability + cost + perf
  3. Secure Score Controls — score breakdown per control
  4. Security Alerts — active threat detections

Usage:
    python export_azure_defender.py
    python export_azure_defender.py --tenant bd29b3ab-aaa2-425a-b882-9e7f73283ca6
"""

import argparse
import csv
import json
import os
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path


HAEA_TENANT = "bd29b3ab-aaa2-425a-b882-9e7f73283ca6"

TENANT_NAMES = {
    "bd29b3ab-aaa2-425a-b882-9e7f73283ca6": "HMGNA",
    "becdc98a-bfc9-4ffa-ade6-892577ce9a58": "HMA",
    "5fed94a0-4129-44a0-b507-a83a5c9e6dac": "KUS",
    "9e0faa00-ea9a-4a44-b68c-8c1f2cc9a765": "PVD",
}
OUTPUT_DIR = Path(__file__).parent.parent / "export-outputs"
RAW_DIR = Path(__file__).parent.parent / "cspm" / "raw"


def run_az(args: list[str], timeout: int = 120) -> str | None:
    cmd = ["az"] + args
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0:
            stderr = r.stderr.strip()
            # Filter out common non-fatal warnings
            if "No registered resource provider" in stderr or "not registered" in stderr:
                return None
            # Only fail on real errors (not just warnings)
            real_errors = [l for l in stderr.split("\n") if l.strip() and "WARNING" not in l and "SyntaxWarning" not in l]
            if real_errors:
                return None
        return r.stdout
    except subprocess.TimeoutExpired:
        return None


def export_azure(tenant_id: str, output_dir: Path) -> int:
    print("=" * 80)
    print("Azure Security — Multi-Source Per-Subscription Export")
    print(f"Tenant: {tenant_id}")
    print(f"Sources: Assessments + Advisor + Secure Score + Alerts")
    print(f"Filter: ALL statuses, ALL dates")
    print(f"Started: {datetime.now().isoformat()}")
    print("=" * 80)

    # Get all enabled subs for this tenant
    raw = run_az(["account", "list", "--output", "json", "--all"])
    if not raw:
        print("[!] Failed to list subscriptions")
        return 1

    all_subs = json.loads(raw)
    subs = [s for s in all_subs if s.get("state") == "Enabled" and s.get("tenantId") == tenant_id]
    print(f"\n[+] {len(subs)} enabled subscriptions in tenant")

    all_findings: list[dict] = []
    source_counts: dict[str, int] = Counter()
    success = 0
    failed = 0

    for idx, sub in enumerate(subs, 1):
        sub_id = sub["id"]
        sub_name = sub["name"]
        sub_total = 0
        print(f"\n[{idx}/{len(subs)}] {sub_name}", flush=True)

        # ── Source 1: Security Assessments (Defender for Cloud) ──
        raw = run_az([
            "security", "assessment", "list",
            "--subscription", sub_id,
            "--output", "json",
        ], timeout=90)

        if raw:
            try:
                assessments = json.loads(raw)
                for a in assessments:
                    status = a.get("status", {})
                    metadata = a.get("metadata", {}) or {}
                    res_details = a.get("resourceDetails", {}) or {}
                    a["_Source"] = "SecurityAssessment"
                    a["_SubscriptionId"] = sub_id
                    a["_SubscriptionName"] = sub_name
                    a["_DisplayName"] = a.get("displayName", "")
                    a["_Severity"] = metadata.get("severity", "Unknown")
                    a["_StatusCode"] = status.get("code", "")
                    a["_StatusChangeDate"] = status.get("statusChangeDate", "")
                    a["_FirstEvaluationDate"] = status.get("firstEvaluationDate", "")
                    a["_Categories"] = json.dumps(metadata.get("categories", []))
                    a["_Threats"] = json.dumps(metadata.get("threats", []))
                    a["_Description"] = metadata.get("description", "")
                    a["_RemediationDescription"] = metadata.get("remediationDescription", "")
                    a["_ResourceId"] = res_details.get("id", a.get("id", ""))
                    a["_ResourceSource"] = res_details.get("source", "")
                    a["_ImplementationEffort"] = metadata.get("implementationEffort", "")
                    a["_UserImpact"] = metadata.get("userImpact", "")
                all_findings.extend(assessments)
                source_counts["SecurityAssessment"] += len(assessments)
                sub_total += len(assessments)
            except json.JSONDecodeError:
                pass

        # ── Source 2: Advisor Recommendations (free, all subs) ──
        raw = run_az([
            "advisor", "recommendation", "list",
            "--subscription", sub_id,
            "--output", "json",
        ], timeout=60)

        if raw:
            try:
                recs = json.loads(raw)
                for r in recs:
                    r["_Source"] = "AdvisorRecommendation"
                    r["_SubscriptionId"] = sub_id
                    r["_SubscriptionName"] = sub_name
                    r["_DisplayName"] = r.get("shortDescription", {}).get("problem", "")
                    r["_Severity"] = r.get("impact", "Unknown")
                    r["_StatusCode"] = "Active"
                    r["_Categories"] = json.dumps([r.get("category", "")])
                    r["_Description"] = r.get("shortDescription", {}).get("solution", "")
                    r["_ResourceId"] = r.get("resourceMetadata", {}).get("resourceId", r.get("id", ""))
                    r["_ResourceSource"] = r.get("resourceMetadata", {}).get("source", "")
                all_findings.extend(recs)
                source_counts["AdvisorRecommendation"] += len(recs)
                sub_total += len(recs)
            except json.JSONDecodeError:
                pass

        # ── Source 3: Secure Score Controls ──
        raw = run_az([
            "security", "secure-score-controls", "list",
            "--subscription", sub_id,
            "--output", "json",
        ], timeout=60)

        if raw:
            try:
                controls = json.loads(raw)
                for c in controls:
                    score = c.get("score", {}) or {}
                    c["_Source"] = "SecureScoreControl"
                    c["_SubscriptionId"] = sub_id
                    c["_SubscriptionName"] = sub_name
                    c["_DisplayName"] = c.get("displayName", "")
                    c["_Severity"] = "High" if score.get("percentage", 1) < 0.5 else "Medium"
                    c["_StatusCode"] = "Unhealthy" if score.get("percentage", 1) < 1.0 else "Healthy"
                    c["_Description"] = c.get("displayName", "")
                    c["_CurrentScore"] = score.get("current", 0)
                    c["_MaxScore"] = score.get("max", 0)
                    c["_ScorePercentage"] = score.get("percentage", 0)
                    c["_UnhealthyCount"] = c.get("unhealthyResourceCount", 0)
                    c["_HealthyCount"] = c.get("healthyResourceCount", 0)
                all_findings.extend(controls)
                source_counts["SecureScoreControl"] += len(controls)
                sub_total += len(controls)
            except json.JSONDecodeError:
                pass

        # ── Source 4: Security Alerts ──
        raw = run_az([
            "security", "alert", "list",
            "--subscription", sub_id,
            "--output", "json",
        ], timeout=60)

        if raw:
            try:
                alerts = json.loads(raw)
                for a in alerts:
                    a["_Source"] = "SecurityAlert"
                    a["_SubscriptionId"] = sub_id
                    a["_SubscriptionName"] = sub_name
                    a["_DisplayName"] = a.get("alertDisplayName", "")
                    a["_Severity"] = a.get("severity", "Unknown")
                    a["_StatusCode"] = a.get("status", "Active")
                    a["_Description"] = a.get("description", "")
                    a["_ResourceId"] = a.get("compromisedEntity", "")
                    a["_AlertType"] = a.get("alertType", "")
                    a["_Intent"] = a.get("intent", "")
                    a["_StartTime"] = a.get("startTimeUtc", "")
                    a["_EndTime"] = a.get("endTimeUtc", "")
                all_findings.extend(alerts)
                source_counts["SecurityAlert"] += len(alerts)
                sub_total += len(alerts)
            except json.JSONDecodeError:
                pass

        print(f"    {sub_total} total", flush=True)
        if sub_total > 0:
            success += 1
        else:
            failed += 1

    print(f"\n{'=' * 80}")
    print(f"[+] Total Azure findings: {len(all_findings):,}")
    print(f"    Subs succeeded: {success}")
    print(f"    Subs failed:    {failed}")

    # Source breakdown
    print("\n[*] Source breakdown:")
    for src, cnt in sorted(source_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"    {src}: {cnt:,}")

    # Status breakdown
    print("\n[*] Status breakdown:")
    status_counts = Counter(f.get("_StatusCode", "Unknown") for f in all_findings)
    for st, cnt in sorted(status_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"    {st}: {cnt:,}")

    # Severity breakdown
    print("\n[*] Severity breakdown:")
    sev_counts = Counter(f.get("_Severity", "Unknown") for f in all_findings)
    for sev, cnt in sorted(sev_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"    {sev}: {cnt:,}")

    # Subscription breakdown (top 10)
    print("\n[*] Top 10 subscriptions:")
    sub_counts = Counter(f.get("_SubscriptionName", "Unknown") for f in all_findings)
    for sub, cnt in sub_counts.most_common(10):
        print(f"    {sub}: {cnt:,}")

    # Write outputs
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    json_path = output_dir / f"azure_all_security_{ts}.json"
    with open(json_path, "w", encoding="utf-8") as fp:
        json.dump(all_findings, fp, default=str)
    json_path.chmod(0o600)
    size_mb = json_path.stat().st_size / (1024 * 1024)
    print(f"\n[+] JSON: {json_path} ({size_mb:.1f} MB)")

    # Flat CSV
    csv_path = output_dir / f"azure_all_security_{ts}.csv"
    csv_fields = [
        "_Source", "_SubscriptionId", "_SubscriptionName", "_DisplayName",
        "_Severity", "_StatusCode", "_StatusChangeDate", "_FirstEvaluationDate",
        "_Categories", "_Threats", "_ResourceId", "_ResourceSource",
        "_ImplementationEffort", "_UserImpact", "_Description",
        "_RemediationDescription", "_AlertType", "_Intent",
    ]
    with open(csv_path, "w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=csv_fields, extrasaction="ignore")
        writer.writeheader()
        for f in all_findings:
            writer.writerow({k: str(f.get(k, "")).replace("\n", " ") for k in csv_fields})
    csv_path.chmod(0o600)
    print(f"[+] CSV:  {csv_path} ({len(all_findings):,} rows)")

    # Write to raw dir for transform script
    if RAW_DIR.exists():
        raw_path = RAW_DIR / "azure_defender_assessments.json"
        with open(raw_path, "w", encoding="utf-8") as fp:
            json.dump(all_findings, fp, default=str)
        raw_path.chmod(0o600)
        print(f"[+] Raw:  {raw_path}")

    print(f"\n[*] Finished: {datetime.now().isoformat()}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Azure Security — Multi-Source Export")
    parser.add_argument("--tenant", default=HAEA_TENANT)
    parser.add_argument("--output-dir", default=str(OUTPUT_DIR))
    args = parser.parse_args()
    return export_azure(args.tenant, Path(args.output_dir))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Cancelled")
        sys.exit(130)
