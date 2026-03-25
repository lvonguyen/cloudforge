#!/usr/bin/env python3
"""
Azure Security — All Tenants, All Sources, Single Output
Iterates all accessible tenants, all subs, all security sources.
Every finding includes _TenantId and _TenantName.

Sources per sub:
  1. Security Assessments (Defender for Cloud) — all statuses
  2. Advisor Recommendations (free) — security + reliability + cost + perf
  3. Secure Score Controls — score breakdown
  4. Security Alerts — threat detections

Usage:
    python export_azure_all_tenants.py
    python export_azure_all_tenants.py --output-dir ./my-outputs
"""

import argparse
import csv
import json
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent.parent / "export-outputs"
RAW_DIR = Path(__file__).parent.parent / "cspm" / "raw"


def run_az(args: list[str], timeout: int = 120) -> str | None:
    cmd = ["az"] + args
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0:
            stderr = r.stderr.strip()
            if "No registered resource provider" in stderr or "not registered" in stderr:
                return None
            real_errors = [l for l in stderr.split("\n")
                          if l.strip() and "WARNING" not in l and "SyntaxWarning" not in l]
            if real_errors:
                return None
        return r.stdout
    except subprocess.TimeoutExpired:
        return None


def discover_tenants() -> list[dict]:
    """Discover all tenants and their subs from cached az login sessions."""
    raw = run_az(["account", "list", "--output", "json", "--all"])
    if not raw:
        return []
    all_subs = json.loads(raw)
    tenants: dict[str, dict] = {}
    for s in all_subs:
        if s.get("state") != "Enabled":
            continue
        tid = s["tenantId"]
        if tid not in tenants:
            tenants[tid] = {
                "id": tid,
                "name": s.get("tenantDisplayName", tid[:8]),
                "subs": [],
            }
        tenants[tid]["subs"].append({
            "id": s["id"],
            "name": s["name"],
        })
    return sorted(tenants.values(), key=lambda t: len(t["subs"]), reverse=True)


def export_sub(sub_id: str, sub_name: str, tenant_id: str, tenant_name: str) -> list[dict]:
    """Export all security sources for a single subscription."""
    findings: list[dict] = []
    base = {"_TenantId": tenant_id, "_TenantName": tenant_name,
            "_SubscriptionId": sub_id, "_SubscriptionName": sub_name}

    # ── Source 1: Security Assessments ──
    raw = run_az(["security", "assessment", "list",
                  "--subscription", sub_id, "--output", "json"], timeout=90)
    if raw:
        try:
            for a in json.loads(raw):
                status = a.get("status", {})
                metadata = a.get("metadata", {}) or {}
                res_details = a.get("resourceDetails", {}) or {}
                a.update(base)
                a["_Source"] = "SecurityAssessment"
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
                findings.append(a)
        except json.JSONDecodeError:
            pass

    # ── Source 2: Advisor Recommendations ──
    raw = run_az(["advisor", "recommendation", "list",
                  "--subscription", sub_id, "--output", "json"], timeout=60)
    if raw:
        try:
            for r in json.loads(raw):
                r.update(base)
                r["_Source"] = "AdvisorRecommendation"
                r["_DisplayName"] = r.get("shortDescription", {}).get("problem", "")
                r["_Severity"] = r.get("impact", "Unknown")
                r["_StatusCode"] = "Active"
                r["_Categories"] = json.dumps([r.get("category", "")])
                r["_Description"] = r.get("shortDescription", {}).get("solution", "")
                r["_ResourceId"] = r.get("resourceMetadata", {}).get("resourceId", r.get("id", ""))
                r["_ResourceSource"] = r.get("resourceMetadata", {}).get("source", "")
                findings.append(r)
        except json.JSONDecodeError:
            pass

    # ── Source 3: Secure Score Controls ──
    raw = run_az(["security", "secure-score-controls", "list",
                  "--subscription", sub_id, "--output", "json"], timeout=60)
    if raw:
        try:
            for c in json.loads(raw):
                score = c.get("score", {}) or {}
                c.update(base)
                c["_Source"] = "SecureScoreControl"
                c["_DisplayName"] = c.get("displayName", "")
                c["_Severity"] = "High" if score.get("percentage", 1) < 0.5 else "Medium"
                c["_StatusCode"] = "Unhealthy" if score.get("percentage", 1) < 1.0 else "Healthy"
                c["_Description"] = c.get("displayName", "")
                c["_CurrentScore"] = score.get("current", 0)
                c["_MaxScore"] = score.get("max", 0)
                c["_ScorePercentage"] = score.get("percentage", 0)
                findings.append(c)
        except json.JSONDecodeError:
            pass

    # ── Source 4: Security Alerts ──
    raw = run_az(["security", "alert", "list",
                  "--subscription", sub_id, "--output", "json"], timeout=60)
    if raw:
        try:
            for a in json.loads(raw):
                a.update(base)
                a["_Source"] = "SecurityAlert"
                a["_DisplayName"] = a.get("alertDisplayName", "")
                a["_Severity"] = a.get("severity", "Unknown")
                a["_StatusCode"] = a.get("status", "Active")
                a["_Description"] = a.get("description", "")
                a["_ResourceId"] = a.get("compromisedEntity", "")
                a["_AlertType"] = a.get("alertType", "")
                a["_Intent"] = a.get("intent", "")
                findings.append(a)
        except json.JSONDecodeError:
            pass

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Azure Security — All Tenants Export")
    parser.add_argument("--output-dir", default=str(OUTPUT_DIR))
    args = parser.parse_args()
    output_dir = Path(args.output_dir)

    print("=" * 80)
    print("Azure Security — All Tenants, All Sources")
    print(f"Sources: Assessments + Advisor + Secure Score + Alerts")
    print(f"Filter: ALL statuses (healthy + unhealthy), ALL dates")
    print(f"Started: {datetime.now().isoformat()}")
    print("=" * 80)

    tenants = discover_tenants()
    if not tenants:
        print("[!] No tenants found. Run: az login")
        return 1

    total_subs = sum(len(t["subs"]) for t in tenants)
    print(f"\n[+] {len(tenants)} tenants, {total_subs} total subscriptions:")
    for t in tenants:
        print(f"    {t['name']:20s}  {t['id']}  ({len(t['subs'])} subs)")

    all_findings: list[dict] = []
    source_counts: Counter = Counter()
    tenant_counts: Counter = Counter()
    sub_idx = 0

    for t in tenants:
        tenant_id = t["id"]
        tenant_name = t["name"]
        print(f"\n{'─' * 60}")
        print(f"Tenant: {tenant_name} ({tenant_id})")
        print(f"{'─' * 60}")

        for sub in t["subs"]:
            sub_idx += 1
            sub_id = sub["id"]
            sub_name = sub["name"]
            print(f"\n  [{sub_idx}/{total_subs}] {sub_name}", end="", flush=True)

            findings = export_sub(sub_id, sub_name, tenant_id, tenant_name)
            all_findings.extend(findings)

            for f in findings:
                source_counts[f.get("_Source", "Unknown")] += 1
            tenant_counts[tenant_name] += len(findings)

            print(f"  -> {len(findings)}", flush=True)

    print(f"\n{'=' * 80}")
    print(f"[+] Total findings: {len(all_findings):,}")

    print("\n[*] Tenant breakdown:")
    for t, cnt in sorted(tenant_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"    {t}: {cnt:,}")

    print("\n[*] Source breakdown:")
    for src, cnt in sorted(source_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"    {src}: {cnt:,}")

    print("\n[*] Status breakdown:")
    status_counts = Counter(f.get("_StatusCode", "Unknown") for f in all_findings)
    for st, cnt in sorted(status_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"    {st}: {cnt:,}")

    print("\n[*] Severity breakdown:")
    sev_counts = Counter(f.get("_Severity", "Unknown") for f in all_findings)
    for sev, cnt in sorted(sev_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"    {sev}: {cnt:,}")

    # Write single unified output
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    json_path = output_dir / f"azure_all_tenants_{ts}.json"
    with open(json_path, "w", encoding="utf-8") as fp:
        json.dump(all_findings, fp, default=str)
    json_path.chmod(0o600)
    size_mb = json_path.stat().st_size / (1024 * 1024)
    print(f"\n[+] JSON: {json_path} ({size_mb:.1f} MB)")

    csv_path = output_dir / f"azure_all_tenants_{ts}.csv"
    csv_fields = [
        "_TenantId", "_TenantName", "_Source",
        "_SubscriptionId", "_SubscriptionName", "_DisplayName",
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

    if RAW_DIR.exists():
        raw_path = RAW_DIR / "azure_defender_assessments.json"
        with open(raw_path, "w", encoding="utf-8") as fp:
            json.dump(all_findings, fp, default=str)
        raw_path.chmod(0o600)
        print(f"[+] Raw:  {raw_path}")

    print(f"\n[*] Finished: {datetime.now().isoformat()}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Cancelled")
        sys.exit(130)
