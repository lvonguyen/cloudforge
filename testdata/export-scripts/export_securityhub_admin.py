#!/usr/bin/env python3
"""
SecurityHub + GuardDuty — Aggregated Admin Export
Queries directly from the SecurityHub admin account (all member findings visible).

Usage:
    python export_securityhub_admin.py
    python export_securityhub_admin.py --profile haea-sso --region us-west-2
    python export_securityhub_admin.py --max-findings 10000
    python export_securityhub_admin.py --severity CRITICAL HIGH MEDIUM

Requires: boto3 (uv pip install boto3)
"""

import argparse
import json
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    print("[!] boto3 not installed. Run: uv pip install boto3")
    sys.exit(1)


def build_account_lookup(session: boto3.Session) -> dict[str, str]:
    """Build account ID -> friendly name map. Tries Organizations API, falls back to SecurityHub members, then known list."""
    lookup: dict[str, str] = {}

    # Try Organizations first
    try:
        org = session.client("organizations")
        paginator = org.get_paginator("list_accounts")
        for page in paginator.paginate():
            for acct in page["Accounts"]:
                lookup[acct["Id"]] = acct.get("Name", acct["Id"])
        print(f"[+] Account lookup: {len(lookup)} accounts from Organizations")
        return lookup
    except ClientError:
        pass

    # Try SecurityHub ListMembers
    try:
        sh = session.client("securityhub")
        paginator = sh.get_paginator("list_members")
        for page in paginator.paginate(OnlyAssociated=True):
            for member in page.get("Members", []):
                mid = member.get("AccountId", "")
                # SecurityHub doesn't give names, but at least we get IDs
                lookup[mid] = mid
    except ClientError:
        pass

    # Merge known account names from hardcoded list
    known = {
        "696796209136": "account-hma-gita-prd",
        "897722706166": "account-hma-bldsearch-prd",
        "713881799553": "account-hma-is-prd",
        "897729138604": "account-hma-incentiveapp-prd",
        "992382715597": "account-hma-bl4b-prod",
        "975050332682": "account-hma-bl4b-stg",
        "034362060116": "account-hma-is-stg",
        "767828722787": "account-hma-incentiveapp-stg",
        "358269447795": "account-hma-gita-stg",
        "337909747443": "account-hma-bldsearch-stg",
        "183631338158": "account-hma-e2ee-dev",
        "575108920204": "account-hma-gita-dev",
        "891377211888": "account-hma-bl4b-dev",
        "992382643245": "account-hma-incentiveapp-dev",
        "010438488970": "account-hma-bldsearch-dev",
        "026090558926": "account-hma-is-dev",
        "700736432587": "account-hma-gita-qa",
        "439722141349": "account-hma-iac",
        "982081080068": "account-hma-is-iac",
        "675810670026": "account-hma-shared",
        "209479266693": "account-hma-is-dr",
        "831926608679": "account-haea-security",
    }
    for k, v in known.items():
        if k not in lookup or lookup[k] == k:
            lookup[k] = v

    print(f"[+] Account lookup: {len(lookup)} accounts (known list + SH members)")
    return lookup


def extract_resource_name(finding: dict) -> str:
    """Extract a human-readable resource name from finding."""
    resources = finding.get("Resources", [])
    if not resources:
        return ""
    res = resources[0]

    # Try Tags.Name first (EC2, RDS, etc.)
    tags = res.get("Tags", {})
    if isinstance(tags, dict) and tags.get("Name"):
        return tags["Name"]

    # Parse from ARN/ID — take the last segment
    res_id = res.get("Id", "")
    if "/" in res_id:
        return res_id.rsplit("/", 1)[-1]
    if ":" in res_id and not res_id.startswith("arn:"):
        return res_id.rsplit(":", 1)[-1]

    return res_id


def export(
    profile: str,
    region: str,
    output_dir: Path,
    max_findings: int,
    severities: list[str] | None,
) -> int:
    print("=" * 80)
    print("SecurityHub + GuardDuty — Aggregated Admin Export")
    print(f"Profile: {profile}  Region: {region}")
    if max_findings:
        print(f"Max findings: {max_findings}")
    if severities:
        print(f"Severities: {', '.join(severities)}")
    print(f"Started: {datetime.now().isoformat()}")
    print("=" * 80)

    # Auth
    try:
        session = boto3.Session(profile_name=profile, region_name=region)
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        print(f"\n[+] Authenticated: {identity['Arn']}")
        print(f"    Account: {identity['Account']}")
    except (ClientError, NoCredentialsError) as e:
        print(f"[!] Auth failed: {e}")
        return 1

    # Account name lookup
    account_names = build_account_lookup(session)

    # Build filters: RecordState=ACTIVE, WorkflowStatus=NEW|NOTIFIED
    filters: dict = {
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        "WorkflowStatus": [
            {"Value": "NEW", "Comparison": "EQUALS"},
            {"Value": "NOTIFIED", "Comparison": "EQUALS"},
        ],
    }
    if severities:
        filters["SeverityLabel"] = [
            {"Value": s, "Comparison": "EQUALS"} for s in severities
        ]

    sh = session.client("securityhub", region_name=region)

    # Verify SecurityHub is enabled
    try:
        hub = sh.describe_hub()
        print(f"[+] SecurityHub: {hub['HubArn']}")
    except ClientError as e:
        print(f"[!] SecurityHub not available: {e}")
        return 1

    # Paginate through all findings with retry/backoff for rate limiting
    print(f"\n[*] Exporting findings (all products: SecurityHub, Inspector, GuardDuty, etc.)...")
    all_findings: list[dict] = []
    page_count = 0
    t0 = time.monotonic()
    next_token: str | None = None
    consecutive_errors = 0
    max_retries = 5
    page_delay = 0.45  # seconds between pages to stay under rate limit

    while True:
        try:
            kwargs: dict = {"Filters": filters, "MaxResults": 100}
            if next_token:
                kwargs["NextToken"] = next_token

            response = sh.get_findings(**kwargs)
            consecutive_errors = 0  # reset on success

            batch = response.get("Findings", [])
            next_token = response.get("NextToken")
            page_count += 1

            for f in batch:
                acct_id = f.get("AwsAccountId", "")
                res = f.get("Resources", [{}])[0]

                # Enrich with requested fields
                f["_AccountId"] = acct_id
                f["_AccountName"] = account_names.get(acct_id, acct_id)
                f["_ResourceArn"] = res.get("Id", "")
                f["_ResourceType"] = res.get("Type", "")
                f["_ResourceName"] = extract_resource_name(f)
                f["_DateCreated"] = f.get("CreatedAt", "")
                f["_DateUpdated"] = f.get("UpdatedAt", "")
                f["_DateFirstObserved"] = f.get("FirstObservedAt", "")
                f["_SeverityLabel"] = f.get("Severity", {}).get("Label", "UNKNOWN")
                f["_SeverityNormalized"] = f.get("Severity", {}).get("Normalized", 0)
                f["_ProductName"] = f.get("ProductName", "")
                f["_GeneratorId"] = f.get("GeneratorId", "")
                f["_WorkflowStatus"] = f.get("Workflow", {}).get("Status", "")
                f["_ComplianceStatus"] = f.get("Compliance", {}).get("Status", "")
                f["_Title"] = f.get("Title", "")

                all_findings.append(f)

            # Progress
            elapsed = time.monotonic() - t0
            rate = len(all_findings) / elapsed if elapsed > 0 else 0
            print(
                f"\r    Page {page_count}: {len(all_findings):,} findings"
                f"  ({rate:.0f}/sec, {elapsed:.0f}s elapsed)",
                end="",
                flush=True,
            )

            if max_findings and len(all_findings) >= max_findings:
                all_findings = all_findings[:max_findings]
                print(f"\n[*] Reached max_findings limit ({max_findings})")
                break

            if not next_token:
                print(f"\n[*] All pages exhausted")
                break

            time.sleep(page_delay)

        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("TooManyRequestsException", "ThrottlingException"):
                consecutive_errors += 1
                if consecutive_errors > max_retries:
                    print(f"\n[!] Max retries ({max_retries}) exceeded. Saving partial results...")
                    break
                backoff = min(2 ** consecutive_errors, 30)
                print(
                    f"\n    [*] Rate limited — backing off {backoff}s"
                    f" (retry {consecutive_errors}/{max_retries})",
                    end="",
                    flush=True,
                )
                time.sleep(backoff)
            else:
                print(f"\n[!] API error after {len(all_findings):,} findings: {e}")
                if not all_findings:
                    return 1
                print("    Saving partial results...")
                break

    elapsed = time.monotonic() - t0
    print(f"\n\n{'=' * 80}")
    print(f"[+] Total findings: {len(all_findings)}")
    print(f"    Pages: {page_count}")
    print(f"    Time: {elapsed:.1f}s ({len(all_findings)/elapsed:.0f} findings/sec)")

    # Severity breakdown
    print("\n[*] Severity breakdown:")
    sev_counts = Counter(f["_SeverityLabel"] for f in all_findings)
    for sev, cnt in sorted(sev_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"    {sev}: {cnt:,}")

    # Product breakdown (SecurityHub vs GuardDuty vs Inspector)
    print("\n[*] Product breakdown:")
    prod_counts = Counter(f["_ProductName"] for f in all_findings)
    for prod, cnt in sorted(prod_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"    {prod}: {cnt:,}")

    # Account breakdown (top 10)
    print("\n[*] Top 10 accounts:")
    acct_counts = Counter(f["_AccountName"] for f in all_findings)
    for acct, cnt in acct_counts.most_common(10):
        print(f"    {acct}: {cnt:,}")

    # Write outputs
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Full ASFF JSON (for transform-real-findings.mjs)
    json_path = output_dir / f"aws_securityhub_guardduty_{ts}.json"
    with open(json_path, "w", encoding="utf-8") as fp:
        json.dump(all_findings, fp, default=str)
    json_path.chmod(0o600)
    size_mb = json_path.stat().st_size / (1024 * 1024)
    print(f"\n[+] JSON: {json_path} ({size_mb:.1f} MB)")

    # Flat summary CSV with requested fields
    import csv

    csv_path = output_dir / f"aws_securityhub_guardduty_{ts}.csv"
    csv_fields = [
        "_AccountId", "_AccountName", "_ResourceArn", "_ResourceType",
        "_ResourceName", "_DateCreated", "_DateUpdated", "_SeverityLabel",
        "_SeverityNormalized", "_ProductName", "_GeneratorId",
        "_WorkflowStatus", "_ComplianceStatus", "_Title",
    ]
    with open(csv_path, "w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=csv_fields, extrasaction="ignore")
        writer.writeheader()
        for f in all_findings:
            writer.writerow({k: f.get(k, "") for k in csv_fields})
    csv_path.chmod(0o600)
    print(f"[+] CSV:  {csv_path} ({len(all_findings):,} rows)")

    # Also write to raw dir for transform script
    raw_dir = Path(__file__).parent.parent / "cspm" / "raw"
    if raw_dir.exists():
        raw_path = raw_dir / "aws_securityhub_findings.json"
        with open(raw_path, "w", encoding="utf-8") as fp:
            json.dump(all_findings, fp, default=str)
        raw_path.chmod(0o600)
        print(f"[+] Raw:  {raw_path} (for transform-real-findings.mjs)")

    print(f"\n[*] Finished: {datetime.now().isoformat()}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="SecurityHub + GuardDuty — Aggregated Admin Export"
    )
    parser.add_argument("--profile", default="haea-sso")
    parser.add_argument("--region", default="us-west-2")
    parser.add_argument("--output-dir", default=str(Path(__file__).parent.parent / "export-outputs"))
    parser.add_argument("--max-findings", type=int, default=0,
                        help="Max findings to export (0 = unlimited)")
    parser.add_argument("--severity", nargs="+",
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"],
                        help="Filter by severity (default: all)")
    args = parser.parse_args()

    return export(
        profile=args.profile,
        region=args.region,
        output_dir=Path(args.output_dir),
        max_findings=args.max_findings,
        severities=args.severity,
    )


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Cancelled")
        sys.exit(130)
