#!/usr/bin/env python3
"""
AWS Security Hub — All CBU Findings Export
Cross-account iteration, all severities, all fields. CSV + JSON.

Usage:
    python query_aws_all_findings.py
    python query_aws_all_findings.py --profile haea-hma-remediation
    python query_aws_all_findings.py --output-dir ./my-outputs

Requires: boto3 (uv pip install boto3)
"""

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    print("[!] boto3 not installed. Run: uv pip install boto3")
    sys.exit(1)

from findings_export_utils import (
    DEFAULT_OUTPUT_DIR,
    print_severity_breakdown,
    timestamp,
    write_outputs,
)

# Known AWS accounts (HMA scope — extend as cross-account roles are added)
AWS_ACCOUNTS = [
    # Production (5)
    {"id": "696796209136", "name": "account-hma-gita-prd", "env": "Production"},
    {"id": "897722706166", "name": "account-hma-bldsearch-prd", "env": "Production"},
    {"id": "713881799553", "name": "account-hma-is-prd", "env": "Production"},
    {"id": "897729138604", "name": "account-hma-incentiveapp-prd", "env": "Production"},
    {"id": "992382715597", "name": "account-hma-bl4b-prod", "env": "Production"},
    # Staging (5)
    {"id": "975050332682", "name": "account-hma-bl4b-stg", "env": "Staging"},
    {"id": "034362060116", "name": "account-hma-is-stg", "env": "Staging"},
    {"id": "767828722787", "name": "account-hma-incentiveapp-stg", "env": "Staging"},
    {"id": "358269447795", "name": "account-hma-gita-stg", "env": "Staging"},
    {"id": "337909747443", "name": "account-hma-bldsearch-stg", "env": "Staging"},
    # Development (6)
    {"id": "183631338158", "name": "account-hma-e2ee-dev", "env": "Development"},
    {"id": "575108920204", "name": "account-hma-gita-dev", "env": "Development"},
    {"id": "891377211888", "name": "account-hma-bl4b-dev", "env": "Development"},
    {"id": "992382643245", "name": "account-hma-incentiveapp-dev", "env": "Development"},
    {"id": "010438488970", "name": "account-hma-bldsearch-dev", "env": "Development"},
    {"id": "026090558926", "name": "account-hma-is-dev", "env": "Development"},
    # QA (1)
    {"id": "700736432587", "name": "account-hma-gita-qa", "env": "QA"},
    # Infrastructure & Shared (3)
    {"id": "439722141349", "name": "account-hma-iac", "env": "Infrastructure"},
    {"id": "982081080068", "name": "account-hma-is-iac", "env": "Infrastructure"},
    {"id": "675810670026", "name": "account-hma-shared", "env": "Shared Services"},
    # DR (1)
    {"id": "209479266693", "name": "account-hma-is-dr", "env": "DR"},
]

AWS_CROSS_ACCOUNT_ROLE = os.environ.get(
    "AWS_CROSS_ACCOUNT_ROLE", "HMA-SecurityRemediation-CrossAccount"
)
AWS_EXTERNAL_ID = os.environ.get("AWS_EXTERNAL_ID", "HMA-SecurityRemediation-2025")


def export_aws(output_dir: Path, profile: str = "haea-hma-remediation") -> Path | None:
    print("=" * 80)
    print("AWS Security Hub")
    print(f"Profile: {profile} — all accounts, all severities")
    print(f"Started: {datetime.now().isoformat()}")
    print("=" * 80)

    # Authenticate
    try:
        base_session = boto3.Session(profile_name=profile)
        sts = base_session.client("sts")
        identity = sts.get_caller_identity()
        print(f"[+] Authenticated: {identity['Arn']}")
    except (ClientError, NoCredentialsError) as e:
        print(f"[!] AWS auth failed: {e}")
        print("    Run: aws-sso-login haea-sso")
        return None

    # Try aggregated query (if this account is SH delegated admin)
    print("\n[*] Checking Security Hub admin status...")
    try:
        sh_admin = base_session.client("securityhub", region_name="us-east-1")
        admin_accounts = sh_admin.list_organization_admin_accounts()
        print(f"    Admin accounts: {admin_accounts.get('AdminAccounts', [])}")
    except ClientError:
        print("    Not an Organizations/SH admin — using per-account iteration")

    # Build account list: known + discovered
    accounts = list(AWS_ACCOUNTS)

    print(f"\n[*] Attempting Organizations account discovery...")
    try:
        org_client = base_session.client("organizations")
        paginator = org_client.get_paginator("list_accounts")
        known_ids = {a["id"] for a in accounts}
        discovered = []
        for page in paginator.paginate():
            for acct in page["Accounts"]:
                if acct["Id"] not in known_ids and acct["Status"] == "ACTIVE":
                    discovered.append({
                        "id": acct["Id"],
                        "name": acct.get("Name", acct["Id"]),
                        "env": "Discovered",
                    })
        if discovered:
            print(f"    [+] Discovered {len(discovered)} additional accounts")
            for d in discovered:
                print(f"        {d['name']} ({d['id']})")
            accounts.extend(discovered)
        else:
            print("    No additional accounts found")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("AccessDeniedException", "AWSOrganizationsNotInUseException"):
            print(f"    Organizations not available ({code})")
        else:
            print(f"    Organizations error: {e}")
    except (boto3.exceptions.Boto3Error, Exception) as e:
        print(f"    Organizations discovery failed: {type(e).__name__}: {e}")

    print(f"\n[*] Querying {len(accounts)} accounts...")

    all_findings: list[dict] = []
    success_count = 0
    fail_count = 0
    sts_client = base_session.client("sts")

    for idx, acct in enumerate(accounts, 1):
        acct_id = acct["id"]
        acct_name = acct["name"]
        acct_env = acct["env"]

        print(f"\n[{idx}/{len(accounts)}] {acct_name} ({acct_id}) — {acct_env}")

        # Assume cross-account role
        try:
            role_arn = f"arn:aws:iam::{acct_id}:role/{AWS_CROSS_ACCOUNT_ROLE}"
            assumed = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=f"AllFindings-{acct_id}",
                ExternalId=AWS_EXTERNAL_ID,
                DurationSeconds=3600,
            )
            creds = assumed["Credentials"]
            target_session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
            )
        except ClientError as e:
            print(f"    [!] Role assumption failed: {e.response['Error']['Code']}")
            fail_count += 1
            continue

        # Query Security Hub — no severity filter, active records only
        regions = ["us-east-1", "us-west-2"]
        for region in regions:
            try:
                sh = target_session.client("securityhub", region_name=region)

                try:
                    sh.describe_hub()
                except ClientError as e:
                    if e.response["Error"]["Code"] == "InvalidAccessException":
                        continue
                    raise

                filters = {
                    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                }

                paginator = sh.get_paginator("get_findings")
                acct_findings: list[dict] = []

                for page in paginator.paginate(Filters=filters, MaxResults=100):
                    for finding in page.get("Findings", []):
                        finding["_AccountName"] = acct_name
                        finding["_AccountEnvironment"] = acct_env
                        finding["_QueryRegion"] = region
                        sev = finding.get("Severity", {})
                        finding["_SeverityLabel"] = (
                            sev.get("Label", "UNKNOWN") if isinstance(sev, dict)
                            else str(sev)
                        )
                        acct_findings.append(finding)

                all_findings.extend(acct_findings)
                print(f"    {region}: {len(acct_findings)} findings")
                success_count += 1
                break  # Only first region with SH enabled

            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "AccessDeniedException":
                    print(f"    {region}: Access denied")
                else:
                    print(f"    {region}: {code}")
            except Exception as e:
                print(f"    {region}: Unexpected error — {e}")

    print(f"\n{'=' * 80}")
    print(f"[+] Total AWS findings: {len(all_findings)}")
    print(f"    Accounts succeeded: {success_count}")
    print(f"    Accounts failed:    {fail_count}")

    print_severity_breakdown(all_findings, severity_key="_SeverityLabel")

    ts = timestamp()
    csv_path = output_dir / f"aws_all_findings_{ts}.csv"
    json_path = output_dir / f"aws_all_findings_{ts}.json"
    write_outputs(all_findings, csv_path, json_path)

    print(f"\n[*] Finished: {datetime.now().isoformat()}")
    return csv_path


def main() -> int:
    parser = argparse.ArgumentParser(description="AWS Security Hub — All CBU Findings Export")
    parser.add_argument("--profile", default="haea-hma-remediation")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    result = export_aws(output_dir, profile=args.profile)
    return 0 if result else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Cancelled")
        sys.exit(130)
