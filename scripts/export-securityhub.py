#!/usr/bin/env python3
"""Export SecurityHub findings from HAEA aggregator account to NDJSON.

Usage:
    python3 scripts/export-securityhub.py \
        --profile haea-sso \
        --region us-west-2 \
        --output data/haea-findings-raw.ndjson \
        [--max-findings 10000] \
        [--workflow-status NEW]

Outputs one ASFF finding per line (NDJSON). Respects 6 TPS rate limit.
Progress printed to stderr.
"""
import argparse
import json
import sys
import time

import boto3


def export_findings(
    profile: str,
    region: str,
    output: str,
    max_findings: int,
    workflow_status: str | None,
) -> None:
    session = boto3.Session(profile_name=profile, region_name=region)
    client = session.client("securityhub")

    filters: dict = {}
    if workflow_status:
        filters["WorkflowStatus"] = [
            {"Value": workflow_status, "Comparison": "EQUALS"}
        ]

    total = 0
    page = 0
    next_token: str | None = None

    with open(output, "w") as f:
        while True:
            kwargs: dict = {"MaxResults": 100}
            if filters:
                kwargs["Filters"] = filters
            if next_token:
                kwargs["NextToken"] = next_token

            try:
                resp = client.get_findings(**kwargs)
            except client.exceptions.ClientError as e:
                print(f"\n[!] API error on page {page}: {e}", file=sys.stderr)
                break

            findings = resp.get("Findings", [])
            for finding in findings:
                f.write(json.dumps(finding, default=str) + "\n")
                total += 1

            page += 1
            batch_size = len(findings)
            print(
                f"\r[+] Page {page}: {batch_size} findings (total: {total})",
                end="",
                file=sys.stderr,
            )

            if max_findings and total >= max_findings:
                print(
                    f"\n[+] Reached max findings limit ({max_findings})",
                    file=sys.stderr,
                )
                break

            next_token = resp.get("NextToken")
            if not next_token:
                print(f"\n[+] No more pages", file=sys.stderr)
                break

            # Rate limit: 6 TPS for GetFindings, sleep ~170ms between calls
            time.sleep(0.17)

    print(f"[+] Exported {total} findings to {output}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description="Export SecurityHub findings")
    parser.add_argument("--profile", required=True, help="AWS SSO profile name")
    parser.add_argument("--region", default="us-west-2", help="AWS region")
    parser.add_argument(
        "--output", default="data/haea-findings-raw.ndjson", help="Output NDJSON path"
    )
    parser.add_argument(
        "--max-findings", type=int, default=0, help="Max findings to export (0=all)"
    )
    parser.add_argument(
        "--workflow-status",
        default=None,
        help="Filter by WorkflowStatus (NEW, NOTIFIED, RESOLVED, SUPPRESSED)",
    )
    args = parser.parse_args()

    export_findings(
        profile=args.profile,
        region=args.region,
        output=args.output,
        max_findings=args.max_findings,
        workflow_status=args.workflow_status,
    )


if __name__ == "__main__":
    main()
