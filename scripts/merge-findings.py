#!/usr/bin/env python3
"""Merge and deduplicate SecurityHub findings from multiple exports.

Reads NDJSON and JSON-array files, deduplicates by ASFF finding Id,
writes merged NDJSON output. Streams to avoid loading everything into memory.

Usage:
    python3 scripts/merge-findings.py \
        --output data/haea-findings-merged.ndjson \
        data/haea-findings-all.ndjson \
        testdata/cspm/raw/aws_securityhub_findings.json
"""
import argparse
import json
import sys
from typing import Iterator


def iter_ndjson(path: str) -> Iterator[dict]:
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def iter_json_array(path: str) -> Iterator[dict]:
    """Stream a JSON array without loading full file into memory."""
    import ijson
    with open(path, "rb") as f:
        for item in ijson.items(f, "item"):
            yield item


def iter_json_array_fallback(path: str) -> Iterator[dict]:
    """Fallback: load full JSON array (high memory)."""
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, list):
        yield from data
    elif isinstance(data, dict) and "Findings" in data:
        yield from data["Findings"]


def detect_format(path: str) -> str:
    with open(path) as f:
        first = f.read(10).strip()
    return "json_array" if first.startswith("[") else "ndjson"


def iter_file(path: str) -> Iterator[dict]:
    fmt = detect_format(path)
    if fmt == "ndjson":
        return iter_ndjson(path)
    try:
        import ijson  # noqa: F401
        return iter_json_array(path)
    except ImportError:
        print(
            f"[!] ijson not installed, loading full JSON array into memory for {path}",
            file=sys.stderr,
        )
        return iter_json_array_fallback(path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Merge + deduplicate findings")
    parser.add_argument("files", nargs="+", help="Input files (NDJSON or JSON array)")
    parser.add_argument(
        "--output",
        default="data/haea-findings-merged.ndjson",
        help="Output NDJSON path",
    )
    args = parser.parse_args()

    seen_ids: set[str] = set()
    total = 0
    dupes = 0
    products: dict[str, int] = {}

    with open(args.output, "w") as out:
        for path in args.files:
            file_count = 0
            file_dupes = 0
            print(f"[+] Processing {path}...", file=sys.stderr)

            for finding in iter_file(path):
                fid = finding.get("Id", "")
                if fid in seen_ids:
                    file_dupes += 1
                    dupes += 1
                    continue
                seen_ids.add(fid)
                out.write(json.dumps(finding, default=str) + "\n")
                total += 1
                file_count += 1

                product = finding.get("ProductName", "?")
                products[product] = products.get(product, 0) + 1

            print(
                f"    {file_count:,} unique + {file_dupes:,} dupes",
                file=sys.stderr,
            )

    print(f"\n[+] Merged: {total:,} unique findings ({dupes:,} duplicates removed)", file=sys.stderr)
    print(f"[+] Output: {args.output}", file=sys.stderr)
    print(f"\n[+] Products:", file=sys.stderr)
    for k, v in sorted(products.items(), key=lambda x: -x[1]):
        print(f"    {k:30s} {v:>8,}", file=sys.stderr)


if __name__ == "__main__":
    main()
