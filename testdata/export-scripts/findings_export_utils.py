"""Shared utilities for all-CBU findings export scripts."""

import csv
import json
import os
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

DEFAULT_OUTPUT_DIR = Path(__file__).parent.parent / "export-outputs"


def flatten_dict(d: dict, parent_key: str = "", sep: str = ".") -> dict:
    """Recursively flatten nested dict. Lists become JSON strings."""
    items: list[tuple[str, Any]] = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep).items())
        elif isinstance(v, list):
            items.append((new_key, json.dumps(v, default=str) if v else ""))
        else:
            items.append((new_key, "" if v is None else v))
    return dict(items)


def write_outputs(findings: list[dict], csv_path: Path, json_path: Path) -> None:
    """Write findings to CSV (all fields flattened) and JSON."""
    if not findings:
        print("[!] No findings to export")
        return

    flat = [flatten_dict(f) for f in findings]

    # Collect superset of all keys in insertion order
    all_keys: list[str] = []
    seen: set[str] = set()
    for row in flat:
        for k in row:
            if k not in seen:
                all_keys.append(k)
                seen.add(k)

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=all_keys, extrasaction="ignore")
        writer.writeheader()
        for row in flat:
            writer.writerow({
                k: ("" if v is None else str(v).replace("\n", " ").replace("\r", ""))
                for k, v in row.items()
            })
    os.chmod(csv_path, 0o600)

    print(f"[+] CSV:  {csv_path}  ({len(flat)} rows, {len(all_keys)} columns)")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2, default=str)
    os.chmod(json_path, 0o600)

    print(f"[+] JSON: {json_path}")


def run_cmd(cmd: list[str], shell: bool | None = None, timeout: int = 300) -> Optional[str]:
    """Run command and return stdout, or None on error."""
    if shell is None:
        shell = sys.platform == "win32"
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, check=True,
                           shell=shell, timeout=timeout)
        return r.stdout
    except subprocess.CalledProcessError as e:
        if isinstance(e.cmd, str):
            cmd_preview = e.cmd[:80]
        else:
            cmd_preview = e.cmd[0] if e.cmd else "<empty>"
        print(f"[!] Command failed: {cmd_preview}...")
        if e.stderr:
            print(f"    stderr: {e.stderr[:500]}")
        return None
    except subprocess.TimeoutExpired:
        print(f"[!] Command timed out after {timeout}s")
        return None


def print_severity_breakdown(findings: list[dict], severity_key: str = "severity") -> None:
    """Print severity counts."""
    counts = Counter(f.get(severity_key, "Unknown") for f in findings)
    for sev, cnt in sorted(counts.items(), key=lambda x: x[1], reverse=True):
        print(f"    {sev}: {cnt}")


def timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")
