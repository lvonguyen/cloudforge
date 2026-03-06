# Handoff: Integrate HAEA Findings Test Data

## Context
CloudForge uses synthetic mock findings (80 records) for the demo. Real-world anonymized findings exports from HAEA (Project 37) need to replace or supplement the synthetic data. Export scripts live in a GitLab repo and are pulled via `git show` (no merge needed).

## What's Already Done
- `make dev` starts backend (:8080) + frontend (:5173) — single command
- Redis rate limiter fixed (nil-check, no Redis needed locally)
- All list pages (Users, Policies, AI Agents, Findings) load correctly
- Dev auth working: `.env.development` has `VITE_DEV_TOKEN`
- Uncommitted changes: Redis fix + Makefile `dev` target — commit these first

## Step 0: Commit Pending Changes
```bash
cd ~/repos/remote/gh/portfolio/tier1-flagship/cloudforge
git add internal/api/gateway/ratelimit.go cmd/server/main.go Makefile
git commit -m "fix: skip Redis rate limiting when unavailable, add make dev target"
```

## Step 1: Pull Export Scripts from GitLab
```bash
cd ~/repos/remote/gh/portfolio/tier1-flagship/cloudforge

# Add GitLab remote (skip if already exists)
git remote add gl-p37 https://gitlab.com/haea-security-tft/project-37.git 2>/dev/null || echo "remote gl-p37 already exists"

# Fetch (no merge)
git fetch gl-p37 main

# Export scripts to testdata/
mkdir -p testdata/export-scripts
git show gl-p37/main:utils/findings-utils/export-scripts/findings_export_utils.py > testdata/export-scripts/findings_export_utils.py
git show gl-p37/main:utils/findings-utils/export-scripts/query_aws_all_findings.py > testdata/export-scripts/query_aws_all_findings.py
git show gl-p37/main:utils/findings-utils/export-scripts/query_azure_all_findings.py > testdata/export-scripts/query_azure_all_findings.py
git show gl-p37/main:utils/findings-utils/export-scripts/query_gcp_all_findings.py > testdata/export-scripts/query_gcp_all_findings.py
git show gl-p37/main:utils/findings-utils/export-scripts/query_all_findings.sh > testdata/export-scripts/query_all_findings.sh
git show gl-p37/main:utils/findings-utils/export-scripts/scrub_findings.py > testdata/export-scripts/scrub_findings.py

echo "[+] Done — scripts exported to testdata/export-scripts/"
```

This uses `git show` from the remote ref so P37 history stays out of cloudforge — just cherry-picks the files cleanly.

## Step 2: Inspect & Understand Export Format
- Read the export scripts to understand the output schema (SecurityHub ASFF, Azure Defender alerts, GCP SCC findings)
- Check if `scrub_findings.py` already handles anonymization or if additional PII scrubbing is needed
- Determine output format: per-provider JSON files or unified format

## Step 3: Transform to CloudForge Finding Schema
Current findings schema (check `frontend/src/lib/mock/findings.json` for structure):
```json
{
  "id": "finding-xxx",
  "title": "...",
  "severity": "critical|high|medium|low",
  "status": "open|in_progress|resolved|suppressed",
  "source": "aws-securityhub|azure-defender|gcp-scc",
  "resource_type": "...",
  "resource_id": "...",
  "account_id": "...",
  "region": "...",
  "first_seen": "...",
  "last_seen": "...",
  "description": "...",
  "remediation": "...",
  "compliance_frameworks": ["CIS", "SOC2", ...]
}
```

Write a transformer script (Python, use `uv`) that:
1. Reads the raw provider exports
2. Normalizes to CloudForge schema
3. Applies PII scrub (see rules below)
4. Outputs to `frontend/src/lib/mock/findings.json`

## PII/Identity Rules
- All emails -> @contoso.dev (use existing mock identity map)
- All account IDs -> contoso-{aws|azure|gcp}-{prod|staging|dev}
- All ARNs -> arn:aws:...:123456789012:... (placeholder account)
- All real IPs -> 10.x.x.x or 172.16.x.x ranges
- Resource names -> generic (e.g., `web-server-01` not `haea-prod-api-3`)
- No real org names, project names, or internal hostnames

## Step 4: Load & Verify
- Backend loads mock data in `cmd/server/main.go` via `loadMockData()`
- Mock JSON files live in `frontend/src/lib/mock/`
- Current: 80 findings — new data should be comparable size or larger
- Attack paths are computed from findings (`computeAttackPaths()`)
- Run `make dev` and verify Findings, FindingDetail, AttackPaths pages render correctly

## Key Files
- `frontend/src/lib/mock/findings.json` — current synthetic findings
- `cmd/server/main.go` — `loadMockData()`, `computeAttackPaths()`
- `frontend/src/hooks/useFindings.ts` — frontend findings hook
- `frontend/src/pages/ops/Findings.tsx` — findings list page
- `frontend/src/pages/ops/FindingDetail.tsx` — finding detail page
- `testdata/export-scripts/` — HAEA export + scrub scripts (from P37)

## Dev Server
```bash
cd ~/repos/remote/gh/portfolio/tier1-flagship/cloudforge
make dev
# Backend: :8080, Frontend: :5173
```
