# Session 15 Handoff

## Resume prompt

```
resume from tasks/session-15-handoff.md
```

## What happened in session 14

Personal demo wired E2E (CORS, DNS, frontend auth, CF Pages deploy). Then pivoted to
real data extraction: 531k multi-cloud findings exported, 3 KMS providers implemented,
detection engines expanded, CT Lake enabled for 24hrs. No sanitization yet — naming
convention TBD.

## Immediate open items (priority order)

### 1. [!] CT Lake: export events + revert (TIME-SENSITIVE)

Data+network events enabled 2026-03-25 01:40 UTC. Revert after ~24hrs.

```bash
# Count what accumulated
aws cloudtrail start-query \
  --query-statement "SELECT eventCategory, count(*) as cnt FROM cd3bd797-a619-4063-94c9-3934798a32e4 WHERE eventTime > '2026-03-25 01:30:00' GROUP BY eventCategory" \
  --profile haea-sso --region us-west-2

# Export data+network events to local
# (paginate get-query-results, save to data/haea-ct-events.ndjson)

# Revert to management-only
aws cloudtrail update-event-data-store \
  --event-data-store "arn:aws:cloudtrail:us-west-2:831926608679:eventdatastore/cd3bd797-a619-4063-94c9-3934798a32e4" \
  --advanced-event-selectors '[{"Name":"Management events","FieldSelectors":[{"Field":"eventCategory","Equals":["Management"]}]}]' \
  --profile haea-sso --region us-west-2

# Verify
aws cloudtrail get-event-data-store \
  --event-data-store "arn:aws:cloudtrail:us-west-2:831926608679:eventdatastore/cd3bd797-a619-4063-94c9-3934798a32e4" \
  --profile haea-sso --region us-west-2 --query 'AdvancedEventSelectors[*].Name'
```

### 2. Merge + deduplicate all exports into canonical files

**Current state: ~9GB of overlapping exports across data/ and testdata/**

Files to merge (by cloud):

**AWS** — merge into `data/aws-findings-canonical.ndjson`:
- `data/haea-findings-all.ndjson` (466k, 2.0GB) — my full export, NDJSON
- `testdata/export-outputs/aws_securityhub_guardduty_20260324_190620.json` (237k, 1.3GB) — parallel, JSON array
- `testdata/export-outputs/aws_securityhub_guardduty_20260324_183014.json` (partial, 47MB)
- `testdata/export-outputs/aws_securityhub_guardduty_20260324_182857.json` (partial, 2.1MB)

**Azure** — merge into `data/azure-findings-canonical.ndjson`:
- `testdata/export-outputs/azure_all_security_20260324_191728.json` (HMGNA, 38k, 225MB)
- `testdata/export-outputs/azure_all_security_20260324_190457.json` (KUS, 1.5k, 5.4MB)
- `testdata/export-outputs/azure_all_security_20260324_190516.json` (HMA, 445, 0.9MB)

**GCP** — merge into `data/gcp-findings-canonical.ndjson`:
- `testdata/export-outputs/gcp_all_findings_allstates_20260324_185736.json` (25k, 187MB)
- `testdata/export-outputs/gcp_all_findings_20260324_184746.json` (partial, 58MB)

**After merge:**
- Enrich every finding with: `Cloud`, `OrgId`, `OrgName`, `TenantId`, `TenantName`
- Produce: `data/all-findings-enriched.ndjson` (single canonical file, ~500k findings)
- **Delete intermediate files** after verifying canonical counts match:
  - `data/haea-findings-raw.ndjson` (10k sample — superseded)
  - `data/haea-findings-merged.ndjson` (407k — superseded by canonical)
  - `data/haea-findings-enriched.ndjson` (407k — superseded by canonical)
  - `data/haea-findings-all.ndjson` (466k — folded into canonical)
  - `testdata/cspm/raw/aws_securityhub_findings.json` (duplicate of parallel export)
  - `testdata/cspm/raw/azure_defender_assessments.json` (duplicate)
  - `testdata/cspm/raw/gcp_scc_findings.json` (duplicate)
  - Partials in testdata/export-outputs/ that are subsets of the full exports
- Keep: `testdata/cspm/raw/` small files (azure-resource-graph, secure-score) — different data types

**Enrichment mapping:**

| Export File Pattern | Cloud | OrgId | OrgName | TenantId (from account name) |
|---|---|---|---|---|
| aws_* / haea-findings-* | `aws` | `o-ug82f7kcwl` | `HMGNA` | Parse `account-{cbu}-*` prefix |
| azure_*_191728 | `azure` | `bd29b3ab-aaa2-425a-b882-9e7f73283ca6` | `HMGNA` | `hmgna` |
| azure_*_190457 | `azure` | `5fed94a0-4129-44a0-b507-a83a5c9e6dac` | `Kia NA` | `kus` |
| azure_*_190516 | `azure` | `becdc98a-bfc9-4ffa-ade6-892577ce9a58` | `Hyundai NA` | `hma` |
| gcp_* | `gcp` | `654662756615` | `autoeveramerica.com` | `haea` |

Use `scripts/merge-findings.py` (already supports NDJSON + JSON array via ijson).

### 3. Design sanitization naming convention (DO NOT sanitize yet)

Current HAEA naming (`account-{cbu}-{app}-{env}`) needs a cleaner demo equivalent.
Propose options in session 15, get approval, then build the sanitization pass.

### 4. DB scaling plan for 500k+ findings

Current personal demo RDS: `db.t3.micro` (1 vCPU, 1GB RAM, 20GB gp2).

**Capacity analysis for 500k findings:**
- Average finding JSON: ~4KB → 500k * 4KB = ~2GB raw data
- With indexes (severity, account, resource_type, status): ~3-4GB total
- db.t3.micro has 20GB storage — fits, but leaves little headroom
- 1GB RAM is tight for 500k row queries with joins

**Recommended scaling (before ingest):**
- Bump to `db.t3.small` (2 vCPU, 2GB RAM) — ~$29/mo → $15/mo delta
- OR keep db.t3.micro and limit ingest to 50-100k representative sample
- Increase storage to 50GB if ingesting full dataset
- Add indexes: `CREATE INDEX idx_findings_severity ON findings(severity)` etc.
- Consider: `COPY` bulk load vs API batch POST (COPY is 10-100x faster for 500k rows)

**TF change** (if scaling): `deploy/terraform/environments/personal/main.tf` — update
`instance_class` and `allocated_storage` in the database module call.

**Alternative: sample instead of full ingest**
- 10k findings (stratified by severity + product + tenant) gives realistic distribution
- Keeps db.t3.micro viable, faster dashboard queries, ~40MB in postgres
- Script: sample N findings per severity bucket, preserving product/tenant ratios

### 5. Wire Asana integration on ECS

Add env vars to ECS task def (or Secrets Manager):
```
ASANA_PAT          → op://Development/asana-cs-remediation-token/credential
ASANA_WORKSPACE_GID → 1205437629727178
ASANA_DEFAULT_PROJECT_GID → 1212451458473619
```

Code is ready: `internal/integrations/asana/{client,adapter}.go`
Test: `POST /api/v1/findings/{id}/remediate` → creates task in Asana

### 6. Commit session 14 work

Uncommitted:
- `internal/secrets/provider_{aws,azure,gcp}.go` — 3 KMS providers (NEW)
- `internal/secrets/manager.go` — stubs replaced with file pointers
- `frontend/src/lib/{api,auth}.ts` — VITE_STATIC_TOKEN support
- `scripts/export-securityhub.py` + `scripts/merge-findings.py` (NEW)
- `deploy/terraform/environments/personal/bad-infra/main.tf` (NEW, not applied, optional)
- `go.mod` / `go.sum` — secretsmanager, azsecrets, secretmanager deps
- `.gitignore` — added `data/`

Suggest 2-3 commits:
```
feat(secrets): implement AWS SM + Azure KV + GCP SM providers
feat(frontend): add VITE_STATIC_TOKEN for demo auth without IdP
chore: add findings export/merge scripts + gitignore data/
```

## Infrastructure context

| Resource | Details |
|----------|---------|
| ECS cluster | `aegis-personal` (us-east-1) |
| ECS service | `aegis-personal-api` (1 task, rev 2, Fargate) |
| RDS | db.t3.micro, `aegis-personal-db` (postgres) |
| Redis | cache.t3.micro, `aegis-personal-redis` |
| ALB | `aegis-personal-alb-824833696.us-east-1.elb.amazonaws.com` |
| API | `https://api-personal.lvonguyen.com` (CF proxied, Flexible SSL) |
| Frontend | `https://cloudguard.lvonguyen.com` (CF Pages, `cloudguard` project) |
| JWT secret | SM `aegis-personal-secrets/jwt-secret` / 1P `aegis-personal-jwt-secret` |
| Teardown | 2026-04-20 |

## AWS profiles

| Profile | Account | Access | Region |
|---------|---------|--------|--------|
| `lvn-personal` | 431330216246 | Admin | us-east-1 |
| `haea-sso` | 831926608679 | PowerUser | us-west-2 |

## Key memory files

| File | Content |
|------|---------|
| `reference_haea_account_catalogue.md` | 56 AWS accounts, 3 Az tenants, 1 GCP org, CBU mapping |
| `reference_asana_integration.md` | PAT path, project GIDs, webhook handler location |
| `reference_cloudtrail_lake.md` | Data store ARN, event selectors, query syntax |
| `reference_cloudflare_api.md` | CF API key, zone ID, SSL mode |
| `project_haea_aws_orgs.md` | 4 AWS orgs full inventory |
