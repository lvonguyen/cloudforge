# Runbook: Cloud Aegis Deployment

## Overview

This runbook covers the current production-style demo deployment path:
- Backend API on Fly.io (`cloudforge-api`)
- Frontend on Cloudflare Pages (`cloudguard` / `cloudforge-demo`)
- PostgreSQL via `AEGIS_DATABASE_URL` when Postgres-backed findings or GRC are enabled

The earlier ECS/RDS rollout path has been retired. Do not use Kubernetes, ECS, or ALB procedures from older notes for the active demo environment.

## Prerequisites

- [ ] GitHub access to the repo and Actions history
- [ ] Fly.io CLI authenticated (`fly auth whoami`)
- [ ] Cloudflare Pages access for the frontend projects
- [ ] `psql` available locally if Postgres migrations are required
- [ ] Change approval / stakeholder notice if this is a live demo environment

## Pre-Deployment Checklist

```bash
# 1. Verify Fly.io app state
fly status -a cloudforge-api
fly releases list -a cloudforge-api | head

# 2. Verify current health
curl -sf https://api.cloudforge.lvonguyen.com/health | jq .

# 3. Review runtime secrets and config
fly secrets list -a cloudforge-api

# 4. If using postgres-backed findings or GRC, confirm DB connectivity
psql "$AEGIS_DATABASE_URL" -c 'select 1;'

# 5. Check the most recent Cloudflare Pages frontend deployment
wrangler pages deployment list --project-name cloudforge-demo | head -5
```

## Deployment Procedure

### Option A: Fly.io API Deployment (Primary)

```bash
# 1. Deploy the backend
fly deploy -a cloudforge-api

# 2. Monitor rollout
fly status -a cloudforge-api
fly logs -a cloudforge-api

# 3. Verify the machine is healthy
curl -sf https://api.cloudforge.lvonguyen.com/health | jq .
```

### Option B: Frontend Deployment (Cloudflare Pages)

Cloudflare Pages deploys automatically from GitHub on pushes to `main`.

```bash
# Inspect recent frontend deployments
wrangler pages deployment list --project-name cloudforge-demo | head -10

# Validate required build-time env vars in the Pages dashboard:
# - VITE_API_URL=https://api.cloudforge.lvonguyen.com/api/v1
# - VITE_DEMO_MODE=true
# - JWT_SECRET=<secret used to generate the static demo token>
```

Cloudflare refs currently present in the `Development` vault:
- Scoped Pages deploy token: `op://Development/cf-pages-deploy/credential`
- Global API key fallback: `op://Development/cf-gbl-api-token/credential`
- Global API key email / username: `op://Development/cf-gbl-api-token/username`
- Verified 2026-03-31: the token can list deployments for `cloudguard` and `cloudforge-demo`. `cloudforge.lvonguyen.com` is the custom domain, not the Pages project name.

### Runtime Secrets Update

If backend configuration changed, update Fly.io secrets before or during deploy:

```bash
# Dry-run the 1Password-backed sync first.
./scripts/fly-sync-runtime-secrets.sh --include-integrations --include-threat-intel

# Apply the core + integration runtime values.
./scripts/fly-sync-runtime-secrets.sh --include-integrations --include-threat-intel --apply
```

Notes:
- `scripts/fly-sync-runtime-secrets.sh` can bootstrap `FLY_API_TOKEN` from `op://Development/flyio-org-deploy-token/credential`, so `--apply` does not depend on an existing `fly auth` session.
- `scripts/fly-sync-runtime-secrets.sh` defaults to the personal demo context and resolves the JWT, Asana, Jira, GreyNoise, HIBP, OTX, and ThreatFox keys from 1Password.
- Personal-context threat-intel refs: `op://Development/glzdciaetfnrafvhntwe6enymu/credential` (GreyNoise), `op://Development/itrqxidqwvzwviz357fqtpcdi4/credential` (HIBP), `op://Development/dy5ds2uttd35prezcbyb4753ra/credential` (OTX), `op://Development/qxi4xw27nzkw6diikdug4arose/wvvuolayxv6m7b75ldy4c52aiu` (abuse.ch ThreatFox Auth-Key).
- For `HAEA` or any renamed 1Password items, override the `*_REF` env vars instead of editing the script.

### Database Migration

Run migrations before shipping a backend version that depends on new schema:

```bash
# Option 1: direct psql from local workstation
for f in migrations/*.sql; do
  echo "=== Running $f ==="
  psql "$AEGIS_DATABASE_URL" -f "$f" || exit 1
done

# Option 2: use the migration container entrypoint
docker build -f deploy/docker/Dockerfile.migrate -t cloudforge-migrate .
docker run --rm -e AEGIS_DATABASE_URL="$AEGIS_DATABASE_URL" cloudforge-migrate
```

### Option C: Full Findings Seed into Fly Postgres (D19)

Use this only during an explicit operator window. This is a destructive load sequence against the target database and should be done against a fresh database or a snapshot-backed restore point.

```bash
export DATABASE_URL='<postgres-dsn>'
export AEGIS_DATABASE_URL="$DATABASE_URL"
export FINDINGS_SOURCE=postgres
export SECGRAPH_AUTO_TICKETS=false

# Required because the schema uses gen_random_uuid().
psql "$DATABASE_URL" -c 'CREATE EXTENSION IF NOT EXISTS pgcrypto;'

# Apply the ordered schema set. Do not rely on older `make migrate` helpers for D19.
for f in \
  migrations/001_exception_management.sql \
  migrations/002_findings_and_compliance.sql \
  migrations/003_operations_and_agents.sql \
  migrations/005_tenant_isolation.sql \
  migrations/006_graph_support.sql \
  migrations/007_security_graph.sql \
  migrations/008_findings_assignment_context.sql \
  migrations/009_finding_tickets.sql
do
  psql "$DATABASE_URL" -f "$f" || exit 1
done

# Full seed requires both --full and the explicit 300K count.
node --max-old-space-size=6144 scripts/aegis-seed.mjs \
  --count 300000 \
  --out testdata/seed \
  --full \
  --seed 42

# Generate SQL, then load it with psql.
node scripts/seed-postgres.mjs --in testdata/seed --out /tmp/seed-findings.sql
psql "$DATABASE_URL" -f /tmp/seed-findings.sql

node scripts/seed-resources.mjs --in testdata/seed --out /tmp/seed-resources.sql
psql "$DATABASE_URL" -f /tmp/seed-resources.sql

# Re-run graph-support/security-graph migrations after findings/resources are loaded.
psql "$DATABASE_URL" -f migrations/006_graph_support.sql
psql "$DATABASE_URL" -f migrations/007_security_graph.sql
```

Verify before cutover:

```bash
psql "$DATABASE_URL" -c 'select count(*) from findings;'
psql "$DATABASE_URL" -c 'select count(*) from resources;'
psql "$DATABASE_URL" -c 'select count(*) from accounts;'
psql "$DATABASE_URL" -c 'select count(*) from graph_edges;'
```

Stage the runtime secrets first, but keep findings on `mock` until the database is fully loaded:

```bash
AEGIS_DATABASE_URL_REF='op://Development/4uvialfye3icuwak32yblswaam/credential' \
./scripts/fly-sync-runtime-secrets.sh --include-integrations --include-threat-intel --include-postgres

AEGIS_DATABASE_URL_REF='op://Development/4uvialfye3icuwak32yblswaam/credential' \
./scripts/fly-sync-runtime-secrets.sh --include-integrations --include-threat-intel --include-postgres --apply
```

Cut over the app only after those counts look correct and startup headroom is acceptable:

```bash
FINDINGS_SOURCE=postgres \
AEGIS_DATABASE_URL_REF='op://Development/4uvialfye3icuwak32yblswaam/credential' \
./scripts/fly-sync-runtime-secrets.sh --include-integrations --include-threat-intel --include-postgres --apply

fly deploy -a cloudforge-api
```

Notes:
- `scripts/seed-postgres.mjs` and `scripts/seed-resources.mjs` generate SQL; they do not load Postgres by themselves.
- Personal-context default: `AEGIS_DATABASE_URL_REF` resolves from the dedicated Development-vault item UUID ref `op://Development/4uvialfye3icuwak32yblswaam/credential` (`cloudforge neon-db`).
- `scripts/fly-sync-runtime-secrets.sh` now defaults `FINDINGS_SOURCE=mock`; the final Postgres cutover must be explicit with `FINDINGS_SOURCE=postgres`.
- Verified March 31, 2026: Neon Launch now fits the full 300K corpus. The seeded `cloudforge` database is `1,078,362,112` bytes (`1028 MB`, about `1.03 GB`).
- Verified March 31, 2026: the live Fly app is now Postgres-backed on the full 300K corpus.
- Leave `LARGE_CORPUS_WARMUP_ENABLED` unset on the current `2 GB` shared Fly VM. Enabling large-corpus search/attack-path warmup on startup causes health flaps and eventual OOM on the current machine size.
- Leave `LARGE_CORPUS_SECGRAPH_SYNC_ENABLED` unset on the current `2 GB` shared Fly VM. That flag refers to the full large-corpus secgraph graph-artifact path, which still causes repeated OOM restarts after backfill on the current machine size.
- Current stable behavior on Fly: findings load from Postgres, the full large-corpus startup warmup stays disabled, authenticated findings search degrades to in-memory keyword mode when the Bleve index is intentionally absent, attack paths lazily materialize a bounded sampled cache on first request, and the operator-facing secgraph issue surface incrementally syncs in bounded startup batches while heavier graph-edge artifacts remain deferred.
- Verified March 31, 2026: the first live issue-surface batch committed `77116` evaluations/issues/issue_findings at `2026-03-31T22:23:46Z`, after which `/api/v1/issues/stats`, `/api/v1/issues`, and `/api/v1/issues/{id}` all responded successfully on the public demo API.
- Verified March 31, 2026: the degraded keyword search path served the live-sized 300K corpus locally in about `748 ms` for a hybrid-mode request while warmup stayed disabled.
- Verified March 31, 2026: the deferred attack-path path served the live-sized 300K corpus locally in about `0.4s` on the first cold request after adjacency skipping, returning `5476` cached paths from `5000` candidate findings with stats mode `sampled`.
- Tune deferred attack-path sampling with `ATTACK_PATH_MAX_FINDINGS` and `ATTACK_PATH_MAX_PER_ACCOUNT` only after verifying memory headroom on Fly.
- If cutover fails, revert `FINDINGS_SOURCE=mock` and restart before doing any deeper DB surgery.
- Verified March 31, 2026: `/api/v1/providers` on the live demo now reports `integrations.default=asana`, `integrations.enabled=[asana,jira,mock]`, `integrations.ticket_store=durable`, and `integrations.asana_webhook=configured`.
- Verified March 31, 2026: live remediation mutation passed against both providers. Asana create/comment/resolve/sync succeeded through `cloudforge-api`, and Jira create/comment/sync succeeded through `cloudforge-api`.

## Verification

### API Health Check

```bash
curl -sf https://api.cloudforge.lvonguyen.com/health | jq .
```

Expected response shape:

```json
{
  "status": "healthy"
}
```

### Functional Verification

```bash
# Authenticated findings request
curl -sf https://api.cloudforge.lvonguyen.com/api/v1/findings?limit=5 \
  -H "Authorization: Bearer $API_TOKEN" | jq '.data | length'

# Provider readiness / durable ticket store
curl -sf https://api.cloudforge.lvonguyen.com/api/v1/providers | jq '.integrations'

# Frontend smoke
open https://cloudforge.lvonguyen.com
```

Check:
- frontend loads without auth redirect loops
- findings and issues views render
- `/api/v1/providers` reports the expected integration provider set and durable ticket store
- findings search returns results even when `LARGE_CORPUS_WARMUP_ENABLED` remains unset
- attack path and graph pages do not 5xx
- first attack-path request may be materially slower on a cold process while the sampled cache is built
- integrations remain disabled unless the required secrets are set

Optional operator-window remediation smoke:

```bash
# Create an Asana-backed remediation ticket for a known finding.
curl -sf -X POST "https://api.cloudforge.lvonguyen.com/api/v1/findings/<finding-id>/remediate" \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"provider":"asana","severity":"CRITICAL"}' | jq .

# Add a comment and then force-refresh status.
curl -sf -X POST "https://api.cloudforge.lvonguyen.com/api/v1/findings/<finding-id>/ticket/comments" \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"body":"operator smoke"}' | jq .

curl -sf -X POST "https://api.cloudforge.lvonguyen.com/api/v1/findings/<finding-id>/ticket/sync" \
  -H "Authorization: Bearer $API_TOKEN" | jq .
```

Notes:
- Use `provider:"jira"` to force the Jira path instead of the default Asana path.
- `integrations.asana_webhook=configured` only proves the handshake token is present. It does not prove that an external Asana webhook registration is currently active.

### Fly.io Release Verification

```bash
fly releases list -a cloudforge-api | head
fly status -a cloudforge-api
```

## Rollback Procedure

### Fly.io Release Rollback

```bash
# Identify the last known-good release
fly releases list -a cloudforge-api

# Roll back to a specific release version
fly releases rollback <version> -a cloudforge-api

# Verify health after rollback
curl -sf https://api.cloudforge.lvonguyen.com/health | jq .
```

### Database Rollback

If a migration introduced an incompatible schema change, restore from backup or manually revert the relevant migration. There is no safe generic `down` path for every migration in this repo; treat DB rollback as an explicit operator action.

## Post-Deployment

1. [ ] Verify Fly.io health and recent logs
2. [ ] Verify frontend loads from Cloudflare Pages
3. [ ] Verify authenticated API calls against `/api/v1/findings`
4. [ ] Verify `/api/v1/providers` reports the expected integration readiness
5. [ ] Verify optional Postgres-backed features if `AEGIS_DATABASE_URL` is enabled
6. [ ] During an operator window, run one remediation create/comment/sync smoke on the active ticket provider path
7. [ ] Notify stakeholders / update the deployment record

## Escalation

| Condition | Action |
|-----------|--------|
| Fly.io deploy fails | Roll back to the last good release, then inspect `fly logs` |
| Health check fails after deploy | Check Fly secrets, DB reachability, and release diff before retrying |
| Frontend 404s or auth loops | Verify `VITE_API_URL`, `JWT_SECRET`, and Pages build env vars |
| Postgres-backed endpoints 5xx | Confirm `AEGIS_DATABASE_URL`, migration state, and DB connectivity |

## Contact

- On-Call: PagerDuty
- Platform Team: `#platform-support`
- Security Team: `#security-ops`
