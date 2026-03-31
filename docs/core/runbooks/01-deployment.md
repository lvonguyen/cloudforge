# Runbook: Cloud Aegis Deployment

## Overview

This runbook covers the current production-style demo deployment path:
- Backend API on Fly.io (`cloudforge-api`)
- Frontend on Cloudflare Pages (`cloudguard` / `cloudaegis-demo`)
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
curl -sf https://api.cloudforge-demo.lvonguyen.com/health | jq .

# 3. Review runtime secrets and config
fly secrets list -a cloudforge-api

# 4. If using postgres-backed findings or GRC, confirm DB connectivity
psql "$AEGIS_DATABASE_URL" -c 'select 1;'

# 5. Check the most recent Cloudflare Pages frontend deployment
wrangler pages deployment list --project-name cloudaegis-demo | head -5
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
curl -sf https://api.cloudforge-demo.lvonguyen.com/health | jq .
```

### Option B: Frontend Deployment (Cloudflare Pages)

Cloudflare Pages deploys automatically from GitHub on pushes to `main`.

```bash
# Inspect recent frontend deployments
wrangler pages deployment list --project-name cloudaegis-demo | head -10

# Validate required build-time env vars in the Pages dashboard:
# - VITE_API_URL=https://api.cloudforge-demo.lvonguyen.com/api/v1
# - VITE_DEMO_MODE=true
# - JWT_SECRET=<secret used to generate the static demo token>
```

### Runtime Secrets Update

If backend configuration changed, update Fly.io secrets before or during deploy:

```bash
fly secrets set \
  AEGIS_JWT_SECRET=... \
  AEGIS_DATABASE_URL=... \
  JIRA_URL=... \
  JIRA_USERNAME=... \
  JIRA_API_TOKEN=... \
  ASANA_PAT=... \
  -a cloudforge-api
```

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

## Verification

### API Health Check

```bash
curl -sf https://api.cloudforge-demo.lvonguyen.com/health | jq .
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
curl -sf https://api.cloudforge-demo.lvonguyen.com/api/v1/findings?limit=5 \
  -H "Authorization: Bearer $API_TOKEN" | jq '.items | length'

# Frontend smoke
open https://cloudaegis-demo.lvonguyen.com
```

Check:
- frontend loads without auth redirect loops
- findings and issues views render
- attack path and graph pages do not 5xx
- integrations remain disabled unless the required secrets are set

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
curl -sf https://api.cloudforge-demo.lvonguyen.com/health | jq .
```

### Database Rollback

If a migration introduced an incompatible schema change, restore from backup or manually revert the relevant migration. There is no safe generic `down` path for every migration in this repo; treat DB rollback as an explicit operator action.

## Post-Deployment

1. [ ] Verify Fly.io health and recent logs
2. [ ] Verify frontend loads from Cloudflare Pages
3. [ ] Verify authenticated API calls against `/api/v1/findings`
4. [ ] Verify optional Postgres-backed features if `AEGIS_DATABASE_URL` is enabled
5. [ ] Notify stakeholders / update the deployment record

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
