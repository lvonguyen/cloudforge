# 48-Hour Teardown Runbook

**Target:** Current personal / portfolio demo stack
**Primary services:** Cloudflare Pages frontend, Fly.io API (`cloudforge-api`), optional Fly Postgres (`cloudforge-db`), optional local PuppyGraph via Docker Compose
**Calendar reminder:** Set at deploy time for every short-lived demo sprint

The earlier AWS-heavy personal stack (ECS, RDS, ALB, NAT gateway, PuppyGraph EC2) has already been torn down. This runbook covers the active Fly.io-based topology only.

---

## 1. Pre-Teardown Checklist

```bash
# Authenticate
fly auth whoami
wrangler whoami

# Inventory current Fly apps
fly apps list | rg 'cloudforge-api|cloudforge-db'

# Verify the API is still reachable before capture / backup
curl -sf https://api.cloudforge.lvonguyen.com/health | jq .

# Optional: verify PuppyGraph local stack state
docker ps --format '{{.Names}}' | rg 'puppy|postgres'

# Screenshot the live demo if needed for portfolio assets
# open https://cloudforge.lvonguyen.com
# open https://api.cloudforge.lvonguyen.com/health
```

**Confirm before proceeding:**
- [ ] Portfolio screenshots or recordings captured
- [ ] If Postgres is attached, a verified backup exists
- [ ] Custom domain / DNS records to remove are known
- [ ] No active demo or stakeholder review depends on the environment

---

## 2. Database Backup (If Postgres Is In Use)

If the current deployment is still using in-memory findings/GRC, skip this section.

```bash
# Preferred: dump from the configured DSN
pg_dump "$AEGIS_DATABASE_URL" > cloudforge-backup-$(date +%Y%m%d).sql

# Sanity check the dump file exists and is non-empty
ls -lh cloudforge-backup-$(date +%Y%m%d).sql
```

If the database is a dedicated Fly Postgres app, keep the backup with the session artifacts before destroying the DB app.

---

## 3. PuppyGraph Cleanup

PuppyGraph is local-only unless explicitly reintroduced.

```bash
# Stop local PuppyGraph stack if it is running
docker compose -f docker-compose.puppygraph.yml down
```

If `PUPPYGRAPH_URL` was set on Fly.io for a temporary graph demo:

```bash
fly secrets unset PUPPYGRAPH_URL -a cloudforge-api
```

---

## 4. Fly.io API Teardown

```bash
# Inspect the current app one last time
fly status -a cloudforge-api
fly releases list -a cloudforge-api | head

# Destroy the API app
fly apps destroy cloudforge-api --yes
```

This removes the `cloudforge-api.fly.dev` origin behind `api.cloudforge.lvonguyen.com`.

---

## 5. Fly Postgres Teardown (Optional)

Only do this if:
- the Postgres app exists
- a backup has already been taken
- no other app is attached to it

```bash
# Confirm the Postgres app exists
fly status -a cloudforge-db

# Destroy the dedicated Fly Postgres app if it is no longer needed
fly apps destroy cloudforge-db --yes
```

If the app does not exist, or the API still runs in memory mode, skip this section.

---

## 6. Cloudflare Pages / DNS Cleanup

Cloudflare Pages is free, so cleanup is optional unless you want a fully blank slate.

```bash
# Review recent Pages deployments before removing anything
wrangler pages deployment list --project-name cloudforge-demo | head -5
```

DNS records to consider:
- `api.cloudforge.lvonguyen.com` -> `cloudforge-api.fly.dev`
- `cloudforge.lvonguyen.com` -> Cloudflare Pages project `cloudforge-demo`
- `cloudguard.lvonguyen.com` -> legacy Cloudflare Pages hostname if it still exists in the account

If decommissioning entirely:
- remove the API CNAME after the Fly.io app is destroyed
- optionally delete the Pages projects from the Cloudflare dashboard

---

## 7. Verification

```bash
# Fly apps should no longer exist
fly apps list | rg 'cloudforge-api|cloudforge-db'

# API endpoint should no longer respond successfully
curl -s -o /dev/null -w "%{http_code}" https://api.cloudforge.lvonguyen.com/health

# PuppyGraph containers should be gone
docker ps --format '{{.Names}}' | rg 'puppy|postgres'
```

**Expected outcome:**
- `cloudforge-api` is absent from `fly apps list`
- `cloudforge-db` is absent if it was intentionally destroyed
- `api.cloudforge.lvonguyen.com` returns `000`, `404`, or a CDN/origin failure after DNS cleanup
- no local PuppyGraph demo containers remain running

---

## 8. Re-Spin Notes

```bash
# Recreate or redeploy the API
fly deploy -a cloudforge-api

# Reapply secrets
fly secrets set AEGIS_JWT_SECRET=... -a cloudforge-api
fly secrets set AEGIS_DATABASE_URL=... -a cloudforge-api

# If using Postgres, restore from backup before enabling postgres-backed modes
psql "$AEGIS_DATABASE_URL" < cloudforge-backup-YYYYMMDD.sql
```

After redeploy:
- restore the API DNS record if it was removed
- verify `https://api.cloudforge.lvonguyen.com/health`
- verify frontend Pages builds still point at `/api/v1`
