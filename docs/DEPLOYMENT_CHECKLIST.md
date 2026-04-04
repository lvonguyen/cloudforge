# Deployment Checklist

Operational nuances discovered during personal demo deployment (March 2026).
Apply to both personal (lvn-personal) and HAEA production environments.

---

## Pre-Deploy

### Credentials & Secrets
- [ ] `fly auth whoami` -- verify Fly.io session active
- [ ] `wrangler whoami` -- verify Cloudflare session active for Pages checks
- [ ] `aws sso login --profile <profile>` only if this deploy uses Bedrock, AWS integrations, or PuppyGraph experiments
- [ ] Secrets Manager populated: JWT secret, Asana PAT, Jira API token
- [ ] 1P stores signing KEYS, not pre-signed JWTs -- generate JWT at build time
- [ ] VITE_STATIC_TOKEN must be a generated HS256 JWT, not the raw secret from 1P

### Frontend Build
- [ ] `VITE_API_URL` must include `/api/v1` prefix (e.g., `https://api.cloudforge.lvonguyen.com/api/v1`)
- [ ] Without prefix: frontend calls `/findings` instead of `/api/v1/findings` -> 404
- [ ] `VITE_DEMO_MODE=true` required for portfolio demo build
- [ ] JWT generation at build time:
  ```bash
  JWT_SECRET="$(op read 'op://Development/aegis-personal-jwt-secret/credential')"
  JWT=$(JWT_SECRET="$JWT_SECRET" node -e "
    const crypto = require('crypto');
    const header = Buffer.from(JSON.stringify({alg:'HS256',typ:'JWT'})).toString('base64url');
    const payload = Buffer.from(JSON.stringify({sub:'demo',role:'viewer',iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+2592000})).toString('base64url');
    const sig = crypto.createHmac('sha256',process.env.JWT_SECRET).update(header+'.'+payload).digest('base64url');
    console.log(header+'.'+payload+'.'+sig);
  ")
  ```

### Database
- [ ] If `GRC_PROVIDER=postgres` or `FINDINGS_SOURCE=postgres`, verify `AEGIS_DATABASE_URL` is set and reachable
- [ ] For a full D19 findings seed, also set `SECGRAPH_AUTO_TICKETS=false` for the first cutover so startup does not auto-dispatch tickets against a freshly materialized corpus
- [ ] Run migrations before deploying a backend version that depends on new schema:
  ```bash
  for f in migrations/*.sql; do
    echo "=== Running $f ==="
    psql "$AEGIS_DATABASE_URL" -f "$f" || exit 1
  done
  ```
- [ ] For containerized migration runs, `deploy/docker/Dockerfile.migrate` can apply the same migration set against `AEGIS_DATABASE_URL`

---

## Deploy

### Fly.io API
- [ ] Verify required Fly secrets before deploy: `fly secrets list -a cloudforge-api`
- [ ] Prefer the 1Password-backed sync script over ad-hoc `fly secrets set` commands:
  ```bash
  ./scripts/fly-sync-runtime-secrets.sh --include-integrations
  ./scripts/fly-sync-runtime-secrets.sh --include-integrations --apply
  ```
- [ ] Fly token in Development vault: `op://Development/flyio-org-deploy-token/credential`
- [ ] Integration env vars (all from Secrets Manager or 1P):
  ```
  ASANA_PAT, ASANA_WORKSPACE_GID, ASANA_DEFAULT_PROJECT_GID
  JIRA_URL, JIRA_USERNAME, JIRA_API_TOKEN, JIRA_PROJECT_KEY
  PUPPYGRAPH_URL (when graph instance active)
  ```
- [ ] For D19 Postgres cutover, keep the DSN in 1Password and pass its ref explicitly:
  ```bash
  AEGIS_DATABASE_URL_REF='op://Development/4uvialfye3icuwak32yblswaam/credential' \
  ./scripts/fly-sync-runtime-secrets.sh --include-integrations --include-threat-intel --include-postgres --apply
  ```
- [ ] Do not flip the demo to `FINDINGS_SOURCE=postgres` until the target DB already has the D19 schema + seeded findings/resources. The sync script now defaults to `FINDINGS_SOURCE=mock`; final cutover must be explicit:
  ```bash
  FINDINGS_SOURCE=postgres \
  AEGIS_DATABASE_URL_REF='op://Development/4uvialfye3icuwak32yblswaam/credential' \
  ./scripts/fly-sync-runtime-secrets.sh --include-integrations --include-threat-intel --include-postgres --apply
  ```
- [ ] Verified March 31, 2026: Neon Launch now fits the full 300K D19 corpus. The seeded `cloudforge` database footprint is `1,078,362,112` bytes (`1028 MB`, about `1.03 GB`).
- [ ] Verified March 31, 2026: leave `LARGE_CORPUS_WARMUP_ENABLED` unset on the current `2 GB` Fly VM. Enabling startup warmup for large-corpus search/attack paths causes health flaps and eventual OOM on the current machine size.
- [ ] Verified March 31, 2026: leave `LARGE_CORPUS_SECGRAPH_SYNC_ENABLED` unset on the current `2 GB` Fly VM. That flag controls the full large-corpus secgraph graph-artifact path, which still causes repeated OOM restarts after backfill on the current machine size.
- [ ] Verified March 31, 2026: even with `LARGE_CORPUS_SECGRAPH_SYNC_ENABLED` unset, the operator-facing secgraph issue surface now incrementally materializes on startup in bounded batches on the current Fly VM size.
- [ ] Verified April 1, 2026: authenticated findings search now remains usable when `LARGE_CORPUS_WARMUP_ENABLED` is unset. `keyword` requests stay in-memory, while `semantic` and `hybrid` requests fall back to candidate-scoped in-memory reranking over keyword candidates instead of requiring full Bleve warmup.
- [ ] Verified March 31, 2026: attack paths now lazily materialize a bounded sampled cache on first request when `LARGE_CORPUS_WARMUP_ENABLED` remains unset; expect a slower first cold request instead of an empty result set.
- [ ] Feature flags: 14 backend features gated by env vars -- all OFF by default
  - PUPPYGRAPH_URL, AEGIS_AI_ENABLED, AEGIS_TRACING_ENABLED
  - GREYNOISE_API_KEY, HIBP_API_KEY, OTX_API_KEY, THREATFOX_AUTH_KEY
  - JIRA_URL, ASANA_WEBHOOK_TOKEN, WS_SERVER_URL
  - RATE_LIMIT_ENABLED, Slack alerting, PagerDuty, Semantic search
- [ ] Threat-intel refs in Development: `op://Development/glzdciaetfnrafvhntwe6enymu/credential` (GreyNoise), `op://Development/itrqxidqwvzwviz357fqtpcdi4/credential` (HIBP), `op://Development/dy5ds2uttd35prezcbyb4753ra/credential` (OTX), `op://Development/qxi4xw27nzkw6diikdug4arose/wvvuolayxv6m7b75ldy4c52aiu` (abuse.ch ThreatFox Auth-Key)
- [ ] Deploy with `fly deploy -a cloudforge-api`
- [ ] Watch rollout with `fly status -a cloudforge-api` and `fly logs -a cloudforge-api`
- [ ] Wait for health check to pass before validating frontend/API flows

### CF Pages
- [ ] **cloudforge-demo** (portfolio Pages project backing `cloudforge.lvonguyen.com`): auto-deploys from GH. Env: `VITE_API_URL` + `VITE_DEMO_MODE=true`
- [ ] `cloudguard` is a legacy Pages project name that may still exist in the account; do not treat it as the active frontend target
- [ ] JWT: add `JWT_SECRET` as encrypted env var in CF Pages settings, update build command to generate token inline
- [ ] Cloudflare token refs in Development: `op://Development/cf-pages-deploy/credential` (Pages deploy), `op://Development/cf-gbl-api-token/credential` (global key), `op://Development/cf-gbl-api-token/username` (email)
- [ ] Verified 2026-03-31: the scoped Pages token can read both `cloudguard` and `cloudforge-demo`
- [ ] Verify CORS: backend must have outer handler chain (gorilla/mux preflight 405 bug)

---

## Post-Deploy

### Verification
- [ ] Health: `curl https://<api-url>/health`
- [ ] Auth: verify JWT accepted (static token flow)
- [ ] Findings: `curl -H "Authorization: Bearer $JWT" https://<api-url>/api/v1/findings?limit=5`
- [ ] Providers: `curl -H "Authorization: Bearer $JWT" https://<api-url>/api/v1/providers`
- [ ] Issues stats: `curl -H "Authorization: Bearer $JWT" https://<api-url>/api/v1/issues/stats`
- [ ] Issues list: `curl -H "Authorization: Bearer $JWT" "https://<api-url>/api/v1/issues?per_page=5&page=1"`
- [ ] Issue detail: `curl -H "Authorization: Bearer $JWT" https://<api-url>/api/v1/issues/<id>`
- [ ] Frontend loads without "Redirecting to login..." loop
- [ ] During an operator window, create one remediation ticket through `/api/v1/findings/{id}/remediate`, add one `/ticket/comments` entry, and run `/ticket/sync`
- [ ] Verified March 31, 2026: live `cloudforge-api` passed Asana create/comment/resolve/sync and Jira create/comment/sync against the public demo API
- [ ] Verified March 31, 2026: live `cloudforge-api` passed `issues/stats`, paginated `issues`, and `issues/{id}` against the public demo API once the first issue-surface batch committed
- [ ] `integrations.asana_webhook=configured` means the handshake token is present; it does not by itself prove an active external Asana webhook registration

### Cost Monitoring
- [ ] AWS Budget set ($65/mo on personal account)
- [ ] Alerts at 50%, 80%, 100% actual + 100% forecasted
- [ ] [!] Bedrock charges are pay-per-token with NO cap -- disable model access in console if not actively using
- [ ] Bedrock model IDs use date-stamp format: `us.anthropic.claude-sonnet-4-20250514-v1:0` (not marketing names)
- [ ] Claude 3.5/3.7 Sonnet are Legacy in Bedrock -- 403 if unused 15 days

---

## PuppyGraph Deployment Gotchas

### Instance Requirements
- [ ] Minimum: r6i.2xlarge (64GB RAM) -- smaller instances get `UnsupportedOperation`
- [ ] Root volume: 64GB (not default 50GB)
- [ ] AMI: Marketplace AMI runs its own startup -- TF `user_data` may be ignored
- [ ] Health takes ~45s after boot (Docker pull + container start)

### Port Mapping
| Port | Protocol | Purpose |
|------|----------|---------|
| 8081 | HTTP | UI only (no query API) |
| 8182 | WebSocket | Gremlin queries (NOT HTTP POST) |
| 8184 | - | Cypher (closed by default on AMI) |

### Authentication
- [ ] Default creds `puppygraph/puppygraph123#` do NOT work on Marketplace AMI
- [ ] Instance ID as password also fails
- [ ] Must set `PUPPYGRAPH_PASSWORD` env var on the Docker container
- [ ] Login endpoint: `POST http://<ip>:8081/login` with `{"username":"puppygraph","password":"<PUPPYGRAPH_PASSWORD>"}`
- [ ] Returns JWT token for subsequent API calls

### Connection to Postgres
- [ ] Local compose points PuppyGraph at the local Postgres container unless you override the PG_* env vars
- [ ] Marketplace AMI behavior is historical only -- the EC2-hosted PuppyGraph instance was terminated on 2026-03-28
- [ ] Data source configuration still happens via the UI/API AFTER boot -- env vars alone do not fully wire the graph datasource
- [ ] To reconfigure: stop container, recreate with correct env vars via SSM:
  ```bash
  aws ssm send-command --instance-ids <id> \
    --document-name "AWS-RunShellScript" \
    --parameters '{"commands":["docker rm -f puppy","docker run -d --name puppy --restart unless-stopped -p 8081:8081 -p 8182:8182 -p 8184:8184 -e PUPPYGRAPH_PASSWORD=<pwd> -e PG_HOST=<postgres-host> -e PG_PORT=5432 -e PG_DATABASE=aegis -e PG_USER=aegis_app -e PG_PASSWORD=<postgres_pass> puppygraph/puppygraph:0.113","sleep 20","docker logs puppy 2>&1 | tail -5"]}'
  ```
- [ ] Container takes ~20s after start before ready (Docker pull + backend connect)
- [ ] Backend graph client needs WebSocket library for Gremlin (`gorilla/websocket`), not HTTP POST
- [ ] Gremlin HTTP POST returns: `Invalid WebSocket handshake method: POST`
- [ ] WebSocket connects but JSON queries timeout -- Gremlin Server requires TinkerPop binary frame protocol, not raw JSON
- [ ] AMI uses DuckDB as default storage -- PG_* env vars are accepted but PuppyGraph boots with DuckDB demo data regardless
- [ ] Data source must be configured post-boot via PuppyGraph REST management API or UI (not env vars alone)
- [ ] Rewrite `queryGremlin()` in Go: add `gorilla/websocket`, use TinkerPop binary serialization

### TF Module Notes
- [ ] TF `user_data` may be ignored -- Marketplace AMI runs its own startup script
- [ ] Container name inside instance: `puppy`
- [ ] SG: em-dash characters in description cause TF parse errors -- use ASCII dashes only
- [ ] Duplicate `tags` blocks cause TF apply errors
- [ ] Volume must be 64GB (not default 50GB) or PuppyGraph fails to start
- [ ] `path.module` references in schema files need fixing for nested module calls
- [ ] For repeated deploys: add `var.use_marketplace_ami` toggle to TF module
  - Marketplace AMI: quick trials (30-day license), but ignores user_data + DuckDB default
  - Vanilla EC2 + Docker: Amazon Linux 2, user_data installs Docker + pulls PuppyGraph image, env vars work correctly. Slower cold start (~60s) but fully controllable. Recommended for HAEA production.

### Cost & Teardown
- [ ] r6i.2xlarge: ~$0.504/hr ($12/day, $363/mo)
- [ ] For demo sprints: deploy for 48-72hr window only (~$24-36)
- [ ] If using local compose, tear down with `docker compose -f docker-compose.puppygraph.yml down`
- [ ] If using Fly.io only, remove graph config with `fly secrets unset PUPPYGRAPH_URL -a cloudforge-api`
- [ ] Calendar reminder is your friend -- set teardown event immediately on deploy

---

## Data Pipeline Gotchas

### Seed Generator (aegis-seed.mjs)
- [ ] Dedup requires composite key (native ID + control+resource+account) -- single-field dedup misses ~40%
- [ ] Large output files (>1MB) excluded via `testdata/seed/.gitignore` -- never commit to git
- [ ] SQL loader needs batched multi-row INSERTs with `ON CONFLICT` upserts
- [ ] JSONB casting required for cves/compliance_mappings fields, TEXT[] for MITRE/factors
- [ ] Frontend mock: 500-finding stratified sample only (not full 20K) -- keep under 1MB
- [ ] Full seed requires `node --max-old-space-size=6144 scripts/aegis-seed.mjs --count 300000 --out testdata/seed --full --seed 42`

### Database Loading
- [ ] db.t3.micro handles ~20K findings; db.t3.medium+ needed for 300K
- [ ] Create `pgcrypto` before applying schema: `psql "$DATABASE_URL" -c 'CREATE EXTENSION IF NOT EXISTS pgcrypto;'`
- [ ] Apply the ordered migrations through `009_finding_tickets.sql`; do not rely on older `make migrate` helpers for D19
- [ ] Findings loader is a two-step flow: `node scripts/seed-postgres.mjs --in testdata/seed --out /tmp/seed-findings.sql` then `psql "$DATABASE_URL" -f /tmp/seed-findings.sql`
- [ ] Resources loader is separate: `node scripts/seed-resources.mjs --in testdata/seed --out /tmp/seed-resources.sql` then `psql "$DATABASE_URL" -f /tmp/seed-resources.sql`
- [ ] Re-run `migrations/006_graph_support.sql` and `migrations/007_security_graph.sql` after findings/resources load so accounts and graph edges backfill from the seeded corpus
- [ ] Verify counts before cutover: `findings`, `resources`, `accounts`, `graph_edges`
- [ ] Current stable live posture: findings load from Postgres, full large-corpus startup warmup stays disabled by default on the current Fly VM, findings search uses the large-corpus in-memory fallback path when the full search service is intentionally absent, attack paths are built lazily from a bounded sampled cache, and the operator-facing secgraph issue surface incrementally syncs in startup batches while full graph-edge secgraph artifacts remain deferred

---

## Frontend Deployment Gotchas

- [ ] Investigation Board crashes on findings without enrichment -- fallback graph nodes required
- [ ] Deploy preview simulation can hang indefinitely -- 30s safety timeout added
- [ ] Trace panel resize: min 150px, max 600px -- below 150 causes layout collapse
- [ ] Severity sort: `sevOrder` mapping must have higher numeric = more severe (CRITICAL=4, not 1)
- [ ] `?limit=N` accepted as alias for `?per_page=N` on API side
- [ ] Base font-size: 15px (bumped from default for readability on larger displays)

---

## Integration Gotchas

### Jira
- [ ] Dead tokens: `lvnio-jiradev-token` (401), `lvn-jira-api-key-gbl` (401) -- do NOT use
- [ ] Working token: `lvn-pvd-dev-jira-token` (liem@pvdsolutions.io, ATATT, expires 03/2027)
- [ ] Project: CVRT (Cloud Vulnerability Remediation Tracking), id: 10001

### Asana
- [ ] Working token: `lvnio-asana-dev-token` in 1P Development vault
- [ ] Workspace: vonguyen.io (GID: 1212540665692548)
- [ ] Project: Cloud Vulnerability Remediation Tracking (GID: 1213803357058798)

### Provider Cascade
- [ ] Order matters: Asana (if `ASANA_PAT`) > Jira (if `JIRA_URL`) > Mock
- [ ] If both set, Asana is primary -- use `providerForFinding()` to route by existing ticket association

### Python Dependencies
- [ ] `websockets` module not pre-installed -- `pip3 install --break-system-packages` required on newer Python
- [ ] `requests` module missing in some contexts -- use `urllib` or install explicitly

---

## Bedrock Cost Control

- [ ] Bedrock charges are pay-per-token with NO spending cap
- [ ] Opus 4.6: input $15/MTok, output $75/MTok -- a single 300K finding analysis = $10-20
- [ ] March 2026 actual: $93.70 Opus alone (4 spike days: Mar 12 $54, Mar 22 $21)
- [ ] If `AEGIS_AI_ENABLED` is OFF, check for rogue scripts calling Bedrock directly
- [ ] Disable model access in Bedrock console when not actively using
- [ ] Model IDs: date-stamp format (`us.anthropic.claude-sonnet-4-20250514-v1:0`), not marketing names
- [ ] Claude 3.5/3.7 Sonnet: Legacy in Bedrock -- 403 after 15 days of inactivity

---

## Known Issues & Workarounds

| Issue | Symptom | Fix |
|-------|---------|-----|
| Missing /api/v1 prefix | Frontend 404 on all API calls | Add `/api/v1` to VITE_API_URL |
| Raw secret as JWT | "Redirecting to login..." loop | Generate JWT from secret at build time |
| ADO push timeout | Post-commit hook hangs | Kill background task, commit still lands on GH/GL |
| gorilla/mux preflight | CORS 405 on OPTIONS | Outer CORS handler chain before mux router |
| Stale Fly.io hostname | 502 on old Fly hostname | Use `cloudforge-api.fly.dev` or `api.cloudforge.lvonguyen.com` |
| JWT secret mismatch | API 401 with valid JWT | Ensure SM secret matches 1P secret used at build |
| PuppyGraph default creds | Login 401 | Set PUPPYGRAPH_PASSWORD env var, not default creds |
| Gremlin HTTP POST | "Invalid WebSocket handshake" | Use WebSocket client on port 8182, not HTTP |
| Cypher port 8184 | Connection refused | Port closed on Marketplace AMI -- Gremlin only |
| PuppyGraph demo data | Graphs show northwind/modern | Reconfigure data source via UI/API post-boot |
| PuppyGraph /health 404 | Health check fails | Use `GET /login` (or `/`) instead; local compose now health-checks `/login` |
| Gremlin JSON timeout | WebSocket connects but query hangs | TinkerPop binary frame protocol required, not raw JSON |
| Severity sort inverted | desc returns LOW first | Higher sevOrder numeric = more severe |

---

## Environment URLs

### Personal Demo
- Frontend: `https://cloudforge.lvonguyen.com` (CF Pages)
- API: `https://api.cloudforge.lvonguyen.com` (Fly.io)
- PuppyGraph: `http://localhost:8081` (local Docker via `docker-compose.puppygraph.yml`; EC2 terminated 2026-03-28)

### Portfolio Demo
- Frontend: `https://cloudforge.lvonguyen.com` (CF Pages)
- API: `https://api.cloudforge.lvonguyen.com` (Fly.io)
