# Deployment Checklist

Operational nuances discovered during personal demo deployment (March 2026).
Apply to both personal (lvn-personal) and HAEA production environments.

---

## Pre-Deploy

### Credentials & Secrets
- [ ] `aws sso login --profile <profile>` -- verify session active
- [ ] Secrets Manager populated: JWT secret, Asana PAT, Jira API token
- [ ] 1P stores signing KEYS, not pre-signed JWTs -- generate JWT at build time
- [ ] VITE_STATIC_TOKEN must be a generated HS256 JWT, not the raw secret from 1P

### Frontend Build
- [ ] `VITE_API_URL` must include `/api/v1` prefix (e.g., `https://api-personal.lvonguyen.com/api/v1`)
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
- [ ] RDS instance sizing: db.t3.micro handles ~20K findings, db.t3.medium+ needed for 300K
- [ ] Storage: gp3 (not gp2) -- better IOPS/$ at same capacity
- [ ] Run migrations before deploying new app version (ECS one-shot task)

---

## Deploy

### ECS Task Definition
- [ ] Verify all env vars set on task def before force-redeploy
- [ ] Integration env vars (all from Secrets Manager or 1P):
  ```
  ASANA_PAT, ASANA_WORKSPACE_GID, ASANA_DEFAULT_PROJECT_GID
  JIRA_URL, JIRA_USERNAME, JIRA_API_TOKEN, JIRA_PROJECT_KEY
  PUPPYGRAPH_URL (when graph instance active)
  ```
- [ ] Feature flags: 13 backend features gated by env vars -- all OFF by default
  - PUPPYGRAPH_URL, AEGIS_AI_ENABLED, AEGIS_TRACING_ENABLED
  - GREYNOISE_API_KEY, HIBP_API_KEY, OTX_API_KEY
  - JIRA_URL, ASANA_WEBHOOK_TOKEN, WSServerURL
  - RateLimitEnabled, Slack alerting, PagerDuty, Semantic search
- [ ] Docker build MUST target `--platform linux/amd64` -- Mac M-series builds arm64 by default, ECS Fargate rejects it silently
- [ ] Tag images per session (`session19-YYYYMMDD-HHMM`) -- don't overwrite `:latest` blindly
- [ ] Force new deployment: `aws ecs update-service --force-new-deployment`
- [ ] Wait 90s for task stabilization, then health check

### CF Pages
- [ ] **cloudguard** (personal demo): auto-deploys from GH on push to `main`. Root: `frontend/`, build: `npx vite build`, output: `dist`
- [ ] **cloudforge-demo** (portfolio): auto-deploys from GH. Env: `VITE_API_URL` + `VITE_DEMO_MODE=true`
- [ ] JWT: add `JWT_SECRET` as encrypted env var in CF Pages settings, update build command to generate token inline
- [ ] Verify CORS: backend must have outer handler chain (gorilla/mux preflight 405 bug)

---

## Post-Deploy

### Verification
- [ ] Health: `curl https://<api-url>/api/v1/health`
- [ ] Auth: verify JWT accepted (static token flow)
- [ ] Findings: `curl -H "Authorization: Bearer $JWT" https://<api-url>/api/v1/findings?limit=5`
- [ ] Frontend loads without "Redirecting to login..." loop

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

### Connection to RDS
- [ ] AMI ships with demo data (modern + northwind graphs) -- NOT connected to app DB
- [ ] PG_* env vars (PG_HOST, PG_PORT, PG_DATABASE, PG_USER, PG_PASSWORD) are passed but PuppyGraph auto-imports demo data first
- [ ] Data source configuration happens via the UI/API AFTER boot -- env vars alone don't wire RDS
- [ ] To reconfigure: stop container, recreate with correct env vars via SSM:
  ```bash
  aws ssm send-command --instance-ids <id> \
    --document-name "AWS-RunShellScript" \
    --parameters '{"commands":["docker rm -f puppy","docker run -d --name puppy --restart unless-stopped -p 8081:8081 -p 8182:8182 -p 8184:8184 -e PUPPYGRAPH_PASSWORD=<pwd> -e PG_HOST=<rds> -e PG_PORT=5432 -e PG_DATABASE=aegis -e PG_USER=aegis_app -e PG_PASSWORD=<rds_pass> puppygraph/puppygraph:0.113","sleep 20","docker logs puppy 2>&1 | tail -5"]}'
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
- [ ] Teardown: `terraform destroy -target=module.puppygraph` + unset PUPPYGRAPH_URL from ECS
- [ ] Calendar reminder is your friend -- set teardown event immediately on deploy

---

## Data Pipeline Gotchas

### Seed Generator (aegis-seed.mjs)
- [ ] Dedup requires composite key (native ID + control+resource+account) -- single-field dedup misses ~40%
- [ ] Large output files (>1MB) excluded via `testdata/seed/.gitignore` -- never commit to git
- [ ] SQL loader needs batched multi-row INSERTs with `ON CONFLICT` upserts
- [ ] JSONB casting required for cves/compliance_mappings fields, TEXT[] for MITRE/factors
- [ ] Frontend mock: 500-finding stratified sample only (not full 20K) -- keep under 1MB

### Database Loading
- [ ] db.t3.micro handles ~20K findings; db.t3.medium+ needed for 300K
- [ ] Run migrations (002 schema) before loading seed data
- [ ] Seed loader: `scripts/load-findings-to-postgres.mjs` (requires Node.js + pg driver)

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
| Stale Fly.io hostname | 502 on aegis-api.fly.dev | Use cloudforge-api.fly.dev or custom domain |
| JWT secret mismatch | API 401 with valid JWT | Ensure SM secret matches 1P secret used at build |
| PuppyGraph default creds | Login 401 | Set PUPPYGRAPH_PASSWORD env var, not default creds |
| Gremlin HTTP POST | "Invalid WebSocket handshake" | Use WebSocket client on port 8182, not HTTP |
| Cypher port 8184 | Connection refused | Port closed on Marketplace AMI -- Gremlin only |
| PuppyGraph demo data | Graphs show northwind/modern | Reconfigure data source via UI/API post-boot |
| PuppyGraph /health 404 | Health check fails | Use `GET /` or `GET /login` instead (both return 200) |
| Gremlin JSON timeout | WebSocket connects but query hangs | TinkerPop binary frame protocol required, not raw JSON |
| Severity sort inverted | desc returns LOW first | Higher sevOrder numeric = more severe |

---

## Environment URLs

### Personal Demo (AWS)
- Frontend: `https://cloudguard.lvonguyen.com` (CF Pages)
- API: `https://api-personal.lvonguyen.com` (ALB -> ECS Fargate)
- PuppyGraph: `http://100.52.183.146:8081` (temporary, teardown March 28)
- PuppyGraph instance: `i-096bba925c464985f` (r6i.2xlarge, us-east-1a)

### Portfolio Demo (Fly.io)
- Frontend: `https://cloudaegis-demo.lvonguyen.com` (CF Pages)
- API: `https://api.cloudforge-demo.lvonguyen.com` (Fly.io)
