# Session 14 Handoff: Complete Personal Demo End-to-End

## Resume from

`project_session_13_handoff.md` — Personal AWS demo deployed, /health returning 200.

## Task: Wire frontend to live API and verify SecurityHub ingestion

The backend is running on ECS Fargate in lvn-personal (431330216246, us-east-1).
This session completes the last mile: HTTPS via Cloudflare, CORS middleware, frontend
wiring, and real SecurityHub findings flowing through to the dashboard.

## Current State

- **Backend:** ECS service `aegis-personal-api` in cluster `aegis-personal`, 1 running task
- **ALB (HTTP):** `aegis-personal-alb-824833696.us-east-1.elb.amazonaws.com`
- **Health:** `curl http://<ALB>/health` returns 200, postgres+finops+workflow all healthy
- **GRC provider:** `postgres` (connected to RDS, migrations applied — 5 SQL files)
- **Frontend:** `cloudguard.lvonguyen.com` (CF Pages, currently using mock data)
- **CORS:** `CORS_ALLOWED_ORIGINS=https://cloudguard.lvonguyen.com` is set as ECS env var,
  but **no CORS middleware exists in the Go server** — the env var is read at
  `cmd/server/main.go:156` into `cfg.CORSOrigins` but never applied to the router.

## Goals (in order)

### 1. Add CORS Middleware to Go Server
- The `CORSOrigins` field is already in the Config struct (`cmd/server/main.go:61`)
- Need to add actual CORS middleware to the chi router (or whatever router is used)
- Must handle: `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods`,
  `Access-Control-Allow-Headers`, preflight `OPTIONS` requests
- Read allowed origins from `cfg.CORSOrigins` (comma-separated string)
- Skip paths: `/health`, `/healthz`, `/ready` (no CORS needed for infra endpoints)
- Rebuild Docker image and push to ECR after:
  `431330216246.dkr.ecr.us-east-1.amazonaws.com/aegis-personal-api:latest`
- Force ECS redeployment: `aws ecs update-service --cluster aegis-personal --service aegis-personal-api --force-new-deployment`

### 2. Create Cloudflare DNS CNAME
- **Record:** `api-personal.lvonguyen.com` CNAME to `aegis-personal-alb-824833696.us-east-1.elb.amazonaws.com`
- **Proxy:** ON (orange cloud) — Cloudflare terminates TLS, ALB stays HTTP-only
- The Cloudflare API token was not found at `op://Automation/Cloudflare API Token/credential`.
  Check 1Password for the correct vault/item path, or create the record in the CF dashboard.
- After creation, verify: `curl -I https://api-personal.lvonguyen.com/health`

### 3. Wire Frontend to Live API
- Update CF Pages project `cloudguard` environment variable:
  `VITE_API_URL=https://api-personal.lvonguyen.com`
- Trigger a CF Pages rebuild (either via `npm run deploy:haea` or Wrangler CLI)
- The frontend code should already read `VITE_API_URL` for API calls — verify in
  `frontend/src/lib/` or similar

### 4. Test SecurityHub Findings Ingestion
- The cspm-aggregator is a separate binary: `cmd/cspm-aggregator/main.go`
- It imports `aegis/internal/cspm/providers/aws` (SecurityHub client)
- The ECS task role (`aegis-personal-ecs`) already has SecurityHub read permissions:
  `securityhub:GetFindings`, `ListFindings`, `BatchGetSecurityControls`, etc.
- Options to test:
  a. Build and run cspm-aggregator as a one-shot ECS task (like the migration runner)
  b. If the main API server has an ingestion endpoint, POST to it
  c. Check `cmd/server/handlers_ingest_test.go` for the ingestion API contract
- Verify findings appear at `https://cloudguard.lvonguyen.com`

### 5. Document Lessons Learned
- Capture the session 13 deploy-first lessons into the codebase (not just memory)
- Consider: ADR or a `docs/lessons/` file documenting the 7 wiring bugs
- Update CLAUDE.md if any pattern should become a standing rule

## Key References

| Item | Location |
|------|----------|
| Personal TF env | `deploy/terraform/environments/personal/main.tf` |
| TF state (local) | `deploy/terraform/environments/personal/terraform.tfstate` |
| Migration Dockerfile | `deploy/docker/Dockerfile.migrate` |
| CORS config field | `cmd/server/main.go:61` (`CORSOrigins string`) |
| CORS env var read | `cmd/server/main.go:156` (`CORS_ALLOWED_ORIGINS`) |
| CSPM aggregator | `cmd/cspm-aggregator/main.go` |
| AWS provider (SH) | `internal/cspm/providers/aws/` |
| Normalizer | `internal/cspm/normalizer/schema.go` |
| Session 13 lessons | `~/.claude/memory/.../feedback_deploy_first.md` |

## AWS Context

- **Profile:** `lvn-personal` (SSO, Admin on 431330216246)
- **Region:** `us-east-1`
- **ECR login:** `aws ecr get-login-password --region us-east-1 --profile lvn-personal | docker login --username AWS --password-stdin 431330216246.dkr.ecr.us-east-1.amazonaws.com`
- **ECS redeploy:** `aws ecs update-service --cluster aegis-personal --service aegis-personal-api --desired-count 1 --force-new-deployment --profile lvn-personal --region us-east-1`

## Constraints

- Use `rs/cors` or `go-chi/cors` middleware (check if already a dependency in go.mod)
- Don't wildcard CORS — only allow explicit origins from the env var
- HTTPS is via Cloudflare proxy, NOT ACM certificates
- Frontend is static (CF Pages) — only `VITE_*` env vars are available at build time
- Teardown target: 2026-04-20 (all personal infra)
