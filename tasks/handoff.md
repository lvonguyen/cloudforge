# Session Handoff

**Generated:** 2026-03-28T17:30:00Z
**Repo:** cloudforge (Cloud Aegis)
**Branch:** main
**Last commit:** `92848881` docs: refresh diagrams with brand palette + icons, update PuppyGraph refs

## Continuation Update (2026-03-29)

- Added `shared` to `.dockerignore` to stop sending the ~8 GB submodule in Docker build context.
- Added API coverage for the FinOps budget alert path via `TestBudgetStatus_ReturnsFiredAlerts`.
- Verified Playwright E2E status: `17 passed, 1 skipped` via `npx playwright test --reporter=line`; the "5 failing selectors" note below was stale.
- Wired `FINDINGS_SOURCE=postgres`: startup now replaces mock findings with rows from PostgreSQL and reuses the existing in-memory handlers/search/attack-path indexing path.
- Extracted DSPM hardcoded assets from `DataClassification.tsx` into `frontend/src/lib/mock/data-assets.json`.
- Extracted startup/provider wiring out of `cmd/server/main.go` into `cmd/server/bootstrap_startup.go`; `main.go` dropped from 951 lines to 582 while keeping the existing boot order and env-driven behavior.
- Removed the orphaned `internal/cicd` package tree (scanner + SAST/VCS providers/tests); no remaining packages import it and `go list ./...` no longer includes `aegis/internal/cicd`.
- Deleted the orphaned Cloudflare DNS record `api-personal.lvonguyen.com` after verifying it still pointed to `aegis-personal-alb-824833696.us-east-1.elb.amazonaws.com`; follow-up zone query confirmed the record is gone.
- Fixed `internal/graph` test flake: `TestQuery_GremlinDialFailure` now uses `localhost.invalid` instead of assuming `localhost:1` is unreachable after the client rewrites to port `8182`.
- Fixed `internal/secrets` coverage hang: `TestCovProviders_NotImplemented` now uses nil-client provider structs instead of constructing real AWS/Azure/GCP SDK clients that can make live network calls.
- Added the first Go fuzz coverage wave:
  - `cmd/server`: `FuzzSanitizeNLQQuery`, `FuzzValidateNLQResponse`
  - `internal/api`: `FuzzValidateToken`
  - `internal/rql`: `FuzzParseAndMatch`
  - `internal/terminal`: `FuzzCheckOrigin`
- Added a second fuzz coverage wave for ingestion adapters:
  - `internal/ingestion/adapters`: `FuzzProwlerAdapterParse`, `FuzzTrivyAdapterParse`, `FuzzAWSConfigAdapterParse`, `FuzzNormalizeSeverity`
- Added graph/auth helper fuzz coverage:
  - `internal/graph`: `FuzzGremlinWSURL`
  - `internal/api`: `FuzzExtractToken`
- Added graph handler normalization fuzz coverage:
  - `cmd/server`: `FuzzValidateAndNormalizeGraphQuery`
- Fuzzing found and fixed a real NLQ sanitizer bug: control characters could mask an unclosed HTML-looking tag on the first pass, so `sanitizeNLQQuery` was not idempotent for some inputs (for example `"<\\x00A0"`). The helper now removes control characters before running the tag regex.
- Hardened `internal/rql.Parse` against malformed ASTs by rejecting trailing junctions (`severity = HIGH AND`) before `Match` can index past the end of `results`.
- Hardened `internal/graph.gremlinWSURL`: base URLs without a hostname now return an error instead of producing `ws://:8182/gremlin`.
- Extracted graph query validation/normalization into a helper used by the handler so it can be fuzzed directly.
- Fuzzing found and fixed a real graph validation bug: whitespace-only or fully stripped queries could normalize to empty and still pass validation. The helper now rejects blank normalized queries with HTTP 400.
- Verification run during continuation:
  - `env GOCACHE=/tmp/go-build-cache go test ./cmd/server -count=1`
  - `npx vitest run src/pages/__tests__/OpsPages.test.tsx`
  - `npx playwright test --reporter=line`
- Additional verification during continuation:
  - `env GOCACHE=/tmp/go-build-cache go list ./...` no longer includes `aegis/internal/cicd`
  - Cloudflare zone query for `api-personal.lvonguyen.com` returns zero records after deletion
  - `env GOCACHE=/tmp/go-build-cache go test ./... -count=1` passes outside the sandbox after the graph/secrets test fixes
  - Short fuzz smokes passed:
    - `env GOCACHE=/tmp/go-build-cache go test ./cmd/server -run=^$ -fuzz=FuzzSanitizeNLQQuery -fuzztime=2s`
    - `env GOCACHE=/tmp/go-build-cache go test ./cmd/server -run=^$ -fuzz=FuzzValidateNLQResponse -fuzztime=2s`
  - `env GOCACHE=/tmp/go-build-cache go test ./internal/api -run=^$ -fuzz=FuzzValidateToken -fuzztime=2s`
  - `env GOCACHE=/tmp/go-build-cache go test ./internal/rql -run=^$ -fuzz=FuzzParseAndMatch -fuzztime=2s`
  - `env GOCACHE=/tmp/go-build-cache go test ./internal/terminal -run=^$ -fuzz=FuzzCheckOrigin -fuzztime=2s`
  - `env GOCACHE=/tmp/go-build-cache go test ./internal/ingestion/adapters -count=1`
  - `env GOCACHE=/tmp/go-build-cache go test ./internal/ingestion/adapters -run=^$ -fuzz=FuzzProwlerAdapterParse -fuzztime=2s`
  - `env GOCACHE=/tmp/go-build-cache go test ./internal/ingestion/adapters -run=^$ -fuzz=FuzzTrivyAdapterParse -fuzztime=2s`
  - `env GOCACHE=/tmp/go-build-cache go test ./internal/ingestion/adapters -run=^$ -fuzz=FuzzAWSConfigAdapterParse -fuzztime=2s`
  - `env GOCACHE=/tmp/go-build-cache go test ./internal/ingestion/adapters -run=^$ -fuzz=FuzzNormalizeSeverity -fuzztime=2s`
  - `env GOCACHE=/tmp/go-build-cache go test ./internal/graph -run=^$ -fuzz=FuzzGremlinWSURL -fuzztime=2s`
  - `env GOCACHE=/tmp/go-build-cache go test ./internal/api -run=^$ -fuzz=FuzzExtractToken -fuzztime=2s`
  - `env GOCACHE=/tmp/go-build-cache go test ./cmd/server -run=^$ -fuzz=FuzzValidateAndNormalizeGraphQuery -fuzztime=2s`
  - `env GOCACHE=/tmp/go-build-cache go test ./... -count=1` passes outside the sandbox after the graph URL hardening
- Worktree is now dirty with local changes in `.dockerignore`, `cmd/server` tests/startup/NLQ+graph handlers, `cmd/server/main.go`, new startup/Postgres helper files, `internal/api`, `internal/graph`, `internal/ingestion/adapters`, `internal/rql`, `internal/terminal`, DSPM fixture extraction, and this handoff file.

## What Was Done

Session 32 was a security hardening + QA sprint:

- Fixed 2 P0s and deployed to Fly.io v59:
  - BD-01-NEW: nil pointer on `claims.Subject` when JWT missing (handlers_api.go)
  - SA-01: WebSocket `checkOrigin` allowed localhost origins in production (terminal/handler.go)
- Ran full QA-Visual ensemble (3 Opus workers: quality-review, bug-discovery, security-audit + Chrome visual sweep)
  - Scores: QR 4.6 / BD 4.1 / SA 4.6
  - Iteration 1 fixed HIGH-severity NBSP Gremlin blocklist bypass (BD-01), origin parse prefix match (BD-02), byte cap inflation (BD-07), plus 4 new regression tests
- Refreshed all 8 core Mermaid diagrams with brand color palette and FA icons
- Updated stale PuppyGraph EC2 references to local Docker (EC2 was still running despite prior session notes claiming terminated — now actually terminated, saving ~$181/mo)
- Patched `invisible-unicode-check.js` hook with Zs category coverage (shared submodule `4ce7680`)

## Current State

- **Build:** passing (Go build clean, golangci-lint 0 issues)
- **Tests:** Go 45 packages all pass with `-race`, Frontend 447/447 vitest
- **CI:** 3/3 workflows GREEN on `92848881` (CI + Docs Site + Pages)
- **Fly.io:** v59 deployed, both machines healthy (sjc region)
- **Uncommitted changes:** none at session-32 handoff; continuation on 2026-03-29 added local edits
- **Stashed work:** none
- **Open PRs:** none

## Key Files

- `cmd/server/handlers_api.go` — Finding API handlers, ABAC scope enforcement (claims nil guard fixed here)
- `cmd/server/handlers_graph.go` — Gremlin/Cypher query proxy with 3-tier mutation blocklist + NFKC/Cf/Zs sanitization
- `cmd/server/handlers_finops.go` — FinOps aggregator with TTL spend cache, budget monitoring
- `internal/terminal/handler.go` — WebSocket terminal handler with devMode-gated origin check
- `internal/graph/client.go` — PuppyGraph Gremlin WS + Cypher HTTP client (310 lines, fully working)
- `docker-compose.puppygraph.yml` — Local PuppyGraph Docker setup (trial ends 2026-04-18)
- `deploy/docker/puppygraph/schema.json` — PuppyGraph vertex/edge schema (findings, resources, compliance)
- `docs/core/diagrams/` — 8 Mermaid sources + SVG renders (all freshly rendered with brand palette)
- `cmd/server/handlers_finops_test.go` — 9 new FinOps handler tests (budget, estimate, resources)

## Pending Work

### P1 — Should Fix

- [x] Add `shared` to `.dockerignore` — fixed 2026-03-29
- [x] Wire `FINDINGS_SOURCE=postgres` — fixed 2026-03-29
- [x] Verify Playwright E2E selectors — stale backlog item; current suite is `17 passed, 1 skipped`
- [x] Delete orphaned CF DNS `api-personal.lvonguyen.com` pointing to deleted ALB — fixed 2026-03-29
- [x] Add budget alert-firing test case (QR-04) — fixed 2026-03-29 in `cmd/server/handlers_finops_test.go`

### P2 — Remaining

- [x] Extract provider wiring from main.go — fixed 2026-03-29 (`cmd/server/bootstrap_startup.go`; `main.go` now 582 lines)
- [x] DSPM hardcoded mock data to JSON fixture — fixed 2026-03-29
- [x] Dead code cleanup: internal/cicd — fixed 2026-03-29
- [ ] CHANGELOG — 17 sessions behind
- [x] Add first fuzz coverage wave — fixed 2026-03-29 (`cmd/server`, `internal/api`, `internal/rql`, `internal/terminal`)
- [x] Add second fuzz coverage wave — fixed 2026-03-29 (`internal/ingestion/adapters`)
- [x] Add graph/auth helper fuzz coverage — fixed 2026-03-29 (`internal/graph`, `internal/api`)
- [x] Add graph handler normalization fuzz coverage — fixed 2026-03-29 (`cmd/server`)
- [ ] Expand fuzz coverage further (remaining parsers, additional structured inputs, longer fuzz time on highest-value boundaries)
- [ ] PuppyGraph: run multi-hop benchmarks on local Docker with 300K seed data

### ACCEPT (no fix needed)

- Budget rules hardcoded in main.go (acceptable for portfolio demo)
- 8 list handlers use `claims, _` without nil guard (mitigated by auth middleware)
- NLQ rate limiter O(n) eviction (acceptable for demo scale)
- TTL cache thundering herd on 3-4 provider keys (negligible)

## Context & Decisions

- **PuppyGraph on local Docker:** EC2 was terminated 2026-03-28 (was still running despite session 29 notes). PuppyGraph now runs via `docker-compose.puppygraph.yml` connecting to local postgres. Trial ends 2026-04-18. Schema key is `jdbcUri` (NOT `url` — PuppyGraph silently rejects wrong key).
- **NBSP bypass was the highest-value QA find:** Unicode category Zs (NBSP) survives NFKC normalization as regular space, but the Cf-only filter didn't strip it. Fixed with Zs normalization + regex allowing optional whitespace between dot and keyword.
- **checkOrigin uses url.Parse not HasPrefix:** `strings.HasPrefix(origin, "http://localhost")` also matches `http://localhost.evil.com`. Fixed with `url.Parse` hostname comparison.
- **Dual length cap on graph queries:** Rune count (4096) prevents logical abuse, byte count (16384 = 4x) prevents payload inflation via multi-byte CJK/emoji runes.
- **Invisible unicode hook expanded:** Zs category (en-space, em-space, thin space, etc.) added alongside existing Cf/bidi/homoglyph checks in `shared/.claude/scripts/hooks/invisible-unicode-check.js`.

## How to Continue

```bash
cd /Users/lvonguyen/repos/gh/cloudforge

# Quick verify everything is healthy
env GOCACHE=/tmp/go-build-cache go test ./... -count=1

# Start local PuppyGraph for graph research
docker compose -f docker-compose.puppygraph.yml up -d
curl http://localhost:8081/  # verify UI

# Run the app locally with PuppyGraph enabled
PUPPYGRAPH_URL=http://localhost:8081 go run ./cmd/server/

# Optional: continue fuzzing from the new seeds/corpus
env GOCACHE=/tmp/go-build-cache go test ./internal/rql -run=^$ -fuzz=FuzzParseAndMatch -fuzztime=30s
```
