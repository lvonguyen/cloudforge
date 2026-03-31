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
- Added webhook URL validation fuzz coverage:
  - `internal/webhooks`: `FuzzValidateWebhookURL`
- Fuzzing found and fixed a real NLQ sanitizer bug: control characters could mask an unclosed HTML-looking tag on the first pass, so `sanitizeNLQQuery` was not idempotent for some inputs (for example `"<\\x00A0"`). The helper now removes control characters before running the tag regex.
- Hardened `internal/rql.Parse` against malformed ASTs by rejecting trailing junctions (`severity = HIGH AND`) before `Match` can index past the end of `results`.
- Hardened `internal/graph.gremlinWSURL`: base URLs without a hostname now return an error instead of producing `ws://:8182/gremlin`.
- Extracted graph query validation/normalization into a helper used by the handler so it can be fuzzed directly.
- Fuzzing found and fixed a real graph validation bug: whitespace-only or fully stripped queries could normalize to empty and still pass validation. The helper now rejects blank normalized queries with HTTP 400.
- Hardened `internal/webhooks.validateWebhookURL`: now rejects `localhost.` and `*.localhost` hostnames in addition to exact `localhost`.
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
  - `env GOCACHE=/tmp/go-build-cache go test ./internal/webhooks -count=1`
  - `env GOCACHE=/tmp/go-build-cache go test ./internal/webhooks -run=^$ -fuzz=FuzzValidateWebhookURL -fuzztime=2s`
  - `env GOCACHE=/tmp/go-build-cache go test ./... -count=1` passes outside the sandbox after the graph URL hardening
- Worktree remains dirty; current local delta is in `cmd/server/attackpath_enrich.go`, `cmd/server/service_enrichment_test.go`, the new fuzz test files under `cmd/server`, `internal/container`, `internal/secrets`, `internal/terminal`, and this handoff file.

## Continuation Update (2026-03-30)

- Added a third Go fuzz coverage wave for remaining structured-input and parser-heavy paths:
  - `cmd/server`: `FuzzPostgresFindingRowToFinding`, `FuzzParseFindingEnrichment`, `FuzzParseEnrichmentResponse`, `FuzzBuildEnrichmentPrompt`
  - `internal/container`: `FuzzParseTrivyK8sJSON`
  - `internal/secrets`: `FuzzScannerScan`
  - `internal/terminal`: `FuzzExecutorValidate`
- Added deterministic `extractIPsFromText` coverage in `cmd/server/service_enrichment_test.go`.
- Verified `gzipResponseWriter` already preserves `http.Flusher` and `http.Hijacker`; added regression tests in `cmd/server/middleware_test.go` and cleared the stale deferred note.
- Fuzzing found and fixed a real prompt-sanitization gap in `cmd/server/attackpath_enrich.go`:
  - `sanitizeForPrompt` now NFKC-normalizes input, strips ASCII control bytes, Unicode format chars, and normalizes non-ASCII space separators.
  - `buildEnrichmentPrompt` now sanitizes edge labels and MITRE tactics before assembling the model prompt.
- Verification during the 2026-03-30 continuation:
  - Targeted package tests passed:
    - `env GOCACHE=/tmp/go-build-cache go test ./cmd/server -run 'TestPostgresFindingRow|TestParseFindingEnrichment|TestTruncateField|TestExtractIPsFromText|TestAttackPaths_' -count=1`
    - `env GOCACHE=/tmp/go-build-cache go test ./cmd/server -run 'TestGzipMiddleware|TestGzipResponseWriter' -count=1`
    - `env GOCACHE=/tmp/go-build-cache go test ./internal/container -run Test -count=1`
    - `env GOCACHE=/tmp/go-build-cache go test ./internal/secrets -run Test -count=1`
    - `env GOCACHE=/tmp/go-build-cache go test ./internal/terminal -run Test -count=1`
  - Extended fuzz runs passed:
    - `env GOCACHE=/tmp/go-build-cache go test ./cmd/server -run=^$ -fuzz=FuzzPostgresFindingRowToFinding -fuzztime=30s`
    - `env GOCACHE=/tmp/go-build-cache go test ./cmd/server -run=^$ -fuzz=FuzzParseFindingEnrichment -fuzztime=30s`
    - `env GOCACHE=/tmp/go-build-cache go test ./cmd/server -run=^$ -fuzz=FuzzParseEnrichmentResponse -fuzztime=30s`
    - `env GOCACHE=/tmp/go-build-cache go test ./cmd/server -run=^$ -fuzz=FuzzBuildEnrichmentPrompt -fuzztime=30s`
    - `env GOCACHE=/tmp/go-build-cache go test ./internal/container -run=^$ -fuzz=FuzzParseTrivyK8sJSON -fuzztime=30s`
    - `env GOCACHE=/tmp/go-build-cache go test ./internal/secrets -run=^$ -fuzz=FuzzScannerScan -fuzztime=30s`
    - `env GOCACHE=/tmp/go-build-cache go test ./internal/terminal -run=^$ -fuzz=FuzzExecutorValidate -fuzztime=30s`
  - `env GOCACHE=/tmp/go-build-cache go test ./... -count=1` passes outside the sandbox; the in-sandbox failure mode was expected because several packages use `httptest.NewServer`, which cannot bind localhost in this environment.

## Architecture Coordination Update (2026-03-30)

Use this file as the shared climbing board for all security-graph work. Before starting a substantial architecture or implementation slice:

- claim the workstream below by appending your session/date
- list the files or domains you intend to touch
- move the item between `In Flight`, `Pending`, `Blocked`, and `Done`
- do not modify another in-flight workstream's files without leaving a coordination note here first

### Done

- `WG-A: Security Graph platform decision` — completed 2026-03-31
  - Scope completed: Neptune vs PuppyGraph vs Postgres role split; eventing backbone; graph source-of-truth recommendation
  - Output: architecture recommendation, tooling tradeoffs, and staged migration path recorded below
  - Working memo: `docs/research/security-graph-platform-options.md`

- `WG-B: Graph data model — Phase 1 (Schema)` — completed 2026-03-30 (session 33)
  - Scope completed: Canonical node taxonomy (6 vertex types) and edge taxonomy (8 edge types). Migration 007 with 6 new tables + 3 backfill queries. PuppyGraph schema updated (6 vertices, 8 edges). Go domain types in `internal/secgraph/types.go`.
  - Output files:
    - `docs/core/architecture/adr/ADR-020-security-graph-architecture.md` — master ADR
    - `migrations/007_security_graph.sql` — accounts, controls, control_evaluations, issues, issue_findings, graph_edges
    - `internal/secgraph/types.go` — Go types: Control, ControlEvaluation, Issue, Account, GraphEdge + enums
    - `deploy/docker/puppygraph/schema.json` — 6 vertices, 8 edges (was 3/2)
    - `docs/core/architecture/graph-native-attack-paths.md` — Gremlin query reference mapping heuristic→graph-native
  - Remaining in WG-B Phase 2: Edge materialization (populate graph_edges on ingestion, control eval, issue creation). Backfill same_account/same_region co-location edges.

- `WG-C: Controls → Issues engine — Phase 1 (Schema)` — completed 2026-03-30 (session 33)
  - Scope completed: Control and Issue entity schemas, evaluation model (per-resource pass/fail), issue lifecycle (OPEN→ACKNOWLEDGED→IN_PROGRESS→RESOLVED→SUPPRESSED), dedup key (control_id, resource_id, tenant_id).
  - Remaining in WG-C Phase 2: Control seeding from `internal/compliance` frameworks, evaluation bridge in `compliance.Manager.MapFinding()`, issue materialization engine, scoring (severity × blast_radius × exposure), ticket dispatch integration.

- `WG-C Phase 2: Deterministic control seeding + materialization helpers` — completed 2026-03-31 (codex)
  - Scope completed: exported framework listing from `internal/compliance`, deterministic control seeding helpers, issue/evaluation materialization helpers, and package tests
  - Output files:
    - `internal/secgraph/materialize.go`
    - `internal/secgraph/materialize_test.go`
    - `internal/secgraph/types.go`
    - `internal/compliance/framework.go`
  - Verification:
    - `env GOCACHE=/tmp/go-build-cache go test ./internal/secgraph -count=1`
    - `env GOCACHE=/tmp/go-build-cache go test ./internal/compliance -count=1`
  - Remaining in WG-C Phase 2: persist seeded controls/evaluations/issues, bridge runtime finding mapping to secgraph writes, and ticket dispatch integration.

- `WG-B Phase 2: Edge materialization` — completed 2026-03-31 (session 33, lead)
  - Scope completed: Backfill functions for affects/belongs_to/maps_to/same_region edges, bootstrap wiring (runs after findings load, gated on auditDB != nil), NopEdgeStore removed (Codex store handles CRUD).
  - Output files:
    - `internal/secgraph/backfill.go` — RunEdgeBackfill + 4 backfill SQL functions
    - `internal/secgraph/backfill_test.go` — 6 unit tests (edge types, node types, newEdge determinism, properties)
    - `cmd/server/main.go` — secgraph.RunEdgeBackfill wired after loadRuntimeData
  - Verification: `go build ./...` clean, `go vet ./...` clean, `go test ./internal/secgraph/ -count=1` — 9/9 pass
  - Note: Codex agent reworked `store.go` during WG-C into a `Store` struct with `UpsertControls`/`UpsertMaterialization`. Backfill uses `*sql.DB` directly (separate concern from per-record CRUD).

- `WSG-3: Eventing and tenant isolation (architecture)` — completed 2026-03-31 (codex)
  - Scope completed: per-tenant event envelope, queueing/fanout recommendations, stage-by-stage graph change propagation design
  - Output file:
    - `docs/research/security-graph-eventing.md`
  - Decision: use SQS + EventBridge Pipes for the internal graph/issue pipeline, SNS or EventBridge bus for many-to-many downstream fanout, and FIFO semantics for tenant/resource-sensitive mutation streams

- `WG-C Phase 2: Startup sync bridge` — completed 2026-03-31 (codex)
  - Scope completed: seed secgraph controls at startup, convert loaded findings into compliance findings, materialize issues/evaluations/edges, and persist them before graph backfill when Postgres is enabled
  - Output files:
    - `cmd/server/secgraph_sync.go`
    - `cmd/server/secgraph_sync_test.go`
    - `cmd/server/main.go`
  - Verification:
    - `env GOCACHE=/tmp/go-build-cache go test ./cmd/server -run 'TestSyncSecurityGraphWithStore|TestToComplianceFinding' -count=1`
    - `env GOCACHE=/tmp/go-build-cache go test ./cmd/server -run 'TestPostgresFindingRow|TestParseFindingEnrichment|TestAttackPaths_|TestSyncSecurityGraphWithStore|TestToComplianceFinding' -count=1`
    - `env GOCACHE=/tmp/go-build-cache go test ./internal/secgraph ./internal/compliance -count=1`

- `WG-C Phase 2: Issue ticket dispatch integration` — completed 2026-03-31 (codex)
  - Scope completed: preserve existing secgraph issue ticket metadata during startup rematerialization, optionally auto-create tickets for unticketed issues through the existing integrations provider/router path, and persist ticket metadata with the issue rows
  - Output files:
    - `cmd/server/secgraph_sync.go`
    - `cmd/server/secgraph_sync_test.go`
    - `cmd/server/main.go`
    - `docs/core/configuration-reference.md`
  - Guardrail: automatic ticket creation is gated behind `SECGRAPH_AUTO_TICKETS=true`; existing ticket metadata is still hydrated even when auto-dispatch is disabled
  - Verification:
    - `env GOCACHE=/tmp/go-build-cache go test ./cmd/server -run 'TestSyncSecurityGraphWithStore|TestSyncSecurityGraphWithStoreAndDispatcher|TestSecgraphTicketDispatcher|TestSecgraphAutoTicketsEnabled|TestToComplianceFinding|TestRemediateFinding|TestGetFindingTicket' -count=1`
    - `env GOCACHE=/tmp/go-build-cache go test ./internal/secgraph ./internal/compliance ./internal/integrations -count=1`

### In Flight

(none currently)

### Pending

- `WG-C Phase 2: Control evaluation + Issue pipeline`
  - Optional follow-up: promote startup sync into incremental ingestion-time writes instead of startup-only materialization
  - Optional follow-up: broaden auto-dispatch policy beyond startup and add issue-level read/write APIs if secgraph issues become a first-class operator surface
  - Likely touchpoints: `internal/secgraph/`, `internal/compliance/`, `cmd/server/handlers_*.go`

- `WG-D: Live graph query/API path`
  - Replace findings-derived frontend graph rendering with backend neighborhood queries and graph-native path projections
  - Likely touchpoints: `cmd/server/handlers_graph.go`, `internal/graph/`, `frontend/src/pages/ops/SecurityGraph.tsx`
  - Blocked by: WG-B Phase 2 (needs populated edges)

- `WG-E: Graph UX modernization`
  - Improve graph layout, expansion model, clustering, inspector rail, and attack-path drill-downs after backend contracts are settled
  - Likely touchpoints: `frontend/src/components/ops/BaseGraphView.tsx`, `frontend/src/pages/ops/AttackPaths.tsx`, `frontend/src/components/attack-path/AttackPathMiniGraph.tsx`
  - Blocked by: WG-D (needs backend graph query API)

### Current Architecture Facts

- Current attack paths are heuristic finding chains, not graph-native issue outputs.
  - Evidence: `computeAttackPaths` builds paths from account grouping, entry/intermediate/target heuristics, and `canConnect` rules in `cmd/server/attackpath.go`.

- The frontend attack-path experience still falls back to mock/precomputed payloads when the API is unavailable.
  - Evidence: `frontend/src/hooks/useAttackPaths.ts`.

- The main Security Graph UI is findings-derived, not backed by live graph neighborhoods.
  - Evidence: `frontend/src/pages/ops/SecurityGraph.tsx`.

- PuppyGraph is wired today as a query surface over relational tables, not yet as the primary risk computation engine.
  - Evidence: `cmd/server/handlers_graph.go`, `internal/graph/client.go`, `deploy/docker/puppygraph/schema.json`.

- The current PuppyGraph schema is too thin for Wiz-like path analysis.
  - Today it models `finding`, `resource`, and `compliance_framework` with `affects` and `maps_to` edges only.

### Working Target

- `Security Graph` = tenant-scoped live graph of evidence and relationships
- `Controls` = graph-native toxic-combination rules evaluated over current graph state
- `Issues` = materialized control matches with lifecycle and severity
- `Attack Paths / Blast Radius / Exposure Views` = projections over issues and graph neighborhoods, not standalone heuristics

### Provisional Recommendation

#### WG-A Decision Output (2026-03-31)

- `Recommended target:` Neptune Database as the primary tenant-scoped security graph if the goal is Wiz-like live Controls -> Issues -> Attack Paths, with Aurora/Postgres retained for high-volume raw findings/config/control metadata and ElastiCache/Valkey considered for diff/cache hot paths.
- `Recommended near-term role for PuppyGraph:` keep it as a federated read/query and analyst exploration layer while the graph-native control plane is being designed. It is useful for ad-hoc Gremlin/openCypher access and relational-to-graph projection, but it should not be the assumed long-term source of truth for live issue materialization.
- `Why:` the current repo uses PuppyGraph as a read-only query surface over a thin relational schema (`finding`, `resource`, `compliance_framework`) and does not drive core risk computation from it. Wiz's published Neptune architecture uses Aurora + Neptune + ElastiCache together: Aurora for high-volume storage, Neptune for the security graph, ElastiCache for scan-comparison offload, and Bedrock for investigation/remediation assistance.
- `AWS-native eventing direction to explore next:` EventBridge Pipes for source-to-target plumbing, or SNS/SQS fan-out when explicit queue isolation per tenant/workstream is needed. This belongs in `WSG-3`.
- `Guardrail:` do not over-invest in graph UI polish until `WSG-B` and `WSG-C` define canonical node/edge taxonomy and the controls/issues contract.

Source pointers:
- AWS case study: https://aws.amazon.com/solutions/case-studies/wiz-neptune/
- Neptune Streams change records: https://docs.aws.amazon.com/neptune/latest/userguide/streams-change-formats.html
- EventBridge Pipes: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes.html
- PuppyGraph getting started / query-as-graph positioning: https://docs.puppygraph.com/getting-started/

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
- `docs/core/architecture/adr/ADR-020-security-graph-architecture.md` — Security Graph master ADR (system roles, taxonomy, phases)
- `migrations/007_security_graph.sql` — accounts, controls, control_evaluations, issues, issue_findings, graph_edges tables
- `internal/secgraph/types.go` — Security Graph domain types (Control, Issue, GraphEdge, Account + enums)
- `docs/core/architecture/graph-native-attack-paths.md` — Gremlin query reference for attack path migration

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
- [x] Add webhook URL validation fuzz coverage — fixed 2026-03-29 (`internal/webhooks`)
- [x] Expand fuzz coverage further — fixed 2026-03-30 (`cmd/server`, `internal/container`, `internal/secrets`, `internal/terminal`; 30s fuzz passes on highest-value boundaries)
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
env GOCACHE=/tmp/go-build-cache go test ./cmd/server -run=^$ -fuzz=FuzzBuildEnrichmentPrompt -fuzztime=60s
env GOCACHE=/tmp/go-build-cache go test ./internal/secrets -run=^$ -fuzz=FuzzScannerScan -fuzztime=60s
env GOCACHE=/tmp/go-build-cache go test ./internal/rql -run=^$ -fuzz=FuzzParseAndMatch -fuzztime=60s
```
