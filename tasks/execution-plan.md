# CloudForge Unified Execution Plan

**Generated:** 2026-03-04
**Source:** WS2 (trace view system) + WS3 (gap analysis) — 2-layer Opus distillation

---

## Dependency Graph

```
                    +--------------------------------------+
                    |       SPRINT 0 (Foundation)          |
                    |                                      |
                    |  [A] RBAC middleware                  |
                    |  [D] GreyNoise client                |
                    |  [E] OTel app-level spans            |
                    |  [L0] TracePanelContext + hooks       |
                    +------+------+----------+-------------+
                           |      |          |
              +------------+      |          +------------+
              v                   v                       v
   +------------------+  +-------------------+  +-------------------+
   |  SPRINT 1        |  |  SPRINT 1         |  |  SPRINT 1         |
   |  [B] Handler     |  |  [C] Backend API  |  |  [L1] P0 buttons  |
   |  tests +         |  |  endpoints for    |  |  (Execute,        |
   |  httptest infra  |  |  findings,        |  |   Remediate,      |
   |                  |  |  compliance,      |  |   Run/Stop)       |
   |  Needs: [A]      |  |  agents, costs    |  |  Needs: [L0]      |
   +--------+---------+  |  Needs: [A]       |  +--------+----------+
            |             +--------+----------+           |
            v                      v                      v
   +--------------------------------------------------------------+
   |                    SPRINT 2                                   |
   |                                                               |
   |  [F] Frontend hook migration (mock JSON -> apiClient)         |
   |  [L2] P1 buttons (Dry Run, Approve, Policy, Exception)       |
   |  [L3] P2 buttons (Retry, Suppress, Invite, New Policy)       |
   |                                                               |
   |  Needs: [C] endpoints live, [L1] panel functional             |
   +--------------------------------------------------------------+
```

**Critical path:** A -> C -> F (RBAC -> API endpoints -> hook migration)

---

## Sprint 0 — Foundation (4 parallel agents)

All items independent. No cross-dependencies.

### Agent RBAC [A] — RBAC middleware + Okta/Entra wiring

| Detail | Value |
|--------|-------|
| Priority | HIGH |
| Create | `internal/api/rbac.go` — `RequireRole()`, `RequireScope()` middleware |
| Modify | `cmd/server/main.go` — add RBAC middleware to subrouter chain, wire identity providers |
| Modify | `internal/api/auth_middleware.go` — extract role from JWT claims |
| Reference | `internal/identity/provider.go` (existing interface) |
| Acceptance | Every handler in `setupRoutes()` has role check. Unauthz = 403. Tests with mock JWT pass. |

### Agent GreyNoise [D] — Threat intel client

| Detail | Value |
|--------|-------|
| Priority | MEDIUM |
| Create | `internal/cspm/threatintel/greynoise.go` — HTTP client, 12h cache (match EPSS pattern) |
| Create | `internal/cspm/threatintel/greynoise_test.go` |
| Modify | `internal/cspm/normalizer/schema.go` — populate `GreyNoiseClass` in enrichment |
| Pattern | Follow `internal/cspm/threatintel/epss.go` exactly |
| Acceptance | `go test ./internal/cspm/threatintel/...` passes. |

### Agent OTel [E] — App-level tracing spans

| Detail | Value |
|--------|-------|
| Priority | MEDIUM |
| Modify | `cmd/server/main.go` — init tracer, inject into Server struct |
| Modify | Handler functions — add `ctx, span := tracer.Start(...)` / `defer span.End()` |
| Acceptance | `go build ./cmd/server` succeeds. Spans emitted to stdout in dev mode. |

### Agent TraceInfra [L0] — Frontend trace panel infrastructure

| Detail | Value |
|--------|-------|
| Priority | HIGH |
| Create | `frontend/src/lib/trace-panel-context.tsx` — TracePanelContext, TracePanelProvider |
| Create | `frontend/src/hooks/useActionCooldown.ts` — generic cooldown hook |
| Create | `frontend/src/hooks/useStreamingTrace.ts` — extracted from useDeployPreview pattern |
| Create | `frontend/src/components/layout/ExecutionTracePanel.tsx` — bottom drawer, 3 modes |
| Modify | `frontend/src/App.tsx` — wrap with TracePanelProvider |
| Acceptance | Panel renders collapsed. useTracePanel().open() works. Cooldown prevents re-fire. |

---

## Sprint 1 — API Endpoints + P0 Buttons (PARTIAL COMPLETE)

Depends on Sprint 0 (RBAC middleware + trace infra).

### Agent HandlerTests [B] — PARTIAL (frontend tests only)

| Detail | Value |
|--------|-------|
| Create | `cmd/server/main_test.go` — test helpers, mock providers, JWT factory |
| Create | `cmd/server/handlers_test.go` — tests for all exception endpoints + /health |
| Status | Frontend tests complete (12 new files: 6 hooks, 6 components), backend handler tests pending |
| Completed | renderWithAuth helper, v8 coverage thresholds, ADR-006/007 fixes |
| Commits | 01967fb (B workstream: tests) |
| Deps | [A] must land first |
| Acceptance | `go test ./cmd/server/...` passes. >= 80% handler coverage. |

### Agent BackendAPI [C] — PARTIAL (1 new endpoint)

| Detail | Value |
|--------|-------|
| Modify | `cmd/server/main.go` — add routes + handlers |
| New routes | `GET /api/v1/findings`, `GET /api/v1/findings/{id}`, `GET /api/v1/compliance/frameworks`, `GET /api/v1/agents`, `GET /api/v1/agents/{id}`, `GET /api/v1/costs/summary`, `GET /api/v1/remediations`, `POST /api/v1/remediations/{id}/execute` |
| Completed | `GET /api/v1/exceptions/mine` (RBAC: requester+), GetExceptionsByRequestor in GRC providers |
| Commits | 999f224 (C workstream: API + hooks) |
| Deps | [A] must land first (endpoints need role guards) |
| Acceptance | All endpoints return valid JSON. RBAC enforced. |

### Agent P0Buttons [L1] — PARTIAL (Execute/Retry wired)

| Detail | Value |
|--------|-------|
| Modify | `frontend/src/pages/ops/RemediationQueue.tsx` — Execute button (30s cooldown, streaming) |
| Modify | `frontend/src/pages/ops/FindingDetail.tsx` — Remediate button (10s cooldown, timeline) |
| Completed | Execute/Retry buttons wired in RemediationQueue + RemediationDetail via useExecuteRemediation hook |
| Commits | 999f224 (C workstream: API + hooks) |
| Deps | [L0] must land first |
| Acceptance | Clicking Execute/Remediate opens bottom panel with trace output. Cooldown active. |

---

## Sprint 2 — Hook Migration + P1/P2 Buttons (PARTIAL — hooks done, buttons deferred)

Depends on Sprint 1 (API endpoints live, P0 buttons functional).
Commits: `01967fb` (tests), `999f224` (API + hooks), `a9c48af` (docs)

### Agent HookMigration [F] — PARTIAL (3 hooks + 1 fix done, 5 remaining)

| Detail | Value |
|--------|-------|
| Modify | 5 hooks: `useFindings.ts`, `useCompliance.ts`, `useAgents.ts`, `useCosts.ts`, `useRemediations.ts` |
| Keep | `useExceptions.ts` (already uses apiClient), `useDeployPreview.ts` (client-side sim) |
| Completed | `useMyExceptions.ts` (MyRequests.tsx now uses real API) |
| Completed | `useCostAnomalies` queryKey fix (cache sharing with useCostSummary) |
| Completed | `useExecuteRemediation` mutation hook (Execute/Retry buttons) |
| Remaining | 5 hooks to migrate from mock JSON to apiClient |
| Deps | [C] endpoints must return compatible JSON shapes |
| Acceptance | Network tab shows real `/api/v1/*` requests. Zero static mock imports in hooks. |
| Commits | 999f224 (C workstream: API + hooks), 01967fb (B workstream: tests) |

### Agent P1P2Buttons [L2/L3] — NOT STARTED

| Detail | Value |
|--------|-------|
| P1 | Dry Run (15s), Approve (1s), Policy Validation (5s), Exception Submit (30s) |
| P2 | Retry (exp backoff), Suppress (1s), Invite User (5s), New Policy (3s) |
| Deps | [L1] + [F] both landed |
| Status | Deferred to Sprint 3 |
| Acceptance | All 12 action buttons from WS2 spec functional with correct cooldowns and panel modes. |

---

## Trace View Action Inventory

| P | Action | Page | Trace Mode | Rate Limit | Effort |
|---|--------|------|-----------|------------|--------|
| P0 | Execute | RemediationQueue | streaming | 1/30s | M |
| P0 | Remediate | FindingDetail | timeline | 1/10s | M |
| P0 | Run Deploy | DeployPreview | streaming | 1 active/user | S (wired) |
| P0 | Stop Deploy | DeployPreview | abort | -- | S (wired) |
| P1 | Dry Run | RemediationQueue | dry-run | 1/15s | M |
| P1 | Approve | CommandCenter | timeline | 1/sec | S |
| P1 | Policy Validation | Request step 2-3 | timeline | 1/5s | M |
| P1 | Exception Submit | Request step 5 | timeline | 1/30s | S |
| P2 | Retry | RemediationQueue | streaming | exp backoff | S |
| P2 | Suppress | FindingDetail | confirm | 1/sec | S |
| P2 | Invite User | Admin Users | modal | 1/5s | S |
| P2 | New Policy | Admin Policies | timeline | 1/3s | M |

---

## Scope Estimate

| Metric | Count |
|--------|-------|
| New Go files | 3 (rbac.go, greynoise.go, greynoise_test.go) |
| New Go test files | 2 (main_test.go, handlers_test.go) |
| New TS files | 6 (context, 2 hooks, panel, 2 button components) |
| Modified Go files | 4 (main.go, auth_middleware.go, schema.go, telemetry.go) |
| Modified TS files | 9 (5 hooks, App.tsx, RemediationQueue, FindingDetail, DeployPreview) |
| Est. new lines | ~2,500 Go + ~1,200 TS = ~3,700 |
| Est. modified lines | ~400 Go + ~300 TS = ~700 |

---

## Risks and Decision Points

1. **[!] RBAC role source** — Backend JWT has `scope` string. Frontend uses localStorage role switching (dev mode). Decision: backend reads `scope` claim; frontend dev switcher sets mock JWT header.

2. **[!] Backend data source** — New endpoints have no DB backing. Recommend: embed JSON from Go for Sprint 1 (demo-quality), add PostgreSQL layer later.

3. **[!] Hook migration schema** — BackendAPI and HookMigration agents must coordinate on response JSON shapes. Types in `frontend/src/types/` may need updates.

4. **[!] OTel collector** — `initTracer()` connects to OTLP gRPC. Without collector, degrades gracefully (warn-log). Local dev needs docker-compose service or stdout exporter.

5. **[!] Test sequencing** — Zero handler tests exist. `handlers_test.go` must be sequenced after RBAC to avoid testing stale behavior.

---

## Deferred Items (Lower Portfolio ROI)

- Attack path computation (XL effort, design doc only)
- Container security TODOs (5 stubs)
- WAF module TODOs (7 stubs)
- Secrets manager TODOs (15 stubs)
- CI/CD dependency scanner stub
- Integration test suite (needs docker-compose test infra)
- Temporal workflow testing
