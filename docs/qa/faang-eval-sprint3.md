# FAANG L6 Portfolio Evaluation — Sprint 3 (Post-Hardening)

**Evaluator:** Claude Opus 4.6 (automated)
**Date:** 2026-03-15
**Scope:** Full codebase after Sprint 2 code review + Sprint 3 D1-D8 implementation
**Commits evaluated:** `358e5b0` through `30fb16c` (12 commits this session)

---

## Consolidated Scores

| # | Dimension | Score | Delta vs Codex | Key Evidence |
|---|-----------|------:|:--------------:|--------------|
| 1 | Security Architecture & Threat Modeling | **4.3** | +0.8 | ADR-013 implemented (EnforceScope, Scopeable, 19 tests), STRIDE T-01/T-02 closed, AES-256-GCM rollback encryption, SHA-256 integrity hashing, DedupCache, tenant middleware with JWT+header+subdomain resolution |
| 2 | System Architecture & Integration Design | **4.1** | +0.6 | Ingestion endpoint shipped (`POST /api/v1/findings/ingest` with admin RBAC + dedup), tenant middleware + /config.json dynamic endpoint, God Object refactored (24→15→22 fields with 3 extracted services), provider abstractions clean |
| 3 | Code Quality & Elegance | **4.2** | +0.7 | CommandCenterContext is a clean useReducer state machine (8 actions, flat layer key system), Recharts pattern reused across FindingsSummaryChart/FindingsTreemap, 326+ frontend tests, role mismatch documented |
| 4 | Frontend Design & UX | **4.0** | +0.5 | Command Center V2: treemap heatmap, faceted filtering, date range temporal filter, keyboard shortcuts with overlay, dark palette consistency, ProviderBadge contrast fix, ConfigProvider for runtime branding |
| 5 | Compliance & GRC Maturity | **4.2** | +0.7 | Resource-scoped RBAC live (EnforceScope + Scopeable interface + ResourceScope on Claims), AuditLogger interface with Memory+Zap implementations wired to 4 handlers, ServiceNow lifecycle complete |
| 6 | Operational Readiness | **3.8** | +0.8 | CI: 8 jobs (Frontend Checks, Build & Test, Lint, Security Scan, OPA, Cloudflare Pages, Fly.io, Docker), vitest in CI, Codecov, gosec+Trivy in SARIF, .gitleaks.toml allowlist, codecov.yml, -race enabled, -timeout 20m |
| 7 | Documentation & Communication | **4.2** | +0.2 | CODEBASE_INDEX.md added, 14 ADRs, STRIDE threat model with T-01/T-02 IMPLEMENTED status, CHANGELOG current, HANDOFF 92%, ADR-013 Accepted |
| 8 | Interview Readiness | **4.1** | +0.6 | Can walk through: tenant middleware chain, EnforceScope RBAC, AES-256-GCM state encryption, AI enrichment pipeline, treemap visualization, faceted filtering architecture. Concrete implementations replace "planned" claims |

**Aggregate: 4.11 / 5.0** (Baseline) — up from ~3.44

---

## Dimension Details

### 1. Security Architecture & Threat Modeling — 4.3

**Strengths:**
- `internal/api/rbac.go`: `EnforceScope()` middleware + `Scopeable` interface with 14+5 tests (`internal/api/rbac_test.go`)
- `internal/remediation/encrypted_state.go`: AES-256-GCM `EncryptedStateStore` closing STRIDE T-02 (8 tests)
- `cmd/server/types.go`: `ComputeIntegrityHash()` SHA-256 for finding integrity (STRIDE T-01)
- `internal/audit/logger.go`: `AuditLogger` interface with Memory+Zap composite, wired to 4 handlers
- `internal/tenant/middleware.go`: 3-step tenant resolution (JWT claim → header → subdomain) with nil-store graceful fallback
- `internal/api/auth_middleware.go:67`: `TenantID` field on Claims struct
- `internal/ingestion/dedup.go`: `DedupCache` with TTL-based eviction, background goroutine

**Gaps to 4.5+:**
- Security scan CI steps use `continue-on-error: true` — findings go to SARIF but don't gate merges
- Zero Trust engine (`internal/identity/zero_trust.go`) still not wired into request flow
- No STS AssumeRole short-lived credentials (long-lived AKIA key documented)

### 2. System Architecture & Integration Design — 4.1

**Strengths:**
- `cmd/server/handlers_ingest.go`: production ingestion endpoint with admin RBAC + dedup
- `internal/tenant/`: full Store interface → MemoryStore (Postgres-ready), middleware, context helpers
- `cmd/server/handlers_config.go`: dynamic `/config.json` endpoint per-tenant branding
- God Object refactored: DataStore, AttackPathService, EnrichmentService extracted
- Provider abstractions: `ai.Provider`, `grc.GRCProvider`, `identity.Provider`, `tenant.Store`
- `cmd/server/routes.go`: correct middleware ordering (CORS → tenant → auth → rate-limit → RBAC)

**Gaps to 4.5+:**
- Event-driven ingestion (ADR-014) still design-only — current path is synchronous POST
- 100K findings/day claim lacks benchmark evidence
- Workflow engine integration is partial (Temporal discussed, not wired)

### 3. Code Quality & Elegance — 4.2

**Strengths:**
- `frontend/src/contexts/CommandCenterContext.tsx`: clean reducer with 8 action types, flat layer key system
- Recharts pattern consistently reused: `TOOLTIP_STYLE`, `SEV_FILL`, `ResponsiveContainer` across 2 chart components
- `frontend/src/components/ops/FindingsTreemap.tsx`: provider→category→finding hierarchical grouping with custom cell renderer
- `frontend/src/hooks/useFindings.ts`: `useEnrichFinding()` mutation with query invalidation pattern
- 326+ frontend tests across 38 files; Go tests pass with -race
- `internal/tenant/middleware_test.go`: 5 test scenarios covering all resolution paths + extractSubdomain

**Gaps to 4.5+:**
- Large page files still exist: `PolicyDetail.tsx`, `Request.tsx`, `AIAgentDetail.tsx` (mixed concerns)
- Backend/frontend role mismatch: `viewer` exists in frontend but not in Go RBAC constants
- `cmd/server/main.go` Server struct now 22 fields (grew from 15 with tenantStore addition)

### 4. Frontend Design & UX — 4.0

**Strengths:**
- Command Center V2: dual-view (charts/treemap) with segmented control and keyboard shortcuts
- `FindingsTreemap`: severity heatmap with per-cell fill colors, interactive click→select
- `StatusBar`: date range temporal filter with native `<input type="date">` + dark calendar chrome
- `ShortcutOverlay`: 6 keyboard shortcuts (Esc, L, D, 1, 2, ?) with styled `<kbd>` elements
- `ProviderBadge`: AWS dark mode contrast fix (`dark:bg-orange-500/20 dark:text-orange-200 font-semibold`)
- `ConfigProvider` wraps entire app for runtime branding

**Gaps to 4.5+:**
- No ARIA `role="tab"` on segmented control (buttons only)
- Mobile responsive testing not verified (375px paths)
- `w-[220px]` fixed sidebar in Findings page
- ShortcutOverlay lacks focus trap (tabbing can escape modal)

### 5. Compliance & GRC Maturity — 4.2

**Strengths:**
- ADR-013 Accepted + implemented: `ResourceScope` on Claims, `EnforceScope()`, `Scopeable` interface
- `internal/audit/logger.go`: `AuditLogger` interface (Memory + Zap composite) — 8 tests
- ServiceNow lifecycle: create/get/update/approve/validate/list-by-requestor
- GRC exception endpoints: RBAC-protected, identity-consistent
- Finding dedup: content-hash based with TTL eviction

**Gaps to 4.5+:**
- Audit log backed by in-memory store — not immutable evidentiary storage
- Cross-provider GRC depth uneven (ServiceNow > Archer > Postgres > Memory)
- No SOC 2 evidence collection automation

### 6. Operational Readiness — 3.8

**Strengths:**
- CI pipeline: 8 jobs including Frontend Checks (tsc -b + vitest + npm audit), Build & Test (-race, -timeout 20m), Lint (golangci-lint), Security Scan (gosec + Trivy + Gitleaks + CycloneDX SBOM), OPA Policy Test
- Frontend tests run in CI (vitest, line 227 of ci.yml)
- Codecov integration with `codecov.yml` config
- `.gitleaks.toml` with testdata allowlist
- Cloudflare Pages deployment + Fly.io (deploy secrets via 1Password)
- `scripts/trim-demo-findings.js`: build-time data reduction (42MB→1.1MB)

**Gaps to 4.5+:**
- Security scans use `continue-on-error: true` — findings in SARIF but don't block
- Integration tests gated behind `//go:build integration` tag (not in default CI path)
- Coverage thresholds in vitest config (70/75/65) but not enforced as CI gate (no `--coverage` flag in CI vitest step)
- No canary/blue-green deployment automation
- No on-call rotation or PagerDuty integration documented

### 7. Documentation & Communication — 4.2

**Strengths:**
- 14 ADRs with real trade-off work (ADR-013 Accepted, ADR-014 Proposed)
- STRIDE threat model with T-01 (integrity) and T-02 (encryption) marked IMPLEMENTED
- `CODEBASE_INDEX.md`: compressed context for agent sessions
- CHANGELOG updated through Sprint 8-10 unreleased section
- HANDOFF.md at 92% completeness

**Gaps to 4.5+:**
- Code-doc drift: some health/metrics claims differ from wired routes
- Runbook ownership placeholders unfilled
- ADR-014 reads as near-term when it's roadmap

### 8. Interview Readiness — 4.1

**Strengths:**
- Can walk concrete implementations: `EnforceScope()` RBAC chain, AES-256-GCM rollback encryption, tenant middleware 3-step resolution, AI enrichment singleflight dedup, Recharts treemap with custom cell renderer
- Trade-off articulation in ADRs is interview-quality
- Vertical slices are deep enough to defend: security (STRIDE→implementation), GRC (ServiceNow lifecycle), frontend (Command Center state machine)

**Gaps to 4.5+:**
- 100K findings/day claim still lacks benchmark evidence
- Zero Trust engine unwired — needs careful framing in interviews
- Event-driven ingestion is design-only

---

## What Changed This Session

| Item | Files | Impact |
|------|-------|--------|
| Treemap heatmap view | `FindingsTreemap.tsx`, `CommandCenterContext.tsx`, `CommandCenter.tsx` | D4 +0.5 (data viz depth) |
| Temporal date range filter | `StatusBar.tsx`, `CommandCenter.tsx` | D4 +0.2 (filtering sophistication) |
| Keyboard shortcuts + overlay | `ShortcutOverlay.tsx`, `CommandCenter.tsx` | D4 +0.2 (power user UX) |
| AI enrich button | `EntityDetailPanel.tsx`, `useFindings.ts` | D1 +0.1, D2 +0.1 (AI integration) |
| AWS badge contrast fix | `ProviderBadge.tsx`, `ProviderIcon.tsx` | D4 +0.1 (a11y) |
| Whitelabel Phase 3 | `internal/tenant/middleware.go`, `handlers_config.go`, `main.go`, `routes.go`, `App.tsx` | D1 +0.2, D2 +0.3 (multi-tenant architecture) |
| CODEBASE_INDEX.md | `CODEBASE_INDEX.md` | D7 +0.2 (developer communication) |
| CI fix (unused imports) | `CommandCenter.tsx` | D6 prerequisite |
| 29 new tests | 7 test files | D3 +0.2, D6 +0.1 (test coverage) |

---

## Verdict

| Target Role | Verdict | Rationale |
|-------------|---------|-----------|
| WBD - Cloud Security Architect | **YES** | Security architecture implemented (not just planned), multi-tenant, RBAC, encryption |
| Vercel - Senior Cloud Security Engineer | **YES** | Full-stack depth, CI pipeline, runtime config, provider abstractions |
| NVIDIA - Senior Cybersecurity Architect | **BORDERLINE→YES** | Strong threat model implementation, needs benchmark evidence |
| Stripe - Staff Security Engineer | **BORDERLINE** | CI gates not enforced (continue-on-error), no immutable audit, no canary deploys |

**Overall: 4.1/5.0 — HIRE signal for L6 Senior/Staff at 3 of 4 target roles.**
