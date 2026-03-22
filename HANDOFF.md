# Handoff: Cloud Aegis Sprints B-E Complete — Attack Paths, Security Graph, AI Budget, Real Data

## Current State (2026-03-17)

[+] Project: 92% complete (reference implementation with enforcement-backed security)
[+] Sprint 8-10 complete: 3.5->4.5 hardening cycle (CI enforcement, RBAC scope, ingest, audit, encryption)
[+] Sprint A + A+ complete: 15 review fixes, performance infra, E2E Chrome QA (21/21 routes)
[+] Sprint B complete: actorFilter validation, RoleViewer backend, compliance drill-down, portal hooks, STRIDE profiles, admin KPI hooks
[+] Sprint C complete: Viewer read-only surface, choke points, metric cards, filter pills, kanban, preview panel, NLQ bar, lifecycle timeline, data layer toggles, blast radius, container security
[+] Sprint D complete: NLQ backend, DSPM classification, security graph, investigation board, LayoutSwitcher; 18/18 Chrome routes PASS
[+] Sprint E complete: attack path fidelity (client-side fallback, pre-computed paths), Bedrock enrichment (confidence scoring, tier routing), SecurityGraph focus mode, AI budget guard, real-data pipeline (9000 findings)
[+] CI gates enforced: gosec HIGH+, Trivy exit-code 1, Codecov fail-on-error, frontend vitest, npm audit
[+] Security: resource-scoped RBAC (ABAC), finding integrity SHA-256, AES-256-GCM rollback encryption, AI cost budget guard
[+] Audit: real audit logging with integrity hashes (MemoryAuditLogger + ZapAuditLogger)
[+] Ingest: POST /api/v1/findings/ingest with SHA-256 dedup, 24h TTL
[+] STRIDE: T-01 (integrity) and T-02 (rollback encryption) controls implemented
[+] Testing: 34 Go packages / 1474 tests (-race clean), 323 frontend tests (38 files), 8 benchmarks
[+] Previous: Sprint 4 (9 commits), Sprint 5-7 (test coverage, docs, interview holes)

## Sprint 4 Summary

### Commits (9 total)
- `b728b33` fix(frontend): rebrand "Portfolio" to "Platform" and focus landing on 2 core modules
- `56a571b` fix(frontend): improve catalog icon readability and add CSP provider dropdown
- `2563431` docs: fix architecture diagram sizing and remove redundant mermaid block
- `0278305` test: add benchmark tests for server performance baseline
- `c377c5b` docs: update README roadmap status and known limitations
- `5de8ff0` docs: add whitelabel exploration design document
- `994acd3` feat(frontend): add env-var-driven branding parameterization
- `4a2ae00` fix(frontend): update attack paths test for pagination query params
- `29d9eb9` fix: address QA findings from quality-review and bug-discovery agents

### Documentation Review Findings
- HLD updated to v3.0: Go 1.25 (was 1.22), gorilla/mux (was Chi/Gin), React 19 (was Backstage), full API reference from routes.go, new sections for Remediation/AttackPath/FinOps
- ADR-001 cross-references fixed (ADR-002 is Database, not API Framework)
- ADR-006 RBAC table corrected (3 backend roles, not 4)
- 4 new ADRs: ADR-009 (Remediation), ADR-010 (FinOps), ADR-011 (Toxic Combos), ADR-012 (Whitelabel)
- 3 new runbooks: 07 (Secrets Rotation), 08 (FinOps Budget Alerts), 09 (Identity Provider Setup)
- CHANGELOG updated with Sprint 3-4 entries (was missing v0.6.0-v0.9.0)
- README GreyNoise status inconsistency fixed

## What's Working

| Component | Status | Details |
|-----------|--------|---------|
| Go backend | Healthy | `go build ./...` clean, `go vet ./...` clean, 1474 tests passing (34 packages), `-race` clean |
| Frontend | Healthy | `tsc` clean, 323 tests passing, Cloudflare Pages deployed, Lighthouse CI budgeted |
| Benchmarks | Passing | 8/8 (GetFinding, ListAttackPaths, ServerStartup, GetCached_Hit/Miss, EvictExpired_5000, AttackPathComputation, ListFindings) |
| CI | Green | golangci-lint clean, all GitHub Actions passing |
| Dev mode | Working | `make dev` starts backend (:8080) + frontend (:5173) |

## Known Limitations

1. [LOW] React 19 lazy() context errors under Playwright (pre-existing, not prod)
2. [P2] CSP style-src still allows 'unsafe-inline' (Tailwind/Radix requirement)
3. [DONE] RoleViewer added in Sprint B (rank 0, read-only surface: /findings, /compliance/frameworks, /agents + traces; 13 RBAC tests)
4. [KNOWN] FinOps cloud API clients are interface-only (not wired to production credentials)
5. [KNOWN] Container, secrets, waf, identity modules have interfaces + mock implementations only
6. [DONE] Compliance drill-down added in Sprint B — FrameworkDetailDrawer with doc links
7. [LOW] Lighthouse TTI 2s budget may flake in CI — monitor, relax if needed

## Key Paths

| Purpose | Path |
|---------|------|
| Server entry | `cmd/server/main.go` (314L) + routes.go, handlers_grc.go, middleware.go, helpers.go |
| Attack paths | `cmd/server/attackpath.go` + `handlers_attackpath.go` |
| CSPM scoring | `internal/cspm/scoring/` (toxic_combos, blast_radius, fp_rules, fn_rules) |
| Threat intel | `internal/cspm/threatintel/` (epss, kev, greynoise) |
| Remediation | `pkg/remediation/` (executor) + `internal/remediation/` (8 domain handlers) |
| FinOps | `internal/finops/` (aggregator, alerting, anomaly, chargeback, estimation) |
| Identity | `internal/identity/` (provider, okta, entra_id, mock, zero_trust) |
| Frontend | `frontend/src/` (21 route pages, shadcn components, hooks, lib) |
| Docs | `docs/architecture/HLD.md`, `docs/adr/`, `docs/runbooks/` |

## Dev Server

```bash
cd ~/repos/gh/cloudforge
make dev
# Backend: :8080, Frontend: :5173
```

## Running Tests

```bash
# Go tests
go test ./... -count=1

# Integration tests
go test ./cmd/server/ -tags=integration -count=1

# Benchmarks
make bench  # or: go test ./cmd/server/... -bench=. -benchmem -count=3

# Frontend tests
cd frontend && npm test
```
