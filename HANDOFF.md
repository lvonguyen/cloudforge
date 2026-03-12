# Handoff: CloudForge Sprint 2 Complete

## Current State (2026-03-12)

[+] Project: 85% complete, QA score 4.0/5 (target: 4.5)
[+] Sprint 2 deliverables committed: 01967fb (tests) + 999f224 (hooks/API)
[!] Open P0: Secrets leak (.env.development with admin JWT committed to git)
[*] Next: Sprint 3 hook migration (5 remaining hooks) + Chrome QA iteration 2

## Sprint 2 Summary

### Workstream B — Tests (01967fb)
- 12 new test files: 6 hook tests (useAuditLog, useCosts, useCatalog, useUsers, useExceptions, useAttackPaths) + 6 component tests (DryRunPreview, CostSummaryCard, AnomalyAlertCard, ExceptionCard, FindingCard, ProtectedRoute)
- Added renderWithAuth helper to test/utils.tsx
- Added v8 coverage thresholds to vitest.config.ts (lines: 70, functions: 75, branches: 65)
- Fixed ADR-006: roles → groups claim, removed analyst role
- Fixed ADR-007: header ADR-003 → ADR-007
- Total: 33 test files, 298 tests passing

### Workstream C — API + Hooks (999f224)
- Added GetExceptionsByRequestor to GRC provider interface + all implementations
- Added GET /exceptions/mine endpoint (RBAC: requester+)
- Fixed useCostAnomalies queryKey to share cache with useCostSummary
- Added useExecuteRemediation mutation hook
- Added useMyExceptions query hook
- Wired Execute/Retry buttons in RemediationQueue and RemediationDetail
- Migrated MyRequests.tsx to use useMyExceptions API hook

### Workstream E — Chrome QA (in progress, ~54% coverage)
- CRITICAL (pre-existing): Some lazy-loaded pages throw context errors (useAuth, useTracePanel) in Playwright — likely React 19 + lazy() edge case
- HIGH: Mobile horizontal overflow at 375px on /ops CommandCenter
- MEDIUM: Role switcher dropdown doesn't open on click
- PASS: /admin dashboard, /admin/ai-agents list, /ops CommandCenter (desktop), /ops/findings (desktop), /portal/catalog, /portal/requests

## What's Already Done
- `make dev` starts backend (:8080) + frontend (:5173) — single command
- Redis rate limiter fixed (nil-check, no Redis needed locally)
- All list pages (Users, Policies, AI Agents, Findings) load correctly
- Dev auth working: `.env.development` has `VITE_DEV_TOKEN` (sourced from 1Password `cloudforge-dev-jwt-secret` vault item)
- Known test failure: TestGetCostSummary nil pointer in handlers_finops.go:47 (pre-existing, not Sprint 2 regression)

## Known Issues

### P0 — SEC-001: Secrets Leak
- `.env.development` with admin JWT committed to git
- Action: `git rm --cached frontend/.env.development`, rotate secret, add to .gitignore

### Pre-existing Backend Issues
- `TestGetCostSummary` nil pointer at handlers_finops.go:47 — not Sprint 2 regression
- Frontend has 4 roles (admin, operator, requester, viewer); backend has 3 (no RoleViewer constant)

### Chrome QA Edge Cases (React 19 + Playwright)
- Lazy-loaded pages throw context errors (useAuth, useTracePanel) in Playwright
- Likely React 19 context propagation with lazy() — not production issue
- Workaround: test eager-loaded routes first

## Next Steps (Sprint 3)

### Hook Migration (5 remaining hooks)
Migrate to real API calls (mock JSON → apiClient):
- useFindings.ts
- useCompliance.ts
- useAgents.ts
- useCosts.ts
- useRemediations.ts

Keep as-is (already correct):
- useExceptions.ts (already uses apiClient)
- useMyExceptions.ts (already uses apiClient)
- useDeployPreview.ts (client-side simulation, no backend)

### Chrome QA Iteration 2
- Complete remaining route coverage (~46% routes untested)
- Fix mobile overflow on /ops CommandCenter
- Fix role switcher dropdown click handler
- Document React 19 lazy() edge case for future reference

### QA Threshold Target
- Current: 4.0/5
- Target: 4.5/5
- Max iterations: 3
- Run quality-review + bug-discovery + security-audit agents after Sprint 3 commits

## Key Files
- `frontend/src/lib/mock/findings.json` — current synthetic findings
- `cmd/server/main.go` — `loadMockData()`, `computeAttackPaths()`
- `frontend/src/hooks/useFindings.ts` — frontend findings hook
- `frontend/src/pages/ops/Findings.tsx` — findings list page
- `frontend/src/pages/ops/FindingDetail.tsx` — finding detail page
- `testdata/export-scripts/` — HAEA export + scrub scripts (from P37)

## Dev Server
```bash
cd ~/repos/remote/gh/portfolio/tier1-flagship/cloudforge
make dev
# Backend: :8080, Frontend: :5173
```
