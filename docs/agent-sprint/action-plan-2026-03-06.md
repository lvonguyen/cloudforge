# CloudForge Agent Sprint — Action Plan

**Date:** 2026-03-06
**Sprint:** 11-agent parallel audit across 6 domains
**Status:** All agents reported. Synthesized below.

---

## Sprint Summary

| Domain | Agent(s) | Verdict |
|--------|----------|---------|
| Backend (Go) | 4A | Production-ready, no critical issues |
| Frontend (React) | 4B, 2A-1, 2A-2, 2A-3 | Production-ready for current scope; 3 bugs + 7 a11y gaps |
| Live QA (Chrome) | 2B | All 22 routes load, dark mode works, CF Pages static build lacks backend data |
| Auth | 5 | 70% backend-ready for OIDC, 10% frontend-ready |
| Bedrock OIDC | 1 | SDK v2 in place, needs OIDC credential provider abstraction |
| Resource Catalog | 6R | AWS 150% covered, Azure 55%, GCP 40% |
| Backlog | 3 | Wave 1 commit blocking (5 min), enterprise integration 70% done |

---

## Decisions — Resolved

1. **IdP:** Demo-friendly approach. Show OIDC/multi-IdP capability via role switcher + CF Access, NOT full Okta tenant. Portfolio viewers (hiring managers, recruiters) won't have Okta credentials. Keep auth functional but simple to demo. Okta moved to P3/defer.
2. **Bedrock OIDC:** Start in parallel with other sprint work. Approved.
3. **Resource Catalog:** Decouple per-provider and parallelize. Each provider (AWS/Azure/GCP) runs as independent workstream.
4. **CF Pages Static Build:** Optimize for portfolio demo impressiveness. Must work without backend for casual viewers. Add mock data fallback for static builds.
5. **Wave 1 Commit:** Approved. Execute immediately.

---

## P1 — Critical / Commit-Blocking

| # | Action | Effort | Source |
|---|--------|--------|--------|
| 1 | Commit Wave 1 pending changes | 5 min | Agent 3 |
| 2 | Fix `useCosts` cache key duplication | 5 min | Agent 2A-1 |
| 3 | Resolve missing `useTracePanel.ts` import (runtime failure risk) | 15 min | Agent 2A-1 |
| 4 | Fix Costs page error message leaking port 8080 | 5 min | Agent 2B |
| 5 | Add `ProtectedRoute` wrapper for RBAC | 30 min | Agent 2A-2 |
| 6 | Add API client timeout + exponential backoff | 1-2h | Agent 2A-3 |
| 7 | Add healthcheck endpoint with Redis status | 2h | Agent 4A |
| 8 | Finalize enterprise findings integration | 1-2h | Agent 3 |

---

## P2 — Important / Next Sprint

| # | Action | Effort | Source |
|---|--------|--------|--------|
| 1 | Add error/loading states to Findings, Compliance, AttackPaths | 2-3h | Agent 2A-2 |
| 2 | Fix array index key anti-patterns in DryRunPreview/TerminalOutput | 10 min | Agent 2A-1 |
| 3 | Add fluctuating count "Simulated" indicator | 10 min | Agent 4B |
| 4 | Debounce filter re-renders on findings table | 30 min | Agent 4B |
| 5 | Populate mock data gaps (CWE, attack paths, compliance URLs) | 2-3h | Agent 2A-3 |
| 6 | Add `aria-labels` to 7 components | 15 min | Agent 2A-1 |
| 7 | Externalize API base URL via `VITE_API_URL` | 1h | Agent 2A-3 |
| 8 | Add rate limiter metrics instrumentation | 4h | Agent 4A |

---

## P3 — Backlog / Parallel Tracks

| # | Action | Effort | Notes | Source |
|---|--------|--------|-------|--------|
| 1 | Azure resource catalog expansion (9 types) | M | PARALLELIZE — independent workstream | Agent 6R |
| 2 | GCP resource catalog expansion (12 types) | M | PARALLELIZE — independent workstream | Agent 6R |
| 3 | Okta OIDC integration | L | DEFERRED — demo doesn't need full Okta tenant | Agent 5 |
| 4 | AWS Bedrock OIDC credential rotation | M (5-8d) | START IN PARALLEL | Agent 1 |
| 5 | Column resize localStorage persistence | 20 min | | Agent 4B |
| 6 | CSV export streaming for >50K findings | 25 min | | Agent 4B |
| 7 | Replace cookie regex with parser library | 1h | | Agent 2A-3 |

---

## Cross-Agent Dependencies

```
Agent 1 (Bedrock) ──── Independent (Okta deferred, no coordination needed)
Agent 3 (Backlog) ──── Wave 2-3 depends on Wave 1 commit
Agent 6R (Catalog) ──── Depends on type system extensibility confirmed by Agent 4A
Agent 2B (Chrome QA) ── Confirms Agent 2A-3's finding: API needs fallback for static builds
```

---

## Risk Flags

| Risk | Severity | Source |
|------|----------|--------|
| CF Pages deployment shows "port 8080" in error message (info leak) | Medium | Agent 2B |
| Missing `useTracePanel.ts` could cause runtime import failure | High | Agent 2A-1 |
| No route-level RBAC guards — all pages accessible without role checks | High | Agent 2A-2 |
| CF Pages needs mock data fallback to impress portfolio viewers without backend | Medium | Agent 2B |
| Okta deferred — no immediate risk | Low | Agent 5 |

---

## Execution Order

```
Phase 1 (now):     P1 items 1-4 (< 30 min, unblocks everything)
Phase 2 (today):   P1 items 5-8 (RBAC, API resilience, healthcheck)
Phase 3 (next):    P2 items (error states, a11y, mock data)
Parallel tracks:   Azure catalog, GCP catalog, Bedrock OIDC (independent)
Deferred:          Okta OIDC (P3, no demo value)
```
