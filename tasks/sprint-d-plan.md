# Sprint D — Security Hardening + Polish

**Previous:** Sprint C (P0-P1 fixes: health checks, nil-guard, STRIDE dots, catalog clamp, region race, heatmap labels)
**Status:** PLANNED
**Theme:** Close security debt and accessibility gaps before whitelabel sprint changes the surface area.
**Estimated effort:** ~1 week (4-5 sessions)

---

## Items

| # | Item | Source | Effort | Why now |
|---|------|--------|--------|---------|
| D1 | localStorage role escalation fix (TODO-DEFERRED D6) | SEC HIGH | 1hr | Only HIGH severity finding in backlog. Must fix before whitelabel — a tenant admin could escalate |
| D2 | OPA fail-open → fail-closed (D15) + health check | SEC MEDIUM | 1hr | Whitelabel means real tenants; fail-open is unacceptable |
| D3 | Mock fallback production guard (D9) | SEC MEDIUM | 30min | Prevents mock data leaking into production deployments |
| D4 | gzipResponseWriter Flusher/Hijacker (D12) | BUG | 1hr | Blocks SSE/WebSocket — needed for real-time features |
| D5 | Accessibility pass (D8 + Q1-Q3) | QUALITY | 2hr | Portfolio differentiator — shows enterprise rigor |
| D6 | Severity color centralization (D7) | DEBT | 30min | 5 independent color defs is a whitelabel landmine — theme changes will miss sources |
| D7 | Frontend decomposition phase 1 (D10) | DEBT | 1 day | PolicyDetail 927L / Request 725L — need to be manageable before whitelabel theme wiring touches every component |

### Implementation Notes

**D1 (localStorage role escalation):**
- File: `frontend/src/lib/auth.ts` lines 94-98, 118, 185-188
- Fix: Always derive role from JWT groups claim in `userFromToken()`. Remove `savedRole` fallback. RoleSwitcher (DEV only) should set role transiently in React state, never persisting to localStorage.

**D2 (OPA fail-closed):**
- File: `cmd/server/handlers_api.go:423-424`
- Fix: Change fail-open to fail-closed (503 response). Add OPA health check endpoint so operators can distinguish misconfiguration from engine absence.

**D3 (Mock fallback guard):**
- Fix: Gate mock fallback on `import.meta.env.VITE_ENABLE_MOCK_FALLBACK`. Only enable for demo/dev.

**D4 (gzipResponseWriter):**
- File: `cmd/server/middleware.go`
- Fix: Implement `http.Flusher` and `http.Hijacker` interfaces on gzipResponseWriter.

**D5 (Accessibility):**
- Charts: aria-label / role="img" (FindingsSummaryChart)
- Sidebar: aria-modal, role="dialog", focus trap
- StatusBar: role="status" with aria-label
- LayerGroup: aria-expanded
- Icon buttons: aria-label (4 buttons in findings filter)
- DOM heading order fix

**D6 (Severity colors):**
- Create `SEVERITY_HEX: Record<string, string>` in severity.ts
- Update 4 consuming files

**D7 (Frontend decomposition):**
- PolicyDetail.tsx (927L) → PolicyHeader, PolicyRules, PolicyExceptions, PolicyHistory
- Request.tsx (725L) → RequestForm, RequestTimeline, RequestApproval

---

## Dependencies

```
D1 (auth fix) → no deps
D2 (OPA) → no deps
D3 (mock guard) → no deps
D4 (gzip) → no deps
D5 (a11y) → no deps
D6 (severity colors) → no deps
D7 (decomposition) → D6 should land first (avoids editing files twice)
```

All D1-D6 are independent — can parallelize across 2-3 sessions.

---

## Commit Strategy

| Commit | Items | Message |
|--------|-------|---------|
| 1 | D1 | `fix(auth): derive role from JWT only, remove localStorage escalation vector` |
| 2 | D2 | `fix(opa): switch to fail-closed + add OPA health check endpoint` |
| 3 | D3 | `fix(frontend): gate mock fallback on VITE_ENABLE_MOCK_FALLBACK env var` |
| 4 | D4 | `fix(middleware): implement Flusher/Hijacker on gzipResponseWriter` |
| 5 | D5 | `fix(a11y): aria-labels, heading order, focus trap, role attributes` |
| 6 | D6 | `refactor(ui): centralize severity colors to SEVERITY_HEX constant` |
| 7 | D7 | `refactor(frontend): decompose PolicyDetail and Request into subcomponents` |

---

## Exit Gate

- [ ] All existing tests pass: `go test -race -timeout 20m ./...` + `npx vitest run` + `npm run build`
- [ ] Zero HIGH findings in backlog
- [ ] Full-stack review passed (see `sprint-d-review-checkpoint.md`)
