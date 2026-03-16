# Sprint E — Whitelabel Readiness

**Previous:** Sprint D (security hardening + polish) + full-stack review checkpoint passed
**Status:** PLANNED
**Theme:** Execute the whitelabel readiness plan — standardize all stub packages on the GRC factory pattern.
**Estimated effort:** ~1 week (5-7 sessions)
**Reference:** `tasks/sprint-whitelabel-readiness.md` (detailed implementation spec)

---

## Items

| # | Item | Effort | Notes |
|---|------|--------|-------|
| E1 | Design token extraction (CSS custom properties) | 1 session | Sprint C P1 — if not done yet, do it first |
| E2 | W1: identity factory | 1 session | Biggest gap — 30 lines inlined in main.go |
| E3 | W3: finops factory + interface composition | 1 session | Biggest code change (80 lines new) |
| E4 | W2: container config threading | 0.5 session | Factory exists, just needs config struct |
| E5 | W4-W6: workflow/waf/secrets env var hooks | 0.5 session | Trivial — 3-10 lines each |
| E6 | W7: PROVIDER_CONFIG.md + /health provider status | 0.5 session | Documents the whole system |

---

## Implementation Reference

Full implementation details for E2-E6 are in `tasks/sprint-whitelabel-readiness.md` (W1-W7).

---

## Dependencies

```
E1 (design tokens) → no deps (can run in parallel with E2-E5)
E2 (identity) → no deps
E3 (finops) → no deps
E4 (container) → no deps
E5 (workflow/waf/secrets) → no deps
E6 (docs + health) → depends on E2-E5 (needs final env var names)
```

E1-E5 are fully independent — parallelize across sessions.

---

## Commit Strategy

| Commit | Items | Message |
|--------|-------|---------|
| 1 | E1 | `refactor(ui): extract design tokens to CSS custom properties` |
| 2 | E2 | `feat(identity): extract provider factory from inline main.go logic` |
| 3 | E3 | `feat(finops): introduce Service factory + interface-based composition` |
| 4 | E4 | `feat(container): thread ScannerConfig through factory` |
| 5 | E5 | `feat: add env var hooks for workflow, waf, secrets providers` |
| 6 | E6 | `docs: provider configuration reference + health endpoint status` |

---

## Exit Gate

- [ ] `go run ./cmd/server` with no env vars = identical behavior to pre-sprint
- [ ] `FINOPS_PROVIDER=aws go run ./cmd/server` returns clean `ErrNotImplemented` errors (not panics)
- [ ] `/api/health` response includes active provider per package
- [ ] `docs/PROVIDER_CONFIG.md` documents all env vars
- [ ] All existing tests pass: `go test -race -timeout 20m ./...` + `npx vitest run` + `npm run build`
- [ ] No new test files required (factory functions tested via existing integration paths)
