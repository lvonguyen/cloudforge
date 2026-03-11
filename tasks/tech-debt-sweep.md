# Tech Debt Sweep — Status & Plan

**Branch:** `feat/tech-debt-sweep`
**Started:** 2026-03-10
**Updated:** 2026-03-11
**Base:** `main` (commit `f3a99c4`)

---

## Completed Chunks (10 commits)

| # | Commit | Type | Summary | Status |
|---|--------|------|---------|--------|
| 1 | `b6a2d36` | fix | Dead ternary, broken link, ProviderFromString, Archer guard, Makefile | DONE |
| 2 | `e4e9673` | refactor | Dead code removal: security.go, workflow/, AI dead types, frontend hooks (-1,912 LOC) | DONE |
| 3 | `6ca8f7f` | refactor | Severity color consolidation, enrichMu->Server, logger.Fatal, otel spans | DONE |
| 4 | `e930b86` | perf | O(1) lookup maps, bg enrichAttackPaths, findings.json->public/, dynamic dates | DONE |
| 5 | `c2abe98` | a11y | Keyboard nav + aria attributes on findings rows + exception cards | DONE |
| 6 | `c7cbab4` | ci | SHA-pin OPA action, frontend CI job, Alpine 3.20, post-deploy healthcheck | DONE |
| 7 | `2f26af4` | docs | .env.example, CONTRIBUTING.md, Go 1.25, ADR-008, config defaults | DONE |
| 8 | `c1a0308` | test | Vitest setup + 22 tests (auth, plan-templates, useActionCooldown) | DONE |
| 9 | `2a499b5` | fix | useActionCooldown effect dependency + test alignment | DONE |
| 10 | `9b3c969` | fix | Distiller regressions: mock path, factory tests, race fix, otel ctx, testServer maps | DONE |

## Quality Improvement Delta

| Dimension | Before | After | Impact |
|-----------|--------|-------|--------|
| Dead code | ~1,912 LOC across Go+frontend | Removed | Cleaner codebase, less maintenance surface |
| Frontend tests | 0 | 22 (3 suites) | Regression safety for auth, plan logic, hooks |
| Go test health | 26 failures (stale expectations + missing path) | 0 failures | CI-green baseline |
| Bundle size | findings.json in JS bundle (~13 MB) | Runtime fetch from public/ | Faster initial load |
| Data access | O(n) linear scans on 5,000 findings | O(1) map lookups | Sub-ms handler response |
| Color consistency | Severity colors duplicated 4+ places | Single severity.ts canonical source | DRY |
| Accessibility | No keyboard nav on interactive elements | tabIndex + role + onKeyDown | WCAG keyboard compliance |
| CI hardening | Unpinned actions, no frontend job, no healthcheck | SHA pins, frontend CI, post-deploy check | Supply chain + regression safety |
| Security defaults | ssl_mode=disable, auth.enabled=false | ssl_mode=require, auth.enabled=true | Secure-by-default config |
| Concurrency | Data race on attackPaths slice | Assignment before goroutine | Race-free startup |
| Code smell | _ = ctx pattern, custom containsSubstring | Clean assignments, stdlib | Idiomatic Go |

## Verification (post-commit 10)

- [x] `go vet ./...` — PASS
- [x] `go test ./...` — ALL PASS
- [x] `npx tsc -b` — PASS
- [x] `npx vitest run` — 22/22 PASS
- [x] Opus distiller review — all FIX items resolved

---

## Next Steps

### Immediate (before PR merge)

- [ ] **QA agent iteration** — Run quality-review + bug-discovery + security-audit per AGENT_REVIEW_ITERATION_PROTOCOL.md. Target: >= 4.5/5 across dimensions (practical tier).
- [ ] **Address any QA findings** — Max 2 more iteration rounds if needed.
- [ ] **Decision: squash vs keep atomic** — 10 commits can be squash-merged (cleaner main history) or kept atomic (per-chunk bisectability). Recommend: squash-merge via PR with chunk list in body.

### Follow-up (separate PRs, not this sweep)

- [ ] **testServer() helper extraction** — The O(1 map init in testServer() duplicates main.go lines 208-218. Consider extracting `Server.buildLookupMaps()` method to DRY both paths. (Low priority — only 2 call sites.)
- [ ] **Callback post-login redirect** — `/callback` currently lands on `/` instead of the originally requested route. `LOGIN_RETURN_KEY` is wired but `Callback.tsx` doesn't read it yet.
- [ ] **Redis graceful degradation logging** — Rate limiter fallback logs are noisy (`Rate limit check failed, using local fallback` on every request). Consider logging once at startup instead of per-request.
- [ ] **OPA nested package query** — `data.cloudforge.ai` returns nested results; `Evaluate()` only checks top-level `allow`. Known design limitation, not a regression.
- [ ] **Frontend test expansion** — Current 22 tests cover auth, plan-templates, useActionCooldown. Gaps: API client, findings table rendering, severity utilities.
- [ ] **Healthcheck/predeploy hooks** — Backend uptime monitoring for Fly.io deployment.

### Relationship to Execution Plan

This sweep is orthogonal to `tasks/execution-plan.md` (feature sprints). The sweep clears technical debt that would have complicated Sprint 0-2 work. Specifically:
- **Sprint 0 [E] OTel spans** — partially done in chunk 3 (handlers have spans now). Remaining: tracer init + stdout exporter in dev mode.
- **Sprint 1 [B] Handler tests** — enabled by chunk 8 (vitest) + chunk 10 (testServer fix). Go handler tests now have a working foundation.
- **Sprint 1 [C] API endpoints** — O(1 maps from chunk 4 make new endpoints faster to implement.
