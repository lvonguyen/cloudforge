# Sprint F — Demo Polish + Limitation Closures

**Previous:** Sprint E (attack path fidelity, Bedrock enrichment, graph UX, real-data pipeline)
**Status:** PLANNED
**Theme:** Close README limitations, wire real cloud APIs, polish demo-visible gaps.
**Estimated effort:** ~1 week (3-4 sessions)

---

## Priority Order

| Priority | Item | Impact | Effort |
|----------|------|--------|--------|
| P0 | F1: FinOps AWS Cost Explorer | Closes limitation #4, real spend data in demo | 1 session |
| P0 | F2: Attack path stats/list fix | Eliminates the most visible demo bug | 1 hour |
| P1 | F3: OIDC auth flow wiring | Closes limitation #2, real SSO in demo | 2-3 hours |
| P1 | F4: Container scanner wiring | Closes limitation #5 (partial), real CVE data | 4 hours |
| P2 | F5: Control-level drill-down | Closes limitation #8, compliance depth | 4 hours |
| P2 | F6: README reframe | Move test coverage from "limitations" to "quality" | 30 min |
| P2 | F7: Existing Sprint F items (from prior plan) | O(1) path lookup, Vite chunks, keyboard shortcuts, SLA | carry-forward |

---

## Workstream Decomposition

```
Workstream A (cloud API wiring — sequential):    Workstream B (frontend polish — parallel):
  F1: FinOps AWS Cost Explorer                     F2: Attack path stats/list fix
       |                                           F5: Control-level drill-down
  F3: OIDC auth flow (Okta via haea-personal)      F7a: Keyboard shortcuts
       |                                           F7b: SLA computation
  F4: Container scanner output parser
```

### Agent team structure

| Agent | Workstream | Model | Scope |
|-------|-----------|-------|-------|
| Worker 1 | A (cloud APIs) | Sonnet | F1 -> F3 -> F4 sequentially |
| Worker 2 | B (frontend) | Sonnet | F2 + F5 + F7a + F7b (independent files) |
| Distiller | -- | Opus | Aggregate after all workers complete |

---

## Item Details

### F1: FinOps AWS Cost Explorer (P0)

**Closes:** README limitation #4 ("Cost aggregation interfaces defined, no cloud API integration yet")

- Wire `GET /api/v1/costs/summary` to AWS Cost Explorer API
- Use `haea-personal` AWS account (SSO via `aws sso login`)
- IAM: read-only Cost Explorer access (`ce:GetCostAndUsage`, `ce:GetCostForecast`)
- 1Password: store credentials as `op://Development/aws-haea-personal-costexplorer/...`
- Env vars: `FINOPS_PROVIDER=aws`, `AWS_COST_EXPLORER_REGION=us-east-1`
- Response shape: daily/monthly spend by service, account, tag — matches existing `CostSummary` type
- Fallback: mock `costs.json` when env vars absent (existing pattern)

**Files:**
- `internal/finops/aws_provider.go` — NEW, implements `FinOpsProvider` interface
- `cmd/server/handlers_costs.go` — wire real provider via factory
- `frontend/src/pages/intelligence/Spend.tsx` — already consumes the API, no changes needed

---

### F2: Attack Path Stats/List Disconnect (P0)

**Closes:** Chrome QA finding — stats cards show hardcoded 274k paths while list shows "0 paths"

Root cause: `useAttackPathStats` and `useAttackPaths` use different data sources in frontend-only mode. Stats hook hits the API, falls back to `getMockAttackPaths().stats`. Paths hook hits the API, falls back to `getMockAttackPaths().paths` with pagination. But when the R2 pre-computed `attack-paths.json` has paths but the client-side compute returns 0, the stats and list diverge.

Fix: ensure `useAttackPathStats` derives stats from the same paths array that `useAttackPaths` returns. Single source of truth — compute stats from the path list, not from a separate endpoint/fallback.

**Files:**
- `frontend/src/hooks/useAttackPaths.ts` — refactor `fetchAttackPathStats` to derive from path data when in mock mode

---

### F3: OIDC Auth Flow Wiring (P1)

**Closes:** README limitation #2 ("Okta/Entra ID providers not wired into auth flow")

- Okta provider code exists in `cmd/server/` (config-driven, `OKTA_DOMAIN` env var)
- Wire into auth middleware: when `OKTA_DOMAIN` is set, validate JWT against Okta JWKS endpoint
- Use `haea-personal` Okta tenant for testing
- Entra ID: similar pattern with `ENTRA_TENANT_ID` — wire if time permits, otherwise document
- Mock fallback: current HS256 dev-mode auth when no OIDC env vars set

**Files:**
- `cmd/server/auth.go` — add JWKS discovery for Okta/Entra
- `cmd/server/routes.go` — conditional middleware selection based on env

---

### F4: Container Scanner Wiring (P1)

**Closes:** README limitation #5 (partial — container module)

- Wire `GET /api/v1/containers` to parse real Trivy JSON output
- Trivy can scan local images or K8s cluster: `trivy k8s --format json`
- Parse Trivy JSON into existing `TopologyResponse` type (clusters -> namespaces -> pods -> containers -> vulns)
- Env var: `CONTAINER_SCANNER=trivy`, `TRIVY_OUTPUT_PATH=/path/to/scan.json`
- Fallback: `DEV_TOPOLOGY` when scanner not configured (existing pattern)

**Files:**
- `internal/container/trivy_parser.go` — NEW, parse Trivy K8s JSON
- `cmd/server/handlers_containers.go` — wire real parser via factory
- Test with: `trivy k8s --report summary --format json -o /tmp/trivy-k8s.json`

---

### F5: Control-Level Drill-Down (P2)

**Closes:** README limitation #8 ("control-level sub-drill-down is not yet implemented")

- `FrameworkDetailDrawer` currently shows framework-level summary
- Add expandable control rows inside the drawer: click a control -> see individual check results
- Data: extend `frameworks.json` mock with control-level findings mapping
- UI: accordion/collapsible inside the drawer, each control shows pass/fail/finding count

**Files:**
- `frontend/src/lib/mock/frameworks.json` — add control-level data
- `frontend/src/pages/ops/ComplianceDetail.tsx` or `FrameworkDetailDrawer` — expand with controls

---

### F6: README Reframe (P2)

- Remove "Test Coverage" from Known Limitations (it's a strength, not a gap)
- Add a "Quality & Testing" section above limitations:
  ```
  ## [+] Quality & Testing
  - 34 Go packages, 1474 tests (including -race), 323 frontend tests
  - 8 Go benchmarks, v8 coverage thresholds active
  - CI: 8 gates (build, lint, test, security scan, Lighthouse, OPA, Docker, deploy)
  ```
- Update route count and test counts to reflect current state

---

### F7: Carry-Forward Items (P2)

From prior Sprint F plan — still valid:

| # | Item | Effort | Notes |
|---|------|--------|-------|
| F7a | Keyboard shortcuts (`D`, `1/2/3`, `?`, arrows) | 0.5 session | Power user polish |
| F7b | SLA computation in admin KPI row | 0.5 session | per-severity deadline computation |
| F7c | O(1) attack path lookup (`PathsByID` map) | 30 min | `handlers_attackpath.go` |
| F7d | Vite manual chunks (recharts, xyflow, tanstack) | 30 min | Bundle size optimization |

---

## Dependencies

```
F1 (FinOps) -> needs haea-personal AWS SSO access
F2 (Stats fix) -> no deps
F3 (OIDC) -> needs haea-personal Okta tenant
F4 (Container) -> needs Trivy installed locally or a scan JSON file
F5 (Drill-down) -> no deps
F6 (README) -> no deps
F7a-d -> no deps
```

---

## Exit Gate

- [ ] `GET /api/v1/costs/summary` returns real AWS spend (or mock fallback gracefully)
- [ ] `/ops/attack-paths` stats and list are consistent (no 274k/0 disconnect)
- [ ] JWT validation works against Okta JWKS when `OKTA_DOMAIN` set
- [ ] `GET /api/v1/containers` parses real Trivy output when configured
- [ ] All tests pass: `go test -race -timeout 20m ./...` + `npx vitest run` + `npm run build`
- [ ] README Known Limitations reduced from 8 -> 5 items
- [ ] Chrome QA sweep clean
- [ ] CI 8/8 green + deployed

---

## Post-Sprint F: Remaining Limitations

After Sprint F, the README limitations reduce to:

1. **Temporal Workflows** — orchestration not wired (significant effort, not demo-visible)
2. **Stub Packages** — WAF, secrets, identity still mock-only
3. **RoleViewer scoping** — per-resource viewer scoping not enforced (ADR-013 phase 2)
4. **Compliance controls** — control-level drill-down (closed if F5 ships)
5. **React 19 lazy()** — pre-existing Playwright edge case (not prod)

These are reasonable for a reference implementation. The high-visibility gaps (FinOps, OIDC, containers, attack paths) are all closed.
