# CloudGuard Visual QA - 2026-05-21

Target: `https://cloudguard.lvonguyen.com`

## Verdict

WS-1 visual sweep is complete. The app renders across the requested operator, admin, and requester surfaces with no error boundaries, no blank pages, and no mobile horizontal overflow in the sampled mobile routes.

Two product/data findings remain outside pure visual QA:

- EC-01 confirmed in the large seed corpus: Cosmos/DocumentDB findings are sometimes assigned non-Azure providers.
- EC-04 confirmed in the frontend RQL adapter: `!=` parses but is discarded before filter application.

## Commands

- `PLAYWRIGHT_BASE_URL=https://cloudguard.lvonguyen.com npx playwright test --workers=1`
  - Result: `19 passed, 1 skipped`
- Desktop screenshot sweep:
  - 25 routes checked
  - Screenshots: `tasks/qa-visual-cloudguard-20260521/screenshots/`
- Mobile overflow sweep:
  - 10 routes checked at `390x844`
  - Result: 10 pass, 0 fail
- GIF captures:
  - `tasks/qa-visual-cloudguard-20260521/captures/trace-expansion.gif`
  - `tasks/qa-visual-cloudguard-20260521/captures/terminal-panel.gif`
  - `tasks/qa-visual-cloudguard-20260521/captures/findings-query-fallback.gif`

## Desktop Routes

| Area | Route | Result | Notes |
|---|---|---:|---|
| Operator | Compliance | PASS | Rendered. |
| Operator | Containers | PASS/WARN | Rendered with fallback data; failed request to `https://api-personal.lvonguyen.com/api/v1/containers` due DNS. |
| Operator | Attack Paths | PASS | Rendered. |
| Operator | Attack Surface | PASS | Rendered. |
| Operator | Spend | PASS | Rendered. |
| Operator | Threat Intel | PASS | Rendered. |
| Operator | Data Sources | PASS | Rendered. |
| Operator | Data Classification | PASS/WARN | Rendered with fallback data; failed request to `https://api-personal.lvonguyen.com/api/v1/data-classification/assets` due DNS. |
| Operator | App Catalog | PASS | Rendered. |
| Operator | Defense Readiness | PASS | Rendered. |
| Operator | Terminal Panel | PASS | Terminal config visible. Initial not-found heuristic was a false positive from a resource name containing `ns`. |
| Admin | Dashboard | PASS/WARN | Rendered; failed request to `https://api-personal.lvonguyen.com/api/v1/exceptions/pending` due DNS. |
| Admin | Policies | PASS | Rendered. |
| Admin | AI Agents | PASS | Rendered. |
| Admin | Users | PASS | Rendered. |
| Admin | Audit Log | PASS | Rendered. |
| Admin | System | PASS | Rendered. |
| Admin | Exceptions | PASS/WARN | Rendered; failed request to `https://api-personal.lvonguyen.com/api/v1/exceptions/pending` due DNS. |
| Admin | Reports | PASS | Rendered. |
| Admin | Webhooks | PASS | Rendered. |
| Admin | Secrets Scan | PASS | Rendered. |
| Requester | Portal Dashboard | PASS/WARN | Rendered; failed request to `https://api-personal.lvonguyen.com/api/v1/exceptions/pending` due DNS. |
| Requester | New Request | PASS | Rendered. |
| Requester | My Requests | PASS | Rendered. |
| Requester | Catalog | PASS | Rendered. |

## Mobile Routes

| Route | Result | Notes |
|---|---:|---|
| Findings | PASS | No horizontal overflow. |
| Compliance | PASS | No horizontal overflow. |
| Remediation | PASS | No horizontal overflow. |
| Attack Paths | PASS | No horizontal overflow. |
| Threat Intel | PASS | No horizontal overflow. |
| Defense Readiness | PASS | No horizontal overflow. |
| Admin Dashboard | PASS/WARN | No horizontal overflow; same exceptions API DNS warning as desktop. |
| Secrets Scan | PASS | No horizontal overflow. |
| New Request | PASS | No horizontal overflow. |
| Catalog | PASS | No horizontal overflow. |

## Edge Cases

| ID | Result | Evidence |
|---|---:|---|
| EC-01 | FAIL | `testdata/seed/findings.json` has 973 Cosmos/DocumentDB matches; 531 are non-Azure provider mismatches: 391 `aws`, 140 `gcp`, all sampled mismatches have `resource_type=compute`. `testdata/cspm/normalized/all_findings.json`, `testdata/cspm/normalized/azure_findings.json`, and public mock findings did not reproduce the mismatch. |
| EC-02 | PASS | Admin agent detail route loaded 10 trace rows; expanding a trace and then an `Expand payload` button displayed payload JSON and changed the control to `Collapse payload`. |
| EC-03 | WARN | Source confirms backend gate: `/api/v1/ai/nlq` is operator/admin only and has a viewer-forbidden test. Live prod could not validate the 403 because `api-personal.lvonguyen.com` DNS fails; both viewer and operator no-keyword queries attempted the endpoint and then fell back client-side. |
| EC-04 | FAIL | Backend RQL evaluator supports `!=`, but `frontend/src/lib/rql-parser.ts` drops `!=` in `rqlToFilters` with `if (cond.op === '!=') continue`. |
| EC-05 | CONFIRMED | `internal/cicd` remains interface-only/not imported by server; this is already recorded in the README accuracy refresh row. |

## Follow-Up

- WS-8 should fix the seed generator/source mapping that creates Cosmos/DocumentDB findings with `aws`/`gcp` providers and `compute` resource type.
- WS-9 should either add exclusion filter support end-to-end or reject `!=` visibly in the RQL UI.
- Prod config should point API calls at a resolvable host or intentionally disable those live requests in demo mode.
