# Sprint 29 — Claimable Task Board

**Protocol:** Each session claims 1 workstream by changing `[ ]` to `[CLAIMED: session-X]`. Write results inline under the task. Next session scans for unclaimed `[ ]` items.

**Prod state:** `cloudguard.lvonguyen.com` (CF Pages, VITE_DEMO_MODE=true, mock data). Personal API DECOMMISSIONED. PuppyGraph TERMINATED. Fly.io API still up at `api.cloudforge-demo.lvonguyen.com`.

---

## URGENT — Ensemble QA Findings (3.9/5 weighted)

Agents: Quality (3.8) | Bugs (3.9) | Security (4.3) | Architecture (3.6)

### Pre-Demo Fixes (HIGH — consensus 2+ agents)

| ID | Finding | Severity | Files | Status |
|----|---------|----------|-------|--------|
| C2 | NLQ prompt injection + AI output validation — unsanitized query → LLM, unvalidated JSON, XSS chain | HIGH | `handlers_nlq.go:113`, `attackpath_enrich.go:37` | [FIXED: session-30] Input sanitized (HTML strip + control chars), output whitelisted (5 field sets), Text field sanitized. 6 tests added. |
| S2 | CORS missing PATCH — breaks remediation status updates cross-origin | HIGH | `internal/api/cors.go:27` | [FIXED: session-30] Added PATCH to Allow-Methods. |
| S3 | Gremlin closure bypass — `coalesce`, `aggregate`, `store`, RTL Unicode, `${}` not blocked | HIGH | `handlers_graph.go:35` | [FIXED: session-30] Added aggregate/store/cap/coalesce to blocklist (parenthesis-guarded). Groovy `${}` template injection check added. 6 test cases added. |
| C4 | In-memory linear scan O(n) per list/filter/pagination request | HIGH | multiple | [FIXED: codex-20260521] `/api/v1/findings` now uses PostgreSQL count/list queries with allowlisted filters, scope predicates, sort, and LIMIT/OFFSET when `FINDINGS_SOURCE=postgres`; mock/dev path remains in-memory. Added migration `011_findings_query_indexes.sql`. |

### Post-Demo (MED)

| ID | Finding | Files | Status |
|----|---------|-------|--------|
| C1 | Server God Object decomposition | `main.go`, `service_*.go` | [ ] |
| C3 | Enrichment cache unbounded map (grows between 5-min eviction) | `main.go:571`, `service_enrichment.go` | [ ] |
| S4 | Audit ring buffer reslice memory leak | `internal/audit/...` | [ ] |
| S6 | Findings.tsx 1055 lines, 15+ state vars | `pages/ops/Findings.tsx` | [ ] |
| S7 | GCP firewall all-ports internal (lateral movement) | `modules/network/main.tf:70-84` | [ ] |

### Scaling Limits

| Dimension | Current | Breaks At | Fix |
|-----------|---------|-----------|-----|
| Findings | 20K in-memory | ~50K (GC) | PostgreSQL indexed queries |
| Concurrent users | ~10 | ~25 (goroutine exhaustion) | Circuit breakers on AI providers |
| Tenants | 2 hardcoded | Any multi-tenant | Wire `tenant.Store` to Postgres (migration 005) |
| Enrichment cache | Unbounded map | ~100K (~400MB) | Bounded LRU + Redis |

---

**Latest verified base before codex C4 patch:** `1c0a40c1` on main.

---

## P0 — Must Do

### WS-1: Chrome QA Visual Sweep (remaining pages)
- [ ] **UNCLAIMED**
- Run `/qa-visual -e` on `cloudguard.lvonguyen.com`
- Pages to cover: Compliance, Containers, Attack Paths, Attack Surface, Spend, Threat Intel, Data Sources, Data Classification, App Catalog, Terminal
- Admin pages: Dashboard, Policies, AI Agents, Users, Audit Log, System, Exceptions, Reports, Webhooks, Secrets Scan
- Requester pages: Portal Dashboard, New Request, My Requests, Catalog
- **Edge cases to probe:**
  - EC-01: Azure Cosmos DB finding shows as AWS provider (seed data quality)
  - EC-02: Trace timeline span detail expansion not clickable in split view
  - EC-03: NLQ AI fallback requires Operator+ role — Demo Viewer only gets client-side keyword extraction
  - EC-04: RQL `!=` operator parsed but silently ignored
  - EC-05: `internal/cicd` interfaces never imported by server (dead code)
  - Test every button/action — flag grayed out or dead-end paths
  - Verify terminal config is visible (even if WS is down post-teardown)
- **Deliverable:** QA report with PASS/FAIL per page, edge case findings, GIF captures

### WS-2: Fix Failing Playwright E2E Tests
- [DONE: session-29] **COMPLETE — 17 pass, 0 fail, 1 skip**
- **Root causes:** (1) Go backend on :8080 returns empty data — mock fallback never triggered (API 200 OK, not error). (2) Strict mode violations (`getByText('Modules')` matched 2 elements). (3) Remediation selectors expected `<table>` but page uses card layout with Tier 1/2/3 labels. (4) Demo access behind env flag.
- **Fixes:** VITE_DEMO_MODE early-return in `fetchFindings()` + `useFinding()`. `.env.e2e` + `--mode e2e` on port 5175. Selector fixes for heading roles, `.first()`, card layout. Demo access test conditionally skips.
- **Deliverable:** 17/18 green (1 conditional skip), ready to commit

### WS-3: Performance Baseline Under 300K Findings
- [ ] **UNCLAIMED**
- **Pre-req:** 300K findings loaded (WS-A completed in parallel session)
- Run `/perf-baseline` or `/benchmarks` against localhost with Go backend + 300K RDS
- Measure: findings list pagination (150/page), command center load, investigation board, NLQ search, attack paths
- Test under different conditions: cold start, warm cache, concurrent requests
- **Deliverable:** Latency table (p50/p95/p99), bottleneck identification

---

## P1 — Should Do

### WS-4: FinOps Module Gap Fixes
- [DONE: session-30] **COMPLETE**
- From FinOps audit (session 28):
  - [x] Wire `aggregator/multi.go` into factory — `FINOPS_PROVIDER=multi` composes AWS+Azure+GCP via `MultiCloudAggregator` (import cycle avoided by composing in main.go)
  - [x] Expose budget alerting via `GET /costs/budgets` — `BudgetMonitor` wired with demo rules ($5K AWS/$3K Azure/$2K GCP), `aggregatorSpendAdapter` bridges Aggregator→SpendProvider
  - [x] Fix README: "ML-based" → "statistical z-score", Slack as "planned" (done in WS-6)
  - [x] Cost estimation endpoint — `GET /costs/estimate?resource_type=ec2&provider=aws&size=medium` + `GET /costs/resources` (21-entry pricing table)
- All 6 finops packages pass with -race
- **Deliverable:** 4 files changed, 3 new endpoints, commit

### WS-5: Airflow Pipeline Prototype
- [ ] **UNCLAIMED**
- From Airflow research (session 28):
  - Design a Go cron-based ingestion pipeline (Airflow pattern without Airflow infra)
  - Structure: fetch → dedup → normalize → enrich → load (retry per stage)
  - Replace `aegis-seed.mjs` single-shot approach
  - Add LLM response caching via Redis (ElastiCache already in stack)
- **Reference:** production-agentic-rag-course patterns (DAG stages, RRF hybrid search, prompt reduction)
- **Deliverable:** Design doc or prototype in `internal/pipeline/`

### WS-6: README Accuracy Refresh
- [DONE: session-30] **COMPLETE**
- 4 corrections verified against source code:
  - `internal/cicd`: "Partial" → "Interface only — not imported by server" (grep confirmed 0 imports)
  - `internal/workflow`: "Stub" → "In-memory — engine wired (list/get/submit handlers), Temporal planned" (handlers_workflow.go + server struct verified)
  - Anomaly detection: "ML-based" → "Statistical z-score" (detector.go:169-186 confirmed)
  - Budget tracking: "via Slack/PagerDuty" → "PagerDuty wired; Slack implemented but not connected" (alerting/slack.go exists, 0 server imports)
  - Known Limitations section updated to match workflow correction
- **Deliverable:** Direct commit

### WS-7: Figma MCP Value Exploration
- [DONE: session-28-parallel] **CLOSED — NOT WORTH IT**
- Evaluated by parallel session. Verdict: Figma MCP integration does not add meaningful value for CloudForge's use case (ops console, not component design system). SVG diagrams rendered via mmdc are sufficient. All 4 "missing" diagrams already exist as .mmd+.svg pairs (rendered session 27).
- **Deliverable:** Decision recorded. No further action.

---

## P2 — Nice to Have

### WS-8: Seed Data Quality
- [ ] **UNCLAIMED**
- Fix Azure Cosmos DB provider mismatch (EC-01)
- Audit 300K seed for other provider/category inconsistencies
- **Deliverable:** Fixed seed script, regenerated data

### WS-9: NLQ Enhancements
- [ ] **UNCLAIMED**
- Wire RQL `!=` exclusion operator (EC-04)
- Consider NLQ AI fallback for Viewer role (EC-03) — or document as intentional RBAC gate
- Add agentic retrieval pattern (query rewriting on low-relevance results)
- **Deliverable:** Code fixes + tests

### WS-10: LLM Observability (Langfuse-style)
- [ ] **UNCLAIMED**
- CloudForge has OTel but no LLM-specific tracing
- `RoutingProvider` already tracks `UsageStats` — expose via dashboard or Langfuse integration
- Track: token counts per tier, latency, cost per request, cache hit rate
- **Deliverable:** Dashboard component or Langfuse integration

---

## Session Log

| Session | Claimed | Result | Commit |
|---------|---------|--------|--------|
| 28-lead | WS-1 (partial), research | 8 pages QA'd, 3 GIFs, FinOps+Airflow audits | `737a934`, `1897d17` |
| 28-parallel-A | WS-A (300K load), WS-B (E2E), WS-D (teardown) | All complete | `ea8870c` |
| 28-parallel-B | GIF capture (WS-C) | In progress | — |
| 29 | Memory cleanup, teardown audit, E2E analysis | DONE: 7 stale refs fixed, TF audit (source clean, DNS orphan critical), E2E root cause identified | — |
| 29 | WS-2: Fix E2E tests | DONE: 17/18 pass (0 fail, 1 skip). Root cause: Go backend returns empty 200 OK, mock fallback never triggered. | pending |
| 29-parallel | WS-3 (300K verify), WS-C (GIFs), WS-D (teardown) | DONE: 300K pipeline complete (streaming fix), local postgres setup, 2 GIFs captured, remediation E2E added | `1897d17`, `ef1f837` |
| 30 | C2 + S2 + S3 (security hardening) | DONE: NLQ prompt injection fix (input sanitize + output whitelist), CORS PATCH, Gremlin blocklist extension (4 steps + Groovy template). 12 new test cases, all green with -race. | pending |
| codex-20260521 | C4 Postgres findings list scaling | DONE: Postgres-backed `/findings` count/list path, allowlisted SQL filters/sorts, ABAC scope predicates, list indexes, preflight migration list update. Verification: focused `cmd/server` tests PASS, full `go test ./... -count=1` PASS. | pending |
