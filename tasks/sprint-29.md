# Sprint 29 — Claimable Task Board

**Protocol:** Each session claims 1 workstream by changing `[ ]` to `[CLAIMED: session-X]`. Write results inline under the task. Next session scans for unclaimed `[ ]` items.

**Prod state:** `cloudguard.lvonguyen.com` (CF Pages, VITE_DEMO_MODE=true, mock data). Personal API DECOMMISSIONED. PuppyGraph TERMINATED. Fly.io API still up at `api.cloudforge-demo.lvonguyen.com`.

**Latest commit:** `1897d17` on main.

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

### WS-2: Fix 5 Failing Playwright E2E Tests
- [ ] **UNCLAIMED**
- 10/15 pass, 5 fail on selector mismatches
- Run `npm run e2e` in `frontend/`, read failure screenshots in `test-results/`
- Fix selectors to match actual DOM (text content, roles, data-testid)
- Target: 15/15 pass
- **Deliverable:** All E2E green, commit

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
- [ ] **UNCLAIMED**
- From FinOps audit (session 28):
  - [ ] Wire `aggregator/multi.go` into factory (replace single-provider path)
  - [ ] Expose budget alerting via `/costs/budgets` endpoint
  - [ ] Fix README: "ML-based" → "statistical z-score", Slack as "planned"
  - [ ] Cost estimation endpoint (21-resource pricing table exists, needs HTTP route)
- Azure/GCP billing SDK wiring is P2 (requires real credentials)
- **Deliverable:** Updated factory, new endpoint, README corrections, commit

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
- [ ] **UNCLAIMED**
- Update all partial/planned markers to match actual wiring state:
  - `internal/cicd`: "Interfaces only, not wired" (currently says "Partial")
  - `internal/workflow`: "In-memory engine wired, Temporal planned" (says "Stub")
  - Anomaly detection: "Statistical z-score" (says "ML-based")
  - Slack alerting: "Planned" (not implemented)
- **Deliverable:** README PR or direct commit

### WS-7: Figma MCP Value Exploration
- [ ] **UNCLAIMED**
- Handoff prompt written in session 28 handoff file
- Score 4 use cases: design token extraction, Code Connect mapping, screenshot round-trip, diagram generation
- **Deliverable:** 1-5 value/effort matrix, recommendation

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
- Cloud Aegis has OTel but no LLM-specific tracing
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
| 28-parallel-C | Monitoring + teardown audit | In progress | — |
