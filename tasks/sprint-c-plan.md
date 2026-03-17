# Sprint C Plan

**Previous:** Sprint B (B1-B8) — actorFilter cap, RoleViewer, compliance drill-down, portal hooks, RequestDetail API, per-agent STRIDE, admin KPI hooks.
**Sprint B QA:** PASS — 3 blind agents → distiller → 11 findings fixed → 6/6 scoped checks → full route sweep clean.

---

## Deferred QA Findings (from Sprint B Review)

### From Agent Review (medium/low — accepted or deferred)

| ID | Finding | Severity | Action |
|----|---------|----------|--------|
| D2 | RoleViewer < RoleRequester privilege inversion | Medium | Intentional — test documents it. Consider ADR for viewer surface in Sprint D. |
| D3 | RoleViewer defined but no routes use it | Medium | [DONE] Viewer routes added in P2 (Sprint C). |
| D12 | Hardcoded timestamps in FRAMEWORK_PROFILES | Low | Use agent.updated_at instead. |
| D13 | Split FRAMEWORK_DOC_LINKS / LAST_ASSESSED maps | Low | Merge to single FRAMEWORK_METADATA constant. |

### From Chrome QA (pre-existing, not Sprint B)

| ID | Finding | Severity | Route |
|----|---------|----------|-------|
| Q1 | 4 icon-only buttons missing aria-label | Medium | [DONE] Fixed in Sprint C P3 (a9b3646) |
| Q2 | h3 before h1 in DOM order | Low | [DONE] Fixed in Sprint C P3 (a9b3646) |
| Q3 | Images missing width/height attributes | Low | [DONE] Fixed in Sprint C P6 (4173d79) |

### From Security Audit (backlog)

| ID | Finding | Severity | Action |
|----|---------|----------|--------|
| SEC-B02 | resultFilter no format validation | Low | Already capped at 100 chars. Add allowlist regex if audit backend adds DB. |
| SEC-B07 | requestor_email no backend validation | Low | Add RFC 5322 validation on API response. |
| SEC-B08 | Admin dashboard 403 shows fallback data | Low | Replace FALLBACK_EXCEPTION_QUEUE with explicit 403 error state. |

---

## Phase 1: Foundation — DONE

| Item | Commit | Summary |
|------|--------|---------|
| P0 | — | Whitelabel readiness assessment |
| P1 | — | Design token extraction (CSS custom properties) |
| P2 | `17f65d3` | Viewer role surface — /findings, /compliance, /agents + traces. 13 RBAC tests |
| P3 | `a9b3646` | Findings filter sidebar a11y (Q1 aria-labels, Q2 heading order) |
| P4+P5 | `4068845` | SLA computation (`computeExceptionSLA`, 72h window) + TREND hook wiring (`useRemediations`, computed counts) |
| P6 | `4173d79` | Image width/height + lazy loading on Landing.tsx |
| P7 | `0156b12` | Mock data extraction — PolicyDetail 927→286L, highlightRego, exportCSV to lib/ |

## Phase 2: Wiz Enhancements — DONE

| Item | Commit | Summary |
|------|--------|---------|
| P8 | `fec84d5` | Toxic combo risk factor chips + attack path arrow-chain on FindingDetail |
| P9 | `67da8a5` | RadialBarChart gauges for top 5 frameworks on Compliance page |
| P10 | `b0cc68a` | SLA compliance progress bar (within SLA / overdue counts) on Dashboard |
| P11 | `67ceec2` | Tabbed FindingDetail — Overview, Remediation, Investigation, Comments |
| P12 | `1c066e7` | GROUP BY tabs (rule/resource/provider/category) with collapsible groups |
| P13 | `30f8aa2` | Temporal trend arrows — 7-day comparison, TrendingUp/TrendingDown/Minus icons |

## Phase 3: Palantir + Competitive — DONE

| Item | Commit | Summary |
|------|--------|---------|
| P15 | `1a7e3f3` | Choke point detection — cross-path resource_id frequency, amber card, dashed border highlight |
| P17 | `381c247` | Clickable metric cards — 6-card grid (CRIT/HIGH/MED/LOW/SLA Breached/Auto-Rem) as filter toggles |
| P18 | `a6b4b19` | Filter pills — collapsible sidebar (default collapsed), horizontal pills with dropdown checkboxes + per-group X clear |
| P16 | `0dc8500` | Kanban remediation pipeline — List/Kanban view toggle, @hello-pangea/dnd, demo-only drag with toast |
| P19 | `434c53b` | Inline preview panel — 380px split layout, single-click=preview, double-click=navigate, arrow keys, Escape |
| P14 | `6249f32` | NLQ bar — POST /api/v1/ai/nlq handler (RoutingProvider TierFast) + NLQueryBar.tsx with Cmd+K shortcut |
| P20 | `58a9158` | Enhanced lifecycle timeline — color-coded icons (CircleDot/UserCheck/Wrench/XCircle), synthetic events, actor info |
| P21 | `3b2d3c6` | 4 new data layer toggles — Compliance, Workflow, Time Window, AI Risk Score groups with faceted counts |
| P22 | `4072b8b` | Blast radius badge — path.nodes.length on PathCard, red >10 / orange 5-10 / yellow <5 |
| P23 | `8f03693` | Container security view — GET /api/v1/containers (mock K8s topology: 3 clusters, 7 containers) + expandable tree UI at /ops/containers |

---

## Verification Status

| Gate | Result |
|------|--------|
| Go build (`go build ./...`) | Clean |
| Frontend tests (`npx vitest run`) | 38 files, 323 tests PASS |
| Production build (`npm run build`) | Clean |
| TypeScript (`tsc --noEmit`) | 0 errors |
| Agent QA review | PENDING — next step |
| Chrome QA (`/ap-chrome-qa`) | PENDING — after agent QA |

---

## Sprint C Final Scorecard

| Metric | Value |
|--------|-------|
| Total items | 23 (P0-P23) |
| Commits | ~25 (Phase 1-3) |
| Files created | 4 (handlers_nlq.go, handlers_containers.go, NLQueryBar.tsx, Containers.tsx) |
| New API endpoints | 2 (POST /ai/nlq, GET /containers) |
| New frontend routes | 1 (/ops/containers) |
| New npm dependency | 1 (@hello-pangea/dnd) |
| Tests | 38 files, 323 tests (unchanged — new features are UI components without unit tests) |

---

## Excluded (Future Sprints)

- Security Graph Explorer — needs new data models (post Sprint F, Neon Postgres)
- Drag-drop dashboard widgets — needs layout persistence layer
- DSPM Data Classification — needs classification engine
- Fix PR Generation — needs GitHub App integration
- Entity Graph Investigation Board — needs graph DB
- Resource Query Language — needs query parser + execution engine
- Anomaly Behavioral Graph — needs time-series anomaly detection

---

## Sprint B Final Scorecard (for reference)

| Gate | Result |
|------|--------|
| Go tests (34 packages, -race) | PASS |
| Frontend tests (38 files, 323 tests) | PASS |
| Production build | Clean |
| Agent review (quality/bugs/security) | 11 findings fixed, all dimensions >= 4.5 post-fix |
| Chrome QA: Priority 1 scoped checks | 6/6 PASS |
| Chrome QA: Full route sweep | 0 CRITICAL, 0 HIGH, 3 pre-existing medium/low |
| Commit | 5736525 (fix: agent review findings) |
