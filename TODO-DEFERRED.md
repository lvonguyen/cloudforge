# CloudForge — Deferred Items

> Migrated on 2026-03-30: the canonical backlog now lives in `tasks/handoff.md`.
> Keep this file as an archival rationale log, not the primary working board.

Items intentionally deferred from the Command Center V2 polish pass.
Each has a clear rationale and can be picked up in future sprints.

---

## D1: Treemap / Topology Center Pane Views

**Original spec:** Phase 3 — alternative center-pane visualizations.

- Treemap: severity-weighted rectangle packing (resource_type x severity)
- Topology: force-directed graph of resource relationships
- View switcher toolbar (grid | treemap | topology)

**Why deferred:** The stacked-bar severity chart + attack-path graph cover the primary use cases. Treemap/topology are exploratory views that require additional UX research.

**Effort:** ~2 days frontend

---

## D2: Temporal Scrubber with Playback Controls

**Original spec:** Phase 5 — time-series navigation.

- Horizontal timeline scrubber showing finding density over time
- Play/pause/step controls for temporal walkthroughs
- Filter findings by date range via scrubber selection

**Why deferred:** Requires backend `first_found_at` indexing and a histogram endpoint. Current data layers panel handles time-based filtering adequately for now.

**Effort:** ~3 days (1 backend, 2 frontend)

---

## D3: Full Keyboard Shortcuts

**Original spec:** Phase 6 — power-user keyboard navigation.

Current shortcuts: `Escape` (deselect), `L` (toggle left panel).

Deferred shortcuts:
- `D` — toggle detail panel
- `1/2/3` — switch center pane view mode
- `Space` — play/pause temporal scrubber
- `Left/Right` — step through attack paths
- `?` — show keyboard shortcut overlay

**Why deferred:** Core mouse/keyboard interaction works. Full shortcuts are a polish item for power users.

**Effort:** ~0.5 day frontend

---

## D4: Frontend `/enrich` API Call

**Status:** Backend fully implemented — `POST /api/v1/findings/{id}/enrich` with Bedrock/Anthropic/OpenAI/Vertex AI providers. EnrichmentService has cache + singleflight dedup.

Frontend: `Finding` type already has `ai_risk_score`, `ai_risk_rationale`, `ai_contextual_factors`. EntityDetailPanel renders the "AI Enrichment" section when these fields exist.

**What's missing:** An "Enrich with AI" button in `FindingDetail.tsx` that calls `POST /findings/{id}/enrich` and refreshes the finding.

**Why deferred:** Requires `AEGIS_AI_ENABLED=true` + valid AI credentials in deployment. Mock data already populates AI fields for demo purposes.

**Effort:** ~0.5 day frontend (button + mutation hook)

---

## D5: Activate Bedrock in Production Deployment

**Status:** `AEGIS_AI_ENABLED` defaults to `false`. Not set in `fly.toml` or `docker-compose.yml`.

**To activate:**
1. Set `AEGIS_AI_ENABLED=true` as Fly.io secret
2. Set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` from 1Password (`op://Development/BedrockAPIKey-1k4n-at-431330216246 (lvn-personal, longterm)/...`)
3. Set `BEDROCK_REGION=us-east-1` and `BEDROCK_MODEL=anthropic.claude-haiku-4-5-20251001-v1:0`
4. Redeploy

**Why deferred:** Demo/portfolio deployment uses mock data. Live AI enrichment incurs Bedrock API costs and requires credential rotation planning.

**Effort:** ~15 minutes (env vars + redeploy)

---

## D6: [SEC] localStorage Role Escalation (F-02, HIGH)

**Status:** Fixed 2026-03-30.

**Files:** `frontend/src/lib/auth.ts`, `frontend/src/lib/api.ts`, auth/route/layout auth tests

**Issue:** The original issue allowed a persisted client-side role override to survive reloads and influence JWT-backed UI access. That started as `localStorage`, then later `sessionStorage`, but the underlying problem was the same: a preview role could leak into authenticated flows.

**Fix landed:** `userFromToken()` now always derives role from JWT groups. Preview role switching is in-memory only via React/module state, legacy persisted role keys are cleared on startup/logout, and dev-only `X-Aegis-Role` forwarding now reads the ephemeral preview override instead of storage.

**Verification:** `npx vitest run src/lib/__tests__/auth.test.ts src/lib/__tests__/api.test.ts src/components/layout/__tests__/RoleSwitcher.test.tsx src/components/auth/__tests__/ProtectedRoute.test.tsx` and `npx tsc --noEmit`

**Why it was previously deferred:** The file was outside the Command Center scope. Server-side RBAC on `/api/v1/*` endpoints remained the real authorization gate, so this was defense-in-depth until picked up.

**Effort:** Completed in ~1 hour (auth.ts refactor + tests)

---

## D7: Centralize Severity Color Constants

**Status:** Fixed 2026-03-30.

**Files:** `frontend/src/lib/severity.ts`, `FindingsSummaryChart.tsx`, `FindingsTreemap.tsx`, `DataLayersPanel.tsx`, `StatusBar.tsx`, `CommandCenter.tsx`, `AttackPaths.tsx`, `AttackPathMiniGraph.tsx`

**Fix landed:** Added `SEVERITY_HEX`, `SEVERITY_DOT_COLORS`, and `SEVERITY_NEUTRAL_HEX` to `severity.ts` and rewired the chart, graph, and panel views to import those shared constants instead of duplicating literal severity colors.

**Verification:** `npx vitest run src/components/ops/__tests__/FindingsTreemap.test.tsx src/components/ops/__tests__/StatusBar.test.tsx src/pages/__tests__/OpsPages.test.tsx` and `npx tsc --noEmit`

**Effort:** Completed in ~30 minutes

---

## D8: Accessibility Pass

**Issues from Sprint 2 code review:**
- Charts lack `aria-label` / `role="img"` (FindingsSummaryChart)
- Mobile sidebar lacks `aria-modal`, `role="dialog"`, focus trap (Sidebar.tsx)
- StatusBar needs `role="status"` or `role="region"` with `aria-label`
- LayerGroup toggle missing `aria-expanded` (DataLayersPanel)
- Severity dot indicators missing `aria-hidden="true"` (DataLayersPanel)

**Effort:** ~2 hours frontend

---

## D9: Mock Fallback Production Guard (F-07, MEDIUM)

**Status:** Fixed 2026-03-30.

**Files:** `frontend/src/lib/api.ts`, `frontend/src/hooks/useFindings.ts`, `frontend/src/hooks/useRemediations.ts`

**Fix landed:** Mock fallback now only activates when `VITE_ENABLE_MOCK_FALLBACK=true` or `VITE_DEMO_MODE=true`. The shared API helper and the custom findings/remediations hooks now surface 5xx errors by default instead of silently masking them.

**Verification:** `npx vitest run src/hooks/__tests__/useFindings.test.ts src/hooks/__tests__/useRemediations.test.ts src/pages/__tests__/OpsPages.test.tsx` and `npx tsc --noEmit`

**Effort:** Completed in ~30 minutes

---

## D10: Split Large Frontend Components

**Files:**
- `PolicyDetail.tsx` (927 lines) — split into PolicyHeader, PolicyRules,
  PolicyExceptions, PolicyHistory subcomponents
- `Request.tsx` (725 lines) — split into RequestForm, RequestTimeline,
  RequestApproval subcomponents

**Effort:** ~1 day frontend

---

## D11: Vite Manual Chunks

**File:** `vite.config.ts`

**Status:** Fixed before 2026-03-30; verified during this sprint.

**Resolution:** `vite.config.ts` already defines `manualChunks` for `react`, `recharts`, `@xyflow/react`, and `@tanstack/*`, plus module preload filtering for the heavy lazy-route vendor chunks. No additional code change was needed in this pass.

**Effort:** No new code change required

---

## D12: gzipResponseWriter Missing Interfaces

**Status:** Fixed before 2026-03-30; verified during this sprint.

**Files:** `cmd/server/middleware.go`, `cmd/server/middleware_test.go`

**Resolution:** `gzipResponseWriter` already forwards `http.Flusher`
and `http.Hijacker`, and gzip middleware still bypasses SSE/WebSocket
requests entirely. Added regression tests for flush delegation,
compressed-body preservation, hijack delegation, and the unsupported
hijack error path so the wrapper cannot silently regress.

**Verification:** `env GOCACHE=/tmp/go-build-cache go test ./cmd/server -run 'TestGzipMiddleware|TestGzipResponseWriter' -count=1`

**Effort:** No runtime code change required; ~20 minutes test/docs cleanup

---

## D13: pathToFlow JSX in useMemo

**File:** `frontend/src/components/ops/CommandCenter.tsx`

`pathToFlow` creates JSX inside a `useMemo` callback. Extract to a
custom React Flow node component for cleaner separation and better
React DevTools readability.

**Effort:** ~1 hour frontend

---

## D14: Attack Path O(n) Linear Scan

**File:** `cmd/server/handlers_attackpath.go:100`

`getAttackPath` does O(n) linear scan over all attack paths to find by
ID. Add an `PathsByID map[string]*AttackPath` to `AttackPathService`
(same pattern as `DataStore.FindingsByID`) for O(1) lookup.

**Effort:** ~30 minutes Go

---

## ~~D15: OPA Fail-Open to Fail-Closed~~ RESOLVED

**Resolved:** 2026-03-20 — Changed to fail-closed (503 + error log).
Nil engine (no policies loaded) still gracefully degrades.
Non-nil engine errors now deny with `503 Service Unavailable`.

---

## D16: OPA RequestContext for Future Policy Expressiveness

**File:** `cmd/server/handlers_api.go:410-421`

`EvaluateToolAccess()` only consumes `(agent, tool)`. A future version
could accept `RequestContext` (UserID, SessionID, IP) to enable
per-user rate limiting, session anomaly detection, and IP geo-restriction
policies. No existing Rego policies reference `input.request`.

**Effort:** ~30 minutes Go + Rego

---

## D17: OPA String Literals to Constants

**File:** `cmd/server/handlers_api.go:413-420`

Bare string literals (`"aegis-api"`, `"enrichment"`, `"ai_enrich"`,
`"analysis"`) should be promoted to package-level constants before a
second OPA gate is added (DRY).

**Effort:** ~15 minutes Go

---

## D18: Global Light/Dark/Auto Theme System

**Context:** Attack Paths page has a local canvas tone toggle (Auto/Light/Dark) from the WG-E readability work. Promote to a global app-level theme system.

**Scope:**
- Promote local attack-path tone control to global setting in AppShell/TopNav
- Wire Tailwind CSS `dark:` variants consistently across all pages (currently dark-only)
- Persist preference in localStorage, respect `prefers-color-scheme` for Auto mode
- Audit all ops pages for light-mode readability: charts, badges, cards, table rows, severity colors
- Graph views (Investigation Board, Attack Paths): canvas background must respect theme
- Sidebar: light variant with proper border/hover states

**Pages requiring light-mode audit:** `/ops`, `/ops/findings`, `/ops/compliance`, `/ops/investigations`, `/ops/attack-paths`, `/admin/*`, `/portal/*`

**Why deferred:** Dark mode is primary ops persona. Light mode is presentation/screen-sharing QoL. Local toggle on Attack Paths proves the pattern.

**Effort:** ~2-3 days frontend

---

## D19: Seed 300K Findings to Fly Postgres

**Context:** Fly Postgres addon is now configured. Pipeline exists (`scripts/aegis-seed.mjs` + `scripts/seed-postgres.mjs`) but hasn't run against Fly.

**Steps:**
1. Get Fly PG connection string: `fly postgres connect -a cloudforge-db`
2. Run migrations 001-008
3. Generate seed: `node scripts/aegis-seed.mjs --full` (~594MB JSON)
4. Stream to Fly PG: `DATABASE_URL=<fly-pg-url> node scripts/seed-postgres.mjs`
5. Set `FINDINGS_SOURCE=postgres` on Fly: `fly secrets set FINDINGS_SOURCE=postgres`
6. Verify pagination: 300K total, 150/page in <25ms

**Why deferred:** Pipeline verified locally (session 29). Fly PG may need sizing check for 300K + graph_edges.

**Effort:** ~1 hour ops

---

## D20: CSPM-Parity Investigation + Remediation Polish

**Context:** Investigation Board and Finding Detail are functional but lack the depth and visual polish of leading CSPM platform views. Key gaps identified during session 33 visual QA.

**Investigation Board gaps:**
- No expandable node detail on click (inline panel within graph with evidence + timeline)
- Generic box shapes for all node types — need distinct icons (shield=finding, server=resource, lock=compliance, user=assignee)
- Force-directed layout — industry standard uses hierarchical (entry points top, targets bottom)
- No compliance mapping cluster grouping
- Edge labels lack directional arrows and clean typography

**Remediation Detail gaps:**
- `RemediationStep` struct exists in Go (`internal/compliance/finding.go`: Order, Title, Description, Command, Platform, Automated) but frontend doesn't render structured steps
- No numbered CLI command blocks with copy-to-clipboard
- No IaC/Terraform/CloudFormation snippet per finding
- No "Fix in Code" button linking to source template
- No evidence screenshots (config snapshots, API response diffs)
- No visual SLA countdown bar (data exists: `sla_breach_date`, `due_date`)

**Finding Detail enrichment:**
- Add "Part of N attack paths" inline context with clickable link to paths
- Add timeline visualization (first seen → triaged → assigned → SLA breach countdown)
- Render `remediation_steps[]` as numbered accordion with command copy buttons
- Render compliance mappings as clickable badges linking to framework detail

**Implementation approach:**
1. Investigation Board: switch to dagre/ELK hierarchical layout, custom node components per type, expandable detail drawer
2. Remediation tab: structured step renderer with syntax-highlighted command blocks
3. Finding Detail: timeline component, attack path context badge, SLA progress bar

**Why deferred:** Functional parity achieved. Visual polish is differentiation work, not correctness. Each sub-item is independent and can be picked up in parallel.

**Effort:** ~4-5 days frontend (Investigation Board ~2d, Remediation steps ~1d, Finding Detail enrichment ~1-2d)

**Context:** Attack Paths page has a local canvas tone toggle (Auto/Light/Dark) from the WG-E readability work. This should be promoted to a global app-level theme system.

**Scope:**
- Promote the local attack-path tone control to a global setting in AppShell/TopNav
- Wire Tailwind CSS `dark:` variants consistently across all pages (currently dark-only)
- Persist preference in localStorage, respect `prefers-color-scheme` for Auto mode
- Ensure all ops pages (Command Center, Findings, Compliance, Investigations, Spend) render correctly in light mode — charts, badges, cards, table rows
- Update severity badge colors for light mode contrast (dark bg badges on white surface)
- Sidebar: light variant with proper border/hover states
- Graph views (Investigation Board, Attack Paths): canvas background must respect theme

**Pages requiring light-mode audit:**
- `/ops` (Command Center) — charts, attack path cards, data layers panel
- `/ops/findings` — table rows, severity badges, detail panel
- `/ops/compliance` — framework health rings, score colors
- `/ops/investigations` — ReactFlow canvas, node colors, edge labels
- `/ops/attack-paths` — already has local toggle, promote to global
- `/admin/*` — tables, status badges, cards
- `/portal/*` — request wizard, dashboard cards

**Why deferred:** Dark mode is the primary ops persona. Light mode is a "nice to have" for presentations and screen sharing. The local toggle on Attack Paths proves the pattern works — promotion is mechanical but touches every page.

**Effort:** ~2-3 days frontend (audit + Tailwind variant pass + component updates)

---

## D19: Seed 300K Findings to Fly Postgres

**Context:** Fly Postgres addon is now configured. The 300K seed pipeline exists (`scripts/aegis-seed.mjs` + `scripts/seed-postgres.mjs`) but hasn't been run against Fly's database.

**Steps:**
1. Get Fly Postgres connection string: `fly postgres connect -a cloudforge-db`
2. Run migrations 001-008: `fly ssh console -C "cd /app && for f in migrations/*.sql; do psql $DATABASE_URL -f $f; done"`
3. Generate seed data locally: `node scripts/aegis-seed.mjs --full` (produces ~594MB JSON)
4. Stream to Fly Postgres: `DATABASE_URL=<fly-pg-url> node scripts/seed-postgres.mjs`
5. Set `FINDINGS_SOURCE=postgres` on Fly app: `fly secrets set FINDINGS_SOURCE=postgres`
6. Verify: `curl https://cloudforge-api.fly.dev/api/v1/findings?per_page=1` should return 300K total

**Why deferred:** Pipeline works locally (verified session 29). Fly Postgres may need sizing check for 300K rows + graph_edges backfill.

**Effort:** ~1 hour ops
