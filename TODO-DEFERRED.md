# CloudForge — Deferred Items

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

**Why deferred:** Requires `CLOUDFORGE_AI_ENABLED=true` + valid AI credentials in deployment. Mock data already populates AI fields for demo purposes.

**Effort:** ~0.5 day frontend (button + mutation hook)

---

## D5: Activate Bedrock in Production Deployment

**Status:** `CLOUDFORGE_AI_ENABLED` defaults to `false`. Not set in `fly.toml` or `docker-compose.yml`.

**To activate:**
1. Set `CLOUDFORGE_AI_ENABLED=true` as Fly.io secret
2. Set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` from 1Password (`op://Development/BedrockAPIKey-1k4n-at-431330216246 (lvn-personal, longterm)/...`)
3. Set `BEDROCK_REGION=us-east-1` and `BEDROCK_MODEL=anthropic.claude-haiku-4-5-20251001-v1:0`
4. Redeploy

**Why deferred:** Demo/portfolio deployment uses mock data. Live AI enrichment incurs Bedrock API costs and requires credential rotation planning.

**Effort:** ~15 minutes (env vars + redeploy)

---

## D6: [SEC] localStorage Role Escalation (F-02, HIGH)

**File:** `frontend/src/lib/auth.ts` lines 94-98, 118, 185-188

**Issue:** `userFromToken()` reads `savedRole` from `localStorage` and trusts it over the JWT groups claim. Any authenticated user can run `localStorage.setItem('cf_role', 'admin')` and reload to gain admin-tier UI access. The `RoleSwitcher` is DEV-gated, but `localStorage` persistence means a dev-mode role override can leak to a prod-like context.

**Fix:** Always derive role from the JWT groups claim in `userFromToken()`. Remove the `savedRole` fallback. The `RoleSwitcher` (DEV only) should set role transiently in React state, never persisting to `localStorage`.

**Why deferred:** The file is outside the Command Center scope. Server-side RBAC on `/api/v1/*` endpoints is the real authorization gate — this is defense-in-depth.

**Effort:** ~1 hour (auth.ts refactor + test)

---

## D7: Centralize Severity Color Constants

**Issue:** Severity colors (`#ef4444`, `#f97316`, `#eab308`, `#3b82f6`) are defined independently in 5 locations:
1. `severity.ts` — Tailwind classes
2. `FindingsSummaryChart.tsx` — `SEV_FILL` hex map
3. `DataLayersPanel.tsx` — `SEVERITY_DOT` Tailwind classes
4. `StatusBar.tsx` — inline Tailwind in JSX
5. `CommandCenter.tsx` — `NODE_BORDER` hex map

**Fix:** Add `SEVERITY_HEX: Record<string, string>` to `severity.ts` and derive all other usages from it.

**Effort:** ~30 minutes (create constant + update 4 files)

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

**Issue:** `useRemediations` / `useFindings` mock fallback catches 5xx errors silently, masking real API failures in production.

**Fix:** Gate mock fallback on `import.meta.env.VITE_ENABLE_MOCK_FALLBACK`. Only enable for demo/dev environments.

**Effort:** ~30 minutes (env var + conditional in each hook)

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

Add `manualChunks` for large dependencies: `recharts`, `@xyflow/react`,
`@tanstack/*`. Currently bundled into a single vendor chunk.

**Effort:** ~30 minutes

---

## D12: gzipResponseWriter Missing Interfaces

**File:** `cmd/server/middleware.go`

`gzipResponseWriter` wraps `http.ResponseWriter` but does not implement
`http.Flusher` or `http.Hijacker`. SSE streams and WebSocket upgrades
will fail when gzip middleware is active.

**Effort:** ~1 hour Go

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

Bare string literals (`"cloudforge-api"`, `"enrichment"`, `"ai_enrich"`,
`"analysis"`) should be promoted to package-level constants before a
second OPA gate is added (DRY).

**Effort:** ~15 minutes Go
