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
