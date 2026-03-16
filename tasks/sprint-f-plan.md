# Sprint F — Production Path + Demo Polish

**Previous:** Sprint E (whitelabel readiness — factory pattern across all packages)
**Status:** PLANNED
**Theme:** Neon Postgres + Bedrock activation + the "wow factor" demo features.
**Estimated effort:** ~1 week (4-5 sessions)

---

## Workstream Decomposition

Sprint F has two independent workstreams that MUST run in parallel:

```
Workstream A (infra chain — sequential):     Workstream B (frontend polish — parallel):
  F1: Neon Postgres provisioning               F4: Attack path O(1) lookup
       ↓                                       F5: Vite manual chunks
  F2: Bedrock activation                       F6: Full keyboard shortcuts
       ↓                                       F7: SLA computation (admin dash)
  F3: "Enrich with AI" button
```

### Why two workstreams?

- **Workstream A** is a sequential chain: you can't activate Bedrock without a database, and you can't wire the Enrich button without Bedrock. These touch infra + backend + one frontend component.
- **Workstream B** items are fully independent of each other AND of Workstream A. They touch different files, different packages, zero shared state. Running them sequentially wastes time.

### Agent team structure

| Agent | Workstream | Model | Scope |
|-------|-----------|-------|-------|
| Worker 1 | A (infra) | Sonnet | F1 → F2 → F3 sequentially |
| Worker 2 | B-backend | Sonnet | F4 (Go handler change) |
| Worker 3 | B-frontend | Sonnet | F5 + F6 + F7 (all frontend, independent files) |
| Distiller | — | Opus | Aggregate after all workers complete |

---

## Items

### Workstream A: Infrastructure Chain (sequential)

| # | Item | Effort | Notes |
|---|------|--------|-------|
| F1 | Neon Postgres provisioning + migration run | 1 session | Unblock DATABASE_URL — run migrations 001-004 against Neon |
| F2 | Bedrock activation (TODO-DEFERRED D5) | 15min | Env vars + redeploy. Enables live AI enrichment |
| F3 | "Enrich with AI" button (TODO-DEFERRED D4) | 0.5 session | Backend done — just a button + mutation hook |

### Workstream B: Polish (parallel)

| # | Item | Effort | Notes |
|---|------|--------|-------|
| F4 | Attack path O(1) lookup (TODO-DEFERRED D14) | 30min | `PathsByID map` — same pattern as `DataStore.FindingsByID` |
| F5 | Vite manual chunks (TODO-DEFERRED D11) | 30min | Bundle size optimization for recharts, xyflow, tanstack |
| F6 | Full keyboard shortcuts (TODO-DEFERRED D3) | 0.5 session | Power user polish with `?` help overlay |
| F7 | SLA computation (Sprint C P4) | 0.5 session | Admin dashboard — compute from created_at + per-type deadline |

---

## Implementation Notes

**F1 (Neon Postgres):**
- See `tasks/blocked.md` for manual provisioning steps
- Run migrations 001-004 against Neon
- Set `DATABASE_URL` as Fly.io secret
- Set `GRC_PROVIDER=postgres` (factory from Sprint E handles the rest)

**F2 (Bedrock activation):**
- Set as Fly.io secrets:
  - `CLOUDFORGE_AI_ENABLED=true`
  - `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (from 1Password)
  - `BEDROCK_REGION=us-east-1`
  - `BEDROCK_MODEL=anthropic.claude-haiku-4-5-20251001-v1:0`
- Redeploy

**F3 (Enrich button):**
- Add "Enrich with AI" button in FindingDetail.tsx
- POST to `/api/v1/findings/{id}/enrich`
- Refresh finding data on success
- Gate button visibility on `CLOUDFORGE_AI_ENABLED` via config endpoint

**F4 (Attack path O(1)):**
- File: `cmd/server/handlers_attackpath.go:100`
- Add `PathsByID map[string]*AttackPath` to AttackPathService
- Populate in constructor, use in `getAttackPath` handler

**F5 (Vite manual chunks):**
- File: `vite.config.ts`
- Add `manualChunks` splitting recharts, @xyflow/react, @tanstack/* into separate vendor chunks

**F6 (Keyboard shortcuts):**
- Add shortcuts: `D` (detail panel), `1/2/3` (view mode), `?` (help overlay), `Left/Right` (step attack paths)
- Use `useEffect` + `keydown` listener, gated on no active input focus

**F7 (SLA computation):**
- Compute SLA from `created_at` + per-severity deadline (Critical: 24h, High: 72h, Medium: 7d, Low: 30d)
- Display in admin dashboard KPI row

---

## Dependencies

```
Workstream A (sequential):
  F1 (Neon) → Sprint E complete (factory pattern must be in place)
  F2 (Bedrock) → F1 (database should be live before enabling AI)
  F3 (Enrich button) → F2 (Bedrock must be active)

Workstream B (all independent):
  F4 (O(1) lookup) → no deps
  F5 (Vite chunks) → no deps
  F6 (Keyboard shortcuts) → no deps
  F7 (SLA computation) → no deps

Cross-workstream: NONE — fully independent
```

---

## Commit Strategy

| Commit | Workstream | Items | Message |
|--------|-----------|-------|---------|
| 1 | A | F1 | `feat(db): provision Neon Postgres + run migrations 001-004` |
| 2 | A | F2 | `feat(ai): activate Bedrock enrichment in production` |
| 3 | A | F3 | `feat(frontend): add Enrich with AI button on FindingDetail` |
| 4 | B | F4 | `perf(attack-paths): O(1) path lookup via PathsByID map` |
| 5 | B | F5 | `perf(frontend): Vite manual chunks for recharts, xyflow, tanstack` |
| 6 | B | F6 | `feat(frontend): full keyboard shortcuts with help overlay` |
| 7 | B | F7 | `feat(frontend): SLA computation in admin dashboard KPI row` |

---

## Exit Gate

- [ ] Neon Postgres connected + migrations 001-004 applied
- [ ] Bedrock live + at least 1 finding enriched via UI
- [ ] All existing tests pass: `go test -race -timeout 20m ./...` + `npx vitest run` + `npm run build`
- [ ] Full E2E Chrome QA sweep (`/ap-chrome-qa`) — all routes clean
- [ ] Production deployment verified on Fly.io

---

## Post-Sprint F: HAEA Pilot Path

After Sprint F, deploying to HAEA requires only:

1. Set env vars: `IDENTITY_PROVIDER=okta`, `CONTAINER_SCANNER=trivy`, `FINOPS_PROVIDER=aws`
2. Provide credentials: `OKTA_DOMAIN`, `OKTA_API_TOKEN`, `AWS_REGION`, etc.
3. The real provider implementations already exist. FinOps AWS provider is the only new code needed (~2 weeks).

No architectural changes. No interface changes. Just config.
