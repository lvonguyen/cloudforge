# CloudForge Docs & Diagrams Audit — Handoff

**Updated:** 2026-04-07 (verified + compact)
**Branch:** main

---

## Session Summary

Diagram content audit + docs gap analysis + fixes. Three phases, all complete.

### Phase 1: Content Fixes + Font Normalization — DONE
- `architecture.mmd`: reconciled route-registration vs published-spec counts; docs-facing diagrams now keep `89 OpenAPI ops`
- Kept "18 handlers / 12 domains" (12 active; `private_cloud/` is stub-only)
- All 16 `.mmd` files normalized to `Georgia, serif` (was: 8 Inter, 4 no init block, 1 Georgia)

### Phase 2: ASCII → Canonical Diagram References — DONE
- DDD 3.4.10: 38-line ASCII state machine → `remediation-dispatcher-flow.svg` reference
- DDD 3.5.2: 21-line ASCII dual-OPA → `dual-opa-architecture.svg` reference
- ADR-009: diagram ref added to References section
- HLD Section 7: already had attack-path diagram — no action

### Phase 3: 3 New Diagrams — DONE
- `cross-cloud-failover.mmd` — sequence diagram: 4-phase failover (detection → DB → compute → DNS)
- `dedup-algorithm.mmd` — flowchart: SHA-256 key → cache check → rule mapping → persist/skip
- `restore-dependency-dag.mmd` — DAG: 7-step restore ordering (DB is critical path)
- All 3 embedded in target docs (DR-BC, HLD) with source links. Gallery updated.

### Post-Verification Follow-Up — DONE
- CF.8 Figma source (`Risk Intelligence Pipeline`) now matches docs wording in dark/light:
  - `OTX + ThreatFox`
  - `IOC Matching`
  - `Known toxic combos`
  - added `GR-004: Severity / score alignment` / `Clamp score to severity band`
- Canonical repo exports refreshed from the corrected dark frame:
  - `docs/core/diagrams/risk-intelligence-pipeline.svg`
  - `docs/core/diagrams/risk-intelligence-pipeline.png`
- CF.2 Figma dark/light (`IaC Deploy Pipeline`) tightened to presentation height again:
  - frame height reduced `1400 -> 1080`
  - footer watermark moved up inside frame
  - embed annotation moved below frame on-page
  - arrow assets checked; no dark/light size drift found
  - removed stale standalone loop arrow next to `back to Step 2`
  - enlarged `↑ back to Step 2` loop label for presentation readability
  - enlarged `evaluates ↓` bridge label above the Rego policy section
  - added one category icon per Rego card:
    - encryption, public exposure, TLS, network boundary, IAM scope
  - verified no duplicate icons, clipping, or crowding in refreshed dark/light exports
- CF.5 Figma dark/light (`Remediation Dispatcher Flow`) font drift fixed:
  - all state-machine internals normalized from `Inter` to `Georgia`
  - verified no clipping in state boxes or notes panel
- CF.4 Figma dark/light (`Compliance Deployment Models`) received a presentation polish pass:
  - header upgraded from a flat slab to a framework legend / tab strip
  - canonical docs exports refreshed from the light frame:
    - `docs/core/diagrams/compliance-deployment-models.svg`
    - `docs/core/diagrams/compliance-deployment-models.png`
  - still treat a fully switchable one-framework-at-a-time view as a separate redesign workstream, not a bugfix
- Docusaurus docs build re-verified after the diagram/doc changes:
  - `npm run build` passes from `docs-site/`
  - remaining noise is the existing `vscode-languageserver-types` webpack warning only

---

## Uncommitted Changes — Mixed Worktree From Multiple Sessions

### Docs (this session):
- 12 `.mmd` files — font normalization (Georgia)
- `architecture.mmd` — route/spec count reconciled; docs-facing label kept at `89 OpenAPI ops`
- `DDD.md` — ASCII blocks replaced with SVG refs (-66 lines)
- `DR-BC.md` — failover + restore diagram refs added
- `HLD.md` — dedup diagram ref added
- `ADR-009` — diagram ref
- `gallery.md` — 3 new entries
- 3 new `.mmd` files (cross-cloud-failover, dedup-algorithm, restore-dependency-dag)

### Docs (prior session, uncommitted):
- `README.md` — ADR count 21→23, handler 17→18, Rust/AI activation caveats, Archer stub note
- `ADR-022`, `ADR-023` — minor additions atop committed versions
- `docs/README.md`, `docs/intro.md`, `docs-site/src/pages/index.tsx` — minor updates
- `attack-path-secgraph-runtime.{mmd,png,svg}` — new diagram (untracked)

### Frontend (prior session, uncommitted):
- `AttackPaths.tsx` — expanded (+118)
- `Investigations.tsx` — major rework (+383/-127)
- `threat-context.ts` — NEW: exposure signal pattern matching
- `threat-context.test.ts` — NEW: tests for above
- `OpsInvestigations.test.tsx` — updated
- `useAttackPaths.ts`, `useFindings.ts`, `api.ts` — hook/API changes
- `ProviderBadge.tsx`, `ProviderIcon.tsx` + tests — UI components
- `attack-path.ts`, `compliance.ts`, `investigation.ts` — type additions
- `helpers.ts` (finding-detail) — helper changes
- **Total frontend**: 16 files, +621/-204

### Do NOT commit:
- `attackpaths-console-errors.txt` — debug artifact
- `tasks/recap-cloudforge-2026-04-04.md` — repo snapshot (informational)

---

## Suggested Commits (when ready)

1. **docs: normalize Mermaid fonts to Georgia + reconcile architecture API count**
   - 12 `.mmd` font changes + architecture.mmd label kept at `89 OpenAPI ops`
2. **docs: replace ASCII diagrams with canonical SVG references**
   - DDD.md, ADR-009
3. **docs: add cross-cloud failover, dedup, and restore dependency diagrams**
   - 3 new `.mmd` files + HLD, DR-BC, gallery refs
4. **docs: README accuracy updates + ADR-022/023 additions**
   - README.md, ADR-022, ADR-023, docs index, intro
5. **feat: attack-path + investigation UI with threat context**
   - All frontend/ changes (16 files)
6. **fix: prefer real session token over baked viewer token for ops routes**
   - `frontend/src/lib/auth.ts`, `frontend/src/lib/api.ts`, focused auth/api tests

---

## Backend Truth Point

Live protected attack-path APIs are healthy when called with a real admin token:
- `GET /api/v1/attack-paths?per_page=1` -> `200`
- `GET /api/v1/attack-paths/stats` -> `200`
- `GET /api/v1/attack-paths/ap-001/analysis` -> `200`

The remaining clickthrough issue was frontend auth precedence, not backend availability:
- live site appears to ship a baked `VITE_STATIC_TOKEN` for viewer mode
- `AuthProvider` and `api.ts` were preferring that static token over a real stored session token
- local fix now prefers valid stored session token first, then falls back to static token
- focused frontend tests pass: `50/50`

## Next High-Value Work

1. **Attack-path / finding-detail IA refresh**: use the Wiz reference as the model for information hierarchy, not visual cloning:
   - dedicated `Public internet` entry anchor / exposure lane
   - explicit owner/resource/network-boundary icons
   - top-level tabs that can grow toward `Overview | Investigation | Code to Cloud | Remediation | Comments | History`
   - keep inferred exposure visually distinct from explicit network facts
2. **Code-to-Cloud subview**: add a CI/CD provenance strip or tab from finding detail into attack-path investigation so the exploit path and delivery path are both visible
3. **Remediation action drawer**: add a compact drawer/panel for response actions with target, reversibility, risk, required permissions, and action instances
4. **Deferred diagrams**: AI tiered routing (target-state only), auth flow, Zero Trust tree
5. **CF.4 redesign candidate**: compact tabbed compliance-model view with one selected framework panel at a time; current long board is acceptable as reference but not ideal as a presentation asset

## Open Items

1. [LOW] mock identity providers Name()='okta'
2. [LOW] os.Setenv("AEGIS_JWKS_URL") fragile init order
3. [DEFERRED] k6 load testing
4. [LOW] React 19 lazy() context errors under Playwright
5. [P2] HLD missing: Document Control, Migration, Decommission, Review Log
6. [LOW] `icon-library` MCP now skips interactive 1Password bootstrap by default; if Brandfetch is needed at startup, use non-interactive 1Password auth (`OP_SERVICE_ACCOUNT_TOKEN` / Connect) or explicitly opt in with `ICON_LIBRARY_ENABLE_INTERACTIVE_1PASSWORD=1`
