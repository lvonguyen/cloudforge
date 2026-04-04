# Diagram Coordination (orchestrator, 2026-04-04)

## [!] Session Roles (ACTIVE — 3 parallel Figma-native sessions)

| Session | Owns | Status |
|---------|------|--------|
| **d1++ 1-3** | CF.2 + CF.3 | CF.2 ✓ DONE. CF.3 Failover Sequence IN PROGRESS. |
| **d3++ 4-6** | CF.4 + CF.5 + CF.6 | CF.4 ✓ DONE. CF.5 + CF.6 IN PROGRESS. |
| **d2++ 7-9** | CF.7 + CF.8 + CF.9 | CF.6 ✓, CF.7 ✓, CF.8 ✓ DONE. CF.9 IaC Light Theme IN PROGRESS. |

All sessions on channel `72snjfrt`, building via figma-create MCP. Handoff: `tasks/handoff-figma-diagrams.md`.

## [!] Enforced Guardrails (G1-G7) — READ BEFORE VERIFICATION

Codified in `docs/DIAGRAM_STYLE_GUIDE.md` v1.2 and `diagram-builder.md` agent. **All 7 must pass before marking a page complete:**

| # | Rule | Common Violation |
|---|------|-----------------|
| G1 | Icons inline-left with labels, not clustered right | Icons pushed to right edge of tier |
| G2 | Every tier MUST have at least one icon | **d2++ CF.7 + CF.8: ZERO icons** |
| G3 | Split-tier sections need visible dividers | Color shift alone is not enough |
| G4 | Consistent 24px+ spacing between component names | Inconsistent gaps between cards |
| G5 | No dead space — bottom margin = top margin | >100px unused at bottom |
| G6 | **Vertical-first layout default** for all frames | Sessions tried horizontal before being corrected |
| G7 | Connector labels 10px+, above line, readable contrast | Labels too small to read at README scale |

## [!] ICON DEFICIT — d2++ CF.7, CF.8

Orchestrator audit (via Figma monitor): **CF.7 Dual OPA and CF.8 Risk Pipeline have ZERO icons.** Structure and layout are excellent, but Phase 2 (Icon Gathering) was skipped entirely. Before marking these pages complete:

1. Search icon-library for: OPA/policy, Terraform, shield/security, EPSS, GreyNoise, brain/AI
2. Place icons inline-left in node cards per G1
3. Add layer-header icons (36px, top-right) per style guide

## [!] LIGHT THEME VARIANTS — ALL DIAGRAMS

User directive: **Every diagram needs a light theme variant for Docusaurus** (`https://docs.cloudforge.lvonguyen.com/`).

Light theme spec (from DIAGRAM_STYLE_GUIDE.md):
- Background: `#ffffff`
- Card fill: `#f5f5f5`
- Text primary: `#1f2937`
- Text secondary: `#6b7280`
- Arrow color: `#9ca3af`
- Layer stroke: layer color @ 30% alpha

Options:
- CF.9 already IS a light variant of CF.2 (d2++ building now)
- Remaining pages need light variants added — can be a follow-up session after all dark themes are complete

## [!] 46% README Litmus Test Results (ALL PAGES)

Viewed at 46% zoom (= GitHub README display for 1920px frames). Scale: `888/1920 = 0.46x`.

| Page | Verdict | Title | Card Labels | Subtitles | Icons | Dead Space | Fix Priority |
|------|---------|-------|-------------|-----------|-------|------------|-------------|
| CF.1 | PASS | ✓ | ✓ | ✓ | ✓ (5 SVGs) | Minimal | — |
| CF.2 | PASS | ✓ | ✓ | ✓ | ✓ (Terraform, Shield) | Minimal | — |
| CF.3 | NEEDS WORK | ✓ | Marginal | Too small | None | **30%+ empty** | HIGH — shrink frame, increase step text, add icons |
| CF.4 | MARGINAL | ✓ | Too small | Too small | None | OK | MED — increase card content font to 16px+, add icons |
| CF.5 | NEEDS WORK | ✓ | ✓ | Too small | None | **25% empty** | HIGH — shrink frame, increase transition labels, add icons |
| CF.7 | GOOD | ✓ | ✓ | Marginal | **NONE** | Moderate | MED — add icons (OPA, Terraform, AI), increase connector labels |
| CF.8 | GOOD | ✓ | ✓ | Marginal | **NONE** | Moderate | MED — add icons (EPSS, GreyNoise, brain/AI), card subtitle 11px→14px |
| CF.9 | IN PROGRESS | ✓ | Truncated | N/A | None | Large | HIGH — text truncation on step labels, needs completion |

### Common Issues Across Pages

1. **Zero icons on CF.3, CF.4, CF.5, CF.7, CF.8** — G2 violation. Every page needs process shapes, brand/service icons, and visual polish (decision diamonds, state circles, flow arrows). Not just text in boxes.
2. **Subtitle/metadata text too small** — 11px source × 0.46 = 5px rendered. Minimum 14px source for any secondary text on 1920px frames (→ 6.4px, still tight but readable bold).
3. **Dead space** — CF.3 and CF.5 have 25-30% empty frame at bottom. Shrink frame height to fit content.
4. **Connector/transition labels too small** — CF.3 step text, CF.5 state transitions, CF.7 protocol labels all need 14px+ source.

### Per-Page Action Items

**CF.3 (d1++):** Shrink frame from 1920x1600 to ~1920x1100. Increase step text to 16px. Add icons: heart/health, bell/alert, globe/DNS, server, database. Fill the yellow summary bar.

**CF.4 (d3++):** Increase requirement card body text from current ~11px to 16px. Add compliance framework icons (shield, lock, certificate). The 1440px canvas helps (0.62x scale) but body text is still too small.

**CF.5 (d3++):** Shrink frame from 1440x1800 to ~1440x1200. Increase transition labels to 14px. Add state machine shapes (circles for start/end, diamonds for decisions). Legend text needs 14px+.

**CF.7 (d2++):** Add icons: OPA logo, Terraform, cloud/shield, AI brain. Increase connector labels from ~10px to 14px. Otherwise structure is excellent.

**CF.8 (d2++):** Add icons: EPSS badge, GreyNoise, HIBP, brain/AI, shield. Increase card subtitle from 11px to 14px. Layer alignment is solid (verified via node positions — consistent 20px/40px gaps).

**CF.9 (d2++):** Fix truncated step labels ("plan-with-pol..." → full text). Light theme colors look correct (F8FAFC bg). Needs same icon set as CF.2.

## Design Direction (all outputs)

- Icons **way bigger** — 64x64 minimum standalone, 48x48 in node cards
- More **color** — use the full palette from DIAGRAM_STYLE_GUIDE.md
- **Less text heavy** — reduce label verbosity, let visuals speak
- **Vertical-first** — tiers stack top-to-bottom. Horizontal only with explicit opt-in.
- Prioritize whitespace and readability over detail density

## Draw.io `%3B` Fix (reference)

Draw.io style parser splits on `;`. URL-encode to `%3B` in data URIs:
- `image=data:image/png%3Bbase64,iVBOR...`
- `image=data:image/svg+xml%3Bbase64,PHN2...`

Documented in `docs/DIAGRAM_STYLE_GUIDE.md` v1.1 and `diagram-builder.md` agent.
