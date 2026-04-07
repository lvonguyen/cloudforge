# CloudForge Figma Diagram Sprint — Master Handoff

**Updated:** 2026-04-07 (cf.2 bug fix + light rebuild session)
**Branch:** main
**Figma file key:** `2l5XrS7QRy5MYFI9PwcPmK`
**figma-create channel:** use `bun run --silent socket:wait-channel` (auto-detect)
**Quality bar:** FAANG L9 Staff Engineer reviewing portfolio

---

## Current State — All 16 Pages Complete (CF.1-8 Dark + Light)

| Page | Dark | Light | Notes |
|------|------|-------|-------|
| CF.1 | **v2 DONE** (98:3704, 11 tiers, 4 icons) | **v2 DONE** (107:2, page 98:3755) | Rebuilt 2026-04-07. 1920x2060, 61 nodes, 4 tier icons (Dashboard/Shield/Monitoring/PostgreSQL), polygon arrows with E/G effects. |
| CF.2 | **v2 DONE** (74:3, 1920x1400, 8 bugs fixed) | **v2 DONE** (108:3988, page 108:3987) | Rebuilt 2026-04-07. Height 950→1400, icons reimported, spacing redistributed, full color swap. |
| CF.3 | DONE (28px, redistributed) | DONE | Full readability overhaul |
| CF.4 | DONE (centered, no arrows) | DONE (98:2875) | Pipeline arrows removed — independent profiles |
| CF.5 | DONE (scan-search, 1280px) | DONE (98:2770) | |
| CF.6 | DONE (Tier2 shrunk, icons LR) | DONE (98:2555) | |
| CF.7 | DONE (readability pass) | DONE (98:2962) | |
| CF.8 | DONE (readability pass) | DONE (98:3107) | |

## 2026-04-07 Addendum — Parallel Figma Session

Verified against live Figma and applied only on unclaimed pages while CF.1 was in use elsewhere.

- WS-2 is complete in the file even though the older workstream table below still shows it as open.
  - CF.3 dark/light badges added: `98:3700`, `98:3701`
  - CF.4 dark/light badges added: `98:3702`, `98:3703`
  - CF.4 body-card text and badge text verified/normalized to Georgia
- CF.2 light bug pass was partially completed on page `85:738`, frame `85:739`
  - Fixed: subtitle width, Step 3 width, `Fix Violations` width, `evaluates` overlap, Terraform icon replacements, OPA shield replacement, Deploy Complete spacing
  - Deferred: small loop arrow sizing / arrow-opacity-only polish
- P3 embed annotations added on current live pages:
  - CF.1 dark/light: `108:4092`, `108:4091`
  - CF.2 dark/light: `98:3832`, `98:3833`
  - CF.3 dark/light: `98:3834`, `98:3835`
  - CF.4 dark/light: `98:3836`, `98:3837`
  - CF.5 dark/light: `98:3838`, `98:3839`
  - CF.6 dark/light: `108:3928`, `108:3929`
  - CF.7 dark/light: `108:3930`, `108:3931`
  - CF.8 dark/light: `108:3932`, `108:3933`
- P3 remaining:
  - none
- CF.2 status note:
  - dark page `1:2`, frame `74:3` — REBUILT. 1920x1400, 8 bugs fixed, icons reimported, spacing redistributed.
  - light page `108:3987`, frame `108:3988` — NEW. Old `85:738` deleted, replaced with dup of fixed dark + 55-op color swap.
  - CF.2 D+L is now COMPLETE.
- P6 cleanup findings:
  - CF.1 dark page `0:1` is clean: authoritative dark frame `98:3704` + embed annotation `108:4092`
  - CF.1 light page `98:3755` was polluted with two stale overlapping duplicate frames
    - deleted stale frame `98:3756` (old light copy with stale `91 ops` text)
    - deleted stale frame `104:2` (dark-themed duplicate mislabeled as light)
    - page `98:3755` now contains only authoritative light frame `107:2` + embed annotation `108:4091`
  - Old CF.7 light page `85:1087` is already gone
  - Old CF.8 light page `85:1343` is already gone
  - Full page-order verification and any remaining stale-page deletes still need a live `figma-create` write session
- Current blocker:
  - `figma-create` write transport is healthy again for targeted page writes
  - full page-enumeration/page-order cleanup is still awkward because the pages API is lazy-loaded and `get_pages` does not currently return all pages without an explicit load
  - CF.1 remains intentionally untouched in this addendum because another session owns that workstream

---

## Remaining Work — Priority Order

### P1. Arrow E/G Batch Replacement — COMPLETE (2026-04-07)

82 arrows replaced across 12 pages (~246 MCP operations). Two styles:
- **E (dark):** thick stroke + #0f172a inner shadow 70% y+3 + color-matched glow 30%
- **G (light):** thick stroke + #ffffff inner highlight 50% y-2 + #0f172a grounding shadow 20%

| Diagram | Dark (E) | Light (G) | Count | Notes |
|---------|----------|-----------|-------|-------|
| CF.1 | DONE | DONE | 10 | 5 tier down arrows |
| CF.2 | DONE | DONE | 18 | 9 arrows (gray/green/red) |
| CF.3 | SKIP | SKIP | — | UML horizontal bars correct |
| CF.4 | SKIP | SKIP | — | Arrows intentionally removed |
| CF.5 | DONE | DONE | 16 | 5 arrows + 3 connectors |
| CF.6 | DONE | DONE | 18 | 6 tier + 3 bundle (stacking bug fixed) |
| CF.7 | DONE | DONE | 16 | Dual-panel 4+4 |
| CF.8 | DONE | DONE | 4 | Confidence threshold split (green/red) |

### P2. CF.1-CF.8 Figma Rebuild — 4 Parallel Workstreams

**Mermaid source:** UPDATED (2026-04-06). 42→61 nodes, 9→11 tiers.
**Landing page:** UPDATED. 5→9 module cards (Self-Service, Attack Paths, Compliance, FinOps).
**Tools:** `/figma` skill, figma-create MCP, `icon-library` MCP
**Model:** Opus for all workstreams

**Completed code changes (cf.1 session):**
- `architecture.mmd` v2 — 61 nodes, 11 tiers, all backed by `internal/` packages
- `Landing.tsx` — 4 new cards, tsc clean
- `branding.ts` — enabledModules default updated

#### WS-1: CF.1 + CF.2 (Hero Rebuild) — HIGH complexity

**CF.1 D+L — COMPLETE (2026-04-07, ~260 MCP ops total)**
- Dark (98:3704): 1920x2060, 11 tiers, 61 nodes, 11 tier icons, 10 P1-style chevron arrows, badge at (1635, 28).
- Light (107:2): Page 98:3755. Full color swap, 11 darker tier icons, 10 G-style chevron arrows, badge synced.
- **Icons (11 total):** T1 Console, T2 Lock, T3 Gear, T4 Graph, T5 Radar, T6 Shield, T7 Chart, T8 Metrics, T9 Building, T10 Database, T11 Cloud. 75x75 frames, 64x64 SVGs. Dark=bright tier colors, Light=one Tailwind shade darker.
- **Arrows:** SVG chevrons (40x28, 7px stroke, `<path d="M4 4L20 22L36 4"/>`). Centered in 40px tier gaps. E-style dark / G-style light effects.
- **Subtitle:** y=92 on both variants. Badge: (1635, 28) on both.
- **G11 lesson:** `set_selection_colors` recolors frame fills — must `set_fill_color(a=0)` on wrapper frames after recoloring.

**CF.2 D+L — COMPLETE (2026-04-07, ~75 MCP ops)**
- Dark (74:3): 1920x1400 (was 950). 8 bugs fixed: height extended, spacing redistributed (+70px gate, +108px rego), Fix Violations widened 260→280, evaluates reordered to front, 3 icons reimported (Terraform homelab, CloudFormation Res_48 white, Shield Res_48 white), Block→Fix arrow 18x14→28x16, all 9 arrows opacity→0.85. Badge "PORTFOLIO + PRODUCTION" added at (1540, 28).
- Light (108:3988): Page 108:3987. Duplicated from fixed dark. Full color swap (55 ops): 19 frame fills, 6 strokes, 28 text colors, 2 icon recolors (G9 #232F3D), 2 G11 frame fill resets.
- **Bug 6 (red bg on gate):** Not visible on dark render — gate fill is correct #1e293b. Marked resolved.

**CF.2 Bug List — ALL RESOLVED (2026-04-07)**
1. ~~Subtitle clips~~ — verified OK at 1100px on dark (was light-only)
2. ~~Fix Violations overflow~~ — widened 260→280px
3. ~~evaluates behind divider~~ — reordered to front
4. ~~Garbled Terraform icons~~ — 3 icons deleted + reimported (homelab TF, Res_48 CF/Shield, white for dark, #232F3D for light)
5. ~~Loop triangle too small~~ — resized 18x14→28x16
6. ~~Red background on gate~~ — not visible (gate fill #1e293b correct)
7. ~~Stage spacing inconsistent~~ — redistributed: +70px gate section, +108px rego section, watermark→y=1360
8. ~~Arrow opacity low~~ — all 9 arrows boosted to 0.85

#### WS-2: CF.3 + CF.4 (Reference Badges) — LOW complexity
**No prerequisites. Pick up independently.**

| Page | Action | Target |
|------|--------|--------|
| CF.3 Dark | Add "PRODUCTION REFERENCE" badge top-right | 1920x1600 |
| CF.3 Light | Dup dark -> color swap (L never created) | 1920x1600 |
| CF.4 Dark | Add "PRODUCTION REFERENCE" badge | 1920x2060 |
| CF.4 Light | Add badge (L exists at 98:2875) | 1920x2060 |

Badge spec: Georgia 18px, #64748b (dark) / #94a3b8 (light), at (frame_width - text_width - 40, 20).

#### WS-3: CF.5 + CF.6 (Light + Polish) — MED complexity
**No prerequisites. Pick up independently.**

| Page | Action | Target |
|------|--------|--------|
| CF.5 Dark | Verify 22px min text | 1440x1280 |
| CF.5 Light | Delete stale -> dup dark -> color swap | 1440x1280 |
| CF.6 Dark | Add "PRODUCTION REFERENCE" badge. Fix Tier 2 dead space (85:525 is 200px, cards end 160px — shrink to 170, cascade -30px downstream) | 1440x1310 |
| CF.6 Light | Delete stale -> dup fixed dark -> color swap | 1440x1310 |

#### WS-4: CF.7 + CF.8 (Light Variants) — LOW complexity
**No prerequisites. Pick up independently.**

| Page | Action | Target |
|------|--------|--------|
| CF.7 Dark | Verify readability (22px min) | 1920x~1600 |
| CF.7 Light | Delete stale -> dup dark -> color swap | 1920x~1600 |
| CF.8 Dark | Readability already verified (43 text nodes, 46% check) | 1920x~1600 |
| CF.8 Light | Delete stale -> dup dark -> color swap | 1920x~1600 |

---

### P3. Embed Location Annotations

Add a text annotation OUTSIDE each Figma frame (below, y = frame_height + 20) showing embed targets. Georgia 14px, #64748b.

| Diagram | Embeds | Export Format |
|---------|--------|---------------|
| **CF.1** | README.md:210 (hero `<img>`), gallery.md:15, diagrams/README.md, STANDARDS.md:361, **portfolio-site** projects.ts:14, docs-site build | PNG 2x + SVG |
| **CF.2** | README.md:485 (table link), gallery.md:42 (->HLD), diagrams/README.md | SVG, create -figma variant |
| **CF.3** | README.md:483, gallery.md:42 (->DR-BC), style-guide:75 | SVG |
| **CF.4** | README.md:482, gallery.md:42 (->HLD), diagrams/README.md | SVG |
| **CF.5** | README.md:486, gallery.md:42 (->HLD), diagrams/README.md | SVG |
| **CF.6** | README.md:484 (figma.png), gallery.md:27 (figma.png), diagrams/README.md (both variants), docs-site build | PNG 2x + SVG |
| **CF.7** | README.md:354 (hero `<img>`), README.md:480 (table), gallery.md:21, style-guide:270, docs-site build | PNG 2x + SVG |
| **CF.8** | README.md:487 (table), gallery.md:33, style-guide:76, docs-site build | PNG 2x + SVG |

Gaps: HLD.md embeds zero images (text refs only). portfolio-site only shows CF.1. docs-site gallery links CF.2-5 to parent docs not assets.

### P4. Diagram Artifact Cleanup — COMPLETE (2026-04-06)

**Result:** 55→41 files, 8.7→6.0MB (2.7MB saved)
- 14 stale renders deleted (Mermaid PNGs/SVGs with -figma/-drawio replacements)
- 12 renames: `-figma`/`-drawio` suffixes consolidated to canonical base names
- Updated references in: README.md, gallery.md, diagrams/README.md, CODEBASE_INDEX.md

### P5. CF.1 Docs Asset Refresh — COMPLETE (2026-04-06)

**Result:** `docs/core/diagrams/architecture.{png,svg}` now export from CF.1 Light (`107:2`)
- Top-right badge preserved: `PORTFOLIO + PRODUCTION`
- Current-state labels synced: `Router (89 ops)`, `Remediation (18h / 12d)`, `Workflow Engine (memory)`
- README and `docs/core/diagrams/gallery.md` already point at the canonical `architecture.png` path

**Follow-up outside this repo:**
- `portfolio-site/public/cloudforge-architecture.svg` in the sibling repo was refreshed under P7 and now matches the canonical docs export
- Additional portfolio/docs-site asset sync for CF.2 / CF.7 / CF.8 is still optional follow-up if those surfaces are expanded
- Consider adding CF.7 (Dual OPA) as second portfolio hero

### P6. Archive/Delete Old Diagram Pages — COMPLETE (2026-04-07)

**Result:** 17→16 pages. Clean CF.1→CF.8 dark/light pairing.
- [x] Deleted `85:671` "CF.1 — Architecture (Light)" — old v1 (6 tiers, pre-rebuild)
- [x] Deleted old CF.2 Light page `85:738` (replaced with `108:3987` this session)
- [x] All pages scanned via cloud `use_figma` API — no orphaned frames or unnamed pages
- [x] Page ordering fixed: CF.2 Light moved from index 16→3, CF.7 Light moved from index 14→13
- [x] Deleted `tasks/handoff-figma-e5-cont.md` (patterns embedded in main handoff)

**Final page order (16 pages):**
| # | ID | Page |
|---|-----|------|
| 0 | 0:1 | CF.1 Dark |
| 1 | 98:3755 | CF.1 Light |
| 2 | 1:2 | CF.2 Dark |
| 3 | 108:3987 | CF.2 Light |
| 4 | 1:3 | CF.3 Dark |
| 5 | 85:819 | CF.3 Light |
| 6 | 1:4 | CF.4 Dark |
| 7 | 98:2875 | CF.4 Light |
| 8 | 1:5 | CF.5 Dark |
| 9 | 98:2770 | CF.5 Light |
| 10 | 1:6 | CF.6 Dark |
| 11 | 98:2555 | CF.6 Light |
| 12 | 1:7 | CF.7 Dark |
| 13 | 98:2962 | CF.7 Light |
| 14 | 1:8 | CF.8 Dark |
| 15 | 98:3107 | CF.8 Light |

### P7. Portfolio Site SVG Refresh — COMPLETE (2026-04-07)

**Pipeline:** `figma-create get_svg` → JSON extract → `.svg` file → `rsvg-convert` → `.png`
**G10 override:** User-approved MCP production export.

**8 SVGs exported from Figma dark frames:**

| CF | File | SVG | PNG |
|----|------|-----|-----|
| CF.1 | architecture | 1.4MB | 394KB |
| CF.2 | iac-deploy-pipeline | 991KB | 264KB |
| CF.3 | failover-sequence | 1.0MB | 299KB |
| CF.4 | compliance-deployment-models | 1.9MB | 386KB |
| CF.5 | remediation-dispatcher-flow | 522KB | 189KB |
| CF.6 | global-deployment-architecture | 896KB | 262KB |
| CF.7 | dual-opa-architecture | 1.4MB | 308KB |
| CF.8 | risk-intelligence-pipeline | 1.2MB | 310KB |

**Portfolio site:** `cloudforge-architecture.svg` updated (32KB → 1.4MB).
**Runbook diagrams** (finops, incident-response, perf-troubleshooting, secrets-rotation) untouched — separate Mermaid renders.

---

## Diagramming Lessons (MUST READ before any WS)

### [!] CRITICAL — Will Waste Hours If Ignored

1. **Native figma-create is the ONLY working approach.** `set_image`, Draw.io CLI, Mermaid mmdc, Plugin API, URL import ALL failed across 6+ sessions. Build with `create_frame`, `create_text`, `set_svg`, `set_effects`.
2. **Delete-then-rebuild for light variants.** Never incrementally patch stale copies. Delete old -> dup fixed dark -> color swap.
3. **Verify at 46% zoom.** 1920px renders at 888px in README. `rendered = source * 0.46`. Hard floor: 22px source -> 10.1px rendered. Below 20px is invisible.
4. **Icons 48px+ for 1920px frames.** CF.7/CF.8 had 11 icons each resized 28→56px. Use Res_* AWS icons (never Arch_* — square backgrounds).
5. **Icon corner clip safe zone: (1695, 15) at 40px.** Three rounds discovered this. (1696, 8) clips with 12px corner-radius.
6. **Max 5 icon-library searches.** Session C1 wasted 1 hour on 20+ searches. Use previously inventoried icons from memory.
7. **No parallel sessions on same Figma page.** D3++ session contaminated CF.2's frame 74:3.
8. **Add arrows during build, not as polish.** CF.4/5/6 shipped with zero arrows initially.
9. **Vertical stack + arrows = sequential ordering.** CF.4 arrows GDPR→PCI→... deleted (independent profiles, not pipeline).
10. **Figma rotation is counterclockwise.** 270deg = right-pointing, 180deg = down-pointing.
11. **Draw.io data URI: encode `;` as `%3B`.** Style parser splits on `;` breaking `data:image/png;base64,...`.
12. **`use_figma` cannot see `figma-create` nodes.** Sync delay. Don't mix MCP tools.
13. **Mermaid SVG foreignObject not supported.** Cannot import Mermaid SVGs into Figma.
14. **Georgia font everywhere.** All Figma builds use Georgia (not Inter). Set via `set_font_name`.
15. **[G8] Mandatory zoom verification after EVERY visual edit.** Read frame width via `get_node_info`, compute `scale = 888 / frame_width`, export at that scale. If frame > 2400px WARN. Verify: text >=10px rendered, icons >=24px rendered, arrows visible. NOT optional. See DIAGRAM_STYLE_GUIDE.md G8.
16. **[G9] Icon family must match: Res_48_Dark (white) on dark, Res_48_Light (#232F3D) on light.** Never Arch_* (square bg). Never mix colored service icons with monochrome generals. 4 standard icons: Console (T1), Shield (T6), Metrics (T8), Database (T10).
17. **[G10] Verification exports are ephemeral.** `export_node_as_image` PNGs must NOT be committed. Only production exports (Figma desktop File > Export > PNG 2x) go to `docs/core/diagrams/`.

### Readability Calculator

| Frame Width | README Zoom | Min Font | Min Icon |
|-------------|-------------|----------|----------|
| 1920px | 46% | 22px | 48px |
| 1440px | 62% | 16px | 36px |

### "PRODUCTION REFERENCE" vs "PORTFOLIO + PRODUCTION"

| Label | Applies to | Meaning |
|-------|-----------|---------|
| `PORTFOLIO + PRODUCTION` | CF.1, CF.2, CF.5, CF.7, CF.8 | Fully deployed in portfolio demo |
| `PRODUCTION REFERENCE` | CF.3, CF.4, CF.6 | Interfaces/stubs exist; enterprise deployment config, not wired in portfolio |

---

## Open Items (Not Diagram Work)

### Code Reconciliation
- [x] Route count reconciled in README / CF.1 asset: `89 ops`
- [x] Remediation handler count reconciled in README: `18 handlers across 12 domains`
- [x] Frontend test count reconciled in README: `482 tests (62 test files)`

### Docs P1s (separate session)
- [x] HLD: Security Graph (secgraph) section
- [ ] ADR-022: Dual BFS Engine (Go + Rust FFI)
- [ ] ADR-023: AI Tiered Model Routing
- [x] HLD: Current/Target State framing
- [x] Runbook-10: Attack Path / SecGraph ops
- [x] Runbook-11: Ingestion Pipeline ops

---

## Stale Handoff Files — CLEANED (2026-04-07)

12 stale handoff files deleted total. Remaining active file:
- `tasks/handoff.md` — This file (master handoff)

---

## Tool & Skill Reference

| Task | Primary Tool | Skill | Notes |
|------|-------------|-------|-------|
| Figma color swap | `figma-create` MCP | `/figma` | `set_fill_color`, `set_stroke_color`, `set_effects` |
| Figma layout/resize | `figma-create` MCP | `/figma` | `move_node`, `resize_node`, `delete_node` |
| Figma page mgmt | `figma-create` MCP | `/figma` | `delete_page`, `duplicate_page`, auto-channel via `socket:wait-channel` |
| Icon lookup | `icon-library` MCP | — | `search_icons`, `get_icon_svg`, `get_icon_base64` |
| Figma screenshot | `figma-desktop` MCP | — | `get_screenshot` (needs Figma desktop open + active tab) |
| Architecture diagram source | Read/Edit | — | `docs/core/diagrams/architecture.mmd` |
| Frontend cards | Read/Edit | `/frontend-patterns` | `frontend/src/pages/Landing.tsx`, `lib/branding.ts` |
| Diagram export | Manual | — | Figma File -> Export -> PNG 2x |
| Artifact cleanup | Bash + Glob | `/repo-hygiene` | Delete orphan PNGs, consolidate naming |
| Code review post-edit | Agent | `/qa` or `/qa-visual` | Verify after frontend changes |

### Light Variant Swap Table (reference)

| Element | Dark | Light |
|---------|------|-------|
| Frame bg | #0f172a | #ffffff |
| Card/tile fill | #1e293b | #f1f5f9 |
| Primary text | #e2e8f0 | #1e293b |
| Secondary text | #94a3b8 | #475569 |
| Stroke | #334155 | #cbd5e1 |
| Container stroke | #1e40af | #3b82f6 |
| Drop shadow | none | rgba(0,0,0,0.08) y+2 r8 |

---

## Startup Command

```
read tasks/handoff.md -- ALL FIGMA WORK COMPLETE. P1-P7 done. 16 clean pages, 8 SVG+PNG exports, portfolio-site updated. Remaining: docs P1s (ADR-022, ADR-023), git commit of diagram exports. figma-create at 127.0.0.1:3846.
```
