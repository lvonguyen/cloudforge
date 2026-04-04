# Session E1 Handoff — Figma Native Build CF.1-CF.3

**Scope:** CF.1 (polish), CF.2 (new), CF.3 (new)
**Date:** 2026-04-04
**Branch:** main
**Quality bar:** FAANG L9 Staff Engineer reviewing portfolio
**Figma file:** `2l5XrS7QRy5MYFI9PwcPmK`, channel `72snjfrt`

---

## CF.1 — CloudForge Architecture (POLISH)

**Status:** Built natively by D1 session. Needs FAANG-level polish.
**Page ID:** 0:1, Frame ID: 74:2
**Source:** `docs/core/diagrams/architecture.mmd` (131 lines)

### What exists
- 1920x1400 dark bg (#0f172a), 6 tiers, 16 text nodes, 7 SVG icons
- Tiers: Portal, API Gateway, Core Engines, Threat Intel / Policy Engine, Data + Infra, Cloud Providers

### Polish tasks
- [ ] Component badges — rounded rect behind each component name (not bare text)
- [ ] More icons — one per major component (findings=magnifying-glass, remediation=wrench, attack-path=route, NLQ=chat-bubble, compliance=clipboard-check)
- [ ] Flow arrows between tiers (top-down data flow, dashed, slate color)
- [ ] Subtle horizontal dividers or spacing refinement between tiers
- [ ] Verify all text uses Georgia font, bold where needed
- [ ] Export PNG @2x + SVG to `docs/core/diagrams/architecture-drawio.{png,svg}`
- [ ] Chrome litmus test at 888px

---

## CF.2 — IaC Deploy Pipeline (NEW)

**Status:** Empty frame in Figma (garbled image, needs delete + rebuild)
**Page ID:** 1:2, Frame ID: 74:3
**Source:** `docs/core/diagrams/iac-deploy-pipeline.mmd` (49 lines)

### Content (from Mermaid)
- Flowchart: Git Push → CI → Plan → OPA Check → Apply → Deploy
- Subgraphs: CI Pipeline, OPA Gate, Cloud Target
- 6-8 main nodes, decision diamond for OPA pass/fail

### Build approach
- 1920x800 dark bg frame (horizontal pipeline is naturally wide)
- Left-to-right flow: 5-6 rounded rect stages with arrows
- OPA gate as a diamond or highlighted decision node
- Icons: git (code-bracket), CI (play-circle), terraform (brand), OPA (brand), cloud providers (aws/azure/gcp)
- Color coding: blue=CI, purple=OPA, green=apply/deploy, red=reject path

---

## CF.3 — Failover Sequence (NEW)

**Status:** Empty frame in Figma. Draw.io vertical flow version exists and passes litmus test.
**Page ID:** 1:3, Frame ID: 74:4
**Source:** `docs/core/diagrams/failover-sequence.mmd` (43 lines)
**Draw.io reference:** `docs/core/diagrams/failover-sequence.drawio` (vertical flow, 10 steps)

### Build approach
- Replicate the vertical flow design that passed Chrome litmus test
- 1920x1400 dark bg frame
- 10 numbered step cards, top to bottom, colored by participant
- Icons: heart (health), bell (pager), user (on-call), globe (DNS), server-stack (DR), circle-stack (DB), beaker (smoke tests)
- RTO summary note at bottom
- Participant colors: red=alerting/DR, amber=PagerDuty, blue=on-call, green=DB, slate=DNS, purple=smoke tests

---

## Recipes

### Figma Native Build Pattern
```
1. join_channel 72snjfrt
2. set_current_page <pageId>
3. Delete garbled content: get_node_info → delete children
4. Create dark bg frame (fill #0f172a, rounded 12px)
5. Create tier/step frames (rounded, colored borders, transparent/dark fill)
6. Add text nodes (Georgia font, bold, light text #e2e8f0)
7. Import SVG icons via set_svg (from icon-library MCP search_icons → get_icon_svg)
8. Export at scale 0.5 for validation, scale 2 for final
9. Chrome litmus test at 888px (host.docker.internal for Playwright Docker)
```

### Icon Search (max 5 queries)
```
search_icons("terraform") → brand icon
search_icons("shield") → heroicons security
search_icons("database postgres") → Azure PG icon
# Use memory for previously found icons — don't re-search
```

### Litmus Test
```
Serve PNG → Playwright at 928x900 viewport → screenshot <img> element
All text readable without zoom. FAANG L9 staff would approve.
```

---

## Key References
- Figma page registry: `~/.claude/projects/.../memory/reference_figma_file_registry.md`
- Diagram pipeline: `~/.claude/projects/.../memory/reference_diagram_pipeline.md`
- Style guide: `docs/DIAGRAM_STYLE_GUIDE.md`
- Design system colors: Core #1e40af, AWS #f59e0b, Azure #3b82f6, GCP #22c55e, Infra #8b5cf6, DR #ef4444, BG #0f172a, Stroke #334155, Text #e2e8f0
