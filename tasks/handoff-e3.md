# Session E3 Handoff — Figma Native Build CF.7-CF.9

**Scope:** CF.7, CF.8, CF.9
**Date:** 2026-04-04
**Branch:** main
**Quality bar:** FAANG L9 Staff Engineer reviewing portfolio
**Figma file:** `2l5XrS7QRy5MYFI9PwcPmK`, channel `72snjfrt`

---

## CF.7 — Dual OPA Architecture (NEW)

**Page ID:** 1:7, Frame ID: 74:7
**Source:** `docs/core/diagrams/dual-opa-architecture.mmd` (62 lines)
**Draw.io reference:** `docs/core/diagrams/dual-opa-architecture.drawio` (passes litmus test)

### Content
- Two parallel OPA evaluation paths: Cloud Provisioning (external OPA server) vs AI Governance (in-process Go SDK)
- Shared Rego Policy Bundle at bottom
- 5 nodes per path, cross-container dashed edges

### Build approach
- 1920x1200 dark bg frame
- Two side-by-side columns: Provisioning (blue #3b82f6), AI (purple #7c3aed)
- Bottom shared bar: Policy Store (green #22c55e)
- Icons: cloud (provisioning), cpu-chip (AI agent), OPA brand (both paths), terraform brand, shield-check, server, bolt, code-bracket
- Vertical flow within each column, dashed edges from policy store to each path

---

## CF.8 — Risk Intelligence Pipeline (NEW)

**Page ID:** 1:8, Frame ID: 74:8
**Source:** `docs/core/diagrams/risk-intelligence-pipeline.mmd` (50 lines)

### Content (from Mermaid)
- Pipeline: Ingest → Enrich → Score → Correlate → Alert
- Enrichment sources: EPSS, GreyNoise, OTX, Toxic Combos
- Correlation: SecGraph (PuppyGraph/Gremlin)
- Output: Risk scores, attack paths, prioritized findings

### Build approach
- 1920x1000 dark bg frame
- Top-down or left-right pipeline flow
- Icons: funnel (ingest), sparkles/brain (enrich), chart-bar (score), share-nodes (correlate), bell (alert)
- Enrichment sources as small badges branching into the enrich stage
- SecGraph node with PuppyGraph icon or graph-network icon
- Color: blue=ingest, purple=enrich/AI, green=score, amber=alert

---

## CF.9 — IaC Deploy Pipeline (Light Theme) (NEW)

**Page ID:** 1:9, Frame ID: 74:9
**Source:** `docs/core/diagrams/iac-deploy-pipeline.mmd` (49 lines, same as CF.2)

### Content
- Same diagram as CF.2 but with light theme for DOCX/print context
- White/light gray background, dark text, colored accents

### Build approach
- 1920x800 light bg frame (fill #ffffff or #f8fafc)
- Same structure as CF.2 but inverted color scheme
- Dark text (#1e293b), colored borders, white card fills
- Useful for DOCX exports and presentation slides

---

## Recipes

Same as E1/E2 handoffs. Key points:
- `join_channel 72snjfrt` first
- Georgia font everywhere
- Dark bg for CF.7, CF.8; light bg for CF.9
- Delete garbled content before building
- Max 5 icon searches, use memory for known icons
- Chrome litmus at 888px after export
- Export PNG @2x + SVG to `docs/core/diagrams/` and `docs-site/static/img/diagrams/`
- Commit and push after each page completion

## Key References
- Figma page registry: `~/.claude/projects/.../memory/reference_figma_file_registry.md`
- Design system colors: Core #1e40af, AWS #f59e0b, Azure #3b82f6, GCP #22c55e, Infra #8b5cf6, DR #ef4444, BG #0f172a, Stroke #334155, Text #e2e8f0
- CF.7 Draw.io source: `docs/core/diagrams/dual-opa-architecture.drawio`
