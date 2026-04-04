# Session E2 Handoff — Figma Native Build CF.4-CF.6

**Scope:** CF.4, CF.5, CF.6
**Date:** 2026-04-04
**Branch:** main
**Quality bar:** FAANG L9 Staff Engineer reviewing portfolio
**Figma file:** `2l5XrS7QRy5MYFI9PwcPmK`, channel `72snjfrt`

---

## CF.4 — Compliance Deployment Models (NEW)

**Page ID:** 1:4, Frame ID: 74:5
**Source:** `docs/core/diagrams/compliance-deployment-models.mmd` (54 lines)
**Draw.io reference:** `docs/core/diagrams/compliance-deployment-models.drawio` (passes litmus test)

### Content
- Central CloudForge hub branching to 5 compliance frameworks
- GDPR (blue), PCI-DSS (amber), HIPAA (green), SOX (dark blue), FedRAMP (red)
- Each framework: 5-6 single-line requirement labels

### Build approach
- 1920x1200 dark bg frame
- Top center: CloudForge shield icon + title
- 5 vertical columns below, each with colored border and header
- Framework icons: globe (GDPR), lock (PCI), heart (HIPAA), library (SOX), flag (FedRAMP)
- Items as rounded rect badges inside each column (white bold text on framework color)
- Hub → framework connector lines (slate, thin)

---

## CF.5 — Remediation Dispatcher Flow (NEW)

**Page ID:** 1:5, Frame ID: 74:6
**Source:** `docs/core/diagrams/remediation-dispatcher-flow.mmd` (45 lines)

### Content (from Mermaid)
- Flowchart: Finding → Triage → Route → Provider Dispatch → Track → Close
- Subgraphs: Triage Engine, Dispatcher, Ticket Providers (Asana/Jira/ADO)
- Decision nodes for severity routing, auto-remediation eligibility

### Build approach
- 1920x1000 dark bg frame
- Left-to-right or top-down flow depending on complexity
- Icons: shield-exclamation (finding), funnel (triage), arrow-path (route), ticket providers (Asana/Jira/ADO logos or generic clipboard)
- Color: blue=triage, purple=dispatch, green=resolve, amber=ticket creation
- Vertical flow preferred (litmus test: 900px canvas = 2x downscale)

---

## CF.6 — Global Deployment Architecture (NEW)

**Page ID:** 1:6, Frame ID: 61:2
**Source:** `docs/core/diagrams/global-deployment-architecture.mmd` (70 lines)

### Content (from Mermaid)
- Multi-region deployment: US-East (primary), US-West (DR), EU-West (GDPR)
- Components per region: K8s, DB, Redis, Object Storage
- Cross-region replication arrows
- DNS/CDN layer at top, monitoring at bottom

### Build approach
- 1920x1200 dark bg frame
- 3 region columns (US-East blue, US-West red/DR, EU-West green/GDPR)
- Each region: stacked component boxes with icons
- Cross-region dashed arrows for replication
- Top bar: DNS/CDN (globe icon), Bottom bar: Monitoring/Alerting
- Cloud provider badges (AWS/Azure/GCP) per region

---

## Recipes

Same as E1 handoff. Key points:
- `join_channel 72snjfrt` first
- Georgia font everywhere, dark bg #0f172a, text #e2e8f0
- Delete garbled content before building
- Max 5 icon searches, use memory for known icons
- Chrome litmus at 888px after export
- Export PNG @2x + SVG to `docs/core/diagrams/` and `docs-site/static/img/diagrams/`

## Key References
- Figma page registry: `~/.claude/projects/.../memory/reference_figma_file_registry.md`
- Design system colors: Core #1e40af, AWS #f59e0b, Azure #3b82f6, GCP #22c55e, Infra #8b5cf6, DR #ef4444, BG #0f172a, Stroke #334155, Text #e2e8f0
