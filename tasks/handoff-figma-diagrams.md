# Figma Diagram Build — Handoff for 3 Sessions

**Generated:** 2026-04-04
**Repo:** cloudforge (main branch)
**Figma file key:** `2l5XrS7QRy5MYFI9PwcPmK`
**figma-create channel:** `72snjfrt`

---

## Status

| Page | Name | Status | Notes |
|------|------|--------|-------|
| CF.1 | CloudForge Architecture | DONE | Built natively via figma-create MCP. 6 tiers, 8 icons, drop shadows, flow arrows. |
| CF.2 | IaC Deploy Pipeline | TODO | Horizontal flow: init → plan → OPA gate → apply |
| CF.3 | Failover Sequence | TODO | Vertical sequence: 7 participants, 13 steps |
| CF.4 | Compliance Deployment Models | TODO | |
| CF.5 | Remediation Dispatcher Flow | TODO | |
| CF.6 | Global Deployment Architecture | TODO | |
| CF.7 | Dual OPA Architecture | TODO | |
| CF.8 | Risk Intelligence Pipeline | TODO | |
| CF.9 | IaC Deploy Pipeline (Light) | TODO | Same content as CF.2 but light theme |

## Session Plan

| Session | Pages | Startup Command |
|---------|-------|----------------|
| S1 | CF.2 + CF.3 | `read tasks/handoff-figma-diagrams.md, build CF.2 and CF.3 natively in Figma` |
| S2 | CF.4 + CF.5 + CF.6 | `read tasks/handoff-figma-diagrams.md, build CF.4, CF.5, CF.6 natively in Figma` |
| S3 | CF.7 + CF.8 + CF.9 | `read tasks/handoff-figma-diagrams.md, build CF.7, CF.8, CF.9 natively in Figma` |

After all sessions complete, one final session to export all 9 pages as PNG/SVG and commit to repo + portfolio.

---

## [!] Proven Approach — Native Figma Build

**Do NOT use Draw.io export or Mermaid mmdc.** The only approach that works is building directly in Figma using `figma-create` MCP primitives:

```
mcp__figma-create__join_channel → channel: 72snjfrt
mcp__figma-create__set_current_page → pageId from table below
mcp__figma-create__set_fill_color → dark bg on frame
mcp__figma-create__create_frame → tier/section containers
mcp__figma-create__create_text → labels + components
mcp__figma-create__set_svg → icon imports from icon-library MCP
mcp__figma-create__set_font_name → Georgia on all text
mcp__figma-create__set_effects → drop shadows
mcp__figma-create__export_node_as_image → validation screenshot
```

### Anti-Patterns (proven failures from D1-D3 sessions)
- `set_image` via figma-create → BROKEN (aspect ratio distortion, all diagrams garbled)
- Draw.io CLI SVG export → strips SVG data URIs (Electron security + semicolon collision)
- Mermaid mmdc PNG → extreme aspect ratios (8:1 to 27:1), garbled when scaled to 1920x1080
- Figma Plugin API code (`use_figma`) → 50K code limit, no atob(), limited to ~5KB JPEG per call
- `set_image_fill` URL import → blocked by domain allowlist

---

## Design System

### Readability Litmus Test

**Every element must be readable in a Chrome viewport inside a GitHub README or DOCX.**

At GitHub README display (~880px from 1920px source = 0.46x scale):
- Title: 48px source → 22px displayed ✓
- Tier labels: 28px bold source → 13px displayed ✓
- Component text: 22px source → 10px displayed ✓ (minimum)
- Icons: 56-64px source → 26-30px displayed ✓

**Absolute minimum source font size: 20px.** Anything below is invisible at README scale.

### Colors

| Token | Hex | RGB (0-1) | Use |
|-------|-----|-----------|-----|
| Background | `#0f172a` | 0.059, 0.09, 0.165 | Frame background |
| Tile Fill | `#1e293b` | 0.118, 0.161, 0.231 | Section/tier fill |
| Text Primary | `#e2e8f0` | 0.886, 0.91, 0.941 | Body text |
| Text Secondary | `#94a3b8` | 0.58, 0.639, 0.722 | Subtitles, captions |
| Stroke | `#334155` | 0.2, 0.255, 0.333 | Borders |
| AWS | `#f59e0b` | 0.961, 0.62, 0.043 | AWS elements |
| Azure | `#3b82f6` | 0.231, 0.51, 0.965 | Azure elements |
| GCP | `#22c55e` | 0.133, 0.773, 0.369 | GCP elements |
| Core | `#1e40af` | 0.118, 0.251, 0.686 | Primary nodes |
| Security | `#ef4444` | 0.937, 0.267, 0.267 | Security/alerts |
| Purple | `#7c3aed` | 0.486, 0.227, 0.929 | Engines/processing |
| Allow/Pass | `#22c55e` | 0.133, 0.773, 0.369 | Success states |
| Block/Fail | `#ef4444` | 0.937, 0.267, 0.267 | Failure states |
| Warn | `#f59e0b` | 0.961, 0.62, 0.043 | Warning states |

### Accent Colors (for labels on dark tiles)

| Base | Light Accent | RGB (0-1) |
|------|-------------|-----------|
| Blue | `#60a5fa` | 0.376, 0.647, 0.98 |
| Indigo | `#6366f1` | 0.388, 0.4, 0.945 |
| Purple | `#a78bfa` | 0.655, 0.545, 0.98 |
| Red | `#f87171` | 0.973, 0.443, 0.443 |
| Amber | `#fbbf24` | 0.984, 0.749, 0.141 |

### Typography
- **Font:** Georgia everywhere (set via `set_font_name`)
- **Title:** 48px bold
- **Section labels:** 28px bold (in accent color)
- **Body/components:** 22-24px regular
- **Captions:** 20px regular (secondary color)
- **Watermark:** 14px (bottom-right, dark subtle)

### Frame Specs
- **Canvas:** 1920 wide, height varies (1200-1600 depending on content)
- **Padding:** 40px sides, 30px top
- **Section frames:** 12px corner radius, 2px stroke in accent color
- **Effects:** `DROP_SHADOW` — `{color: rgba(0,0,0,0.4), offset: {x:0, y:4}, radius: 12}`
- **Flow arrows:** 3-sided polygon (triangle), 20x12px, rotated 180° (points down), fill `#64748b` at 0.6 opacity

---

## Page IDs and Frame IDs

| Page | Page ID | Frame ID | Frame Size |
|------|---------|----------|------------|
| CF.1 | 0:1 | 74:2 | 1920x1400 DONE |
| CF.2 | 1:2 | 74:3 | Currently 1440x300 (garbled IMAGE fill, needs reset) |
| CF.3 | 1:3 | 74:4 | 1920x1080 (empty frame) |
| CF.4 | 1:4 | 74:5 | (garbled IMAGE fill, needs reset) |
| CF.5 | 1:5 | 74:6 | 1920x1080 (empty frame) |
| CF.6 | 1:6 | 61:2 | Pre-existing frame |
| CF.7 | 1:7 | 74:7 | May have SVG import from B2 |
| CF.8 | 1:8 | 74:8 | 1920x1080 (empty frame) |
| CF.9 | 1:9 | 74:9 | 1920x1080 (empty frame) |

For each page: `set_current_page(pageId)` → `set_fill_color(frameId, bg)` → `resize_node(frameId, w, h)` → build children.

---

## Mermaid Source Files (content reference)

All at `docs/core/diagrams/`:

| Page | Source File | Diagram Type | Key Elements |
|------|-----------|-------------|--------------|
| CF.2 | iac-deploy-pipeline.mmd | flowchart LR | 5 TF steps, OPA gate (allow/warn/block), 8 rego policies, fix loop |
| CF.3 | failover-sequence.mmd | sequenceDiagram | 7 participants (HC, PD, OnCall, DNS, DR, DB, Smoke), 13 numbered steps, 23-53min RTO |
| CF.4 | compliance-deployment-models.mmd | (read file) | Compliance deployment topology |
| CF.5 | remediation-dispatcher-flow.mmd | (read file) | Remediation workflow |
| CF.6 | global-deployment-architecture.mmd | (read file) | Multi-region deployment |
| CF.7 | dual-opa-architecture.mmd | (read file) | Dual OPA (admission + IaC) |
| CF.8 | risk-intelligence-pipeline.mmd | (read file) | EPSS/GreyNoise/OTX pipeline |
| CF.9 | iac-deploy-pipeline.mmd | Same as CF.2 | Light theme variant |

### CF.2 Build Spec (IaC Deploy Pipeline)
**Layout:** Horizontal flow, 1920x1200
- Left column: Entry → Step 1 (init) → Step 2 (plan) → Step 3 (show)
- Center: OPA POLICY GATE (highlighted frame, Core blue border)
  - conftest test → Exit Code decision
  - 3 outcomes: Allow (green), Warn (amber), Block (red)
- Right: Step 5 (apply) → Deploy Complete
- Bottom panel: 8 Rego policies (SECURITY-001 through SECURITY-008)
- Fix loop arrow: Block → back to Step 2

**Key colors:** Core blue for gate, green for allow, red for block, amber for warn.

### CF.3 Build Spec (Failover Sequence)
**Layout:** Vertical timeline, 1920x1600
- 7 participant columns across top (each a colored header box)
- Numbered steps (1-13) flowing downward
- Horizontal arrows between participant columns for each step
- Note boxes (amber bg) for commands (kubectl, aws rds, etc.)
- Bottom summary: "Total switchover: 23-53 min (within 2h RTO)"

**Key colors:** Red for alerts, amber for notes, green for completion.

---

## Icon Library (icon-library MCP)

Search: `search_icons(query, provider, limit)`
Fetch SVG: `get_icon_svg(path)` → returns raw SVG string
Import: `set_svg(svgString, parentId, x, y, name)` → places in Figma

### Icons Used in CF.1 (reusable)

| Icon | Provider | Path |
|------|----------|------|
| AWS Cloud | aws | `icons/_sources/.../AWS-Cloud_32.svg` |
| AWS Shield | aws | `icons/icons-cloudaegis/aws/Security-Identity/Arch_AWS-Shield_64.svg` |
| Azure Security | azure | `icons/icons-cloudaegis/azure/identity/00321-icon-service-Security_64.svg` |
| GCP SCC | gcp | `icons/gcp-icons/docs/images/security_command_center.svg` |
| API Gateway | aws | `icons/icons-cloudaegis/aws/Networking-Content-Delivery/Arch_Amazon-API-Gateway_64.svg` |
| PostgreSQL | azure | `icons/icons-cloudaegis/azure/databases/10131-icon-service-Azure-Database-PostgreSQL-Server_64.svg` |
| Redis | azure | `icons/icons-cloudaegis/azure/databases/10137-icon-service-Cache-Redis_64.svg` |
| Terraform | homelab | `icons/homelab-svg-assets/assets/terraform.svg` |
| Workflow | azure | `icons/icons-cloudaegis/azure/general/10852-icon-service-Workflow_64.svg` |

All paths relative to `/Users/lvonguyen/repos/gh/lvn-library/`

### Additional Icons to Search For

- CF.2: Terraform (have it), OPA/Conftest (search "policy"), Lock/Shield (search "lock")
- CF.3: Heart/Health (search "health"), Bell/Alert (search "alert"), Globe/DNS (search "globe"), Server (search "server"), Database (have it)
- CF.4-9: Search as needed per diagram content

---

## CF.1 Element Reference (for style consistency)

Node tree of completed CF.1 (frame 74:2, 1920x1400):

```
74:2  CF.1 — CloudForge Architecture (FRAME, #0f172a, 1920x1400)
├── 76:78  Title (TEXT, Georgia Bold 48px, #e2e8f0)
├── 76:79  Subtitle (TEXT, Georgia 22px, #94a3b8)
├── 76:81  T1 — Portal (FRAME, #1e293b, stroke #3b82f6, r12, shadow)
│   ├── 76:87  T1 Label (TEXT, Georgia Bold 28px, #60a5fa)
│   └── 76:89  T1 Components (TEXT, Georgia 22px, #e2e8f0)
├── 76:82  T2 — API Gateway (FRAME, stroke #1e40af, shadow)
│   ├── 76:90  Label (Bold 28px, #6366f1)
│   ├── 76:92  Components (22px, #e2e8f0)
│   └── 76:106 Icon — API Gateway (SVG 64x64)
├── 76:83  T3 — Core Engines (FRAME, stroke #7c3aed, shadow)
│   ├── 76:93  Label (Bold 28px, #a78bfa)
│   ├── 76:94  Row1 (22px) — CSPM, Remediation, Attack Path, AI Gov
│   ├── 76:95  Row2 (22px) — SecGraph, ASM, NLQ, Compliance
│   └── 76:109 Icon — AWS Shield (SVG 64x64)
├── 76:84  T4 — Intelligence + Policy (FRAME, stroke #ef4444, shadow)
│   ├── 76:96  Label Left "THREAT INTELLIGENCE" (Bold 24px, #f87171)
│   ├── 76:97  Label Right "POLICY ENGINE" (Bold 24px, #fbbf24)
│   ├── 76:98  Intel Components (22px)
│   ├── 76:99  Policy Components (22px)
│   └── 76:105 T4 Divider (RECT 2x140, #64748b @ 0.4)
├── 76:85  T5 — Data + Infra (FRAME, stroke #64748b, shadow)
│   ├── 76:100 Label (Bold 28px, #94a3b8)
│   ├── 76:101 Components (22px)
│   ├── 76:112 Icon — PostgreSQL (SVG 56x56)
│   ├── 76:116 Icon — Redis (SVG 56x56)
│   └── 76:123 Icon — Terraform (SVG 56x56)
├── 76:86  T6 — Cloud Providers (FRAME, stroke #f59e0b, shadow)
│   ├── 76:102 Label (Bold 28px, #fbbf24)
│   ├── 76:103 Providers (24px)
│   ├── 76:104 Integrations (20px, #94a3b8)
│   ├── 76:137 Icon — AWS Cloud (SVG 64x64)
│   ├── 76:135 Icon — Azure Security (SVG 64x64)
│   └── 76:129 Icon — GCP SCC (SVG 64x64)
├── 76:140-144 Flow arrows (POLYGON 3-sided, rotated 180°, #64748b @ 0.6)
└── 76:145 Watermark (TEXT, Georgia 14px, #4b5563)
```

---

## Export (after all sessions complete)

```bash
# From Figma desktop: File → Export → PNG 2x for each page
# Save to:
docs/core/diagrams/architecture-figma.png       # CF.1
docs/core/diagrams/iac-deploy-pipeline-figma.png # CF.2
docs/core/diagrams/failover-sequence-figma.png   # CF.3
# ... etc for CF.4-CF.9

# Copy to portfolio
cp docs/core/diagrams/architecture-figma.svg /Users/lvonguyen/repos/gh/portfolio-site/public/cloudforge-architecture.svg

# Or use figma-create export:
# export_node_as_image(nodeId=frameId, format="PNG", scale=2)
```
