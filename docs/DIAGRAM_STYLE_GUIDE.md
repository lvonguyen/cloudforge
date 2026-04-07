# Diagram Style Guide — ByteByteGo-Inspired

**Version:** 1.0
**Based on:** ByteByteGo system design visual language + CLAUDE.md palette
**Applies to:** All CloudForge architecture diagrams (Figma + Mermaid SVG)

---

## [+] Color Palette

### Layer Semantics

| Layer | Hex | RGB (0-1) | Use |
|-------|-----|-----------|-----|
| Portal / Frontend | `#3b82f6` | 0.231, 0.510, 0.965 | User-facing UI layers |
| API Gateway | `#1e40af` | 0.118, 0.251, 0.686 | Request routing, auth, rate limiting |
| Core Engines | `#7c3aed` | 0.486, 0.227, 0.929 | Business logic, scoring, dispatch |
| Risk / Security | `#dc2626` | 0.863, 0.149, 0.149 | Threat intel, vulnerability, breach |
| Policy / Governance | `#f59e0b` | 0.961, 0.620, 0.043 | OPA, guardrails, compliance |
| FinOps / Cost | `#22c55e` | 0.133, 0.773, 0.369 | Cost aggregation, budgets, alerts |
| Infrastructure | `#64748b` | 0.392, 0.455, 0.545 | Storage, compute, cloud APIs |

### Accent Colors

| Purpose | Hex | Use |
|---------|-----|-----|
| Async / Queues | `#ec4899` | Dashed arrows, event-driven paths |
| DR / Failover | `#ef4444` | Failover paths, disaster recovery |
| Success / Pass | `#22c55e` | Threshold pass, healthy state |
| Warning | `#f59e0b` | Threshold warn, degraded state |
| Labels / Metadata | `#6b7280` | Subtitle text, secondary info |
| Background (dark) | `#0f172a` | Main frame background |
| Card fill | `rgba(255,255,255,0.08)` | Node card background |

---

## [+] Typography

| Element | Font | Size | Weight | Color |
|---------|------|------|--------|-------|
| Diagram title | System (Inter) | 28px | 700 (Bold) | `#ffffff` |
| Layer title | System (Inter) | 16px | 700 (Bold) | Layer color |
| Layer subtitle | System (Inter) | 11px | 400 (Regular) | `#99a3b3` |
| Node label | System (Inter) | 13px | 500 (Medium) | `#ffffff` |
| Node metadata | System (Inter) | 9px | 400 (Regular) | `#8c94a5` |

---

## [!] Canvas Width Rule (README / DOCX Litmus Test)

**Design for the display context, not the authoring tool.**

GitHub README content column: **~888px**. DOCX body at 150 DPI: **~975px**.

| Canvas Width | Downscale at 888px | 14px text renders as | Verdict |
|-------------|-------------------|---------------------|---------|
| 3000px | 3.4x | 4.1px | Unreadable |
| 1920px | 2.2x | 6.4px | Marginal |
| 1200px | 1.4x | 10px | OK with bold |
| **900px** | **1.0x** | **14px** | **Crisp** |

**Rule:** All diagrams targeting README or DOCX embed must use a **900px canvas width** (or max 1200px with 20px+ font). This forces vertical stacking over wide side-by-side layouts — which is better for scrolling documents anyway.

For Figma presentation frames (portfolio, slides), use 1920x1080 with proportionally larger text (28px+).

---

## [+] Layout

### Composition Patterns

| Pattern | Use | Example |
|---------|-----|---------|
| **Horizontal tiers (LR)** | System overview, data flow | `architecture.mmd` |
| **Vertical tiers (TD)** | Deep dives, sequence flows | `failover-sequence.mmd` |
| **Hub-spoke** | Central engine with satellites | `risk-intelligence-pipeline.mmd` |

### Spacing

| Element | Value |
|---------|-------|
| Main frame padding | 40-140px |
| Layer frame width | 310px |
| Layer gap | 25px |
| Node card size | 260 x 50px |
| Node vertical spacing | 110-160px (varies by count) |
| Card internal padding | 15px left, 15px top |
| Metadata offset | y+18px below label |
| Snap grid | 20px |

### Corner Radius

| Element | Radius |
|---------|--------|
| Main frame | 16px |
| Layer subframe | 12px |
| Node card | 8px |
| Icon badge | 4px |

---

## [+] Icons

### Sourcing Priority

1. **Official CSP icons** (AWS/Azure/GCP) via `icon-library` MCP — 64px source, render at 32-36px
2. **Homelab icons** (Terraform, Redis, Prometheus) — `homelab-svg-assets/`
3. **Figma primitives** — diamond (queue), hexagon (cache), circle (endpoint)

### Placement

| Position | Size | Use |
|----------|------|-----|
| Layer header (top-right) | 36x36px | One icon per layer representing its domain |
| Inside node card (left) | 24x24px | Per-component icon (ByteByteGo standard) |
| Standalone (diagram) | 48x48px | Hero/focal point icons |

### Icon Mapping (CloudForge)

| Component | Icon | Provider |
|-----------|------|----------|
| API Gateway | Arch_Amazon-API-Gateway_64 | AWS |
| Auth / Shield | Arch_AWS-Shield_64 | AWS |
| Vulnerability | Arch_Amazon-Inspector_64 | AWS |
| Cost/FinOps | Arch_AWS-Cost-Explorer_64 | AWS |
| Terraform | terraform.svg | Homelab |
| PostgreSQL | Azure-Database-PostgreSQL-Server_64 | Azure |
| Redis | Cache-Redis_64 | Azure |
| Workflows | Arch_AWS-Express-Workflows_64 | AWS |

---

## [+] Connectors / Arrows

### Line Styles

| Style | Stroke | Pattern | Use |
|-------|--------|---------|-----|
| **Sync API** | 2px `#94a3b8` | Solid | REST calls, direct invocations |
| **Async event** | 2px `#ec4899` | Dashed (5px/3px) | Webhooks, queues, CDC |
| **Optional path** | 1.5px `#6b7280` | Dotted (2px/4px) | Fallback, optional enrichment |
| **Failover** | 2.5px `#ef4444` | Dashed (8px/4px) | DR paths, circuit breaker |

### Arrowheads

- **Standard:** Filled triangle, 10px, same color as stroke
- **Bidirectional:** Double arrowhead for two-way sync
- **No head:** Plain line for association/grouping

### Labels on Arrows

- Font: 10px, centered above line, 6-8px offset
- Color: `#94a3b8` (same as line, or slightly lighter)
- Content: Protocol or action (e.g., "REST", "gRPC", "webhook", "CDC")

---

## [+] Node Card Anatomy

```
+------------------------------------------+
|  [Icon 24x24]  Service Name              |  <- 13px white, medium
|                 (implementation detail)   |  <- 9px #8c94a5, regular
+------------------------------------------+
   8px corner radius
   rgba(255,255,255,0.08) fill
   260 x 50px
```

### Two-Line Label Format

```
Primary Label           <- Title case, 13px
tech-stack, key-detail  <- lowercase, 9px, gray
```

---

## [+] Dark Theme vs Light Theme

| Property | Dark (default) | Light (BBG classic) |
|----------|---------------|---------------------|
| Background | `#0f172a` | `#ffffff` |
| Card fill | `rgba(255,255,255,0.08)` | `#f5f5f5` |
| Text primary | `#ffffff` | `#1f2937` |
| Text secondary | `#8c94a5` | `#6b7280` |
| Layer stroke | Layer color @ 50% alpha | Layer color @ 30% alpha |
| Arrow color | `#94a3b8` | `#9ca3af` |

**Default:** Dark theme for portfolio, presentations, Figma.
**Use light theme for:** README embeds, printed docs, high-contrast accessibility.

---

## [+] Figma Workflow

### Creating a New Diagram

1. **Create main frame** — 2600x900 (LR) or 1200x1600 (TD), dark bg `#0f172a`, radius 16px
2. **Add title** — 28px bold white, top-left with 40px margin
3. **Create layer subframes** — 310px wide, layer color fill @ 15% alpha, stroke @ 50%, radius 12px
4. **Add layer titles** — 16px bold in layer color, subtitle 11px gray
5. **Create node cards** — 260x50, `rgba(255,255,255,0.08)`, radius 8px
6. **Add labels** — 13px white label + 9px gray metadata inside each card
7. **Place icons** — Layer headers (36px) + node cards (24px) via `icon-library` MCP
8. **Draw arrows** — SVG connectors between layers, varied styles per type
9. **Export** — PNG @2x for Figma, SVG for README embedding

### MCP Tool Sequence

```
icon-library:search_icons → icon-library:get_icon_svg → figma:create_from_svg
figma:create_frame (main) → create_frame (layers) → create_frame (cards)
figma:create_text (labels) → set_corner_radius → export_node_as_image
```

---

## [!] Draw.io Icon Embedding

### The Semicolon Trap

Draw.io XML uses CSS-like style attributes: `style="key=value;key=value"` where `;` is the property delimiter. Data URIs contain a literal `;` in the MIME type (`data:image/png;base64,...`) which the style parser splits on **before** the image decoder sees it — silently breaking the icon.

**Symptom:** Icons render in Draw.io desktop but disappear in CLI export (`--export --format png`).

### Fix: URL-Encode the Semicolon

Replace `;` with `%3B` in the data URI MIME separator:

```
WRONG:  image=data:image/png;base64,iVBOR...
RIGHT:  image=data:image/png%3Bbase64,iVBOR...

WRONG:  image=data:image/svg+xml;base64,PHN2...
RIGHT:  image=data:image/svg+xml%3Bbase64,PHN2...
```

This works for **all** MIME types. Draw.io's image renderer URL-decodes `%3B` back to `;` after style parsing completes.

### Icon Embedding Workflow

```bash
# 1. Get icon SVG from icon-library MCP or local filesystem
#    search_icons("shield", provider="aws") → get_icon_base64(path)

# 2. For PNG embedding (heroicons, rasterized icons):
rsvg-convert -w 128 -h 128 icon.svg -o icon.png
BASE64=$(base64 -i icon.png | tr -d '\n')

# 3. For SVG embedding (CSP icons, vector):
BASE64=$(base64 -i icon.svg | tr -d '\n')

# 4. In Draw.io XML style attribute — NOTE THE %3B:
# PNG:  style="shape=image;image=data:image/png%3Bbase64,${BASE64};..."
# SVG:  style="shape=image;image=data:image/svg+xml%3Bbase64,${BASE64};..."
```

### Icon Sizing in Draw.io

| Context | Width/Height | Notes |
|---------|-------------|-------|
| Standalone hero | 64x64 | Primary diagram icons |
| Node card inline | 48x48 | Inside labeled containers |
| Layer header badge | 36x36 | Top-right of tier frames |
| Dense layouts (>15 icons) | 32x32 | Minimum readable size |

### Battle-Tested: 2026-04-04

Confirmed working with 12 heroicons (cloud, check-circle, cpu-chip, bolt, shield-check, server, etc.) across `dual-opa-architecture.drawio`. Both PNG and SVG URIs survive CLI export with `%3B` encoding.

---

## [!] Visual Polish Guardrails (Enforced)

These rules are **mandatory** for all diagram outputs. Sessions that violate them must self-correct before marking a diagram complete.

### G1: Icon Placement — Inline Left, Not Clustered Right

Icons MUST be positioned **inside** their parent node card or tier, **left-aligned** with the component label text. The ByteByteGo pattern is: `[Icon 24px] [8px gap] [Label text]`.

- **WRONG:** Icons clustered in a column on the right edge of the tier frame
- **RIGHT:** Each icon sits left of its corresponding component name inside the node card
- Layer-level header icons (36px, top-right of tier frame) are the only exception

### G2: Tier Icon Completeness

Every tier frame MUST contain at least one representative icon. If no specific service icon exists, use a generic shape (hexagon for cache, diamond for queue, circle for endpoint) or a colored rectangle placeholder — but **never leave a tier icon-less**.

### G3: Split-Tier Dividers

When two logical sections share a horizontal row (e.g., "Threat Intelligence" + "Policy Engine" side-by-side), they MUST have:

- A **visible vertical divider** (1px `#334155` or tier stroke color at 50% alpha)
- OR a **16px minimum gap** with distinct background fills
- The divider must be visually distinct — not just a color shift

### G4: Component Text Spacing

All component names within a tier must use **consistent spacing**:

- Minimum **24px horizontal gap** between adjacent component names
- Text nodes must be baseline-aligned within their tier row
- If components wrap to a second row, maintain the same left margin and gap

### G5: No Dead Space

Tier frames must **fill the parent frame** with consistent padding:

- Bottom margin below the last tier: **same as top margin** (frame padding value, typically 40-64px)
- No tier should have >20% internal empty space (resize the tier frame to fit content)
- If the frame has >100px of unused space at the bottom, shrink the frame height to match

### G6: Vertical-First Layout

Diagrams MUST default to **vertical (top-down) flow** unless the user explicitly requests horizontal:

- **Tier stacking:** Tiers stack vertically (Portal at top → Cloud Providers at bottom)
- **Component detail:** When a tier has >4 components, stack them in rows within the tier rather than stretching horizontally
- **Split sections:** Side-by-side sections within a tier are acceptable (e.g., Threat Intel + Policy Engine), but the tiers themselves flow top-to-bottom
- **Why:** Vertical layouts survive downscaling for README/DOCX (scrolling context). Horizontal layouts require side-scrolling or extreme shrinkage.

This applies to BOTH presentation frames (1920px) and README frames (900px). Horizontal tier-to-tier flow requires explicit opt-in.

### G7: Connector Label Legibility

Arrow labels must be:

- **10px minimum** font size (never smaller)
- Positioned **above** the line with 6-8px offset (never overlapping the stroke)
- Contrast ratio: label text must be readable against the background (use `#94a3b8` on dark, `#6b7280` on light)

### G8: README Zoom Verification (MANDATORY)

After **any** visual edit to a Figma diagram frame (`set_svg`, `set_effects`, `set_fill_color`, `move_node`, `resize_node`, `set_image_fill`, `delete_node` followed by re-import), you MUST verify readability at the rendered scale before proceeding.

**Step 1 — Read the frame width dynamically:**

```
frame_info = get_node_info(nodeId=<frame>)
frame_width = frame_info.absoluteBoundingBox.width
```

**Step 2 — Validate frame is within acceptable embed range:**

| Condition | Action |
|-----------|--------|
| `frame_width < 888` | No downscaling needed. Verify at `scale=1.0`. |
| `888 <= frame_width <= 2400` | Normal range. Compute scale and verify. |
| `frame_width > 2400` | **WARN:** Heavy downscaling will degrade readability. Consider reducing frame width or increasing font sizes proportionally. |

**Step 3 — Compute scale and export:**

```
README_COLUMN = 888   # GitHub README content width in px
scale = README_COLUMN / frame_width
export_node_as_image(nodeId=<frame>, format="PNG", scale=scale)
```

**Step 4 — Derive minimum source sizes from scale:**

```
min_source_font = ceil(10 / scale)    # 10px rendered = readable threshold
min_source_icon = ceil(24 / scale)    # 24px rendered = recognizable threshold
```

**Reference table (derived from formula, not hardcoded):**

| Frame Width | Scale | Min Font | Min Icon |
|-------------|-------|----------|----------|
| 1920px | 0.46 | 22px | 53px |
| 1440px | 0.62 | 17px | 39px |
| 1200px | 0.74 | 14px | 33px |
| 900px | 0.99 | 11px | 25px |

**Step 5 — Verification checklist (must ALL pass at scaled export):**

1. All tier labels readable (not blurred/aliased)
2. All component text legible (individual words distinguishable)
3. All icons recognizable (shape identifiable, not amorphous blobs)
4. All arrows visible (direction clear, effects not washed out)
5. Badge/watermark text at least partially readable

**Enforcement:** This step is NOT optional. A diagram edit is not complete until the scaled verification export confirms readability. If any item fails, fix the source and re-verify before moving to the next edit.

### G9: Icon Style Consistency

All icons within a diagram frame MUST come from the same visual family:

| Background | Icon Source | Fill Color | Example |
|------------|-----------|------------|---------|
| Dark (`#0f172a`) | `Res_48_Dark` | `#FFFFFF` (white monochrome) | Console, Shield, Metrics, Database |
| Light (`#ffffff`) | `Res_48_Light` | `#232F3D` (charcoal monochrome) | Same glyphs, dark fill |

**Rules:**

- **NEVER** use `Arch_*` icons in tier frames — they have opaque colored square backgrounds that clash with card fills
- **NEVER** mix colored service icons (pink CloudWatch, purple Aurora) with monochrome general icons
- All 4 tier icons in CF.1 use the `Res_General-Icons` family: Console (T1), Shield (T6), Metrics (T8), Database (T10)
- Light variants use identical glyph paths with `#232F3D` fill instead of `#FFFFFF`
- Max **5 `icon-library` searches** per session — use the Res_48_Dark/Light inventory instead of ad-hoc searching

### G10: Export Artifact Cleanup

Verification exports from `export_node_as_image` are **ephemeral** — they exist only to confirm readability during the edit session.

**Rules:**

- One-time verification PNGs MUST NOT be committed to git
- If `export_node_as_image` writes to disk (e.g., via save parameter), delete the file immediately after visual confirmation
- Only **final production exports** (File > Export > PNG 2x from Figma desktop) belong in `docs/core/diagrams/`
- The `export_node_as_image` tool returns inline image data by default — prefer this over disk writes for verification
- If a verification PNG is found in the working tree during `git status`, remove it before committing

---

## [+] Mermaid Alignment

When generating `.mmd` source files, use these theme variables to approximate the dark theme:

```
%%{init: {'theme': 'base', 'themeVariables': {
  'fontFamily': 'Inter, system-ui, sans-serif',
  'fontSize': '14px',
  'primaryColor': '#3b82f6',
  'primaryTextColor': '#fff',
  'primaryBorderColor': '#1e3a8a',
  'lineColor': '#64748b',
  'secondaryColor': '#f59e0b',
  'tertiaryColor': '#22c55e'
}}}%%
```

The Mermaid SVGs support CSS edge animation (`stroke-dasharray` + `@keyframes dash`) — these animate when viewed in browsers but not in GitHub `<img>` tags.

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-03-24 | Initial release — BBG style research + CloudForge implementation |
| 1.1 | 2026-04-04 | Added Draw.io icon embedding section — semicolon trap + `%3B` fix, icon sizing table, battle-tested workflow |
| 1.2 | 2026-04-04 | Added [!] Visual Polish Guardrails (G1-G7) — icon placement, tier completeness, split-tier dividers, spacing, dead space, vertical-first layout, connector labels |
| 1.3 | 2026-04-06 | Added G8 (README zoom verification — mandatory), G9 (icon style consistency — Res_48_Dark/Light only), G10 (export artifact cleanup) |
