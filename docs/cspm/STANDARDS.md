# Documentation Standards

**Version:** 2.0
**Last Updated:** February 2026

---

## Table of Contents

| Section | Description |
|---------|-------------|
| [Overview](#overview) | Purpose and scope |
| [Required Documents](#required-documents) | HLD, DDD, DR/BC hierarchy |
| [Symbol Standards](#symbol-standards-no-emoji) | ASCII-only conventions |
| [Typography Standards](#typography-standards) | Georgia font, heading styles |
| [Diagram Specifications](#diagram-specifications) | Color palette, icons, layouts |
| [Diagram Creation Process](#diagram-creation-process) | Step-by-step methodology |
| [Export Requirements](#export-requirements) | SVG, PNG, DOCX formats |
| [HLD Document Structure](#hld-document-structure) | High-Level Design template |
| [DDD Document Structure](#ddd-document-structure) | Detailed Design template |
| [DR/BC Documentation](#drbc-documentation-standard) | Disaster Recovery template |
| [Appendix A: Technology References](#appendix-a-technology-references) | Icon sources, tools |

---

## Overview

This document provides standardized specifications for documentation, diagrams, pitch decks, and architecture documents across all portfolio projects. All documentation must follow these standards to ensure consistency, professionalism, and maintainability.

---

## Required Documents

### Document Hierarchy

Each project requires the following documentation artifacts:

| Document | Type | Purpose | Dependencies |
|----------|------|---------|--------------|
| **HLD** | Primary | High-level architecture, executive summary | None |
| **DDD** | Supporting | Detailed design, ADRs, API specs, data models | HLD |
| **DR/BC** | Supporting | Disaster recovery, business continuity | HLD |

### Relationship Model

```text
HLD (High-Level Design)
├── DDD (Detailed Design Document)
│   ├── Architecture Decision Records
│   ├── API Specifications
│   └── Data Models
└── DR/BC (Disaster Recovery / Business Continuity)
    ├── Recovery Objectives
    ├── Failover Procedures
    └── Testing Protocols
```

### Cross-References

- HLD documents must reference supporting DDD and DR/BC artifacts
- DDD must reference parent HLD and related ADRs
- DR/BC must align with architecture defined in HLD

---

## Symbol Standards (No Emoji)

For professional documentation, use ASCII symbols only:

| Instead of | Use |
|------------|-----|
| Emoji checkmarks | `[x]` or `(done)` |
| Emoji warnings | `[!]` or `(warning)` |
| Emoji X marks | `[ ]` or `(no)` |
| Colored bullets | `-` or `*` |
| Arrows | `->`, `<-`, `>>` |

### Section Header Symbols

Use consistent ASCII prefixes for section headers in Markdown:

| Symbol | Usage | Example |
|--------|-------|---------|
| `[*]` | Important notes or key points | `## [*] Agent Guidelines` |
| `[+]` | Additions, features, standards | `## [+] Coding Standards` |
| `[-]` | Removals, deprecations | `## [-] Deprecated APIs` |
| `[!]` | Warnings, critical rules | `## [!] Security Rules` |
| `[>]` | Processes, workflows, navigation | `## [>] Documentation Flow` |
| `[/]` | Structure, organization | `## [/] Repository Layout` |

### Status Indicators

| Indicator | Meaning |
|-----------|---------|
| `(WIP)` | Work in progress |
| `(DRAFT)` | Draft, not finalized |
| `(REVIEW)` | Pending review |
| `(APPROVED)` | Approved for use |
| `(DEPRECATED)` | Scheduled for removal |

---

## Typography Standards

### Font Family

**Primary Font:** Georgia (serif)

Georgia is required for all documentation text, diagrams, and exported materials. This font provides:

- Professional, readable appearance
- Cross-platform availability
- Print and screen optimization

### Heading Styles

| Level | Style | Usage |
|-------|-------|-------|
| H1 | Georgia 24pt Bold | Document title |
| H2 | Georgia 18pt Bold | Major sections |
| H3 | Georgia 14pt Bold | Subsections |
| H4 | Georgia 12pt Bold | Sub-subsections |

### Body Text

| Element | Style |
|---------|-------|
| Body text | Georgia 11pt Regular |
| Code blocks | Monospace 10pt |
| Table headers | Georgia 11pt Bold |
| Captions | Georgia 10pt Italic |

### Collapsible Headers (Markdown)

Use HTML `<details>` tags with bolded summaries:

```markdown
<details>
<summary><strong>Section Title</strong></summary>

Content here...

</details>
```

---

## Diagram Specifications

### Color Palette

| Provider/Function | Primary | Background | Border |
|-------------------|---------|------------|--------|
| **AWS** | `#f59e0b` | `#fef3c7` | `#f59e0b` |
| **Azure** | `#3b82f6` | `#eff6ff` | `#3b82f6` |
| **GCP** | `#22c55e` | `#ecfdf5` | `#22c55e` |
| **Core/Orchestration** | `#1e40af` | `#eef2ff` | `#1e40af` |
| **AI/ML** | `#8b5cf6` | `#faf5ff` | `#8b5cf6` |
| **DR/Failover** | `#ef4444` | `#fef2f2` | `#ef4444` |
| **Storage** | `#f59e0b` | `#fef3c7` | `#f59e0b` |
| **Output/Export** | `#ef4444` | `#fef2f2` | `#ef4444` |

### Background Gradient

```xml
<linearGradient id="bg-gradient" x1="0%" y1="0%" x2="100%" y2="100%">
  <stop offset="0%" style="stop-color:#fafbfc"/>
  <stop offset="100%" style="stop-color:#f1f5f9"/>
</linearGradient>
```

### Arrow Styles

| Type | Color | Pattern | Usage |
|------|-------|---------|-------|
| Control flow | `#94a3b8` | Solid | Process steps |
| Data flow | `#3b82f6` | Dashed (`5,3`) | Data movement |
| Error/Failover | `#ef4444` | Solid | Error paths |

### Typography in Diagrams

| Element | Font | Size | Weight | Color |
|---------|------|------|--------|-------|
| Title | Georgia | 18px | Bold (700) | `#1a1a1a` |
| Section title | Georgia | 12px | Semibold (600) | `#64748b` |
| Component title | Georgia | 11px | Semibold (600) | `#1e293b` |
| Tech label | Georgia | 9px | Regular (400) | `#94a3b8` |
| Stage number | Georgia | 10px | Semibold (600) | `#ffffff` |

### SVG Style Block Template

```xml
<style>
  text { font-family: Georgia, 'Times New Roman', serif; font-size: 11px; fill: #333; }
  .title { font-size: 18px; font-weight: 700; fill: #1a1a1a; }
  .section-title { font-size: 12px; font-weight: 600; fill: #64748b; text-transform: uppercase; letter-spacing: 0.5px; }
  .box { fill: #fff; stroke: #e2e8f0; stroke-width: 1.5; }
  .cloud-aws { fill: #fef3c7; stroke: #f59e0b; stroke-width: 2; }
  .cloud-azure { fill: #eff6ff; stroke: #3b82f6; stroke-width: 2; }
  .cloud-gcp { fill: #ecfdf5; stroke: #22c55e; stroke-width: 2; }
  .process { fill: #eef2ff; stroke: #1e40af; stroke-width: 2; }
  .ai { fill: #faf5ff; stroke: #8b5cf6; stroke-width: 2; }
  .storage { fill: #fef3c7; stroke: #f59e0b; stroke-width: 2; }
  .output { fill: #fef2f2; stroke: #ef4444; stroke-width: 2; }
  .arrow { stroke: #94a3b8; stroke-width: 2; fill: none; marker-end: url(#arrow); }
  .arrow-data { stroke: #3b82f6; stroke-width: 2; stroke-dasharray: 5,3; fill: none; marker-end: url(#arrow-blue); }
  .label { font-size: 9px; fill: #64748b; font-weight: 500; }
  .component-title { font-size: 11px; font-weight: 600; fill: #1e293b; }
  .tech-label { font-size: 9px; fill: #94a3b8; }
</style>
```

### Branding Badge

Each diagram must include a branding badge in the bottom-left corner:

```xml
<!-- Version & Branding -->
<text x="1170" y="505" text-anchor="end" class="tech-label">v1.0 - 2026-01-08</text>
<rect x="30" y="490" width="140" height="18" rx="4" style="fill:#e2e8f0"/>
<text x="100" y="502" text-anchor="middle" fill="#475569" font-size="10" font-weight="600">Project Name</text>
```

---

## Diagram Creation Process

### Step 1: Plan Layout

1. Identify major components and data flows
2. Sketch logical groupings (cloud providers, processing stages, outputs)
3. Determine diagram dimensions based on complexity:
   - Simple: `viewBox="0 0 1000 400"`
   - Medium: `viewBox="0 0 1200 520"`
   - Complex: `viewBox="0 0 1400 700"`

### Step 2: Create SVG Structure

```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"
     viewBox="0 0 1200 520" width="1200" height="520">

  <!-- 1. Style definitions -->
  <style>...</style>

  <!-- 2. Defs (markers, gradients, symbols) -->
  <defs>
    <!-- Arrow markers -->
    <marker id="arrow" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
      <polygon points="0 0, 8 3, 0 6" fill="#94a3b8"/>
    </marker>

    <!-- Inline icon symbols -->
    <symbol id="icon-name" viewBox="0 0 24 24">...</symbol>
  </defs>

  <!-- 3. Background -->
  <rect width="1200" height="520" fill="url(#bg-gradient)"/>

  <!-- 4. Title -->
  <text x="600" y="32" text-anchor="middle" class="title">Diagram Title</text>

  <!-- 5. Components (grouped by section) -->
  <!-- 6. Arrows and connections -->
  <!-- 7. Legend -->
  <!-- 8. Branding badge -->

</svg>
```

### Step 3: Add Technology Icons

Icons must be embedded as inline `<symbol>` elements within `<defs>`. Do NOT use external image references.

```xml
<defs>
  <symbol id="icon-fastapi" viewBox="0 0 24 24">
    <path fill="#009688" d="M12 0C5.375 0 0 5.375 0 12c0 6.627 5.375 12 12 12 6.626 0 12-5.373 12-12 0-6.625-5.373-12-12-12zm-.624 21.62v-7.528H7.19L13.203 2.38v7.528h4.029L11.376 21.62z"/>
  </symbol>
</defs>

<!-- Usage -->
<use href="#icon-fastapi" x="100" y="100" width="24" height="24"/>
```

### Step 4: Add Section Stages

Use numbered circles for multi-stage pipelines:

```xml
<!-- Stage indicator -->
<circle cx="50" cy="80" r="12" fill="#1e40af"/>
<text x="50" y="84" text-anchor="middle" class="stage-num">1</text>
<text x="70" y="84" class="section-title">Stage Name</text>
```

### Step 5: Validate XML

Before export, validate for common issues:

| Issue | Cause | Fix |
|-------|-------|-----|
| `xmlParseEntityRef: no name` | Unescaped `&` | Use `&amp;` |
| Missing namespace | Missing xmlns | Add `xmlns="http://www.w3.org/2000/svg"` |
| Font not rendering | Missing fallback | Use `Georgia, 'Times New Roman', serif` |

---

## Export Requirements

### Required Formats

| Format | Purpose | Location |
|--------|---------|----------|
| `.svg` | Source file, vector graphics | `docs/diagrams/*.svg` |
| `.png` | Documentation embed, web use | `docs/diagrams/*.png` |
| `.docx` | Microsoft Word export (optional) | `docs/exports/*.docx` |

### PNG Export Process

**Required Tool:** `rsvg-convert` (librsvg)

Installation:

```bash
# macOS
brew install librsvg

# Ubuntu/Debian
apt-get install librsvg2-bin

# Windows (via MSYS2)
pacman -S mingw-w64-x86_64-librsvg
```

**Export Commands:**

```bash
# High-resolution export (recommended)
rsvg-convert -h 2000 input.svg -o output.png

# Standard export
rsvg-convert -h 1500 input.svg -o output.png

# With specific DPI
rsvg-convert -d 300 -p 300 input.svg -o output.png
```

**Recommended Heights by Diagram Type:**

| Diagram Type | Export Height | Approximate File Size |
|--------------|---------------|----------------------|
| HLD Architecture | 2000-2400px | 400-600KB |
| Data Flow | 1500-2000px | 300-500KB |
| Swimlane/Sequence | 1400-1800px | 250-400KB |

### Markdown Embedding

```markdown
![Diagram Title](diagrams/diagram_name.png)
```

### DOCX Export

For formal document delivery, export Markdown to DOCX using Pandoc with the shared reference template.

**Reference Template Location:** `shared/standards/templates/reference.docx`

The reference template provides:

- 1" margins on all sides
- Table borders with header row shading (dark blue `#1F4E79`, white text)
- Georgia font for body text and headings
- Proper table cell padding and alignment

**Export Command (two-step process):**

```bash
# Step 1: Generate DOCX with pandoc
pandoc HLD_Document.md \
  -o exports/HLD_Document_raw.docx \
  --from=gfm \
  --to=docx \
  --reference-doc=/path/to/shared/standards/templates/reference.docx \
  --toc \
  --toc-depth=3

# Step 2: Apply comprehensive DOCX formatting
python3 /path/to/shared/standards/templates/docx-post-processor.py \
  exports/HLD_Document_raw.docx \
  exports/HLD_Document.docx

# Step 3: Clean up intermediate file
rm exports/HLD_Document_raw.docx
```

**Pandoc Options:**

| Option | Purpose |
|--------|---------|
| `--from=gfm` | GitHub Flavored Markdown (proper pipe table support) |
| `--reference-doc` | Applies styles from template (margins, fonts) |
| `--toc` | Generates Table of Contents |
| `--toc-depth=3` | TOC includes H1, H2, H3 |

**Template Files:**

| File | Purpose |
|------|---------|
| `templates/reference.docx` | Base styles (margins, headings, fonts) |
| `templates/docx-post-processor.py` | Comprehensive DOCX post-processing |

**Output Location:** Place exports in `docs/exports/` directory

### DOCX Generation Pipeline

The complete Markdown to DOCX pipeline includes diagram rendering, icon injection, and comprehensive document styling.

**Pipeline Overview:**

```text
.mmd (Mermaid) → .svg (mmdc) → -icons.svg (inject) → -final.png (puppeteer)
                                                            ↓
.md (Markdown) → pandoc → _raw.docx → docx-post-processor.py → .docx
```

**Pipeline Scripts:**

| Script | Location | Purpose |
|--------|----------|---------|
| `render-diagrams.sh` | `scripts/` | Orchestrates full pipeline |
| `inject-svg-icons.py` | `scripts/` | Injects technology icons into SVGs |
| `svg-to-png.mjs` | `scripts/` | Puppeteer-based 10x scale PNG conversion |
| `md-to-docx-convert.py` | `scripts/` | Markdown to DOCX with diagram replacement |
| `docx-post-processor.py` | `templates/` | Comprehensive DOCX styling |

**Usage:**

```bash
# Run full pipeline (diagrams + DOCX)
cd standards/.claude/docs/scripts
./render-diagrams.sh --docx

# Diagrams only
./render-diagrams.sh

# Single DOCX file
python3 md-to-docx-convert.py WORKFLOW_OPTIMIZATION.md
```

### Post-Processor Script Details

The `docx-post-processor.py` script uses the `python-docx` library to apply professional formatting that pandoc cannot achieve natively.

**Dependencies:**

```bash
uv pip install python-docx  # v1.2.0+
```

**What the Script Does:**

1. **Table Borders** - Adds dark gray (#333333) borders to all table edges and internal grid lines
2. **Header Row Styling** - First row of each table gets:
   - Dark blue background (#1F4E78)
   - Bold white text
3. **Cell Margins** - Removes excessive padding (top/bottom: 0, left/right: 108 twips)
4. **Vertical Centering** - Centers text vertically within each cell
5. **Paragraph Spacing** - Minimal spacing (2pt before/after) for compact appearance
6. **ToC Styling** - Table of Contents with Georgia font, 12pt size
7. **Theme Font Modification** - Ensures consistent Georgia font throughout via theme1.xml
8. **Page Break Optimization** - Prevents orphaned headings with `keep_with_next` and `widow_control`

**Key Implementation Details:**

```python
from docx import Document
from docx.shared import Pt, RGBColor
from docx.oxml.ns import nsdecls, qn
from docx.oxml import parse_xml
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT

# Table borders via OOXML (tblBorders with insideH/insideV for grid)
tblBorders = parse_xml(
    r'<w:tblBorders %s>'
    r'<w:top w:val="single" w:sz="4" w:space="0" w:color="333333"/>'
    r'<w:left w:val="single" w:sz="4" w:space="0" w:color="333333"/>'
    r'<w:bottom w:val="single" w:sz="4" w:space="0" w:color="333333"/>'
    r'<w:right w:val="single" w:sz="4" w:space="0" w:color="333333"/>'
    r'<w:insideH w:val="single" w:sz="4" w:space="0" w:color="333333"/>'
    r'<w:insideV w:val="single" w:sz="4" w:space="0" w:color="333333"/>'
    r'</w:tblBorders>' % nsdecls('w')
)

# Header shading via OOXML
shading = parse_xml(r'<w:shd %s w:fill="1F4E78" w:val="clear"/>' % nsdecls('w'))

# Cell margins via OOXML (values in twips: 20 twips = 1pt)
tcMar = parse_xml(
    r'<w:tcMar %s>'
    r'<w:top w:w="0" w:type="dxa"/>'
    r'<w:bottom w:w="0" w:type="dxa"/>'
    r'<w:left w:w="108" w:type="dxa"/>'
    r'<w:right w:w="108" w:type="dxa"/>'
    r'</w:tcMar>' % nsdecls('w')
)

# Vertical centering (python-docx native)
cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER

# Paragraph spacing (python-docx native)
paragraph.paragraph_format.space_before = Pt(2)
paragraph.paragraph_format.space_after = Pt(2)

# Header text styling (python-docx native)
run.bold = True
run.font.color.rgb = RGBColor(255, 255, 255)
```

### Issues Encountered and Resolutions

| Issue | Root Cause | Resolution |
|-------|------------|------------|
| ToC page numbers showing Aptos font | Theme fonts in theme1.xml use system defaults | Added `set_theme_fonts()` to modify theme1.xml inside DOCX archive |
| ToC heading 11pt instead of 12pt | Half-point sizing mismatch | Changed from 22 (11pt) to 24 (12pt) half-points |
| Orphaned headings at page breaks | No widow/orphan control | Added `optimize_page_breaks()` with `keep_with_next` property |
| Icons not rendering in PNG | CSS specificity issues | Added `!important` to all icon fill colors in SVG injection |
| Puppeteer SVG blurry | Default 1x scale | Increased viewport to 10x scale for crisp rendering |
| ToC inside SDT elements | Word uses Structured Document Tags | Traverse SDT to find and style ToC paragraphs |

**OOXML Sizing Reference:**

| Points | Half-Points (w:sz) | Usage |
|--------|-------------------|-------|
| 8pt | 16 | Small labels |
| 10pt | 20 | Captions |
| 11pt | 22 | Body text |
| 12pt | 24 | ToC entries |
| 14pt | 28 | Section headers |

**Troubleshooting:**

| Issue | Cause | Solution |
|-------|-------|----------|
| No borders visible | VS Code Office Viewer caching | Close and re-open file |
| Header not styled | Empty header cell or no runs | Script handles both `paragraph.runs` and raw `paragraph.text` |
| Text not centered vertically | Missing vertical alignment | Use `WD_CELL_VERTICAL_ALIGNMENT.CENTER` |
| Too much vertical padding | Default paragraph spacing | Set `space_before`/`space_after` to 2pt |
| Font mismatch in ToC | Theme fonts override explicit fonts | Modify theme1.xml in DOCX archive |

### Hyperlinks in Tables

For Technology Stack and similar reference tables, embed hyperlinks directly in markdown table cells. Pandoc preserves these as clickable links in DOCX output.

**Syntax:**

```markdown
| Layer | Technology | Rationale |
|-------|------------|-----------|
| **Language** | [Go 1.23+](https://go.dev/) | Performance, single binary |
| **Container** | [Docker](https://www.docker.com/) ([Alpine](https://www.alpinelinux.org/)) | Minimal attack surface |
```

**Guidelines:**

- Link technology names to official documentation or product pages
- For multiple technologies in one cell, link each separately
- Use parenthetical links for sub-technologies (e.g., `[Kubernetes](url) ([AKS](url))`)
- Verify links resolve before export

---

## HLD Document Structure

```markdown
# {Project Name} - High-Level Design (HLD)

---

## Document Control

| Version | Date | Author | Role | Contact |
|---------|------|--------|------|---------|
| 1.0 | DD Month YYYY | Name | Title | email |

---

## Table of Contents

| Section | Page |
|---------|------|
| [Executive Summary](#executive-summary) | 1 |
| [Architecture Overview](#architecture-overview) | 2 |
| ... | ... |

---

## Executive Summary
## Architecture Overview
## Component Descriptions
## Data Flow
## Security Architecture
## Integration Points
## Build vs. Buy Analysis
## Cost Analysis
## Deployment Model
## DR/BC Architecture
## Technology Stack
## Architecture Decision Records
## Future Roadmap
```

### Required Diagrams for HLD

| Diagram | Purpose |
|---------|---------|
| `hld_architecture.svg/png` | System architecture overview |
| `dfd_*.svg/png` | Data flow diagrams (1-3 as needed) |

### Supporting Artifacts Reference

At the end of HLD, include:

```markdown
---

## Related Documents

| Document | Description |
|----------|-------------|
| [DDD - Detailed Design](DDD_ProjectName.md) | ADRs, API specs, data models |
| [DR/BC Plan](DRBC_ProjectName.md) | Disaster recovery procedures |
```

---

## DDD Document Structure

```markdown
# {Project Name} - Detailed Design Document (DDD)

---

## Document Control

| Version | Date | Author | Role | Contact |
|---------|------|--------|------|---------|
| 1.0 | DD Month YYYY | Name | Title | email |

---

## Table of Contents

---

## Overview
## Architecture Decision Records (ADRs)
### ADR-001: {Decision Title}
### ADR-002: {Decision Title}
...
## API Specifications
### Endpoints
### Request/Response Models
### Error Handling
## Data Models
### Entity Definitions
### Relationships
### Validation Rules
## Service Interfaces
## Configuration Reference
## Testing Strategy
## Appendix: Code Examples
```

### ADR Template

```markdown
### ADR-001: {Decision Title}

| Attribute | Value |
|-----------|-------|
| **Status** | Accepted / Proposed / Deprecated |
| **Date** | YYYY-MM-DD |
| **Deciders** | Names |

**Context:** What is the issue or question?

**Decision:** What was decided?

**Rationale:** Why was this decision made?

**Consequences:** What are the implications?

**Alternatives Considered:**
- Option A: Description
- Option B: Description
```

---

## DR/BC Documentation Standard

### Required Sections

1. **Recovery Objectives**
   - RTO (Recovery Time Objective)
   - RPO (Recovery Point Objective)
   - MTTR (Mean Time to Recovery)

2. **Architecture by Cloud Provider**
   - AWS DR architecture
   - Azure DR architecture
   - GCP DR architecture
   - Cross-cloud failover options

3. **Backup Strategy**
   - Data backup frequency
   - Backup locations (cross-region, cross-cloud)
   - Retention policies

4. **Failover Procedures**
   - Automated failover triggers
   - Manual failover steps
   - Rollback procedures

5. **Testing Protocols**
   - Quarterly DR tests
   - Test scenarios
   - Success criteria
   - Post-test review process

---

## Appendix A: Technology References

### Icon Sources

| Source | URL | License | Best For |
|--------|-----|---------|----------|
| **Simple Icons** | [simpleicons.org](https://simpleicons.org) | CC0 1.0 | Brand logos (AWS, Azure, GCP) |
| **Material Symbols** | [fonts.google.com/icons](https://fonts.google.com/icons) | Apache 2.0 | UI/system icons |
| **Lucide** | [lucide.dev](https://lucide.dev) | ISC | General-purpose icons |
| **Heroicons** | [heroicons.com](https://heroicons.com) | MIT | UI icons |

### Icon Embedding Method

1. Download SVG from source
2. Extract `<path>` or `<g>` content
3. Wrap in `<symbol>` with unique ID
4. Place in `<defs>` section
5. Reference with `<use href="#icon-id">`

### Required Tools

| Tool | Purpose | Installation |
|------|---------|--------------|
| `rsvg-convert` | SVG to PNG conversion | `brew install librsvg` |
| `pandoc` | Markdown to DOCX | `brew install pandoc` |
| Text editor | SVG editing | VS Code, Cursor |
| Image viewer | PNG verification | Preview, GIMP |

### Recommended VS Code Extensions

| Extension | Purpose | ID |
|-----------|---------|-----|
| **vscode-icons** | Enhanced file icons | `vscode-icons-team.vscode-icons` |
| **PDF Preview** | View PDFs inline | `tomoki1207.pdf` |
| **XML Tools** | XML formatting/validation | `redhat.vscode-xml` |
| **Office Viewer** | View Excel/Word docs | `cweijan.vscode-office` |
| **SVG Preview** | SVG viewing/editing | `jock.svg` |

### Font Installation

Georgia is typically pre-installed on macOS and Windows. For Linux:

```bash
# Ubuntu/Debian (Microsoft fonts)
sudo apt-get install ttf-mscorefonts-installer

# Or use compatible alternative
# Liberation Serif provides similar metrics
```

### Validation Commands

```bash
# Check SVG syntax
xmllint --noout diagram.svg

# Verify PNG export
file output.png
# Expected: PNG image data, XXXX x YYYY, 8-bit/color RGBA

# Check file size
ls -lh docs/diagrams/*.png
```

---

## Document Conversion Agents

For automated document conversion, use the `md-to-docx` agent:

```bash
# Invoke the agent
claude --agent md-to-docx.md

# Or reference in conversation
# "Use the md-to-docx agent to convert HLD_Document.md to DOCX"
```

See `.claude/agents/md-to-docx.md` for full conversion workflow.

---

## Quick Reference: Icon Embedding Checklist

- [ ] Download SVG from approved source (Simple Icons, Lucide, etc.)
- [ ] Extract `<path>` content from SVG
- [ ] Create `<symbol>` with unique ID in `<defs>`
- [ ] Reference with `<use href="#icon-id">`
- [ ] Never use external image references (`<image href="url">`)
- [ ] Verify colors match brand palette

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | January 2026 | Initial release |
| 2.0 | January 2026 | Added DDD requirements, diagram methodology, icon standards, export process |
| 2.1 | January 2026 | Added section symbols, status indicators, agent reference |
| 2.2 | January 2026 | Comprehensive DOCX pipeline docs, renamed to docx-post-processor.py, added ToC styling, theme fonts, page break optimization, issues/resolutions |
