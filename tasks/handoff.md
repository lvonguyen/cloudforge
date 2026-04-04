# Parallel Session Handoff — Diagram Redesign Sprint

**Generated:** 2026-04-04T19:00:00Z
**Repo:** cloudforge (CloudForge)
**Branch:** main
**Working tree:** clean
**Previous session:** C1 (Figma MCP uploads — FAILED, pivoted to Draw.io pipeline)

---

## Background

C1 confirmed that Figma's `set_image` via MCP garbles all diagram uploads (aspect ratio distortion — mmdc PNGs are 8:1 to 27:1, frames are 16:9). The solution is to rebuild portfolio-facing diagrams using Draw.io with real cloud provider icons from the icon-library MCP, then export for README, portfolio site, and manual Figma import.

**Draw.io desktop:** `/Applications/draw.io.app/Contents/MacOS/draw.io`
**Export:** `--export --format svg|png [--scale 2] --output <out> <in.drawio>`

---

## Session D1: Architecture Diagram Redesign

**Scope:** Create `architecture.drawio` using icon-library icons, export, update README + portfolio site
**Files touched:** cloudforge/docs/core/diagrams/, portfolio-site/public/
**Conflict risk:** None with D2 (different diagram files), none with D3 (zero git)

### What to Build

A new `docs/core/diagrams/architecture.drawio` replacing the current hand-crafted `architecture-figma.svg` (1200x620, 9-11px text — too cramped for web).

**Design specs:**
- **Canvas:** 1600x900 (16:9, web-optimized)
- **Background:** `#0f172a` (dark, per design system)
- **Text:** `#e2e8f0` (light), 14-16px labels, 12px details — Georgia font
- **Layout:** 5-6 horizontal tiers (simplified from 9 Mermaid subgraphs)

**Tier structure (simplified for readability):**

| Tier | Color | Content |
|------|-------|---------|
| Portal | `#3b82f6` | React 19 / Vite 7 — Self-Service Catalog, Findings, Compliance Dashboard, Cost Mgmt |
| API Gateway | `#1e40af` | Go 1.25 — JWT Auth + RBAC, Rate Limit, 91 Operations, Health/Obs, Audit Log |
| Core Engines | `#7c3aed` | CSPM Risk, Remediation, Attack Path BFS, AI Gov OPA, Security Graph, ASM |
| Intelligence + Policy | `#ef4444` / `#f59e0b` | Risk Intel (EPSS, GreyNoise, Toxic Combo, OTX) + OPA/Rego Policies |
| Data + Infra | `#64748b` | PostgreSQL, Redis, PuppyGraph, Terraform, Temporal |
| Cloud Providers | AWS `#f59e0b`, Azure `#3b82f6`, GCP `#22c55e` | Provider badges with real icons |
| Integrations | `#0ea5e9` | Asana, Jira, Azure DevOps |

**Icons to embed (base64 data URIs in Draw.io XML):**
- Search icon-library MCP: `search_icons("security shield", provider="aws")`, etc.
- Get base64: `get_icon_base64(path)` for each
- Already collected in C1 session (see memory `project_diagram_pipeline.md`):
  - AWS Cloud Logo, AWS Shield, Azure Security, GCP SCC, Terraform, PostgreSQL

**Icon searches still needed:**
- `search_icons("redis cache")` → Azure Redis icon
- `search_icons("graph database")` → for PuppyGraph
- `search_icons("jira")` / `search_icons("asana")` → ticket providers (probably not in lib — use generic)
- `search_icons("react")` → frontend (not in lib — use generic web icon)
- `search_icons("go golang")` → backend (returned no results in C1 — use generic API icon)

### Export Steps

```bash
# SVG for web (README, portfolio, docs-site)
/Applications/draw.io.app/Contents/MacOS/draw.io --export --format svg --output docs/core/diagrams/architecture-figma.svg docs/core/diagrams/architecture.drawio

# PNG for GitHub README (2x scale for retina)
/Applications/draw.io.app/Contents/MacOS/draw.io --export --format png --scale 2 --output docs/core/diagrams/architecture-figma.png docs/core/diagrams/architecture.drawio

# Copy to portfolio site
cp docs/core/diagrams/architecture-figma.svg /Users/lvonguyen/repos/gh/portfolio-site/public/cloudforge-architecture.svg

# Copy to docs-site
cp docs/core/diagrams/architecture-figma.svg docs-site/static/img/diagrams/architecture-figma.svg
cp docs/core/diagrams/architecture-figma.png docs-site/static/img/diagrams/architecture-figma.png
```

### Commit

```bash
# In cloudforge
git add docs/core/diagrams/architecture.drawio docs/core/diagrams/architecture-figma.{svg,png}
git add docs-site/static/img/diagrams/architecture-figma.{svg,png}
git commit -m "docs: redesign architecture diagram with Draw.io + cloud icons"
git push origin main

# In portfolio-site
cd /Users/lvonguyen/repos/gh/portfolio-site
git add public/cloudforge-architecture.svg
git commit -m "docs: update architecture diagram from Draw.io redesign"
git push origin main
```

### Acceptance Criteria
- [ ] Diagram renders cleanly at 800px browser width (text readable, icons recognizable)
- [ ] All tier colors match the palette above
- [ ] Cloud provider icons are real SVGs from icon-library (not FA unicode)
- [ ] Title says "CloudForge — High-Level Architecture"
- [ ] README `<img>` still works with full-width click-to-zoom
- [ ] Portfolio site SVG updated and CF Pages auto-deploys

---

## Session D2: Remaining Diagrams → Draw.io (OPTIONAL / LOWER PRIORITY)

**Scope:** Convert remaining 7 Mermaid diagrams to Draw.io format with icons
**Files touched:** cloudforge/docs/core/diagrams/ only
**Conflict risk:** None with D1 (architecture.drawio is the only D1 file), none with D3

### Priority Order

| Priority | Diagram | Current SVG | Reason |
|----------|---------|-------------|--------|
| 1 | dual-opa-architecture | 28KB | Smallest, appears in README, good ROI |
| 2 | compliance-deployment-models | 70KB | Appears in docs links table |
| 3 | failover-sequence | 34KB | Sequence diagram, good layout |
| 4 | global-deployment-architecture | 79KB | Multi-region layout benefits from icons |
| 5 | iac-deploy-pipeline | 156KB | LR flowchart — Draw.io handles LR much better than Mermaid |
| 6 | remediation-dispatcher-flow | 464KB | Complex, highest effort |
| 7 | risk-intelligence-pipeline | 111KB | Complex pipeline, medium effort |

### Process per Diagram

1. Read the `.mmd` source to extract content/structure
2. Search icon-library for relevant icons
3. Create `<name>.drawio` with embedded icons
4. Export: SVG (-w 2400, transparent bg) + PNG (2x scale)
5. Copy to `docs-site/static/img/diagrams/`
6. Update any `-figma.svg` / `-figma.png` variants
7. Verify render

### Note
This session is OPTIONAL. The Mermaid-rendered diagrams are fine for docs-site inline use. Draw.io upgrades are only needed for portfolio/Figma presentation quality. Do priorities 1-3 if time permits.

---

## Session D3: Figma Manual Import

**Scope:** Figma desktop only. Zero git changes.
**Depends on:** D1 output (architecture) + existing PNGs for the rest
**Can start immediately** with existing PNGs, update CF.1 later with D1 output

### Process

1. Open Figma file `2l5XrS7QRy5MYFI9PwcPmK` in Figma desktop
2. For each page: select the 1920x1080 frame → Place Image (Cmd+Shift+K) → select PNG
3. Adjust fill mode to FIT or FILL as appropriate
4. For garbled pages (CF.1, CF.2, CF.4): delete existing image fill first, then re-import

### Import Map

| Page | Page ID | Frame ID | Source PNG |
|------|---------|----------|------------|
| CF.1 | 0:1 | 74:2 | D1 output OR architecture-figma.png (42KB) |
| CF.2 | 1:2 | 74:3 | iac-deploy-pipeline.png (161KB) |
| CF.3 | 1:3 | 74:4 | failover-sequence.png (343KB) |
| CF.4 | 1:4 | 74:5 | compliance-deployment-models.png (101KB) |
| CF.5 | 1:5 | 74:6 | remediation-dispatcher-flow.png (390KB) |
| CF.6 | 1:6 | 61:2 | global-deployment-figma.png (185KB) |
| CF.7 | 1:7 | 74:7 | dual-opa-architecture-figma.png (474KB) |
| CF.8 | 1:8 | 74:8 | risk-intelligence-pipeline.png (387KB) |
| CF.9 | 1:9 | 74:9 | iac-deploy-pipeline.png (161KB, same as CF.2) |

All PNGs at: `docs/core/diagrams/`

### Alternative: Figma Official MCP

The new Figma official MCP (claude.ai) has `capture_web_page` and `generate_diagram` tools. If available, try:
- `capture_web_page` on `docs.cloudforge.lvonguyen.com` diagram pages
- Or `generate_diagram` with the diagram content

This may bypass the manual import entirely. Check MCP availability first.

---

## Verified State (at handoff)

- Go: 47 pkg / ~1,550 tests (clean)
- Frontend: 62 files / 476 vitest (clean)
- Fly.io: v116 healthy, CORS live
- Live docs: docs.cloudforge.lvonguyen.com (CloudForge branding)
- GitHub README: CloudForge branding, architecture-figma.png embedded

## Key Files

| Purpose | Path |
|---------|------|
| Diagram sources | `docs/core/diagrams/*.mmd` |
| Diagram renders | `docs/core/diagrams/*.svg`, `*.png` |
| Hand-crafted diagrams | `docs/core/diagrams/*-figma.{svg,png}` |
| Docs-site images | `docs-site/static/img/diagrams/` |
| Gallery page | `docs/core/diagrams/gallery.md` |
| Style guide | `docs/DIAGRAM_STYLE_GUIDE.md` |
| Figma registry | `~/.claude/projects/.../memory/reference_figma_file_registry.md` |
| Pipeline memory | `~/.claude/projects/.../memory/project_diagram_pipeline.md` |
| Draw.io CLI | `/Applications/draw.io.app/Contents/MacOS/draw.io` |
| mmdc | `/usr/local/bin/mmdc` (v11.12.0) |
| Portfolio site | `/Users/lvonguyen/repos/gh/portfolio-site` |
| Portfolio diagram | `portfolio-site/public/cloudforge-architecture.svg` (STALE, Mar 4) |

## Session Startup

```bash
cd /Users/lvonguyen/repos/gh/cloudforge
git pull origin main
git status -sb  # should be clean
```

**D1:** Read memory `project_diagram_pipeline.md` for icon base64s. Build architecture.drawio. Export. Update portfolio-site.
**D2:** Pick diagrams in priority order. Same Draw.io + icon-library workflow as D1.
**D3:** Open Figma desktop. Import PNGs manually. Or try Figma official MCP tools.
**C2-deep:** Continue Go/TS tenant sanitization below.

---

## Session C2-deep: Go/TS Tenant Sanitization (haea→acme)

**Scope:** Go source, Go tests, frontend mock data, CHANGELOG. No docs (docs sanitization done).
**Conflict risk:** Low — touches Go test fixtures and bootstrap, not API logic.
**Unstaged edit:** `cmd/server/bootstrap_startup.go` already has haea→acme (5 lines changed, NOT committed).

### Remaining Files (12 files, ~45 replacements)

Run: `git grep -n "HAEA\|haea" -- '*.go' '*.ts' 'CHANGELOG.md' 'testdata/**/*.md'`

| File | Count | Pattern |
|------|-------|---------|
| `cmd/server/bootstrap_startup.go` | 5 | DONE (unstaged) |
| `cmd/server/handlers_config_test.go` | 14 | haea→acme, "HAEA Security"→"Acme Corp", haea.io→acme.example.com |
| `internal/tenant/middleware.go` | 1 | Docstring: "haea.aegis.io"→"acme.aegis.io" |
| `internal/tenant/middleware_test.go` | 11 | Test fixtures: same pattern |
| `internal/tenant/tenant.go` | 2 | Docstring examples |
| `internal/tenant/tenant_test.go` | 8 | Test fixtures |
| `internal/terminal/mock_outputs.go` | 5 | Mock terminal strings |
| `frontend/src/lib/mock-data-utils.ts` | 1 | `@haea.io`→`@acme.example.com` |
| `CHANGELOG.md` | 1 | "HAEA findings"→"enterprise findings" |
| `testdata/export-scripts/asana/README.md` | 1 | Check context |
| `testdata/seed/README.md` | 1 | Check context |

### Replacement Rules

- Tenant ID: `haea` → `acme`
- Display name: `HAEA Security` / `HAEA` → `Acme Corp`
- Email domain: `haea.io` → `acme.example.com`
- Logo: `/haea-logo.svg` → `/acme-logo.svg`
- Subdomain: `haea.aegis.io` → `acme.aegis.io`
- Test func name: `TestHandleConfig_HAEATenant` → `TestHandleConfig_AcmeTenant`
- CHANGELOG: `HAEA` → `enterprise`

### Post-Edit Verification

```bash
# Zero remaining refs
git grep -c "HAEA\|haea" -- '*.go' '*.ts' '*.md' | grep -v INDUSTRY_LANDSCAPE | grep -v node_modules

# Go tests (critical — tenant package + server handlers)
go test -race ./internal/tenant/... ./cmd/server/...

# Frontend tests
cd frontend && npx vitest run --reporter=verbose 2>&1 | tail -20

# Commit
git add -u
git commit -m "refactor: sanitize haea tenant references to acme in Go source + tests"
git push origin main
```
