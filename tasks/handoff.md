# Parallel Session Handoff — Diagram E2E

**Generated:** 2026-04-04T03:45:00Z
**Repo:** cloudforge (CloudForge)
**Branch:** main
**Latest commit:** `751e65f5` (pushed to origin)
**Working tree:** clean

## What Just Landed (this session)

- `fc0bd47d` `docs: re-render diagrams with CloudForge branding + PNG exports` (43 files)
- `96c0e028` `docs: Docusaurus overhaul — CloudForge branding, auth honesty, ADR-021` (21 files)
- `01d0ea73` `feat: attack-path readability + trace helpers + ops UI polish` (18 files)
- `39e4b992` `docs: complete Cloud Aegis -> CloudForge rename across 95 files`
- `751e65f5` `docs: add CloudForge favicon to docs site + README diagram polish`
- `.gitignore` fixed: PNG exception for `docs-site/static/img/**/*.png`, `.playwright-cli/` added
- README diagram section: full-width `<img>` with click-to-zoom, endpoint count fixed
- Docs-site favicon: shield+cloud+spark logo (`docs-site/static/img/favicon.svg`)

All pushed to origin. CF Pages will auto-rebuild from main.

---

## Session C1: Figma Diagram Upload

**Scope:** Figma MCP operations ONLY. Zero git file changes.
**Owner:** figma-create MCP, chrome for visual verification
**Conflict risk:** None (no file changes)

### Context

All 9 Figma pages are broken/empty. Screenshots confirmed:

| Page | Current State | Root Cause |
|------|--------------|------------|
| CF.1 Architecture | Garbled pixels | SVG 77KB exceeded MCP base64 limit |
| CF.2 IaC Pipeline | Empty dark frame | Never uploaded |
| CF.3 Failover | Empty dark frame | Never uploaded |
| CF.4 Compliance | Empty white frame | SVG 70KB exceeded limit, silent fail |
| CF.5 Remediation | Empty dark frame | Never uploaded |
| CF.6 Architecture Overview | Stale "Cloud Aegis" | Old upload, wrong branding |
| CF.7 Dual OPA | Partial, wrong size | SVG fit but dimensions wrong |
| CF.8 Risk Intel | Empty dark frame | Never uploaded |
| CF.9 IaC Light | Empty dark frame | Never uploaded |

### Figma File

- **File key:** `2l5XrS7QRy5MYFI9PwcPmK`
- **Channel:** `72snjfrt` (must `join_channel` first)
- **9 pages:** CF.1-CF.9

### Frame IDs (from registry)

| Page | Page ID | Frame ID |
|------|---------|----------|
| CF.1 | 0:1 | 74:2 |
| CF.2 | 1:2 | 74:3 |
| CF.3 | 1:3 | 74:4 |
| CF.4 | 1:4 | 74:5 |
| CF.5 | 1:5 | 74:6 |
| CF.6 | 1:6 | 61:2 |
| CF.7 | 1:7 | 74:7 (SVG child: 68:18) |
| CF.8 | 1:8 | 74:8 |
| CF.9 | 1:9 | 74:9 |

### Upload Strategy

**MCP practical limit:** ~25KB base64 PNG for `set_image`. ~50KB for `set_svg` text. Larger payloads truncate silently or corrupt.

**Step 1: Generate compact PNGs for MCP upload**
```bash
cd /Users/lvonguyen/repos/gh/cloudforge/docs/core/diagrams
for f in architecture compliance-deployment-models failover-sequence iac-deploy-pipeline remediation-dispatcher-flow risk-intelligence-pipeline global-deployment-architecture dual-opa-architecture; do
  mmdc -i ${f}.mmd -o /tmp/figma-${f}.png -w 960 -b '#0f172a' 2>/dev/null
done
ls -lhS /tmp/figma-*.png
```

**Step 2: Check which fit under 25KB** -- only those can use MCP `set_image`.

**Step 3: For files that fit** -- upload via:
```
1. join_channel("72snjfrt")
2. set_current_page(page_id)
3. delete existing frame children (clean slate)
4. set_image(frame_id, base64_png)
```

**Step 4: For files that don't fit** -- try `set_svg` with raw SVG content (higher text limit). If still too large, document which pages need manual import and provide instructions to user.

**Step 5: For -figma.svg variants** (CF.6, CF.1) -- hand-crafted SVGs with branded headers. Try `set_svg` first. If too large, fall back to compact PNG.

**Step 6: Verify** -- `export_node_as_image` or `get_screenshot` on each frame after upload.

### Source File Sizes

| Diagram | SVG | PNG | Notes |
|---------|-----|-----|-------|
| architecture | 77KB | 141KB | CF.1 + CF.6 (-figma variant) |
| compliance-deployment-models | 70KB | 101KB | CF.4 |
| dual-opa-architecture | 28KB | 319KB | CF.7 -- smallest SVG, best MCP candidate |
| failover-sequence | 34KB | 343KB | CF.3 -- second smallest SVG |
| global-deployment-architecture | 79KB | 408KB | CF.6 uses -figma.svg (54KB) |
| iac-deploy-pipeline | 156KB | 161KB | CF.2 + CF.9 (light variant) |
| remediation-dispatcher-flow | 464KB | 390KB | CF.5 -- largest, definitely manual |
| risk-intelligence-pipeline | 111KB | 387KB | CF.8 |

**Realistic expectation:** 2-3 diagrams via MCP (dual-opa, failover, maybe compliance). The rest need manual Figma import. Produce a clear list of pages needing manual import with exact file paths.

### Manual Import Paths (for user)

PNGs: `docs/core/diagrams/*.png`
Figma PNGs: `docs/core/diagrams/*-figma.png`

---

## Session C2: Runbook Diagrams + Docs Audit

**Scope:** docs/ file changes only. No Figma, no frontend.
**Owner:** Mermaid CLI, file editing, /docs-audit skill
**Conflict risk:** None (C1 makes zero file changes)

### Task 1: Create 4 Missing Runbook Diagrams

| Runbook | Diagram Type | Description |
|---------|-------------|-------------|
| 02-incident-response.md | Flowchart | Severity triage -> escalation -> containment -> resolution |
| 04-performance-troubleshooting.md | Decision tree | Symptom -> diagnosis -> action branching |
| 07-secrets-rotation.md | Sequence diagram | Detection -> rotation -> validation -> notification |
| 08-finops-budget-alerts.md | Flowchart | Budget threshold -> alert routing -> remediation |

**Process for each:**
1. Read the runbook to extract procedure steps
2. Create `docs/core/diagrams/{runbook-name}.mmd`
3. Render: `mmdc -i {name}.mmd -o {name}.svg -w 2400 -b transparent`
4. Export: `mmdc -i {name}.mmd -o {name}.png -w 2400 -b transparent -s 2`
5. Copy to `docs-site/static/img/diagrams/`
6. Embed `![diagram](../diagrams/{name}.svg)` in the runbook .md

**Style (from DIAGRAM_STYLE_GUIDE.md):**
- Core `#1e40af`, AWS `#f59e0b`, DR `#ef4444`, Infra `#8b5cf6`, GCP `#22c55e`
- Transparent bg, 2400px width

### Task 2: /docs-audit (comprehensive, max depth)

```
/docs-audit
```

Focus areas:
- Remaining stale refs (bulk rename hit 95 files but SVGs and edge cases may remain)
- Broken internal links (many file moves across 39 sessions)
- Missing cross-references between ADRs, runbooks, HLD
- Documentation completeness gaps

### Task 3: HLD Diagram Quality

User flagged HLD diagrams as "crude." Review:
- `docs/core/architecture/HLD.md` embedded Mermaid diagrams
- Simplify overly complex diagrams
- Ensure consistent styling per diagram style guide
- Consider splitting large diagrams into focused sub-diagrams

### Task 4: Commit + Push

```bash
git add docs/core/diagrams/*.mmd docs/core/diagrams/*.svg docs/core/diagrams/*.png
git add docs-site/static/img/diagrams/
git add docs/core/runbooks/*.md
git add -u  # any other doc fixes from audit
git commit -m "docs: add runbook diagrams + docs-audit fixes"
git push origin main
```

---

## Verified State (at handoff)

- Go: 47 pkg / ~1,550 tests (clean)
- Frontend: 62 files / 476 vitest (clean)
- Playwright: 19 passed, 1 skipped
- Fly.io: v116 healthy, CORS live
- Live docs: docs.cloudforge.lvonguyen.com (CloudForge branding)
- GitHub README: CloudForge branding, full-width architecture diagram

## Key Files

| Purpose | Path |
|---------|------|
| Diagram sources | `docs/core/diagrams/*.mmd` |
| Diagram renders | `docs/core/diagrams/*.svg`, `*.png` |
| Docs-site images | `docs-site/static/img/diagrams/` (24 files) |
| Gallery page | `docs/core/diagrams/gallery.md` |
| Style guide | `docs/DIAGRAM_STYLE_GUIDE.md` |
| Figma registry | `~/.claude/projects/.../memory/reference_figma_file_registry.md` |
| mmdc | `/usr/local/bin/mmdc` (v11.12.0) |

## Session Startup

```bash
cd /Users/lvonguyen/repos/gh/cloudforge
git pull origin main
git status -sb  # should be clean
```

**C1:** Open Figma file, run compact PNG generation, start uploads.
**C2:** Read runbooks, create Mermaid sources, run /docs-audit.
