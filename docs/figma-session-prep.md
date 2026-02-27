# CloudForge — Figma Session Prep

**Date:** 2026-02-28
**Status:** Pre-session reference

---

## 1. Available Figma MCP Tools

### 1.1 figma-create (55 tools) — Write path via WebSocket

**Source:** Local build at `~/repos/local/claude-talk-to-figma-mcp/`
**[!] Do NOT use `npx @latest` — SDK 1.26.0 has a Zod 4 bug that breaks `tools/list`.**

Key tools: `join_channel`, `create_frame`, `create_from_svg`, `create_text`, `create_rectangle`, `set_fill_color`, `set_auto_layout`, `set_corner_radius`, `move_node`, `resize_node`, `group_nodes`, `create_component_from_node`, `create_component_instance`, `export_node_as_image`, `get_pages`, `get_selection`

### 1.2 figma-desktop (7 tools) — Read/verify path (Pro license required)

Tools: `get_design_context`, `get_screenshot`, `get_metadata`, `get_figjam`, `get_variable_defs`, `create_design_system_rules`

### 1.3 mcp__claude_ai_Figma — Figma REST API

Tools: `get_design_context`, `get_screenshot`, `generate_diagram`, Code Connect tools, `whoami`

---

## 2. Icon Library (8,500+ SVGs)

Providers: AWS, Azure, GCP, Entra, Homelab

| Tool | Purpose |
|---|---|
| `list_categories(provider?)` | List categories by provider |
| `search_icons(query, provider?, limit?)` | Fuzzy search |
| `get_icon_svg(path)` | Raw SVG |
| `get_icon_base64(path)` | Base64 for Figma embedding |
| `get_color_palette()` | Standard hex palette |

**[!] Requires explicit session permission grant.**

### Color Palette

| Provider | Hex | Notes |
|---|---|---|
| AWS | #f59e0b | Amber |
| Azure | #3b82f6 | Blue |
| GCP | #22c55e | Green |
| Core | #1e40af | Dark Blue |
| Security/DR | #ef4444 | Red |

---

## 3. Existing Diagrams (Mermaid → SVG)

Located in `/docs/diagrams/`: architecture, dual-opa, failover-sequence, global-deployment, iac-deploy-pipeline, remediation-dispatcher-flow, risk-intelligence-pipeline, compliance-deployment-models

**Import strategy:** `create_from_svg` to place as flat images, then rebuild with CSP icons.

---

## 4. Session Workflow

### Setup
```bash
# Terminal 1 — socket FIRST
cd ~/repos/local/claude-talk-to-figma-mcp && bun run socket

# Terminal 2 — Claude Code AFTER socket
claude
```

### Smoke test
1. `get_pages()` → document pages
2. `search_icons("lambda", "aws")` → results
3. `create_frame("test", 0, 0, 100, 100)` → nodeId
4. `delete_node(nodeId)` → cleanup

### Session Priority Order
1. Dual-OPA architecture diagram (highest differentiation)
2. Global deployment architecture (multi-cloud credibility)
3. Remediation dispatcher flow (engineering depth)
4. UI wireframe: AI Agent Detail screen
5. UI wireframe: Policy Exception form
6. Icon component library (reusable)

---

## 5. Layout Constants

| Property | Value |
|---|---|
| Frame (presentation) | 1920x1080 |
| Frame (documentation) | 1440x900 |
| Icon size | 64x64 (standard), 48x48 (dense) |
| Component spacing | 32px |
| Tier spacing | 64px |
| Label font | Inter 14px |
| Background (dark) | #1e1e2e |

---

## 6. Prerequisites Checklist

- [ ] Figma Desktop installed + logged in
- [ ] Claude Talk to Figma plugin installed
- [ ] Local `claude-talk-to-figma-mcp` build current
- [ ] New Figma file created ("CloudForge Architecture")
- [ ] Socket running before Claude Code launch
- [ ] `/mcp` confirms figma-create (55 tools) + icon-library (5 tools)
- [ ] Plugin channel ID noted
