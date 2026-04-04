# Diagram Coordination (orchestrator, 2026-04-04)

## [!] Session Roles (FINAL)

| Session | Owns | Action |
|---------|------|--------|
| **D1+** | Figma pages (native MCP build) | Build diagrams directly in Figma via figma-create tools. Plugin connected, channel `72snjfrt`. Do NOT import — construct natively. |
| **D2+** | Draw.io exports (README, portfolio, docs-site) | Commit .drawio + exported SVG/PNG. These are the web/git assets. Figma is NOT your concern. |
| **D3+** | STAND DOWN | D1+ owns Figma now. Your JPEG imports were placeholders — D1+ will overwrite with native vector construction. Focus on handoff or help D2 commit. |

## [!] Import Pipeline is Dead

All approaches failed for Figma import:
- `set_image` → aspect ratio distortion (extreme ratios from Mermaid/Draw.io)
- Plugin API `createImage(bytes)` → 50K code limit, JPEG compression, low quality
- SVG import → viewBox/viewport misinterpretation, content crammed into horizontal strip

**The only path that works:** Build directly in Figma using `create_frame`, `create_text`, `set_fill_color`, `set_svg` via figma-create MCP. This is what diagram-builder agent was designed for.

## Design Direction (all outputs)

- Icons **way bigger** — 64x64 minimum standalone, 48x48 in node cards
- More **color** — use the full palette from DIAGRAM_STYLE_GUIDE.md
- **Less text heavy** — reduce label verbosity, let visuals speak
- Prioritize whitespace and readability over detail density

## Draw.io `%3B` Fix (reference)

Draw.io style parser splits on `;`. URL-encode to `%3B` in data URIs:
- `image=data:image/png%3Bbase64,iVBOR...`
- `image=data:image/svg+xml%3Bbase64,PHN2...`

Documented in `docs/DIAGRAM_STYLE_GUIDE.md` v1.1 and `diagram-builder.md` agent.
