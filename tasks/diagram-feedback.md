# Diagram Design Feedback (from orchestrator, 2026-04-04)

## Apply to ALL Draw.io diagrams (D1 + D2)

### Design Direction
- Icons need to be **way bigger** — 64x64 minimum standalone, 48x48 in node cards
- More **color** — use the full palette from DIAGRAM_STYLE_GUIDE.md, don't be conservative
- **Less text heavy** — reduce label verbosity, let the visual hierarchy speak
- First drafts are too cramped — prioritize whitespace and readability over detail density

### [!] Icon Export Fix (D2 SOLVED)

**Root cause:** NOT Electron stripping SVGs. It's **semicolon collision** in Draw.io's style parser.

`data:image/png;base64,...` contains a literal `;` which Draw.io's style attribute parser splits on as a property delimiter, breaking the data URI into two invalid fragments.

**Fix:** URL-encode the semicolon → `data:image/png%3Bbase64,...`

This works for ANY MIME type (PNG and SVG both):
- `image=data:image/png%3Bbase64,iVBOR...` 
- `image=data:image/svg+xml%3Bbase64,PHN2...`

D2 confirmed: all 12 icons rendering perfectly with `%3B` encoding.

### Source Reference
- diagram-builder agent: `.claude/agents/diagram-builder.md` (Figma-native, not Draw.io)
- Style guide: `docs/DIAGRAM_STYLE_GUIDE.md`
- Icon cascade: local filesystem → GitHub repos → Brandfetch → icon-library MCP

## C2-deep: Untracked Files

You have D2 output files in your worktree that belong in D2's commit:
- `docs/core/diagrams/dual-opa-architecture.drawio`
- `docs/core/diagrams/dual-opa-architecture-drawio.png`
- `docs/core/diagrams/dual-opa-architecture-drawio.svg`

Do NOT commit these — let D2 handle them. `git checkout -- <file>` or leave untracked.
