# Session D3 Handoff — Figma Import

**Session:** D3 (Figma manual import)
**Date:** 2026-04-04
**Branch:** main (ZERO git changes — Figma only)
**Status:** Mechanism proven, CF.1 + CF.6 imported (low-res placeholders)

---

## Critical Finding: Plugin API Image Import Works

The `use_figma` official MCP tool can import images via `figma.createImage(bytes)`. Key constraints:

1. **No `atob`/`fetch`/`Buffer`/`TextDecoder`** in the Plugin API sandbox
2. **Custom base64 decoder required** — 6-bit lookup table → Uint8Array
3. **50K char code limit** on `use_figma` — max ~36KB binary image per call
4. **`figma.createImage()`** IS available and returns an image hash for fills
5. **`figma-create` MCP URL import** blocked by domain allowlist (GitHub raw, localhost both fail)

### Working Pattern

```javascript
// Custom decoder (atob unavailable in Plugin API)
function b64d(s) {
  const t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const o = []; let i = 0;
  s = s.replace(/[^A-Za-z0-9+/]/g, "");
  while (i < s.length) {
    const a = t.indexOf(s[i++]), b = t.indexOf(s[i++]);
    const c = t.indexOf(s[i++]), d = t.indexOf(s[i++]);
    o.push((a << 2) | (b >> 4));
    if (c >= 0) o.push(((b & 15) << 4) | (c >> 2));
    if (d >= 0) o.push(((c & 3) << 6) | d);
  }
  return new Uint8Array(o);
}

// Import to frame
const page = figma.root.children.find(p => p.id === "PAGE_ID");
await figma.setCurrentPageAsync(page);
const frame = figma.getNodeById("FRAME_ID");
const bytes = b64d("BASE64_DATA");
const img = figma.createImage(bytes);
frame.fills = [{ type: "IMAGE", scaleMode: "FIT", imageHash: img.hash }];
```

### Quality Constraint

Images must be compressed to ~6-8KB JPEG (480px, q15-30) to fit in the 50K code limit via context. This produces blurry placeholders in 1920x1080 frames. For higher quality:

- **Option A:** Manual desktop import (Cmd+Shift+K) — best quality, manual effort
- **Option B:** PluginData chunking — store base64 across multiple use_figma calls, combine in final call
- **Option C:** Figma-native build via diagram-builder agent — best long-term approach (see below)

---

## Figma-Native Approach (diagram-builder agent)

D3 research confirmed the `diagram-builder` agent was designed for Figma-native diagrams:

**Pipeline:** `icon-library:search_icons` → `get_icon_svg` → `figma-create:set_svg`

Icons are injected as raw SVG strings directly into Figma nodes — no export pipeline, no stripping. This bypasses both the Draw.io Electron SVG-stripping bug AND the image import size limits.

**Recommendation:** For portfolio-quality Figma pages, use `diagram-builder` agent to create diagrams natively in Figma using figma-create primitives (frames, rectangles, text, SVG icons). This produces vector-quality, editable, properly sized diagrams.

---

## What's Done

| Page | Status | Quality |
|------|--------|---------|
| CF.1 | IMPORTED | Low-res placeholder (3.2KB JPEG) |
| CF.2 | NOT DONE | base64 fetched, not yet imported |
| CF.3 | NOT DONE | — |
| CF.4 | MECHANISM TEST | b64d decoder proven, code file generated |
| CF.5 | NOT DONE | — |
| CF.6 | IMPORTED | Low-res placeholder (4.4KB JPEG, first successful test) |
| CF.7 | NOT DONE | — |
| CF.8 | NOT DONE | Portrait image, needs extra compression |
| CF.9 | NOT DONE | — |

## What's NOT Done

- [ ] Import CF.2, CF.3, CF.4, CF.5, CF.7, CF.8, CF.9 (same pattern as CF.1/CF.6)
- [ ] Higher quality imports (Option A, B, or C above)
- [ ] Verify all 9 pages with screenshots
- [ ] Consider diagram-builder agent for portfolio-quality native Figma diagrams

## Page Mapping

| Page | Page ID | Frame ID | Source PNG | Dimensions |
|------|---------|----------|------------|------------|
| CF.1 | 0:1 | 74:2 | architecture-figma.png | 1904x293 (6.5:1) |
| CF.2 | 1:2 | 74:3 | iac-deploy-pipeline.png | 4768x578 (8.2:1) |
| CF.3 | 1:3 | 74:4 | failover-sequence.png | 3528x2568 (1.4:1) |
| CF.4 | 1:4 | 74:5 | compliance-deployment-models.png | 4768x176 (27:1) |
| CF.5 | 1:5 | 74:6 | remediation-dispatcher-flow.png | 3114x2592 (1.2:1) |
| CF.6 | 1:6 | 61:2 | global-deployment-figma.png | 1920x1080 (16:9) |
| CF.7 | 1:7 | 74:7 | dual-opa-architecture-figma.png | 7152x2322 (3:1) |
| CF.8 | 1:8 | 74:8 | risk-intelligence-pipeline.png | 1932x5542 (1:2.9) |
| CF.9 | 1:9 | 74:9 | iac-deploy-pipeline.png | 4768x578 (8.2:1) |

## Micro JPEG Files (ready for import)

All at `/tmp/figma-import/micro_CF{N}.jpg` — pre-compressed to fit 50K code limit.

## Key Files

| Purpose | Path |
|---------|------|
| Figma file key | `2l5XrS7QRy5MYFI9PwcPmK` |
| figma-create channel | `72snjfrt` |
| Micro JPEGs | `/tmp/figma-import/micro_CF*.jpg` |
| Code files | `/tmp/figma-import/code_CF*.js` |
| Figma registry | `~/.claude/projects/.../memory/reference_figma_file_registry.md` |
