# Diagram Coordination (orchestrator, 2026-04-04 — audit #3)

## [!] Active Sessions (wave 4 — continuation)

| Session | Tokens | Working On | Status |
|---------|--------|-----------|--------|
| **cf E diagrams 1-3** | 151K | CF.1-3 ALL DONE | COMPLETE (218 ops, all dark+light synced) |
| **cf E diagrams e+ 1-3** | 290K | CF.1 icons+align, CF.2 overflow fixes, CF.3 icons+boxes+arrows | COMPLETE — handoff at tasks/handoff-e1plus-13.md. 8 CF.2 bugs remain. |
| **cf E diagrams 4-6** | 133K | CF.4/5/6 polish | Loading context |
| **cf E diagrams 7-8** | 147K | CF.7 Dark readability fix | Starting |

## [!] Current Page Status (13 Figma pages)

| Page | ID | Dark | Light | Verdict |
|------|----|------|-------|---------|
| CF.1 | 0:1 | DONE (text 56/34/26, 3 brand logos 80x80, 3 new icons, arrows 28x16, frame 1920x1300) | 85:671 — DONE (synced: text+icons+logos+arrows+frame) | PASS |
| CF.2 | 1:2 | DONE (readability overhaul: 37 text bumps, shield 80px, checkmark, arrows 16x28) | 85:738 — DONE (synced: text+shield+arrows+check) | PASS |
| CF.3 | 1:3 | DONE (text bump +4px on 19 steps, labels 26, summary 28, 5 icons 34) | 85:819 — DONE (synced: same bumps) | PASS |
| CF.4 | 1:4 | Structure + arrows done, cards need repositioning, ZERO icons | NOT STARTED | IN PROGRESS (4-6) |
| CF.5 | 1:5 | DONE (frame shrunk, icons, arrows, text alignment fixed) | NOT STARTED | DARK PASS |
| CF.6 | 1:6 | Structure + partial arrows, needs icons + text bump | NOT STARTED | IN PROGRESS (4-6) |
| CF.7 | 1:7 | Icons+arrows present but ALL TEXT TOO SMALL, right-shifted | 85:1087 — created, not colored | IN PROGRESS (7-8) |
| CF.8 | 1:8 | Icons+arrows present but ALL TEXT TOO SMALL | Light created | NEEDS READABILITY PASS (7-8) |
| CF.9 | 1:9 | N/A | Renamed [OLD] | SUPERSEDED by CF.2L |

### Completed (no further work needed)
- **CF.1 dark + light** — PASS (session "cf E diagrams 1-3", 218 ops)
- **CF.2 dark + light** — PASS (readability overhaul + sync, same session)
- **CF.3 dark + light** — PASS (text +4px per user feedback, same session)
- **CF.5 dark** — PASS (light variant still needed)

## [!] Per-Session Remaining Work

### 1-3: COMPLETE ✓ (+ e+ continuation)
All CF.1/CF.2/CF.3 work done in session "cf E diagrams 1-3". Continuation session "e+ 1-3" added:
- CF.1 Light: 19 text bumps, 5 icon resizes, 3 brand logos 80x80, 3 new icons (Portal dashboard, Threat Intel shield-alert, Policy Engine shield-check), 5 arrows 28x16, frame 1920x1300
- CF.2 Dark: 37 text bumps (title 56, steps 28/24, gate 34, policies 22), shield 48→80, 9 arrows resized, checkmark icon added
- CF.2 Light: Full sync (37 text + 9 arrows + shield + check)
- CF.3 Dark+Light: 31 text bumps each (+4px on steps per user feedback: 20→24), 5 participant icons 28→34, summary 24→28
- **e+ 1-3 continuation:** CF.1 Light subtitle sanitized ("7 Tenants/~270 Environments" → "Multi-Tenant/Multi-Environment"), T6 provider counts removed, icon column aligned to local x=1720 on both dark (2 moves: T3+T4 Policy) and light (3 moves: T1+T3+T4 Policy). No green artifacts found.

### 4-6: CF.4 cards + CF.6 icons + polish
1. CF.5: Mark DONE (text alignment fix landed)
2. CF.4: Reposition 26 cards to new grid, add framework icons (shield/lock/globe/medical/flag) at 48x48
3. CF.6: Cloud provider icons (AWS/Azure/GCP), text size bump (24px titles, 18px subtitles)
4. Drop shadows on CF.4/5/6 containers
5. Light variants CF.4L/5L/6L (may need continuation)

### 7-8: CF.7 + CF.8 readability pass
1. CF.7 Dark: Widen step boxes 480→700px, titles 18→24px bold, subtitles 12→18px, transition labels 10→16px bold, icons 24→48px, vertical gaps 15→35px, fix right-column centering, grow frame to ~1600px
2. CF.7 Light (85:1087): Apply same fixes + color swap
3. CF.8 Dark: Same readability treatment — all text +50%, icons to 48px, 35px gaps
4. CF.8 Light: Apply same fixes + color swap

## [!] Enforced Guardrails (G1-G7)

| # | Rule | Key Violations |
|---|------|---------------|
| G1 | Icons inline-left | CF.7 icons present but small |
| G2 | Every tier has icon | CF.4 ✗, CF.6 ✗ |
| G3 | Visible dividers | All OK |
| G4 | 24px+ spacing | CF.7 ✗ (15px gaps) |
| G5 | No dead space | CF.1 ✓ (trimmed 1300), CF.4 ✗ (bottom) |
| G6 | Vertical-first | All OK |
| G7 | Connector labels 10px+ | CF.7 ✗ (10px), CF.8 ✗ |

## Readability Calculator Reference

| Frame Width | Scale | Min Source Font |
|-------------|-------|----------------|
| 1920px | 0.46x | 22px |
| 1440px | 0.62x | 16px |
| 900px | 1.0x | 10px |

## Color Swap Reference (Dark → Light)

| Element | Dark RGB (0-1) | Light RGB (0-1) |
|---------|---------------|-----------------|
| Frame bg | 0.059, 0.09, 0.165 | 1, 1, 1 |
| Tile fill | 0.118, 0.161, 0.231 | 0.945, 0.961, 0.976 |
| Primary text | 0.886, 0.91, 0.941 | 0.118, 0.161, 0.231 |
| Secondary text | 0.58, 0.639, 0.722 | 0.278, 0.333, 0.412 |
| Stroke | 0.2, 0.255, 0.333 | 0.796, 0.835, 0.882 |
