# Sprint B: Review & QA (Continuation)

**Created:** 2026-03-16
**Status:** READY FOR NEXT SESSION
**Depends on:** Sprint B implementation commits (30ea7f9..ac45e90)
**Context budget:** Split from implementation session to avoid compaction

---

## Pre-Requisites

Before starting, verify the implementation commits are in place:

```bash
git log --oneline -6
# Expected: 5 commits (B1/B2, B4/B5, B6/B7, B8, import fix)
```

---

## Phase 5: Full-Stack Agent Review

### Step 0.5: Mechanical Linters

```bash
cd /Users/lvonguyen/repos/gh/cloudforge
golangci-lint run ./... 2>&1 | tee /tmp/lint-output.txt
cd frontend && npx tsc --noEmit 2>&1 | tee -a /tmp/lint-output.txt
```

### Step 1: Parallel Sonnet Workers (3 agents)

Spawn in a **single message** — blind review (agents do NOT see threshold):

| Agent | Focus | Scope |
|-------|-------|-------|
| `quality-review` | KISS/YAGNI, readability, architecture, code smells | All changed files (B1-B8) + linter output |
| `bug-discovery` | Race conditions, edge cases, logic errors, nil handling | All changed files + test files |
| `security-audit` | OWASP, input validation, auth bypass, XSS | Backend (B1, B2) + frontend hooks (B5, B6, B8) |

Each agent receives:
- Linter output from Step 0.5
- Diff: `git diff HEAD~5..HEAD`
- File list with line numbers

### Step 2: Opus Distiller

After all 3 workers complete, spawn Opus distiller to:
1. Deduplicate findings by `file:line` key
2. Group by severity (critical > high > medium > low)
3. Produce compressed FIX/ACCEPT summary (~500-1K tokens)

### Step 3: Apply Fixes + Threshold Check

- **Threshold:** 4.5+ practical (per QA Policy in CLAUDE.md)
- Fix all critical/high findings, commit as: `fix: agent review findings — <summary>`
- If below threshold: re-run Step 1 (max 3 iterations)

### Changed Files Reference

| File | Items | Key Changes |
|------|-------|-------------|
| `internal/api/rbac.go` | B2 | RoleViewer const, rank shift, RoleFromClaims matched-tracking |
| `internal/api/rbac_test.go` | B2 | TestRoleFromClaims_ViewerBelowRequester |
| `cmd/server/handlers_api.go` | B1 | actorFilter 255-char cap |
| `frontend/src/components/compliance/FrameworkDetailDrawer.tsx` | B4 | docLink prop + ExternalLink render |
| `frontend/src/pages/ops/Compliance.tsx` | B4 | Table rows clickable, selectedFramework state, drawer instance |
| `frontend/src/pages/portal/Dashboard.tsx` | B5 | useMyExceptions/useExceptions hooks, timeSince, loading guard |
| `frontend/src/hooks/useExceptions.ts` | B6 | useException(id) hook |
| `frontend/src/pages/portal/RequestDetail.tsx` | B6 | Hook-driven with apiMapped fallback |
| `frontend/src/pages/admin/AIAgentDetail.tsx` | B7 | FRAMEWORK_PROFILES map, getThreatModelForAgent factory |
| `frontend/src/pages/admin/Dashboard.tsx` | B8 | usePolicies/useAgents/useCompliance/useExceptions KPI wiring |

---

## Phase 6: Comprehensive Chrome E2E QA

Run `/ap-chrome-qa` against `http://localhost:5173` — full 8-module audit.

### Prerequisites

```bash
# Terminal 1: Backend
cd /Users/lvonguyen/repos/gh/cloudforge && go run ./cmd/server

# Terminal 2: Frontend dev server
cd /Users/lvonguyen/repos/gh/cloudforge/frontend && npm run dev

# Chrome: MCP extension connected
```

### Route Coverage (22 routes)

All routes at 5 viewports (320, 375, 768, 1024, 1440) in light + dark mode.

### Scoped Checks for Sprint B Features

**B1 — actorFilter cap:**
- `/admin/audit-log?actor=<256+ chars>` — verify truncation, no crash

**B4 — Compliance drill-down:**
- `/ops/compliance` — click each framework row → drawer opens, doc link opens in new tab

**B5 — Portal Dashboard hooks:**
- `/portal` — My Requests + Pending Approvals populated, KPI cards computed

**B6 — RequestDetail API wiring:**
- `/portal/requests/EXC-002` — loads from hook or mock fallback
- `/portal/requests/NONEXISTENT` — "Request not found" renders

**B7 — Per-agent STRIDE:**
- `/admin/ai-agents/:id` → STRIDE tab shows different profiles per framework

**B8 — Admin Dashboard KPIs:**
- `/admin` — KPI values computed from hooks (not hardcoded 42/7/84%/12)

### Fix Cycle

CRITICAL/HIGH findings → commit as: `fix(frontend): Chrome QA fixes — <summary>`
Re-run scoped checks only (not full sweep).

---

## Verification Checklist

- [ ] All 8 scoring dimensions >= 4.5 (Phase 5)
- [ ] All critical/high findings resolved
- [ ] All 22 routes visited in light + dark mode
- [ ] T1-T8 module summary: zero CRITICAL, zero HIGH
- [ ] B-item scoped checks: all 6 PASS
- [ ] `go test -race -timeout 20m ./...` — all PASS
- [ ] `npx vitest run` — 38/38 files PASS
- [ ] `npm run build` — clean build
