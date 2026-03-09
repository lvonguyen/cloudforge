# Sprint 4 Advisory: Polish & Resilience

**Generated:** 2026-03-06
**Source:** Verified against `frontend-patterns/SKILL.md` + codebase scan
**Prerequisite:** Sprint 3 DONE, Chrome QA 38/38 PASS

---

## 1. Skill Review: `frontend-patterns/SKILL.md`

**Location:** `shared/dev-profile/.claude/skills/frontend-patterns/SKILL.md`

### Coverage Matrix

| Pattern | In Skill? | CloudForge Status |
|---------|-----------|-------------------|
| Composition over inheritance | Yes | YES -- Card/CardHeader via shadcn |
| Compound components (Context tabs) | Yes | Partial -- `TracePanelContext` uses this |
| `useDebounce` hook | Yes | **NO** -- keystroke filtering in Findings + Catalog |
| Custom `useQuery` hook | Yes | **SUPERSEDED** -- all 13 hooks use `@tanstack/react-query` |
| Context + useReducer | Yes | YES -- `trace-panel-context.tsx` (7 dispatch actions) |
| `useMemo` / `useCallback` / `React.memo` | Yes | YES -- Findings.tsx (8x), Catalog.tsx (3x), AttackPaths |
| Code splitting (`lazy` / `Suspense`) | Yes | **NO** -- 22 pages eagerly loaded in App.tsx |
| Virtualization (`@tanstack/react-virtual`) | Yes | **NO** -- Findings table renders all rows |
| Form validation (Zod) | Yes | Partial -- `zod@4.3.6` in deps, no form schemas |
| Error boundary | Yes | **NO** -- zero crash protection |
| Keyboard navigation | Yes | **NO** -- no custom keyboard handlers |
| Focus management (modals) | Yes | **NO** -- drawers/modals don't manage focus |

### Verdict: Useful reference, do NOT invoke wholesale

**[+] Directly applicable (cherry-pick these 4):**

1. **`useDebounce`** -- Findings + Catalog both filter on every keystroke. Debounce 300ms.
2. **Code splitting** -- 22 pages imported eagerly in App.tsx:11-40. `lazy()` on admin/ops.
3. **Error boundary** -- Zero ErrorBoundary in codebase. One crash kills the whole app.
4. **Virtualization** -- Findings table (80 rows now, target 5000+) needs virtual scrolling.

**[-] Skip (conflicts with existing stack):**

- Custom `useQuery` hook -- conflicts with `@tanstack/react-query` (all 13 hooks use it)

**[!] Gaps in the skill (CloudForge needs, skill doesn't cover):**

- shadcn/ui + Radix component patterns
- React Router `location.state` for preselect flows
- Tailwind utility-first design tokens
- React 19.2 features (`use()`, Actions)

---

## 2. Codebase Verification Summary

All claims verified against source on 2026-03-06.

| Claim | Result |
|-------|--------|
| 13 hooks using `apiClient` + `@tanstack/react-query` | CONFIRMED -- all 13 in `src/hooks/` |
| No ErrorBoundary | CONFIRMED -- 0 matches |
| No lazy/Suspense | CONFIRMED -- 0 matches, 22 eager imports in App.tsx |
| No useDebounce/debounce | CONFIRMED -- 0 matches |
| No virtualization | CONFIRMED -- 0 matches |
| No TODO/FIXME in frontend source | CONFIRMED -- 0 matches |
| Context + Reducer in trace-panel-context | CONFIRMED -- `useReducer` + 7 dispatch actions |
| useMemo in Findings.tsx | **8 instances** (plan draft said 6) |
| useMemo in Catalog.tsx | **3 instances** (plan draft said 2) |
| zod in deps but no form schemas | CONFIRMED -- `zod@^4.3.6` in package.json, 0 schemas in src |
| Costs.tsx is thin / needs charts | **INCORRECT** -- already has SpendChart, AnomalyAlertCard, ChargebackTable, MoM trends (136 lines, fully featured) |
| MyRequests.tsx needs real data | CONFIRMED -- still uses hardcoded `const REQUESTS` array (line 23) |

---

## 3. Sprint 4 Backlog: Polish & Resilience

**Theme:** Production-readiness hardening -- error handling, performance, accessibility.

### Recommended Scope (4 items, all parallelizable)

| # | Item | Files | Size | Priority | Backend? |
|---|------|-------|------|----------|----------|
| 1 | Error boundary + code splitting | `App.tsx`, new `ErrorBoundary.tsx` | S | HIGH | No |
| 2 | Findings table virtualization | `Findings.tsx` | M | HIGH | No |
| 3 | useDebounce for search | `Findings.tsx`, `Catalog.tsx`, new `useDebounce.ts` | S | MEDIUM | No |
| 4 | P2 action buttons | RemediationQueue, FindingDetail, Users, Policies | M | MEDIUM | Needs endpoints |

### Item 1: Error Boundary + Code Splitting

**Create:** `frontend/src/components/ErrorBoundary.tsx`
- Class component with `getDerivedStateFromError` + retry button
- Wrap each `<Route>` group (admin, ops, portal) in its own boundary

**Modify:** `frontend/src/App.tsx`
- Replace 22 static imports (lines 11-40) with `React.lazy()` calls
- Add `<Suspense fallback={<PageSkeleton />}>` around route groups
- Keep `Landing` and `NotFound` as eager imports (small, always needed)

**Acceptance:** Component error in `/admin/*` doesn't crash `/ops/*` or `/portal/*`.

### Item 2: Findings Table Virtualization

**Install:** `@tanstack/react-virtual`

**Modify:** `frontend/src/pages/ops/Findings.tsx`
- Add `useVirtualizer` to the table body
- `estimateSize: () => 48` (current row height)
- `overscan: 10` for smooth scrolling
- Keep existing 8 `useMemo` computations unchanged

**Acceptance:** Table renders 5000+ rows without visible jank. DOM node count < 100 for table rows.

### Item 3: useDebounce for Search

**Create:** `frontend/src/hooks/useDebounce.ts`
- Generic `useDebounce<T>(value: T, delay: number): T` hook
- Default delay: 300ms

**Modify:** `frontend/src/pages/ops/Findings.tsx` -- debounce search input
**Modify:** `frontend/src/pages/portal/Catalog.tsx` -- debounce search input

**Acceptance:** Typing in search box doesn't trigger re-render on every keystroke. 300ms delay before filter applies.

### Item 4: P2 Action Buttons (4 remaining)

From trace view spec (execution-plan.md lines 165-168):

| Button | Page | Trace Mode | Cooldown |
|--------|------|-----------|----------|
| Retry | RemediationQueue | streaming | exp backoff |
| Suppress | FindingDetail | confirm | 1/sec |
| Invite User | Admin Users | modal | 1/5s |
| New Policy | Admin Policies | timeline | 1/3s |

**Deps:** Backend endpoints for Retry + Suppress if not already stubbed. Invite User and New Policy may use existing admin endpoints.

---

## 4. Removed / Deprioritized Items

| Item | Original Priority | Reason for Change |
|------|-------------------|-------------------|
| Costs page enrichment | LOW | **Already done** -- SpendChart, AnomalyAlertCard, ChargebackTable, MoM trends all exist |
| MyRequests real data | LOW | Deferred -- requires backend `GET /api/v1/exceptions/mine` endpoint |
| Container security stubs | LOW | Backend-only, no frontend impact |
| Integration test suite | LOW | Needs docker-compose infra, separate workstream |
| Accessibility pass | MEDIUM | Deferred to Sprint 5 -- needs design spec for focus order and ARIA roles |

---

## 5. Agent Team Structure (Sprint 4)

All 4 items are independent (different files, different concerns). Recommend parallel execution:

```
Agent ErrorBoundary  [Sonnet]  -->  App.tsx + new ErrorBoundary.tsx
Agent Virtualizer    [Sonnet]  -->  Findings.tsx + @tanstack/react-virtual install
Agent Debounce       [Sonnet]  -->  new useDebounce.ts + Findings.tsx + Catalog.tsx
Agent P2Buttons      [Sonnet]  -->  RemediationQueue, FindingDetail, Users, Policies
                                      |
                              Opus Distiller  -->  aggregate + verify no conflicts
```

**[!] Conflict risk:** Agent Debounce and Agent Virtualizer both touch `Findings.tsx`. Virtualizer should modify the table body rendering; Debounce should modify the search input state. No overlap in code regions, but coordinate via the distiller.

---

## 6. `/frontend-patterns` Skill Recommendation

**Do NOT invoke `/frontend-patterns` directly for CloudForge work.**

Reasons:
1. The custom `useQuery` hook pattern conflicts with `@tanstack/react-query`
2. CSS class examples don't match Tailwind utility-first approach
3. No shadcn/Radix patterns (CloudForge's primary component library)
4. No React 19 features (CloudForge is on 19.2)

**Instead:** Reference the skill for the 4 applicable patterns (debounce, lazy, ErrorBoundary, virtualization) and implement CloudForge-specific versions that integrate with the existing stack.
