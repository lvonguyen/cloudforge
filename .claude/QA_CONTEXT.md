# CloudForge QA Context

## Application URL
http://localhost:5173/

## Roles
Three roles available via header dropdown (RoleSwitcher component, dev mode).

**How to switch roles:**
1. Click the role name button in the top-right header bar (shows current role: "Operator", "Admin", or "Requester")
2. A dropdown menu opens with `role="menuitem"` items
3. Click the target role
4. App redirects to that role's home route

**[!] Known quirk:** The first click on the role button may not open the dropdown if element refs are stale from navigation. If the dropdown doesn't appear, click the role button by coordinates (~930, 25) or re-read the page first.

- **operator** — primary ops persona, home: /ops, sees /ops/* routes
- **requester** — portal persona, home: /, sees /portal/* routes
- **admin** — full access, home: /admin, sees /admin/* + /ops/* + /portal/*

## Critical Journeys (T4)
1. **Finding triage:** Switch to Operator → navigate to /ops/findings → wait 3s for data load → click a finding ROW BODY (not header — header triggers sort) → verify detail panel opens with severity, description, remediation
2. **Compliance drill-down:** Navigate to /ops/compliance → click a framework → verify control list drawer opens with citations
3. **Remediation kanban:** Navigate to /ops/remediation → toggle to Kanban view → verify columns render with items
4. **Exception request:** Switch to Requester → navigate to /portal/request → verify form renders with fields
5. **Admin KPIs:** Switch to Admin → navigate to /admin (NOT /admin/dashboard — that 404s) → verify 4 KPI cards render with numeric values
6. **NLQ search:** Use search bar → type "critical GCP" → verify results appear or NLQ short-circuit fires
7. **Data consistency:** Compare Command Center (20K findings) vs Findings page count — document any discrepancy

## Known WIP (mark SKIPPED, not FAIL)
- G-08 heatmap readability (deferred — cosmetic)
- G-10 R2 data re-upload pending (demo findings regeneration needed)
- Mock data is non-deterministic — finding totals may vary between loads (6,001 → 6,620 → 6,645 observed)

## Search Queries (T11)
- "critical GCP" → should return GCP findings with critical severity
- "S3 bucket" → should return AWS S3 findings
- "open GCP misconfigs" → should match NLQ short-circuit (instant result, no API call)

## Route Coverage — Local Dev (updated 2026-03-18, post-rename + Sprint G/H)

### Operator (/ops/*) — 8 routes
- /ops (Command Center — home for Operator role)
- /ops/findings (Finding list — 6K+ items, filterable)
- /ops/remediation (Remediation queue — List/Kanban toggle)
- /ops/costs (Cost dashboard)
- /ops/compliance (Compliance frameworks — 6 frameworks)
- /ops/containers (Container security)
- /ops/data-classification (Data classification)
- /ops/investigations (Investigation workflows)

### Portal (/portal/*) — 4 routes
- /portal (My Dashboard)
- /portal/request (New Request form)
- /portal/requests (My Requests)
- /portal/catalog (Application Catalog)

### Admin (/admin/*) — 9 routes
- /admin (Dashboard — NOT /admin/dashboard, that 404s)
- /admin/policies (Policy management)
- /admin/ai-agents (AI Agent management)
- /admin/users (User management)
- /admin/audit-log (Audit log)
- /admin/system (System configuration)
- /admin/exceptions (Exception queue — Sprint G)
- /admin/reports (Reports + CSV export — Sprint G)
- /admin/app-catalog (Application Catalog — Sprint G)

### Shared
- / (redirects to role home: /ops for Operator, / for Requester, /admin for Admin)

**Total:** 21 routes + landing

## Scope
- All 21 routes × 3 roles
- Light + dark mode
- Full T1-T11 suite (75+ tests)
- T4: Classify every button/filter by action type — FAIL as UNWIRED if no state change
- T9: Verify every sidebar link navigates correctly per role
- T10: Compare Command Center counts vs Findings page counts
- T11: Test NLQ search bar + all filter dropdowns on /ops/findings

## Rename Validation (2026-03-18)
- Verify NO "CloudForge" text appears in any UI element (nav, headings, footer, title bar)
- Verify "CloudForge" appears where product name is expected
- Verify logo loads from /icons/aegis-logo.svg
- Verify sessionStorage keys use "aegis_" prefix (not "cloudforge_")
