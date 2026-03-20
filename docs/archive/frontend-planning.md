# CloudForge Web UI Frontend — Planning Document

**Author:** Liem Vo-Nguyen
**Date:** 2026-02-27
**Status:** Superseded — portal implemented with React 19 / Vite 7 / Tailwind CSS v4 (see `frontend/`)

---

## 1. Backend API Surface Inventory

### Currently Exposed Endpoints (`/api/v1`)

```
GET    /health
POST   /api/v1/exceptions
GET    /api/v1/exceptions/pending
GET    /api/v1/exceptions/expiring
GET    /api/v1/exceptions/{id}
POST   /api/v1/exceptions/{id}/approve
GET    /api/v1/applications/{appId}/exceptions
POST   /api/v1/validate/exception
GET    /metrics  (Prometheus)
```

### Implemented Modules With No Exposed Endpoints (Frontend Needs New Routes)

| Module | Domain Objects | New Endpoints Needed |
|---|---|---|
| `internal/compliance` | `Framework`, `Control`, `Finding` (20+ frameworks) | `GET /findings`, `GET /frameworks` |
| `internal/finops` | `CostRecord`, `AnomalyAlert`, `ChargebackReport` | `GET /costs/summary`, `GET /costs/anomalies` |
| `internal/ai-governance` | `Agent`, `AgentTrace`, `ThreatModel`, `MaturityAssessment` | `GET /agents`, `GET /agents/{id}/traces` |
| `pkg/remediation` | `RemediationRecord`, `RemediationResult`, `DryRunResult` | `GET /remediations`, `POST /remediations/{id}/execute` |
| `internal/policy` | `PolicyInput`, `PolicyResult`, `PolicyViolation` | `POST /policy/evaluate` |

---

## 2. Three Role-Based Views

### 2.1 Admin View — Platform Administration

**Purpose:** Platform operators managing policies, AI agents, users, and system health.

#### Pages (7 screens)

| Page | Key Components | Backend | Complexity |
|---|---|---|---|
| `/admin` — Dashboard | KPI cards: active policies, agent count, compliance score, open exceptions | Existing `/health` + new `/admin/stats` | Low |
| `/admin/policies` — Policy Manager | Table of OPA policies, CRUD forms, Rego editor | New `GET/POST /policies` | High |
| `/admin/ai-agents` — Agent Registry | Agent cards: name, framework, risk level, status badge | New `GET /agents` | Med |
| `/admin/ai-agents/{id}` — Agent Detail | Trace timeline, security signals, token usage chart | New `GET /agents/{id}/traces` | High |
| `/admin/users` — User Management | Table + invite form, role assignment (admin/operator/requester) | New `GET/POST /users` | Med |
| `/admin/audit-log` — Audit Log | Filterable event stream table | New `GET /audit` | Med |
| `/admin/system` — System Health | Service status grid, Prometheus metrics charts | Existing `/health`, `/metrics` | Low |

#### Wireframe — Admin Dashboard

```
+------------------------------------------------------------------+
| CloudForge  [Admin]    Search...           [avatar] Liem VN [v] |
+--------+---------------------------------------------------------+
|        |  PLATFORM OVERVIEW                   [Last 30d] [v]    |
| [*]    |  +----------+ +----------+ +----------+ +----------+   |
| Dash   |  | Policies | | AI Agents| | Findings | |Compliance|   |
|        |  |    24    | |    12    | |  143 crit| |  87.3%   |   |
| [/]    |  | 3 DRAFT  | | 2 SUSP'D | | 31 OPEN  | | NIST CSF |   |
| Policy |  +----------+ +----------+ +----------+ +----------+   |
|        |                                                         |
| [+]    |  EXCEPTION QUEUE                  [View All ->]        |
| Agents |  +--------------------------------------------------+  |
|        |  | ID       | App      | Policy    | Status  | Age |  |
| [>]    |  | EXC-0042 | payments | REGION-01 | PENDING | 2d  |  |
| Users  |  | EXC-0041 | catalog  | COST-002  | PENDING | 5d  |  |
|        |  | EXC-0039 | auth-svc | NET-003   | APPROVED| 1d  |  |
| [!]    |  +--------------------------------------------------+  |
| Audit  |                                                         |
|        |  SECURITY SIGNALS (24h)           AI COST TREND (7d)  |
| [#]    |  [sparkline: 3 high, 12 med]      [sparkline: $142]   |
| System |                                                         |
+--------+---------------------------------------------------------+
```

---

### 2.2 Operator View — Day-to-Day Cloud Operations

**Purpose:** Security/cloud engineers triaging findings, running remediations, monitoring costs.

#### Pages (6 screens)

| Page | Key Components | Backend | Complexity |
|---|---|---|---|
| `/ops` — Command Center | Live finding feed, remediation queue status, anomaly alerts | New `GET /findings` | Med |
| `/ops/findings` — Findings Board | Kanban or table: severity badge, MITRE tag, SLA countdown, assign button | New `GET /findings` with filters | High |
| `/ops/findings/{id}` — Finding Detail | Full finding card, CVE refs, compliance mappings, remediation steps | New `GET /findings/{id}` | High |
| `/ops/remediation` — Remediation Queue | Tier 1/2/3 queue, dry-run preview, execute/rollback buttons | New `GET/POST /remediations` | High |
| `/ops/costs` — FinOps Dashboard | Spend by provider chart, anomaly alerts, chargeback table | New `GET /costs/summary`, `/costs/anomalies` | High |
| `/ops/compliance` — Compliance Status | Framework grid (20+ frameworks), pass/fail per control | New `GET /compliance/status` | Med |

#### Wireframe — Findings Board

```
+------------------------------------------------------------------+
| CloudForge  [Operator]  Findings        [Filter: ALL] [v]       |
+------------------------------------------------------------------+
| Severity: [ALL][CRIT][HIGH][MED][LOW]  Provider: [ALL][v]       |
| Framework: [ALL][v]  Status: [OPEN][v]   SLA: [BREACHED][v]     |
+-------------------+-------------------+---------------------------+
| CRITICAL (31)     | HIGH (87)         | MEDIUM (112)              |
+-------------------+-------------------+---------------------------+
| [!] CVE-2024-9999 | [!] S3-PUBLIC-01  | [~] LOGGING-007           |
| payments/ec2-123  | catalog/s3-bucket | auth-svc/cloudtrail       |
| CVSS 9.8  AWS-ap  | AWS-us-east-1     | AWS-us-east-1             |
| SLA: 0d LEFT [!!] | SLA: 3d left      | SLA: 18d left             |
| T.1: PrivEsc      | AUTO-REMEDIATABLE | [Assign] [Suppress]       |
| [DryRun][Execute] | [DryRun][Execute] |                           |
+-------------------+-------------------+---------------------------+
```

#### Wireframe — FinOps Dashboard

```
+------------------------------------------------------------------+
| CloudForge  [Operator]  Cost Management          [Feb 2026]     |
+------------------------------------------------------------------+
| TOTAL SPEND     | AWS          | AZURE        | GCP             |
| $1,284,320      | $847,200     | $298,100     | $139,020        |
| +12.3% MoM      | EC2: 42%     | Compute: 38% | GKE: 51%        |
+------------------------------+-----------------------------------+
| ANOMALY ALERTS (3 active)    | CHARGEBACK BY COST CENTER        |
| [!] S3 Data Transfer +340%   | Platform: 34% ($436k)           |
|   payments-service, AWS      | Payments: 28% ($359k)           |
| [!] Azure VM spike +89%      | Auth: 18% ($231k)               |
|   qa-environment, westus2    | Catalog: 12% ($154k)            |
| [~] GCP GKE +22% (expected)  | Other: 8% ($104k)              |
+------------------------------+-----------------------------------+
| SPEND TREND (90d)  [recharts area chart: AWS+Azure+GCP stacked] |
+------------------------------------------------------------------+
```

---

### 2.3 Requester View — Self-Service Portal

**Purpose:** Developers and product teams requesting cloud resources, tracking exceptions.

#### Pages (5 screens)

| Page | Key Components | Backend | Complexity |
|---|---|---|---|
| `/portal` — My Dashboard | My requests status, pending approvals, my resources | Existing `/exceptions/pending` | Low |
| `/portal/request` — New Request | Multi-step form: resource type → config → policy check → submit | Existing `POST /validate/exception`, `POST /exceptions` | High |
| `/portal/requests` — My Requests | Request history table with status badges, expiry countdown | Existing `GET /applications/{appId}/exceptions` | Low |
| `/portal/requests/{id}` — Request Detail | Exception lifecycle view, approver chain, comments | Existing `GET /exceptions/{id}` | Med |
| `/portal/catalog` — Resource Catalog | Card grid of Terraform golden modules (S3, EC2, RDS, AKS, GKE) | New `GET /catalog/modules` (static JSON fine) | Low |

#### Wireframe — New Request Form (Multi-step, Step 1)

```
+------------------------------------------------------------------+
| CloudForge  [Self-Service Portal]  New Resource Request         |
+------------------------------------------------------------------+
| Step 1 > Step 2 > Step 3 > Step 4 > Submit                      |
|    [=]      [ ]      [ ]      [ ]     [ ]                       |
+------------------------------------------------------------------+
| STEP 1: Resource Type                                           |
|                                                                 |
| What would you like to provision?                               |
|                                                                 |
| +--------+ +--------+ +--------+ +--------+ +--------+        |
| |  [S3]  | | [EC2]  | | [RDS]  | |  [AKS] | |  [GKE] |        |
| | Object | |Compute | |Database| | K8s    | | K8s    |        |
| | Storage| |        | |        | | Azure  | | GCP    |        |
| +--------+ +--------+ +--------+ +--------+ +--------+        |
|                                                                 |
| Cloud Provider: [AWS v]  Region: [us-east-1 v]                 |
|                                                                 |
| [Cancel]                              [Next: Configuration ->] |
+------------------------------------------------------------------+
```

#### Wireframe — Policy Check Result (Step 3)

```
+------------------------------------------------------------------+
| STEP 3: Policy Validation                                       |
|                                                                 |
| Checking your request against CloudForge policies...           |
|                                                                 |
| [X] REGION-001  ap-southeast-3 not in approved regions         |
|     Approved: us-east-1, eu-west-1, ap-southeast-1             |
|     -> Request Exception? [Yes, continue] [Change region]      |
|                                                                 |
| [!] COST-002  t3.2xlarge exceeds standard size (t3.large)      |
|     Requires: Business justification + manager approval        |
|     -> Accepted, will route to approval chain                  |
|                                                                 |
| [*] TAGGING-001  Missing required tags: team, cost-center      |
|     -> Add below: team [_______] cost-center [_______]         |
|                                                                 |
| [Cancel]                              [Next: Review ->]        |
+------------------------------------------------------------------+
```

---

## 3. Level of Effort Estimates

### Admin View

| Attribute | Detail |
|---|---|
| Screens | 7 |
| Key components | `PolicyEditor` (Monaco Rego), `AgentTraceTimeline`, `AuditLogTable`, `MetricsChart`, `UserTable` |
| New API endpoints | 6 (policies CRUD, agents list, traces, users, audit, admin stats) |
| Complexity | High |
| Agent-hours estimate | 12-16h |

### Operator View

| Attribute | Detail |
|---|---|
| Screens | 6 |
| Key components | `FindingsTable` (TanStack Table, sortable/filterable), `RemediationQueue`, `CostSummaryChart`, `ComplianceGrid`, `AnomalyAlertCard` |
| New API endpoints | 5 (findings CRUD, remediations, costs summary, anomalies, compliance status) |
| Complexity | High |
| Agent-hours estimate | 14-18h |

### Requester View

| Attribute | Detail |
|---|---|
| Screens | 5 |
| Key components | `MultiStepRequestForm`, `PolicyCheckResult`, `ResourceCatalogCard`, `ExceptionStatusBadge`, `ApproverChain` |
| New API endpoints | 1 (catalog modules — static JSON acceptable) |
| Existing endpoints used | 5 (all GRC exception endpoints already live) |
| Complexity | Medium |
| Agent-hours estimate | 8-10h |

### Summary

| View | Screens | Complexity | Agent-Hours |
|---|---|---|---|
| Admin | 7 | High | 12-16h |
| Operator | 6 | High | 14-18h |
| Requester | 5 | Med | 8-10h |
| **Total** | **18** | — | **34-44h** |

---

## 4. Tech Stack Recommendation

```
React 18 + Vite 5 + TypeScript
Tailwind CSS v3 + shadcn/ui
React Router v6 (SPA routing)
TanStack Query (React Query) — server state management
TanStack Table v8 — findings/exception data grids with virtualization
Recharts — cost/trend charts (raw recharts, avoids Tremor bundle overhead)
React Hook Form + Zod — multi-step request forms with validation
Monaco Editor — Rego policy editor (admin only, code-split, Phase 2)
Lucide React — icon set (shadcn/ui default)
Cloudflare Pages — hosting (consistent with OT hosting architecture)
```

### Why Not Next.js

- No SEO requirement for an internal platform demo
- Vite builds faster; simpler CF Pages deploy (pure static assets)
- OT frontend is already React+Vite — consistent toolchain across portfolio
- SSR adds complexity with no benefit for a JWT-gated SPA

### Auth Approach

**Development:** Mock auth in localStorage with a role switcher dropdown (`Admin / Operator / Requester`). No OAuth round-trip needed for demo.

**Production:** Cloudflare Access header decode (`Cf-Access-Jwt-Assertion`). Stateless JWT decode on the frontend — no session cookies. Identical to OT hosting architecture plan.

---

## 5. Interview Impact Ranking

Ranked by value for Senior Security Architect roles (Deloitte, Vercel, GitLab, Stripe, Anthropic):

### Tier 1 — Maximum Impact

**1. AI Governance Dashboard (`/admin/ai-agents/{id}`)** — Highest differentiation
- STRIDE + ATLAS threat modeling, agent trace observability, policy decisions per tool call
- Directly demonstrates the AgentGuard-to-CF merge — unique in portfolio
- Deloitte: maps precisely to "AI governance in cloud" — exact hot-button topic for 2026
- Anthropic: shows AI safety at infrastructure level, not just product layer

**2. Policy Violation + Exception Workflow (`/portal/request` + `/ops/findings`)** — Core narrative
- Multi-step form with live OPA policy check is the CloudForge story in a demo
- Policy-as-Code made tangible: "it blocked the deploy, here is the GRC override path"
- Universally legible to any hiring manager regardless of technical depth

**3. Compliance Framework Grid (`/ops/compliance`)** — Breadth signal
- 20+ frameworks visualized (NIST CSF, PCI-DSS, HIPAA, ISO 42001, TISAX) shows enterprise depth
- Automotive frames (ISO 21434, TISAX) differentiate for automotive sector narrative
- Deloitte / Stripe: high signal. Vercel / GitLab: less relevant.

### Tier 2 — Strong Supporting Evidence

**4. FinOps Dashboard (`/ops/costs`)** — Multi-cloud credibility
- Multi-provider spend breakdown (AWS + Azure + GCP) + anomaly alerts
- Chargeback by cost center shows enterprise org awareness (Big 4 context)

**5. Remediation Queue with DryRun (`/ops/remediation`)** — Engineering depth
- Tier 1/2/3 execution model with dry-run preview shows change management understanding
- Stripe: engineering excellence signal

### Tier 3 — Nice-to-Have

**6.** Admin Policy Editor — technically impressive, lower demo accessibility
**7.** Audit Log Viewer — required for enterprise credibility, low visual impact
**8.** User/Role Management — expected, not differentiating

---

## 6. Minimum Viable Demo (4-Screen Narrative)

The complete CloudForge story told in a 5-minute demo:

```
1. /portal/request — New resource request
   [select EC2 in ap-southeast-3 -> REGION-001 violation fires ->
    request exception with business case -> submit]

2. /ops/findings   — Operator triage
   [pending exception visible in queue ->
    approve it -> status transitions PENDING -> APPROVED]

3. /admin/ai-agents/{id} — AI governance
   [agent trace: tool call blocked by OPA policy ->
    STRIDE threat model for that agent type]

4. /ops/costs      — FinOps
   [anomaly alert: 340% S3 spike in payments-service ->
    chargeback breakdown showing payments cost center at 28%]
```

These 4 screens + ~8 API calls demonstrate: Policy-as-Code, GRC exception workflow, AI governance, and FinOps — the complete platform pitch.

---

## 7. Phased Build Plan

### Phase 1 — MVP (12-15 agent-hours)

**Goal:** Demoable. 4 screens. Real backend for exception workflow, static mock JSON for everything else.

**Screens:**
- `/portal/request` — MultiStep request form with OPA policy check
- `/ops` — Exception/findings queue (operator command center)
- `/admin/ai-agents/{id}` — AI agent detail with trace timeline
- `/ops/costs` — FinOps dashboard

**Backend connections:**
- Real: `POST /exceptions`, `GET /exceptions/pending`, `POST /exceptions/{id}/approve`, `POST /validate/exception`
- Mocked: findings, AI agent traces, cost data (static JSON in `src/lib/mock/`)

**Directory structure:**
```
frontend/
  src/
    components/
      layout/      — Sidebar, TopNav, RoleSwitcher (dev toggle)
      grc/         — ExceptionCard, ApproverChain, StatusBadge, PolicyViolationBanner
      finops/      — CostSummaryCard, AnomalyAlert, SpendChart
      ai/          — AgentCard, TraceTimeline, SecuritySignalBadge
      portal/      — MultiStepForm, ResourceCatalogCard, PolicyCheckResult
    pages/
      portal/Request.tsx
      ops/ExceptionQueue.tsx
      admin/AIAgentDetail.tsx
      ops/Costs.tsx
    lib/
      api.ts        — fetch wrapper + React Query hooks
      auth.ts       — mock auth with role switcher
      mock/         — findings.json, agents.json, costs.json
```

---

### Phase 2 — Polish (10-14 agent-hours)

**Goal:** Production-grade appearance. Looks like a real SaaS product.

**Additions:**
- Dark mode toggle (Tailwind `dark:` class strategy)
- Skeleton loading states on all data grids
- Empty state components (simple SVG inline)
- Responsive layout (mobile breakpoints for tables)
- `/admin/policies` — Monaco Rego editor (code-split, lazy loaded)
- `/ops/findings` — Full filterable TanStack Table (sortable, virtualized, 20+ columns)
- `/ops/compliance` — Framework grid with pass/fail per control category
- Error boundaries and toast notifications (sonner)

---

### Phase 3 — Advanced (15-20 agent-hours)

**Goal:** Portfolio differentiator. Demonstrates systems thinking beyond typical frontend work.

**Additions:**
- `/admin/ai-agents/{id}/threats` — Force-directed STRIDE threat graph (D3 or custom SVG)
- Agent trace timeline — animated span visualization with policy decision overlays
- Live policy evaluation — SSE from Go server for real-time OPA decisions
- `GET /metrics` Prometheus scrape rendered as recharts time-series dashboard
- Terraform module cost estimation inline in request form (mock $/mo estimate card)
- Compliance posture PDF export (jsPDF)

---

## 8. New Backend Endpoints Required

Listed in priority order for phased implementation:

```go
// Priority 1 — Phase 1 unblock (mock-friendly until added)
GET  /api/v1/findings              paginated, filterable by severity/provider/status
GET  /api/v1/agents                list AI agents with status
GET  /api/v1/costs/summary         aggregated spend by provider + period
GET  /api/v1/costs/anomalies       active anomaly alerts

// Priority 2 — Phase 2 completion
GET  /api/v1/compliance/status     per-framework pass/fail summary
GET  /api/v1/remediations          remediation queue with tier + status
POST /api/v1/remediations/{id}/dryrun
POST /api/v1/remediations/{id}/execute
GET  /api/v1/agents/{id}
GET  /api/v1/agents/{id}/traces

// Priority 3 — Phase 3 advanced
GET  /api/v1/policies              OPA policy list
POST /api/v1/policy/evaluate       ad-hoc policy check (evaluator.go handler exists, needs HTTP route)
GET  /api/v1/audit                 audit log stream (paginated)
GET  /api/v1/catalog/modules       Terraform golden module catalog
```

---

## 9. Recommended Project Structure

```
cloudforge/
  frontend/
    index.html
    vite.config.ts
    tailwind.config.ts
    tsconfig.json
    package.json
    src/
      main.tsx
      App.tsx                — Router + auth provider + React Query client
      lib/
        api.ts               — base fetch client + per-resource hooks
        auth.ts              — mock auth, role switcher, CF Access header decode
        mock/
          findings.json
          agents.json
          traces.json
          costs.json
          frameworks.json
      components/
        layout/              — AppShell, Sidebar, TopNav, RoleSwitcher
        ui/                  — shadcn/ui re-exports (Button, Card, Table, Badge, etc.)
        grc/                 — ExceptionCard, ApproverChain, StatusBadge, PolicyViolationBanner
        findings/            — FindingCard, SeverityBadge, MITRETagList, SLACountdown
        finops/              — CostSummaryCard, SpendChart, AnomalyAlertCard, ChargebackTable
        ai/                  — AgentCard, AgentStatusBadge, TraceTimeline, SecuritySignalBadge
        compliance/          — FrameworkGrid, ControlStatusRow, ComplianceScore
        remediation/         — DryRunPreview, RemediationTierBadge, ExecutionStatus
      pages/
        admin/
          Dashboard.tsx
          AIAgents.tsx
          AIAgentDetail.tsx
          Policies.tsx
          Users.tsx
          AuditLog.tsx
          SystemHealth.tsx
        ops/
          CommandCenter.tsx
          Findings.tsx
          FindingDetail.tsx
          RemediationQueue.tsx
          Costs.tsx
          Compliance.tsx
        portal/
          Dashboard.tsx
          Request.tsx
          MyRequests.tsx
          RequestDetail.tsx
          Catalog.tsx
      hooks/
        useExceptions.ts
        useFindings.ts
        useAgents.ts
        useCosts.ts
        useCompliance.ts
        useRemediations.ts
      types/
        grc.ts               — TypeScript interfaces matching grc/provider.go
        compliance.ts        — Matches compliance/finding.go
        finops.ts            — Matches finops/finops.go
        ai-governance.ts     — Matches ai-governance/models.go
        remediation.ts       — Matches pkg/remediation/types.go
        policy.ts            — Matches policy/evaluator.go
```

---

## 10. TypeScript Type Alignment

The Go domain models map directly to TypeScript interfaces. The Go structs are already JSON-tagged, so alignment is straightforward:

| Go Package | Go Type | TypeScript File | Notes |
|---|---|---|---|
| `internal/grc` | `ExceptionRequest`, `Approver`, `RiskAssessment` | `types/grc.ts` | All fields JSON-tagged |
| `internal/compliance` | `Finding`, `ComplianceMapping`, `CVEReference` | `types/compliance.ts` | Rich struct, ~40 fields |
| `internal/finops` | `CostRecord`, `AnomalyAlert`, `ChargebackReport` | `types/finops.ts` | Simple, clean |
| `internal/ai-governance` | `Agent`, `AgentTrace`, `Span`, `ThreatModel` | `types/ai-governance.ts` | Nested, use discriminated unions for `SpanData` |
| `pkg/remediation` | `RemediationRecord`, `DryRunResult`, `ValidationResult` | `types/remediation.ts` | Simple |
| `internal/policy` | `PolicyInput`, `PolicyResult`, `PolicyViolation` | `types/policy.ts` | Simple |

---

*Document generated by cf-frontend-planning agent, session-14-housekeeping team.*
*Next step: Phase 1 implementation — estimated 12-15 agent-hours.*
