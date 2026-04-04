# Session 16 Handoff

## Resume prompt

```
resume from tasks/session-16-handoff.md
```

## What happened in session 15

6 commits: KMS providers (AWS/Azure/GCP), export scripts, TF env + Dockerfile, Asana
viewport backend + frontend (Sheet drawer), merge script multi-cloud fix, gp3 TF change.
CT Lake reverted to management-only (27k events captured). Naming convention approved
(Option A: industry-generic). 2.6GB stale exports deleted. All tasks complete.

## Primary task: Redesign FindingDetail to embedded viewport pattern

### [!] Design change: Sheet drawer -> embedded viewport with tabs

The Sheet drawer (`RemediationSheet.tsx`) built in session 15 works but is the wrong UX
pattern. The user wants the **LinkedIn job detail / opportunity-tracker pattern** instead:

```
Current:                              Target:
┌────────────────────┐ ┌──────┐      ┌────────────┬───────────────────────────┐
│                    │ │Sheet │      │  Findings  │  Finding Detail (75%)     │
│  Finding Detail    │ │drawer│      │  List (25%) │  ┌─────────────────────┐ │
│  (full page route) │ │(over-│  ->  │  (compact)  │  │ Header + risk card  │ │
│                    │ │ lay) │      │             │  ├─────────────────────┤ │
│                    │ │      │      │             │  │ [Overview] [Remed]  │ │
│                    │ │      │      │             │  │ finding tab content  │ │
└────────────────────┘ └──────┘      │             │  ├─────────────────────┤ │
                                     │             │  │ [Asana][Jira][SNow] │ │
                                     │             │  │ ┌─────────────────┐ │ │
                                     │             │  │ │ viewport content│ │ │
                                     │             │  │ └─────────────────┘ │ │
                                     └────────────┴───┴─────────────────────┘ │
```

### Reference implementations

**opportunity-tracker** (`JobDetailPanel.tsx` + `JobsPage.tsx`):
- 3-column flexbox: FilterSidebar | CompactList (w-[380px] shrink-0) | DetailPanel (flex-1)
- `JobDetailPanel` has `mode: 'inline' | 'dialog'` prop
- Tabs: "Summary" | "Original" — Original renders iframe with 5s timeout + fallback link
- Outer container: `flex gap-0 flex-1 min-h-0 overflow-hidden`
- Desktop (>=1024px): inline. Mobile: Radix Dialog flyout.

**lvn-property-bros** (`ApplianceDetailPanel.tsx`):
- Overlay-only (no inline mode) with "details" | "original" tabs
- iframe proxied through CF Worker to bypass X-Frame-Options
- Loading spinner until `onLoad`, 20s timeout → fallback

### Implementation plan

#### Phase 1: List-detail split on Findings page

Transform `Findings.tsx` from table+preview(380px) to table+detail(flex-1):

1. **`FindingDetail.tsx`** — Add `mode` prop:
   ```typescript
   interface FindingDetailProps {
     mode?: 'page' | 'inline'
     findingId?: string      // used in inline mode (no useParams)
     onClose?: () => void    // inline mode close handler
   }
   ```
   - `page` mode: current behavior (full route, useParams, back button)
   - `inline` mode: no back button, uses prop `findingId`, renders as `<aside>`

2. **`Findings.tsx`** — Replace `FindingPreviewPanel` with inline `FindingDetail`:
   ```tsx
   <div className="flex gap-0 flex-1 min-h-0 overflow-hidden">
     {/* West: table (shrinks when detail open) */}
     <div className={cn(
       "overflow-y-auto transition-all",
       selectedId ? "w-[380px] shrink-0 border-r" : "flex-1"
     )}>
       {/* compact table when selectedId, full table otherwise */}
     </div>
     {/* East: detail (expands to ~75%) */}
     {selectedId && (
       <div className="flex-1 min-w-0 overflow-hidden">
         <FindingDetail mode="inline" findingId={selectedId} onClose={() => setSelectedId(null)} />
       </div>
     )}
   </div>
   ```

3. **Responsive**: Use `useMediaQuery('(min-width: 1024px)')` — inline on desktop, full route on mobile.

#### Phase 2: Integration viewport tabs (below finding content)

Add a second tab bar at the bottom of FindingDetail for integration viewports:

```tsx
{/* Finding content tabs (existing) */}
<Tabs value={activeTab} onValueChange={setActiveTab}>
  <TabsList>
    <TabsTrigger value="overview">Overview</TabsTrigger>
    <TabsTrigger value="remediation">Remediation</TabsTrigger>
    <TabsTrigger value="investigation">Investigation</TabsTrigger>
    <TabsTrigger value="comments">Comments</TabsTrigger>
  </TabsList>
  {/* tab contents */}
</Tabs>

<Separator />

{/* Integration viewport tabs (new) */}
<IntegrationViewport findingId={finding.id} ticket={ticket} />
```

**`IntegrationViewport.tsx`** component:
```tsx
<Tabs defaultValue={ticket?.provider ?? 'asana'}>
  <TabsList>
    <TabsTrigger value="asana" disabled={!hasAsana}>
      <ProviderIcon provider="asana" /> Asana
    </TabsTrigger>
    <TabsTrigger value="jira" disabled={!hasJira}>
      <ProviderIcon provider="jira" /> Jira
    </TabsTrigger>
    <TabsTrigger value="servicenow" disabled={!hasSNow}>
      <ProviderIcon provider="servicenow" /> ServiceNow
    </TabsTrigger>
  </TabsList>
  <TabsContent value="asana" className="flex-1 overflow-y-auto">
    {/* Reuse RemediationSheet CONTENT (not the Sheet wrapper) */}
    {/* TicketSummaryCard + ActivityTimeline + CommentForm */}
  </TabsContent>
  {/* other providers: placeholder or iframe to their UI */}
</Tabs>
```

**Key refactor:** Extract the content from `RemediationSheet.tsx` into a reusable
`TicketViewportContent.tsx` component. Then both the Sheet (mobile fallback) and the
inline viewport tabs can use the same content.

#### Phase 3: Compact table mode

When detail panel is open, the findings table switches to compact mode:
- Hide columns: description, region, category (keep: severity, title, provider, status)
- Reduce row height
- Highlight selected row

### Files to modify

| File | Change |
|------|--------|
| `FindingDetail.tsx` | Add `mode`/`findingId`/`onClose` props, conditional layout |
| `Findings.tsx` | Replace preview panel with inline FindingDetail, list-detail split |
| `RemediationSheet.tsx` | Extract content into `TicketViewportContent.tsx` |
| `TicketViewportContent.tsx` | **NEW** — reusable ticket content (summary + timeline + comments) |
| `IntegrationViewport.tsx` | **NEW** — tabbed viewport container for Asana/Jira/SNow |

### CSS layout from opportunity-tracker (copy this pattern)

```tsx
// Outer container (Findings.tsx)
<div className="flex gap-0 flex-1 min-h-0 overflow-hidden">
  {/* List */}
  <div className="w-[380px] shrink-0 overflow-y-auto border-r">
    {renderCompactTable()}
  </div>
  {/* Detail */}
  <div className="flex-1 min-w-0 overflow-hidden">
    <aside className="flex flex-col h-full border-l bg-surface overflow-hidden">
      {/* header + meta */}
      {/* finding tabs */}
      <div className="flex-1 overflow-y-auto">
        {/* tab content */}
      </div>
      {/* integration viewport tabs */}
    </aside>
  </div>
</div>
```

### Phase 4: QA visual ensemble

After all 3 phases are implemented and committed, run the full visual QA ensemble:

```
/qa-visual -e
```

This runs backend code review + frontend code review + Chrome visual QA with ensemble
cross-validation. Must pass before merging or deploying the viewport redesign.

---

## Sprint Roadmap (n+1 through n+5)

### Sprint n+1 (session 16): Embedded viewport redesign
- Phases 1-3 above (list-detail split + integration viewport + compact table)
- `/qa-visual -e` ensemble pass
- Deploy to CF Pages + verify in browser
- **Teardown:** N/A (no new infra)

### Sprint n+2: Real data pipeline + sanitization
- Run findings merge (script ready, ~9GB processing)
- Build sanitization script (Option A naming convention approved)
- Apply sanitization to canonical NDJSON files
- Verify no real org names leak (`grep -i real-org-names`)
- Build ECS one-shot bulk loader (`pgx.CopyFrom` from R2/S3)
- Apply gp3 TF change (`terraform apply`)
- Load sanitized sample (20-50k stratified) into RDS
- `/qa-visual -e` ensemble pass
- **Teardown:** Delete `data/enterprise-findings-{raw,merged,enriched}.ndjson` after canonical verified

### Sprint n+3: Findings persistence + query layer
- Build DB write path for findings (currently in-memory only)
- Add `resource_type` index + composite `(tenant_id, severity)`, `(tenant_id, status)`
- Wire ingest endpoint to postgres (POST `/api/v1/findings/ingest` -> DB persist)
- Add pagination + server-side filtering (currently client-side on 500 findings)
- Evaluate: upgrade db.t3.micro -> db.t3.small if loading >50k
- `/qa-visual -e` ensemble pass
- **Teardown:** Remove in-memory `DataStore` fallback once DB path is stable

### Sprint n+4: Multi-provider integration viewport
- Jira provider: implement `internal/integrations/jira/{client,adapter}.go`
- ServiceNow provider: implement `internal/integrations/servicenow/{client,adapter}.go`
- Wire Jira + ServiceNow tabs in `IntegrationViewport.tsx` (currently disabled/placeholder)
- Asana env vars on ECS (PAT, workspace GID, project GID)
- Webhook handlers for Jira + ServiceNow status sync
- End-to-end test: finding -> create ticket -> comment -> resolve -> status reflects
- `/qa-visual -e` ensemble pass
- **Teardown:** N/A

### Sprint n+5: Performance + polish + infra cleanup
- k6 load testing (deferred from session 10): 500 concurrent users, p95 latency targets
- `/perf-baseline` capture before/after
- `/benchmarks` comparison
- React 19 lazy() context error fix (LOW from session 10)
- MemoryAuditLogger ring buffer (LOW from session 10)
- Lighthouse audit via `/chrome-qa`
- Final `/qa-all -e` full pipeline ensemble (code + visual + benchmarks)
- **Teardown after demo:** Destroy personal AWS infra (ECS, RDS, Redis, ALB, NAT)
  ```bash
  cd deploy/terraform/environments/personal
  terraform destroy -auto-approve
  ```
  Verify: `aws ecs list-clusters --profile lvn-personal --region us-east-1`
  Verify: `aws rds describe-db-instances --profile lvn-personal --region us-east-1`
  Delete CF Pages project if no longer needed: `npx wrangler pages project delete cloudguard`
  Calendar reminder: **2026-04-20** (already set)

### Post-sprint: autonomous execution notes

Each sprint should be executable autonomously by resuming from this handoff. Pattern:
1. Read handoff -> plan mode -> execute phases -> commit
2. Run `/qa-visual -e` after final commit
3. Fix any findings from ensemble (max 3 iterations per AGENT_REVIEW_ITERATION_PROTOCOL)
4. Update handoff for next sprint (mark completed, add any carry-forward)
5. Sprint n+5 teardown: `terraform destroy` + verify zero running resources + delete CF Pages

---

## Secondary tasks (carry-forward)

### Run actual findings merge

Script is fixed (`scripts/merge-findings.py` now handles multi-cloud dedup).

```bash
uv pip install ijson

# AWS
python3 scripts/merge-findings.py --cloud aws \
  --output data/aws-findings-canonical.ndjson \
  data/enterprise-findings-all.ndjson \
  testdata/export-outputs/aws_securityhub_guardduty_20260324_190620.json

# Azure
python3 scripts/merge-findings.py --cloud azure \
  --output data/azure-findings-canonical.ndjson \
  testdata/export-outputs/azure_all_security_20260324_191728.json

# GCP (all-states)
python3 scripts/merge-findings.py --cloud gcp \
  --output data/gcp-findings-canonical.ndjson \
  testdata/export-outputs/gcp_all_findings_allstates_20260324_185736.json

# Verify
wc -l data/*-canonical.ndjson
```

Expected: ~500k AWS + 38k Azure + 25k GCP.

Delete after verification: `data/enterprise-findings-{raw,merged,enriched}.ndjson`,
partial export-outputs files.

### Build sanitization script

Apply Option A naming convention (memory: `project_naming_convention.md`):
- CBU replacements: hma->northstar, kus->meridian, etc.
- Process canonical NDJSON files
- Verify no real org names leak

### Apply TF changes

```bash
cd deploy/terraform/environments/personal
terraform plan  # verify gp3 change
terraform apply
```

### Wire Asana env vars on ECS

```
ASANA_PAT          -> op://Development/asana-cs-remediation-token/credential
ASANA_WORKSPACE_GID -> 1205437629727178
ASANA_DEFAULT_PROJECT_GID -> 1212451458473619
```

### Build findings persistence layer

Current findings served from in-memory JSON (no DB write path).
Plan: ECS one-shot bulk loader using `pgx.CopyFrom`.
See DB scaling analysis in session 15 — Option A (keep micro + gp3) now,
Option C (t3.small) when building persistence.

### Deploy + test Asana viewport

Rebuild Docker image, push to ECR, verify backend endpoints.
Frontend needs CF Pages rebuild with VITE_API_URL.

## Infrastructure context

| Resource | Details |
|----------|---------|
| ECS cluster | `aegis-personal` (us-east-1) |
| API | `https://api-personal.lvonguyen.com` |
| Frontend | `https://cloudguard.lvonguyen.com` (CF Pages) |
| JWT secret | SM `aegis-personal-secrets/jwt-secret` |
| Teardown | 2026-04-20 |

## Session 15 commits

```
9a12b92 perf(terraform): switch RDS storage from gp2 to gp3
2d39152 fix(scripts): multi-cloud dedup key + enrichment in merge-findings
988ff98 feat(integrations): add Asana remediation viewport (Sheet drawer)
fe3ba58 chore: add personal TF env + migration Dockerfile + session handoffs
d84d08c chore: add multi-cloud findings export/merge scripts
2d4a1af feat(secrets): implement AWS SM + Azure KV + GCP SM providers
```
