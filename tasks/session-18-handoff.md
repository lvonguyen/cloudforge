# Session 18 Handoff — 5 Decoupled Workstreams

## Resume prompt

```
resume from tasks/session-18-handoff.md — workstream {A|B|C|D|E}
```

## What happened in session 17

- Deployed both frontends (cloudguard + cloudaegis-demo) to CF Pages
- Ran ensemble QA (Phase A code triad): 3 Opus workers (quality-review, bug-discovery, security-audit)
- Fixed 10 FIX-priority findings in 1 commit: `0429c1e`
- 447 tests green, tsc clean
- Manual walkthrough by user surfaced 28 additional items (12 bugs, 12 features, 4 infra)
- Deep feature flag audit: 13 backend features wired but OFF
- Asana webhook created and live (secret saved to 1P)
- PuppyGraph wired but not deployed
- Bedrock Sonnet 4.6 wired but not enabled
- Brainstormed: 56-service taxonomy, naming standard, 300K seed generator, dummy user strategy

### Commits this session

```
0429c1e fix(viewport): resolve 10 ensemble QA findings from session 17
```

### Blocked items from session 17

- cloudguard.lvonguyen.com API auth: JWT signing secret mismatch between 1P and Secrets Manager
- Fly.io handoff had stale URL (aegis-api.fly.dev → actual: cloudforge-api.fly.dev / api.cloudforge-demo.lvonguyen.com)
- VITE_API_URL was missing /api/v1 prefix — fixed in redeploy

---

## Workstream A: Data Pipeline (aegis-seed)

**Goal:** Merge 322K+ real findings into a unified, sanitized dataset. Load to RDS Postgres.

**Resume:** `resume from tasks/session-18-handoff.md — workstream A`

### Input sources

| # | File | Findings | Size |
|---|------|----------|------|
| 1 | `testdata/export-scripts/output/scrubbed/*_aws_*_002652.json` | ~20K | Original Mar 6 AWS scrub |
| 2 | `testdata/export-scripts/output/scrubbed/scrubbed_azure_*_002937.json` | ? | Original Mar 6 Azure scrub |
| 3 | `testdata/export-scripts/output/scrubbed/scrubbed_gcp_*_002606.json` | ? | Original Mar 6 GCP scrub |
| 4 | `testdata/export-outputs/aws_*_190620.json` | ~237K | Mar 24 AWS SecurityHub+GuardDuty (1.3GB) |
| 5 | `testdata/export-outputs/azure_*_191728.json` | ~38K | Mar 24 Azure HMGNA (225MB) |
| 6 | `testdata/export-outputs/azure_*_190457.json` | ~1.5K | Mar 24 Azure KUS |
| 7 | `testdata/export-outputs/azure_*_190516.json` | ~445 | Mar 24 Azure HMA |
| 8 | `testdata/export-outputs/gcp_*_185736.json` | ~25K | Mar 24 GCP all states |
| 9 | `testdata/cspm/raw/*.json` | bonus | Pre-export raw (dedup catches overlaps) |

### Pipeline

```
Phase 1: Collect all sources (#1-9)
Phase 2: Dedup (canonical_rule_id + resource_id + account_id) → ~300K unique
Phase 3: Unified scrub
  - Re-ID: f-000001 through f-300000
  - CBU remap: hma→ns, kus→mr, hacc→pl, haea→nx, hmgma→sm
  - Account remap: account-hma-bldsearch-dev → account-ns-product-search-dev
  - Resource remap: {svc}-{cbu}-{app}-{env}-{seq} taxonomy
  - ARN scrub: replace real account IDs with synthetic 12-digit
  - IP scrub: RFC 5737 ranges (192.0.2.x, 198.51.100.x)
  - Preserve: real CVE IDs, real control IDs, real severity, real timestamps
Phase 4: Enrich
  - compliance_mappings: 80% of findings (ISO 27001, NIST CSF, HIPAA, PCI DSS, TISAX, CIS)
  - impacted_resources: 40% (derive from resource graph adjacency)
  - assignee: 30% (round-robin across 50 dummy personas)
  - tickets: 25% of HIGH/CRITICAL linked to Asana/Jira
  - attack paths: derive from resource adjacency
Phase 5: Jitter severity distribution (no round numbers)
Phase 6: Output
  - findings.json (~300K, unified schema)
  - attack-paths.json (derived)
  - tickets.json (linked)
  - resources.json (~20K unique)
  - accounts.json (~170 account-env combos)
Phase 7: Load to RDS Postgres
```

### Finding state distribution

```
ACTIVE (90%+):   new 35%, triaged 25%, assigned 20%, in_progress 10%
INACTIVE (~10%): resolved 60%, suppressed 20%, false_positive 15%, archived 5%
```

### Naming taxonomy — 56 services

```typescript
const CBUS = {
  ns: 'Northstar',  // hma → consumer digital
  mr: 'Meridian',   // kus → operations/finance
  pl: 'Polaris',    // hacc → regional ops
  nx: 'Nexus',      // haea → shared infra / ITSP
  sm: 'Summit',     // hmgma → group-level
}

// Pattern: {service_prefix}-{cbu}-{app}-{env}-{seq}
// Example: s3-ns-product-search-prd-00001

// 56 services across 7 infra types:
// Cloud (22), SaaS (10), On-prem (7), Hybrid (10), Self (7)
```

<details>
<summary>Full 56-service catalog (click to expand)</summary>

**Consumer Digital (Northstar)**
- ns-product-search: Product Search Platform (cloud)
- ns-ecommerce-web: E-Commerce Storefront (cloud)
- ns-iac-platform: Infrastructure Automation (cloud)
- ns-partner-incentives: Partner Incentive Portal (cloud)
- ns-secure-messaging: E2E Encrypted Messaging (cloud)
- ns-iot-telemetry: IoT Device Telemetry (cloud)
- ns-ciam-forgerock: ForgeRock Identity Cloud / CIAM (hybrid)

**Operations/Finance (Meridian)**
- mr-claims-mgmt: Claims Management System (cloud)
- mr-learning-platform: Learning Management (cloud)
- mr-mobile-payments: Mobile Payments Gateway (cloud)
- mr-bi-pipeline: BI Analytics Pipeline (cloud)
- mr-erp-sap: SAP S/4HANA ERP (hybrid)
- mr-erp-oracle: Oracle EBS Financials (hybrid)
- mr-crm-salesforce: Salesforce CRM (saas)

**Regional (Polaris)**
- pl-identity-svc: Identity Provider (cloud)
- pl-partner-portal: Partner Portal (cloud)
- pl-web-gateway: Web Application Gateway (cloud)

**Shared Infra / ITSP (Nexus)**
- nx-security-hub: Security Operations Center (cloud)
- nx-ai-platform: AI/ML Platform (cloud)
- nx-network-core: Core Network Services (cloud)
- nx-data-vault: Data Backup & Recovery (cloud)

**Group-Level (Summit)**
- sm-workflow-engine: Business Process Automation (cloud)

**ERP / Business-Critical**
(listed under Meridian above)

**Security / GRC Tooling**
- nx-grc-archer: RSA Archer GRC Platform (onprem)
- nx-cmdb-servicenow: ServiceNow CMDB (saas)
- nx-siem-splunk: Splunk Enterprise SIEM (hybrid)
- nx-pam-cyberark: CyberArk PAM Vault (onprem)
- nx-edr-crowdstrike: CrowdStrike Falcon EDR (saas)
- nx-vuln-qualys: Qualys VMDR Scanner (saas)
- nx-ad-onprem: Active Directory on-prem (onprem)
- nx-dns-infoblox: Infoblox DDI (onprem)

**Identity & Access Governance**
- nx-iga-sailpoint-iiq: SailPoint IdentityIQ Legacy (onprem)
- nx-iga-sailpoint-idn: SailPoint IdentityNow (hybrid)
- nx-sso-okta: Okta Workforce Identity (saas)

**Azure Shared Infrastructure**
- nx-expressroute-pri: ExpressRoute Primary East US (cloud)
- nx-expressroute-sec: ExpressRoute Secondary West EU (cloud)
- nx-hub-vnet: Hub VNet Transit Network (cloud)
- nx-azure-firewall: Azure Firewall Hub (cloud)
- nx-private-dns: Private DNS Zones (cloud)
- nx-bastion-hub: Azure Bastion Shared (cloud)
- nx-log-analytics: Log Analytics Workspace (cloud)
- nx-entra-id: Microsoft Entra ID (saas)
- nx-intune-mdm: Intune MDM/MAM (saas)
- nx-defender-cloud: Microsoft Defender for Cloud (saas)
- nx-key-vault-shared: Shared Key Vault PKI/Certs (cloud)
- nx-azure-policy: Azure Policy Governance (cloud)

**DR / BC Failover**
- nx-dr-pilot-light: DR Pilot Light us-west-2 (cloud)
- nx-dr-warm-standby: DR Warm Standby eu-west-1 (cloud)
- nx-bc-azure-asr: Azure Site Recovery (cloud)
- nx-bc-backup-vault: Cross-Region Backup Vault (cloud)

**CloudForge Platform (self)**
- nx-aegis-api: CloudForge API Gateway (cloud)
- nx-aegis-opa: Aegis OPA Policy Engine (cloud)
- nx-aegis-ingest: Findings Ingestion Pipeline (cloud)
- nx-aegis-webapp: Aegis Web Console (saas/cloudflare)
- nx-aegis-db: Aegis PostgreSQL Findings DB (cloud)
- nx-aegis-redis: Aegis Cache Session/Query (cloud)
- nx-aegis-otel: Aegis OTel Collector (cloud)

</details>

### CMDB notes

Every service entry gets a `cmdb_note` explaining deployment topology:
- Hybrid services explain which components are on-prem vs cloud
- SaaS services explain what agents/connectors run on-prem
- DR services explain RPO/RTO and failover topology

### Missing catalog entries to add

Add to `frontend/src/lib/mock/catalog.json`:
- `azure-entra-id` (identity, SaaS)
- `azure-intune` (identity, SaaS)
- `azure-defender` (security, SaaS)

### Acceptance criteria

- [ ] All 322K+ raw findings merged and deduped
- [ ] All findings use f-NNNNN ID format (no FIND- prefix)
- [ ] CBU/account/resource names follow {svc}-{cbu}-{app}-{env} taxonomy
- [ ] 80%+ findings have compliance_mappings populated
- [ ] Severity distribution has natural jitter (no round numbers)
- [ ] 90%+ findings ACTIVE, ~10% INACTIVE
- [ ] Delta indicators on KPI cards (+47 24h, -12 7d style)
- [ ] Output loaded to RDS Postgres via migration/seed script
- [ ] `--count` flag for 20K (dev) vs 300K (prod) output

---

## Workstream B: Frontend Bug Fixes

**Goal:** Fix all 12 bugs from the manual walkthrough.

**Resume:** `resume from tasks/session-18-handoff.md — workstream B`

| # | Page | Bug | Files to touch |
|---|------|-----|---------------|
| 1 | Investigation Board | Only f-00001 gets rich graph | `Investigations.tsx` — enrich client-side fallback when PuppyGraph is off |
| 2 | Findings overview | Flat round KPI numbers | Seed data fix (workstream A) + frontend delta indicators |
| 4 | Attack Surface | Scan dead, mock only | `handlers_asm.go` + `useOrgScan.ts` — wire real scan or improve mock |
| 5 | New Resource Request | Provider filter broken (Azure/GCP show AWS) | `Request.tsx` or catalog hook — filter resources by selected provider |
| 7 | NRR Step 2 | Validation fires on placeholders | Form component — treat placeholders as default values |
| 8 | NRR Step 4 | Deploy preview stuck forever | `Request.tsx` deploy preview step — add timeout + simulated completion |
| 9 | NRR Step 5 | No trace/audit for Submit | Wire OTel span on submit action |
| 12 | Trace Timeline | OK spans red, thin payload | `TraceTimeline.tsx` — green for OK, expand span payload schema |
| 15 | Command Center | AWS badge invisible on dark bg | `ProviderBadge.tsx` — add light variant for dark backgrounds |
| 16 | Role Switcher | All roles see same sidebar | `RoleSwitcher.tsx` + sidebar — "Demo Viewer (all modules)" label + real RBAC gating |
| 18 | Spend | $2823K should be $2.8M | Number formatter utility — use M notation above 999K |
| 23 | Global | Base font too small at 100% zoom | Root CSS `font-size` bump (14px→15-16px) or Tailwind config |

### Acceptance criteria

- [ ] Each bug verified in Chrome after fix
- [ ] No test regressions (447+ tests passing)
- [ ] tsc --noEmit clean
- [ ] Deploy to cloudaegis-demo.lvonguyen.com for visual verification

---

## Workstream C: Frontend Features

**Goal:** Implement UI/UX features from walkthrough.

**Resume:** `resume from tasks/session-18-handoff.md — workstream C`

| # | Page | Feature | Complexity |
|---|------|---------|-----------|
| 3 | Findings table | Date First Observed + Resource ID columns + column picker for more metadata | Medium |
| 6 | NRR | IaaS/SaaS/PaaS service model dropdown | Low |
| 13 | Trace Timeline | Drag handle for height-adjustable panel | Medium |
| 17 | Sidebar | Collapsible role-scoped module groups (Admin/Operator/Requester) | Medium |
| 23 | Global | Font size bump for accessibility | Low |
| 28 | Trace Timeline | Expanded traceview with real OTel spans for all critical paths | Medium (blocked on E enabling OTel) |

### Pagination (server-side)

When workstream E enables the pagination API:
- Max 150 items per page
- 10+ pages with back/forward navigation
- Page size selector (25 / 50 / 100 / 150)
- URL-synced page state (?page=2&limit=150&severity=CRITICAL)

### Acceptance criteria

- [ ] Each feature visually verified in Chrome
- [ ] Keyboard navigation works for new components
- [ ] No test regressions
- [ ] Deploy + screenshot

---

## Workstream D: Integration Wiring

**Goal:** Wire Asana, Jira, ADO, TI feeds, PuppyGraph, dummy users.

**Resume:** `resume from tasks/session-18-handoff.md — workstream D`

### Asana

- PAT: `op://Development/lvnio-asana-dev-token/credential`
- Workspace: vonguyen.io (1212540665692548)
- Project: integration-testing (1213740188136410)
- Webhook: LIVE (GID 1213802067759557, secret in 1P `aegis-asana-webhook-secret`)
- [ ] Create demo project "Cloud Vulnerability Remediation Tracking"
- [ ] Seed 20-30 dummy tickets linked to HIGH/CRITICAL findings
- [ ] Invite 50 guest users (Gmail+ aliases from GmailBurners vault)

### Jira

- PAT: `op://Development/lvnio-jiradev-token/credential`
- Also: `op://Development/lvn-jira-api-key-gbl/credential`
- [ ] Create demo project
- [ ] Seed 20-30 dummy tickets
- [ ] Create 10 free-tier user accounts (burner Gmails)
- [ ] Update 1P item with project IDs, tenant IDs

### ADO

- SBX token: TBD (need to create or locate)
- [ ] Eval Stakeholder access for dummy users (free, unlimited)
- [ ] Create PMO tracking board
- [ ] Seed work items

### Dummy Users — 50 personas

```
GmailBurners vault: 31 accounts (vault ID: qotsasr24v67p7ob7fbdc7wcqq)
Strategy: 31 base + Gmail+ aliases = 50+ personas at $0

Personas across 5 teams × 5 roles × 2 seniority:
  Teams: security-ops, platform-eng, cloud-infra, grc, soc
  Roles: analyst, engineer, lead, manager, architect
```

### TI Module

- [ ] Research SaaS TI feed UX (Wiz, CrowdStrike Falcon Intel, Recorded Future, Mandiant)
- [ ] Design drilldown view: recent entries, enrichment stats, query interface
- [ ] Wire Command Center TI sidebar items (#14) to new module
- [ ] Implement feed detail pages for EPSS, CISA KEV, GreyNoise, HIBP, OTX

### PuppyGraph

- TF module exists: `deploy/terraform/modules/puppygraph/`
- [ ] Deploy PuppyGraph instance
- [ ] Set PUPPYGRAPH_URL on ECS task definition
- [ ] Verify graph queries return real traversal data
- [ ] Add context annotations to each graph explaining significance/blast radius

### Acceptance criteria

- [ ] Asana tab in IntegrationViewport shows real ticket data
- [ ] Jira tab shows real tickets
- [ ] TI feed cards are clickable with drilldown views
- [ ] Investigation Board shows rich graphs for all findings
- [ ] 50 dummy users active across Asana + Jira

---

## Workstream E: Infrastructure + Performance

**Goal:** DB upgrade, enable feature flags, pagination API, performance audit, deploy verification.

**Resume:** `resume from tasks/session-18-handoff.md — workstream E`

### DB Upgrade

```
Current:  RDS db.t3.micro (1GB RAM) — will OOM on 300K load
Target:   RDS db.t3.medium (4GB) or db.t3.large (8GB)
Account:  lvn-personal (431330216246), us-east-1
```

- [ ] Upgrade RDS instance type
- [ ] Verify 300K finding load + index creation
- [ ] Test query performance (filter, sort, paginate 300K)

### Enable Feature Flags

Set on ECS task definition:

```
AEGIS_AI_ENABLED=true
AEGIS_AI_REGION=us-east-1
AEGIS_AI_MODEL=us.anthropic.claude-sonnet-4-6
AEGIS_TRACING_ENABLED=true
AEGIS_SAMPLING_RATE=1.0
ASANA_WEBHOOK_TOKEN=<from 1P aegis-asana-webhook-secret>
JIRA_URL=<from 1P lvnio-jiradev-token setup>
PUPPYGRAPH_URL=<from TF module output>
GREYNOISE_API_KEY=<if available in 1P>
HIBP_API_KEY=<if available in 1P>
OTX_API_KEY=<if available in 1P>
```

### Pagination API

Backend already has paginated endpoints — verify and extend:

```
GET /api/v1/findings?page=1&limit=150&severity=CRITICAL&sort=ai_risk&order=desc
GET /api/v1/findings/stats  (server-side KPI counts — no full scan)
GET /api/v1/findings?q=search  (BM25 search, already built)
```

- [ ] Verify pagination params work end-to-end
- [ ] Add /findings/stats endpoint if missing (severity counts, SLA breached, auto-rem)
- [ ] Max 150 per page, 10+ pages with cursor/offset

### Performance Audit

| Concern | Fix |
|---------|-----|
| recharts (119KB) loaded on every page | Lazy load only on Dashboard/Spend |
| 300K client-side filter/sort | Move to server-side (already built) |
| KPI counts from full array | /findings/stats API endpoint |
| useAttackPaths(1, 200) on every FindingDetail mount | Lazy: fetch only when Investigation tab active |
| Bundle: 200KB index.js | Code-split by route (already lazy — verify) |

### Deploy Verification

- [ ] Verify cloudguard.lvonguyen.com loads and authenticates (fix JWT secret mismatch)
- [ ] Verify cloudaegis-demo.lvonguyen.com loads with DEMO_MODE
- [ ] Verify api-personal.lvonguyen.com/api/v1/findings returns paginated data
- [ ] Verify api.cloudforge-demo.lvonguyen.com/health returns 200
- [ ] Fix VITE_API_URL to include /api/v1 prefix in all deploy scripts
- [ ] Fix JWT: generate HS256 JWT at build time using secret from SM (not 1P raw key)

### Acceptance criteria

- [ ] 300K findings load to Postgres in <5 minutes
- [ ] /findings?page=1&limit=150 responds in <200ms
- [ ] /findings/stats responds in <50ms
- [ ] All 13 feature flags enabled and verified
- [ ] Both frontends load in <2s (LCP)
- [ ] No client-side OOM on 300K dataset

---

## Cross-Session Dependencies

```
A (data) ─────────────────────────────────────────────────────────
  │  outputs: findings.json, seed SQL, naming taxonomy
  │
B (bugs) ─────────────────────────────────────────────────────────
  │  independent — can start immediately
  │  benefits from A: #1 (investigation graphs) and #2 (jitter) resolved by seed data
  │
C (features) ──────────────────────────────────────────────────────
  │  independent — can start immediately
  │  benefits from E: pagination API needed for 300K-scale table
  │
D (integrations) ──────────────────────────────────────────────────
  │  partially blocked on A: dummy tickets need finding IDs from seed
  │  can start: Asana/Jira project setup, dummy user creation, TI research
  │
E (infra) ─────────────────────────────────────────────────────────
     partially blocked on A: DB load needs seed data
     can start: DB upgrade, feature flags, performance audit, deploy fixes
```

**Optimal execution order:**
1. Start A + B + C in parallel (fully independent)
2. D and E start immediately on non-blocked tasks
3. A's output feeds D (ticket seeding) and E (DB load) when ready

---

## 1P Reference

| Item | Vault | UUID | Purpose |
|------|-------|------|---------|
| SA token | Development | `yrqd4x7zsye45ftzj4nimnvavi` | Service account (Automation + Development + GmailBurners) |
| Asana PAT | Development | `tji7y2jgwfmzb7ijuj6x7nk454` | lvnio-asana-dev-token |
| Asana WH secret | Development | `dd732qytenwg4s75ghob6samky` | aegis-asana-webhook-secret |
| Asana remediation | Development | `3s5t46lwhhv65hvzl2cigtanfm` | asana-cs-remediation-token |
| Jira PAT | Development | `wolozhfbw7bocglcjfmuyrbxte` | lvnio-jiradev-token |
| Jira API key | Development | `lxkulrzjec7vzwhx7xb5ou4b2y` | lvn-jira-api-key-gbl |
| JWT secret | Development | ? | aegis-personal-jwt-secret |
| GmailBurners | GmailBurners | vault: `qotsasr24v67p7ob7fbdc7wcqq` | 31 burner Gmail accounts |

## Infrastructure Context

| Resource | Details |
|----------|---------|
| ECS cluster | `aegis-personal` (us-east-1) |
| API (personal) | `https://api-personal.lvonguyen.com` (CF → ALB → ECS) |
| API (portfolio) | `https://api.cloudforge-demo.lvonguyen.com` (Fly.io) |
| Frontend (personal) | `https://cloudguard.lvonguyen.com` (CF Pages) |
| Frontend (portfolio) | `https://cloudaegis-demo.lvonguyen.com` (CF Pages) |
| RDS | db.t3.micro → upgrade to db.t3.medium+ |
| Redis | cache.t3.micro |
| AWS profile | `lvn-personal` (431330216246) |
| Teardown deadline | 2026-04-20 |
