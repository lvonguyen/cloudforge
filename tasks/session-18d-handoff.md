# Session 18D Handoff — Integration Wiring

## What was done

### 1. Multi-provider ticket wiring (Asana + Jira)
- `cmd/server/handlers_integration.go`: Added `providers` map, `ticketStore` (finding->ticket mapping), `selectProvider()`, `providerForFinding()`, `storeTicket()` methods
- `cmd/server/main.go`: Provider cascade: Asana (if `ASANA_PAT`) > Jira (if `JIRA_URL`) > Mock. Both real adapters now wired (were dead code before)
- `cmd/server/main_test.go`: Updated test server init with new fields
- All 7 integration handler tests pass, full server suite green

**Env vars for ECS (not yet set on task def):**
```
ASANA_PAT=op://Development/lvnio-asana-dev-token/credential
ASANA_WORKSPACE_GID=1212540665692548
ASANA_DEFAULT_PROJECT_GID=1213803357058798
JIRA_URL=https://lvn-jira-dev.atlassian.net
JIRA_USERNAME=liem@pvdsolutions.io
JIRA_API_TOKEN=op://Development/lvn-pvd-dev-jira-token/credential
JIRA_PROJECT_KEY=CVRT
```

### 2. 50 dummy personas
- `testdata/seed/personas.json`: 50 personas across 5 teams (security-ops, platform-eng, cloud-infra, grc, soc) x 5 roles x 2 seniority levels
- 29 base Gmail accounts from GmailBurners vault + Gmail+ aliases
- Distribution: 5 CBUs (nx:18, ns:9, mr:9, pl:9, sm:5)

### 3. Asana demo project
- **Project:** "Cloud Vulnerability Remediation Tracking" (GID: 1213803357058798)
- **Workspace:** vonguyen.io (1212540665692548)
- **Sections:** Triage (8), In Progress (6), Blocked (3), In Review (4), Resolved (4)
- **Tickets:** 25 seeded — 8 CRITICAL + 17 HIGH, linked to finding IDs, with persona assignees
- **1P updated** with project GID

### 4. Jira demo project
- **Site:** lvn-jira-dev.atlassian.net
- **Token:** `lvn-pvd-dev-jira-token` (liem@pvdsolutions.io, ATATT, expires 03/2027)
- **Project:** CVRT (Cloud Vulnerability Remediation Tracking), id: 10001
- **Tickets:** 25 seeded (CVRT-1 to CVRT-26), 21 open + 4 Done
- **1P updated** with project details

### 5. Threat Intel drilldown page
- `frontend/src/pages/ops/ThreatIntel.tsx`: Tabbed page (Overview + EPSS + KEV + GreyNoise + HIBP + OTX)
- Overview: 4 KPI cards + feed status list with click-to-navigate
- EPSS: Score distribution bars + top-20 table
- KEV: Exploited count + CRITICAL intersection + top-20 table
- GreyNoise/HIBP/OTX: Per-finding enrichment info cards
- Route: `/ops/threat-intel` in App.tsx
- Sidebar: "Threat Intel" added to Intelligence section (operator + viewer roles)
- tsc clean, 447 tests pass

### 6. PuppyGraph deployment
- **Status:** Deploying (EC2 replacement for public IP in progress)
- **Instance:** r6i.2xlarge (64GB, minimum supported), us-east-1a
- **AMI:** ami-083dcc3841cd6538b (PuppyGraph v0.113, 30-day free trial)
- **TEARDOWN BY: March 28, 2026** (~72h, ~$36 cost)
- TF module fixes: em-dash in SG description, duplicate tags, volume 50->64GB, public IP, path.module schema fix
- SG rules: operator IP + ECS ingress on 8081/8182/8184, PuppyGraph->RDS on 5432

### Dead/stale tokens discovered
- `lvnio-jiradev-token` (ATATT under liem@vonguyen.io) — not a member of any Jira site
- `lvn-jira-api-key-gbl` (ATCTT OAuth) — revoked/expired
- Both return 401 on all sites. Do NOT use.

## Files changed
```
M cmd/server/handlers_integration.go  (multi-provider + ticket store)
M cmd/server/main.go                  (Asana/Jira wiring, PuppyGraph TF)
M cmd/server/main_test.go             (test init with new fields)
A frontend/src/pages/ops/ThreatIntel.tsx  (TI drilldown page)
M frontend/src/App.tsx                (TI route)
M frontend/src/components/layout/Sidebar.tsx  (TI nav item)
A testdata/seed/personas.json         (50 dummy personas)
M deploy/terraform/environments/personal/main.tf  (PuppyGraph module)
M deploy/terraform/environments/personal/variables.tf  (PuppyGraph vars)
M deploy/terraform/modules/puppygraph/main.tf  (fixes: SG, tags, vol, IP, path)
```

## Parallel QA session

A `/qa-visual -e` ensemble is running in parallel against the full codebase.
- 3 Opus workers (quality-review, bug-discovery, security-audit) + Chrome visual sweep
- If QA flags integration-related issues (TI page, ticket viewport, Sidebar nav), fixes belong here
- If QA flags perf issues, defer to the perf audit session (see benchmarking handoff prompt)
- Coordinate: do NOT duplicate fixes across sessions

## Remaining for next session
- [ ] Set integration env vars on ECS task definition (ASANA_*, JIRA_*, PUPPYGRAPH_URL)
- [ ] Verify PuppyGraph UI accessible at http://<public-ip>:8081
- [ ] Verify graph queries from backend (POST /api/v1/graph/query)
- [ ] Invite dummy personas as Asana guests
- [ ] ADO integration (TBD — needs SBX token)
- [ ] PuppyGraph teardown by March 28 (gcal reminder set)
