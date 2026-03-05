# Continuation Prompt: Mock Data Bulk + Postgres Backends

**Run after:** /compact
**Pattern:** L0 Distill Agent -> Agent Teams -> Opus Distiller

---

## L0 Distill Agent Instructions

Before spawning any workers, run this as a Plan agent to read context and produce the launch plan:

**Read these files first:**
1. `tasks/execution-plan.md` — overall sprint plan and architecture
2. Memory: check MEMORY.md for current state
3. `frontend/src/lib/mock/findings.json` — existing finding schema (8 entries)
4. `frontend/src/lib/mock/agents.json` — existing agent schema (4 entries)
5. `frontend/src/lib/mock/costs.json` — existing cost schema
6. `frontend/src/lib/mock/traces.json` — existing trace schema (2 entries)
7. `frontend/src/lib/mock/frameworks.json` — existing framework schema (6 entries)
8. `migrations/001_exception_management.sql` — existing Postgres schema
9. `internal/grc/postgres_provider.go` — existing Postgres provider pattern
10. `frontend/src/types/*.ts` — all TypeScript type definitions

**Then produce:**
- Exact field schemas for each mock file (derived from existing entries + TS types)
- Agent assignments with file paths and entry counts
- Postgres migration numbers and table designs
- Dependency ordering

---

## Workstream A: Frontend Mock Data (4 parallel agents)

### Agent Mock-Findings
**File:** `frontend/src/lib/mock/findings.json`
**Target:** 80 entries (currently 8)
**Schema:** Match existing finding shape exactly (see first entry for all fields)
**Distribution:**
- Provider: 52 AWS (65%), 20 Azure (25%), 8 GCP (10%)
- Severity: 8 CRITICAL (10%), 20 HIGH (25%), 28 MEDIUM (35%), 24 LOW (30%)
- Types: vulnerability, misconfiguration, network_exposure, iam_risk, data_exposure, compliance_drift
- Status: 50 open, 15 in_progress, 10 resolved, 5 suppressed
- Environments: 40% production, 30% staging, 20% development, 10% sandbox

**Realism requirements:**
- Use real CVE IDs (CVE-2024-xxxx, CVE-2025-xxxx range)
- AWS accounts: `acme-payments-prod` (123456789012), `acme-data-lake-dev` (234567890123), `acme-shared-services` (345678901234), `acme-networking-hub` (456789012345), `acme-security-tooling` (567890123456), etc. (10-15 unique accounts)
- Azure subs: `shared-services-hub`, `corp-identity-prod`, `workload-finance-prod`, `workload-hr-dev`, `platform-monitoring` (6-8 unique)
- GCP projects: `analytics-data-warehouse`, `ml-platform-prod`, `bigquery-finance`, `gke-ml-serving` (4-5 unique)
- Regions: us-east-1, us-west-2, eu-west-1, ap-southeast-1 (AWS); eastus, westeurope, southeastasia (Azure); us-central1, europe-west1 (GCP)
- Resource types: EC2, S3, RDS, Lambda, EKS, IAM roles (AWS); VMs, Storage, AKS, Key Vault, NSG (Azure); BigQuery, GKE, Cloud SQL (GCP)
- EPSS scores: realistic distribution (most < 0.1, some high for critical CVEs)
- MITRE ATT&CK: use real tactic/technique IDs
- SLA dates: realistic based on severity (Critical 24h, High 7d, Medium 30d, Low 90d)
- Auto-remediatable: ~30% of findings (mostly misconfigs)

### Agent Mock-Agents-Traces
**Files:** `frontend/src/lib/mock/agents.json` (4->12) + `frontend/src/lib/mock/traces.json` (2->10)
**Agent types:** risk-scorer, remediation-dispatcher, compliance-mapper, threat-intel-enricher, anomaly-detector, policy-evaluator, triage-router, report-generator, finding-deduplicator, blast-radius-analyzer, sla-enforcer, drift-detector
**Trace diversity:** Mix of success/warning/error, varying durations, different span depths

### Agent Mock-Costs-Remediations
**Files:**
- `frontend/src/lib/mock/costs.json` — expand with 15+ services, 10+ accounts, monthly trends, 3-5 anomalies
- `frontend/src/lib/mock/remediations.json` (NEW) — 50 entries across Tier 1/2/3, mixed statuses (pending/executing/completed/failed/rolled_back), match remediation types from `internal/remediation/` domains

**Cost realism:**
- Total monthly: ~$2.8M (realistic for 3,500 accounts)
- AWS: ~$1.8M (EC2 40%, RDS 15%, S3 10%, Lambda 8%, EKS 12%, other 15%)
- Azure: ~$700K (VMs 35%, AKS 20%, Storage 15%, SQL 15%, other 15%)
- GCP: ~$300K (BigQuery 45%, GKE 25%, Cloud SQL 15%, other 15%)
- YoY trend: +12% growth
- 3-5 anomalies: sudden spike in a dev account, unusual egress, new service adoption

### Agent Mock-Policies-Users-Audit
**Files:**
- `frontend/src/lib/mock/policies.json` (NEW) — 30 policies across region/cost/network/tagging/encryption/iam categories. Match `frontend/src/types/policy.ts` type shape.
- `frontend/src/lib/mock/users.json` (NEW) — 18 users (6 admin, 6 operator, 6 requester) with realistic enterprise names/emails/departments
- `frontend/src/lib/mock/audit-log.json` (NEW) — 60 entries, mixed actions (exception.created, policy.evaluated, remediation.executed, agent.invoked, user.role_changed, etc.)

**Also update hooks to import new files:**
- `frontend/src/hooks/useRemediations.ts` — import from mock/remediations.json instead of empty array

---

## Workstream B: Postgres Migrations (2 parallel agents)

### Agent Migration-Core
**File:** `migrations/002_findings_and_compliance.sql`
**Tables:**
- `findings` — mirrors mock JSON schema (id, source, title, severity, cloud_provider, region, account_id, resource_id, status, ai_risk_score, epss, cves JSONB, mitre_tactics TEXT[], compliance_mappings JSONB, remediation TEXT, auto_remediatable BOOL, sla_deadline TIMESTAMPTZ, created_at, updated_at)
- `compliance_frameworks` — (id, name, version, category, control_count, passing_count, score NUMERIC, last_assessed TIMESTAMPTZ)
- `compliance_mappings` — (finding_id FK, framework_id FK, control_id, control_title, section, severity)
- Proper indexes on severity, cloud_provider, status, account_id

### Agent Migration-Operations
**File:** `migrations/003_operations_and_agents.sql`
**Tables:**
- `ai_agents` — (id, name, type, status, model, purpose, last_active, total_invocations BIGINT, avg_latency_ms INT, error_rate NUMERIC, created_at)
- `agent_traces` — (id, agent_id FK, action, status, started_at, completed_at, duration_ms, token_count INT, spans JSONB)
- `remediations` — (id, finding_id FK, handler, tier INT, status, dry_run_result JSONB, executed_at, completed_at, rolled_back_at, executor_email)
- `cost_summaries` — (id, period_start DATE, period_end DATE, cloud_provider, account_id, service, amount NUMERIC, currency, tags JSONB)
- `audit_log` — (id, action, actor_email, actor_role, target_type, target_id, result, details JSONB, timestamp TIMESTAMPTZ)
- `users` — (id, email, name, role, department, last_login TIMESTAMPTZ, created_at)
- Proper indexes on all FK columns, timestamps, status fields

### Agent Seed-Data
**File:** `migrations/004_seed_data.sql`
**Generate INSERT statements matching the mock JSON data** — same accounts, findings, agents, costs.
This enables `make seed` to populate a local Postgres with demo data matching the frontend.

---

## Workstream C: Hook Updates (1 agent, after A completes)

Update hooks that reference empty stubs or inline mocks to use new mock files:
- `useRemediations.ts` — import from `mock/remediations.json`
- Update inline MOCK_ constants in `CommandCenter.tsx`, `RequestDetail.tsx` to import from centralized mock files
- Add `usePolicies.ts`, `useUsers.ts`, `useAuditLog.ts` hooks importing from new mock files
- Wire into existing pages: `Policies.tsx`, `Users.tsx`, `AuditLog.tsx`

---

## After All Agents Complete: Opus Distiller

Spawn Opus distiller to:
1. Verify all mock JSON files parse correctly (`node -e "JSON.parse(fs.readFileSync(...))"`)
2. Verify provider distribution matches targets (65/25/10)
3. Verify severity distribution matches targets
4. Verify Postgres migrations have no syntax errors (`psql -f ... --dry-run` or parse check)
5. Verify all TypeScript compiles (`npx tsc --noEmit`)
6. Verify Go builds (`go build ./...`)
7. Produce compressed summary for main context

---

## L0 Pattern Notes

If this L0 distill -> agent team -> Opus distiller pattern works well:
- Update `/Users/lvonguyen/repos/remote/gh/reference/env-config/shared/standards/.claude/` with the pattern
- Document in CLAUDE.md under Agent Workflow as "L0 Plan-Feed Pattern"
- Key insight: L0 reads ALL context files before spawning, ensuring workers get precise schemas
- Prevents schema drift between workers (L0 normalizes the field definitions)
- Opus distiller validates cross-agent consistency (provider counts, FK references, type alignment)
