# Changelog

All notable changes to Cloud Aegis are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

### Added

- Rust hot-path library (`libaegispath`) for attack path BFS computation via CGo FFI with rayon parallelism (Sprint I+1)
- `ComputeAttackPaths()` and `LoadAndSerializeFindings()` Go bridge functions (Sprint I+2)
- Criterion benchmarks for Rust attack path computation (Sprint I+1)
- ws-server connection pooling + health check registration (Sprint I+3)
- Performance baseline document with Go vs Rust benchmark comparison (Sprint I+5)
- Cloud service icons for resource catalogue items (Sprint N+6)
- ProviderBadge enhanced with inline ProviderIcon SVGs (Sprint N+6)

### Fixed

- QA iteration 2: Vec capacity UB, edge_type passthrough, 64MB FFI input cap, serialization limit (Sprint I+4)
- QA iteration 3: C.int truncation fix, staticlib for deployment, strip_prefix ID renumbering (Sprint I+4)

### Changed

- Renamed CloudForge to Cloud Aegis across README, ADRs, and frontend README (Sprint N+6)
- Custom domain updated to cloudaegis-demo.lvonguyen.com (Sprint N+6)

### Added (prior sprints)

- **Sprint E**: Client-side mock attack path generator for standalone demo; `AttackPathMiniGraph` embedded in `FindingDetail` Investigation tab (Wiz pattern) (Sprint E)
- **Sprint E**: `SecurityGraph` focus mode — BFS 2-hop subgraph from selected node; connected-only default (hides isolated nodes) (Sprint E)
- **Sprint E**: AI cost budget guard — `MonthlyBudgetCents` config, `ErrBudgetExhausted` error, enforced before enrichment calls (Sprint E)
- **Sprint E**: Extended Bedrock enrichment — confidence scoring field, Opus/Sonnet tier routing based on finding severity (Sprint E)
- **Sprint E**: Container mock data — 3 clusters with realistic K8s topology for `GET /api/v1/containers` (Sprint E)
- **Sprint E**: `GET /api/v1/ai/usage` endpoint — AI budget status, admin-only (Sprint E)
- **Sprint D**: `POST /api/v1/ai/nlq` — natural language query handler (`handlers_nlq.go`) (Sprint D)
- **Sprint D**: DSPM data classification surface — sensitivity labels on findings (Sprint D)
- **Sprint D**: Security graph page (`/ops/security-graph`) with ReactFlow visualization (Sprint D)
- **Sprint D**: Investigation board page with kanban-style investigation tracking (Sprint D)
- **Sprint D**: `LayoutSwitcher` component with layout presets (list, split, full) (Sprint D)
- **Sprint C**: Viewer read-only surface — `/ops/findings`, `/ops/compliance`, `/ops/agents` + traces; 13 RBAC tests (Sprint C)
- **Sprint C**: Choke point detection — cross-path resource frequency analysis; amber card + dashed border highlights (Sprint C)
- **Sprint C**: Clickable metric cards — 6-card grid (CRIT/HIGH/MED/LOW/SLA/AutoRem) as filter toggles (Sprint C)
- **Sprint C**: Filter pills — collapsible sidebar, horizontal pills with dropdown checkboxes (Sprint C)
- **Sprint C**: Kanban remediation pipeline — List/Kanban toggle, `@hello-pangea/dnd`, demo-only drag (Sprint C)
- **Sprint C**: Inline preview panel — 380px split layout, single-click=preview, double-click=navigate, arrow keys (Sprint C)
- **Sprint C**: NLQ bar frontend — `NLQueryBar.tsx` with Cmd+K shortcut (Sprint C)
- **Sprint C**: Enhanced lifecycle timeline — color-coded icons, synthetic events, actor info (Sprint C)
- **Sprint C**: 4 new data layer toggles — compliance, workflow, time window, AI risk score (Sprint C)
- **Sprint C**: Blast radius badge — resource count on `PathCard`, color-coded by threshold (Sprint C)
- **Sprint C**: Container security view — `GET /api/v1/containers` + expandable K8s tree (`handlers_containers.go`) (Sprint C)
- **Sprint B**: `actorFilter` 400 rejection (was truncation at >255 chars); `resultFilter` + `searchFilter` capped (Sprint B)
- **Sprint B**: `RoleViewer` Go constant + rank 0 + `groupRoleMap` entry + 13 backend RBAC tests (Sprint B)
- **Sprint B**: Compliance drill-down drawer — `FrameworkDetailDrawer` opens on row click with `https://` scheme-guarded doc links (Sprint B)
- **Sprint B**: Portal dashboard hooks — `useMyExceptions`, `useExceptions` with try/catch + mock fallback (Sprint B)
- **Sprint B**: `useException(id)` hook + `RequestDetail` API wiring; `approver_chain ?? []` + conditional timeline (Sprint B)
- **Sprint B**: `FRAMEWORK_PROFILES` + `getThreatModelForAgent` — per-framework STRIDE data (Sprint B)
- **Sprint B**: Admin dashboard 4 KPI hooks + computed KPIs + `FALLBACK_KPI` named constant (Sprint B)
- Performance infrastructure: pprof dev endpoint (127.0.0.1:6060, dev-only), enrichment benchmarks (GetCached_Hit/Miss, EvictExpired_5000), `make bench` + `make profile` targets (Sprint A+)
- Frontend performance: `useDeferredValue` for search inputs in Findings + Catalog, vendor chunk splitting (@xyflow 180KB, recharts 379KB, @tanstack 60KB) (Sprint A+)
- Lighthouse CI budget: performance >= 90, TTI < 2s, LCP < 2.5s, CLS < 0.1 (Sprint A+)

### Fixed

- **Sprint E**: Gitleaks CI `continue-on-error` to prevent false-positive blocks on testdata fixtures (Sprint E)
- **Sprint D**: Production build errors in graph pages (D-15..D-17) (Sprint D)
- **Sprint D**: Chrome QA route sweep — 4 findings resolved (Sprint D)
- **Sprint B**: 11 agent review findings across 7 files (Sprint B)
- **go.mod**: module path `test/example` → `cloudforge` with full dependency resolution (Sprint A)
- **crypto/rand**: `math/rand` → `crypto/rand` in secrets memory_provider (CSPRNG for UUID generation) (Sprint A)
- **EnrichmentService**: `sync.Mutex` → `sync.RWMutex` for concurrent cache reads; O(n^2) bubble sort → `sort.Slice` in eviction (Sprint A)
- **Audit log**: `parsePagination` moved before `auditLogger.List` so Limit uses client-requested perPage (Sprint A)
- **CORS**: `X-CloudForge-Role` header only allowed in dev mode (was exposed in prod) (Sprint A)
- **Tenant middleware**: X-Tenant-ID header fallback gated on JWT claims presence (Sprint A)
- **Entra ID**: `fmt.Sprintf` → `url.Values.Encode()` for token request body (proper percent-encoding) (Sprint A)
- **redactSecret**: full `***REDACTED***` only — removed partial prefix/suffix reveal (Sprint A)
- **OPA**: `LoadPolicies` always updates default query key (was stale after first load) (Sprint A)
- **Attack paths**: `canConnect` gate for cross-region buildChain fallback; outer-loop dedup check for lateral movement (Sprint A)
- **Identity handler**: `errors.Is(err, ErrNotFound)` → 404, other errors → 500 (was blanket 404) (Sprint A)
- **Frontend auth**: `localStorage` → `sessionStorage` for role key (prevents cross-session persistence) (Sprint A)
- **useFindings**: per-query `{ data, usingMockData }` return (was module-level mutable sentinel) (Sprint A)
- `golang.org/x/sync` promoted from indirect to direct in `go.mod` (directly imported for `singleflight`)
- Dead `Request` field removed from OPA evaluation input in enrichment handler (never read by `EvaluateToolAccess`)
- Findings table header now sticky during scroll (fixed intermediate `overflow-x-auto` scroll context)
- Provider badges switched to text-only for readability (SVG icons illegible at badge size)

### Changed

- **Sprint E**: Real-data transform pipeline — 9000 anonymized HAEA findings; uploaded to R2 bucket; test fixture IDs updated (Sprint E)
- **Sprint E**: `POST /api/v1/secrets/scan` — changed from GET with query param to POST with body (content in body) (Sprint E)
- Resource-scoped RBAC (ADR-013 Accepted): `ResourceScope` in JWT claims with `Scopeable` interface — findings and attack paths filtered by account, region, environment, business unit (Sprint 8B)
- Finding ingestion endpoint: `POST /api/v1/findings/ingest` with SHA-256 dedup cache, 24h TTL, admin-only (Sprint 9A)
- Finding integrity hashing: tamper-evident SHA-256 hash on all findings at load time (Sprint 9B, STRIDE T-01)
- Real audit logging: `AuditLogger` interface with `MemoryAuditLogger` + `ZapAuditLogger`, integrity-hashed entries, merged with mock audit data (Sprint 10A)
- Rollback state encryption: AES-256-GCM `EncryptedStateStore` with env-var key, random nonce (Sprint 10B, STRIDE T-02)
- CI enforcement: gosec `-severity high`, Trivy `exit-code 1`, Codecov `fail_ci_if_error true`, frontend vitest gate, integration tests, `codecov.yml` (Sprint 8A)
- Documentation review: HLD v3.0, 4 new ADRs (009-012), 3 new runbooks (07-09), cross-cutting fixes
- Frontend planning doc — 18-screen React/Vite UI across Admin, Operator, and Requester role views with phased build plan and TypeScript type alignment (`docs/frontend-planning.md`)
- IaC planning doc — Terraform module catalog, Rego policy expansion, two-track OPA architecture, Cloud Run + CF Pages deployment design (`docs/iac-planning.md`)
- ADR-013 status: Proposed to Accepted (resource-scoped RBAC implemented)
- Threat model checklist: T-01 (integrity hashing) and T-02 (rollback encryption) checked off
- npm audit CI gate: removed `|| true` fallback — now fails on high-severity advisories

---

## [0.9.0] — 2026-03-12

### Added

- Landing page rebranded: "Portfolio" to "Platform", focused on 2 core modules (CloudForge + CSPM Aggregator)
- Catalog CSP filter: horizontal buttons replaced with shadcn Select dropdown
- Benchmark tests: 5 tests for server startup, finding retrieval, and attack path computation
- Whitelabel design document (`docs/whitelabel-exploration.md`) — 4-phase strategy
- Environment-variable-driven branding parameterization (`frontend/src/lib/branding.ts`)

### Fixed

- Attack path pagination: default 20/page, max 100/page (prevents browser timeout)
- Factory functions: removed 4 panics (NewEngine, NewScanner, NewLifecycle, NewTemplateManager) — now return (T, error)
- Audit log React key: Fragment key pattern for .map() with sibling rows
- QA findings from quality-review and bug-discovery agents

### Changed

- README roadmap audit: 41/41 items checked (100% complete)

---

## [0.8.0] — 2026-03-12

### Added

- Okta/Entra ID auth wired: config-driven provider selection (OKTA_DOMAIN / ENTRA_TENANT_ID env vars, mock fallback)
- Server.identityProviders map for runtime provider lookup
- Handler-level unit tests: 31 coverage tests across all endpoints
- Integration test suite: 12-step server lifecycle + 34-subtest RBAC authorization matrix (`go test -tags=integration`)
- GreyNoise integration: HTTP client with 12h cache, IP classification enrichment (`internal/cspm/threatintel/greynoise.go`)

### Fixed

- TestGetCostSummary nil pointer: added finopsSvc to testServer and benchServer
- All golangci-lint CI failures resolved

---

## [0.7.0] — 2026-03-04

### Added

- Self-service portal: React 19 + Vite 7 + Tailwind CSS v4 + shadcn/ui — 21 route pages across Admin, Operator, and Requester role views
- Dark mode with CSS variable overrides and anti-flash script
- Cloudflare Pages deployment (cloudforge-demo.lvonguyen.com)
- Terraform networking module (`deploy/terraform/modules/network/`) — AWS VPC, Azure VNet, GCP VPC
- Staging and production Terraform environments
- Temporal workflow testing: 23 tests (concurrent + lifecycle + error cases)
- Attack path computation engine: in-memory BFS graph + ReactFlow DAG visualization (ADR-008)
- EPSS scoring integration (FIRST API, batch fetching, 12h cache)
- CISA KEV catalog integration (auto-refresh, known exploit lookup)
- Toxic combination detection: 4 patterns in `internal/cspm/scoring/toxic_combos.go`
- Blast radius computation: account/VPC/transit reachability in `blast_radius.go`
- False-severity detection: 3 FP suppression + 3 FN escalation rules
- Cost estimation: 21-resource lookup table in `internal/finops/estimation.go`
- Budget alerting: Slack Block Kit + PagerDuty Events API v2 + BudgetMonitor
- Multi-cloud Terraform modules: compute, database, redis
- Rego policy gate: 5 policies, 25 rules (security, cost, naming, network, AI)
- Container Dockerfiles: frontend (nginx) + backend (Go)

### Changed

- Architecture documentation reorganized: archived v1 HLD and impl plan, added diagram references

---

## [0.6.0] — 2026-03-04

### Added

- JWT authentication middleware: HS256/RS256 validation, JWKS caching
- RBAC authorization middleware: role-based endpoint access (admin, operator, requester)
- 12 frontend test files: 6 hook tests + 6 component tests
- v8 coverage thresholds: lines 70%, functions 75%, branches 65%
- GetExceptionsByRequestor: GRC provider interface + all implementations
- GET /exceptions/mine endpoint (RBAC: requester+)
- useExecuteRemediation mutation hook
- useMyExceptions query hook
- Execute/Retry button wiring in RemediationQueue and RemediationDetail

### Fixed

- useCostAnomalies queryKey cache sharing with useCostSummary
- ADR-006: roles claim corrected to groups
- ADR-007: header corrected from ADR-003 to ADR-007
- MyRequests.tsx migrated to use useMyExceptions API hook

---

## [0.5.0] — 2026-02-26

### Added

- AI governance module — selective merge from AgentGuard; embedded OPA Go library engine for in-process AI agent tool and data-flow control (Rego namespace: `cloudforge.ai.*`)
- Agent registry — lifecycle tracking, observability, status management across agent fleet
- STRIDE + ATLAS threat models — structured threat modeling structs per registered agent type
- Maturity assessment — governance readiness scoring across 5 maturity dimensions
- AI governance OPA policies — example YAML policies for tool access and data-flow control (`internal/ai-governance/policies/examples/`)
- MIT License

### Fixed

- Missing `s3control` dependency causing build failures in remediators
- Injectable client pattern for remediators (testability improvement)

### Changed

- AI model reference updated from `claude-opus-4-5-20250514` to `claude-opus-4-6` across all docs and config
- Architecture hardened: BOLA fix on exception endpoints, N+1 query resolved in PostgreSQL GRC provider, CI action pins, OPA evaluator timeout cap

---

## [0.4.0] — 2026-02-26

### Fixed

- Security audit fixes SEC-001 through SEC-012:
  - SEC-001: Input sanitization on exception request fields
  - SEC-002: BOLA — authorization check before resource fetch
  - SEC-003: Rate limiting wired to all API routes
  - SEC-004 through SEC-012: Hardening across GRC, policy, and observability layers

---

## [0.3.0] — 2026-02-11

### Added

- Remediation dispatcher — concurrent batch executor with semaphore-controlled parallelism (`pkg/remediation/`)
- 10 remediation handlers across 8 security domains:
  - Network: SSH/RDP ingress blocking
  - Security services: GuardDuty enablement, Azure Defender (stub)
  - Storage: S3 public access block
  - Compute: EC2 IMDSv2 enforcement
  - Identity: IAM key rotation (Tier 2)
  - Secrets: Manual rotation guidance
  - Patching: SSM patch compliance (query-only, Tier 3)
  - Rollback: 48-hour state snapshot engine
- Tiered execution model — Tier 1 (auto-safe), Tier 2 (requires verification), Tier 3 (change window)
- Findings bridge package (`internal/findings/`) — temporary bridge to cspm-aggregator types pending monorepo merge
- Executor engine unit tests — 14 test cases covering core execution paths
- Domain READMEs for all 8 remediation domains

---

## [0.2.0] — 2026-01-xx

### Added

- FinOps cost management module:
  - Multi-cloud cost aggregation (AWS Cost Explorer, Azure Cost Management, GCP Billing)
  - ML-based anomaly detection with configurable thresholds
  - Tag-based chargeback/showback engine
  - Budget alerting via Slack/PagerDuty
- CI/CD security scanning:
  - SAST integrations: SonarQube, Checkov, Veracode
  - VCS integrations: GitHub, GitLab, Azure DevOps
- Rate limiting middleware — Redis-backed, tier-based limits wired to all API routes
- CI/CD pipeline — GitHub Actions with build, test, lint, and security scanning
- Dockerfile — multi-stage Go build, non-root user, Alpine runtime

### Changed

- AI provider abstraction extended to support Claude and OpenAI behind a common interface

---

## [0.1.0] — 2025-12-xx

### Added

- Core API server (`cmd/server/`) — HTTP handlers, health probes (`/health`, `/ready`, `/live`), Prometheus metrics (`/metrics`)
- GRC provider abstraction — pluggable interface with RSA Archer, ServiceNow GRC, PostgreSQL, and in-memory implementations
- Compliance framework engine — 20+ frameworks: CIS, NIST CSF, ISO 27001, PCI-DSS, HIPAA, HITRUST, SOX, FedRAMP, CMMC, ISO 21434, TISAX, NIST AI RMF, ISO 42001
- OPA/Rego policy engine — region, cost, and network policies for cloud provisioning governance
- AI integration — Claude/OpenAI provider abstraction for contextual risk scoring and remediation generation
- Temporal workflow definitions — registration, approval, provisioning, and compliance scan workflows
- Identity module — Entra ID and Okta provider stubs with Zero Trust policy enforcement patterns
- WAF golden templates and compliance scanner
- Container security module
- Structured logging (zap), OpenTelemetry tracing (basic spans)
- PostgreSQL migrations
- Architecture documentation: HLD, DDD, ADRs (001-006), DR/BC plan, runbooks
