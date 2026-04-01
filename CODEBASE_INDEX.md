# Cloud Aegis Codebase Index

Compressed context for AI agents. Updated: 2026-03-26.

## Repository Structure

```
cloudforge/
  cmd/
    server/           # Main HTTP server — composition root, routes, 65 routes (89 operations)
    cspm-aggregator/  # CSPM finding aggregation CLI
    cspm-testgen/     # Test data generator
    remediation-dispatcher/  # Remediation execution runner
  internal/
    ai/               # AI provider abstraction (Bedrock, mock)
    ai-governance/    # OPA policy engine integration
    api/              # Auth middleware, CORS, RBAC (Claims, RoleEnforcer)
      gateway/        # Rate limiter (Redis + local fallback)
    asm/              # Attack Surface Management: domain scanning, asset discovery
    audit/            # AuditLogger interface (Memory + Zap implementations)
    compliance/       # Compliance framework mapping
    container/        # Container image scanner
    cspm/             # CSPM modules: scoring, normalizer, contextual, threatintel
    finops/           # FinOps: aggregator, anomaly detection, chargeback, alerting
    graph/            # PuppyGraph client: Gremlin (WebSocket :8182) + openCypher (HTTP)
    grc/              # GRC exception management (memory + Postgres providers)
    identity/         # Identity providers: Okta, Entra ID (real + mock)
    ingestion/        # Finding ingestion + DedupCache
    integrations/     # Ticket providers: Asana, Jira, ADO adapters + risk-aware router
      asana/          # Asana adapter (webhook + REST)
      jira/           # Jira Cloud adapter
      ado/            # Azure DevOps adapter
    observability/    # Health checker
    policy/           # OPA evaluation bridge
    remediation/      # Remediation types + state store (AES-256-GCM encrypted)
    rql/              # Resource Query Language: field op value, AND/OR parser
    secgraph/         # Security Graph: controls, issues, evaluations, edges, adjacency BFS (ADR-020)
    secrets/          # Secrets management (memory provider + manager)
    tenant/           # Multi-tenant: Store, MemoryStore, middleware, context helpers
    terminal/         # Integrated terminal: xterm.js WS handler, command whitelist, RBAC
      ticketstore     # SA-002 one-time nonce auth for WebSocket connections (60s TTL)
    waf/              # WAF template management
    webhooks/         # Outbound webhook delivery engine (event types, HMAC signing)
    workflow/         # Workflow orchestration engine
  frontend/
    src/
      components/
        ops/          # Command Center components (see below)
        ui/           # Shared: Badge, ProviderBadge, ProviderIcon
        findings/     # SeverityBadge, SLACountdown, FindingCard
        attack-path/  # AttackPathMiniGraph
        remediation/  # RemediationTierBadge, DryRunPreview
        compliance/   # ComplianceScore
        finops/       # CostSummaryCard, AnomalyAlertCard
        grc/          # StatusBadge, ExceptionCard
        ai/           # AgentStatusBadge
        auth/         # ProtectedRoute
        layout/       # AppShell, TopNav, ExecutionTracePanel
        portal/       # DeployPreview, MultiStepForm, ResourceCatalogCard, TerminalOutput
      contexts/       # CommandCenterContext, TerminalContext, TracePanelContext
      hooks/          # useFindings, useAttackPaths, useRemediations, useEnrichFinding,
                      # useTerminalWS, useASM, useIntegrations, useWebhooks, useCatalog,
                      # useComments, useDeployPreview, useOrgScan, usePolicies, useUsers,
                      # useAuditLog, useCompliancePosture, useCosts, useAgents, +utilities
      lib/            # api, auth, branding, config-context, runtime-config, severity, utils,
                      # terminal-context, trace-panel-context, rql-parser, plan-templates
      pages/          # Route pages: admin/, ops/, portal/
      types/          # compliance, attack-path, remediation, catalog, dashboard, deploy,
                      # dspm, finops, grc, investigation, policy, security-graph, ai-governance
    public/           # Static assets, mock data (trimmed 500 findings)
  migrations/         # SQL migration files (001-008, incl. security graph + assignment context)
  policies/           # OPA .rego policy files
  docs/               # ADRs, architecture, threat models, QA codex, sprint docs
    api/              # OpenAPI 3.1 specification
  deploy/             # Dockerfile, k8s manifests, Terraform, deploy scripts
  configs/            # Config YAML files (config.example.yaml, cspm-aggregator.yaml)
  scripts/            # Seed pipeline + build scripts (see below)
  testdata/           # Test fixtures (CSPM, export scripts)
  k6/                 # Load testing (smoke.js, stress.js, config.js)
  rust/               # Rust FFI bridge (libaegispath — attack path computation)
```

## Migrations

| File | Purpose |
|------|---------|
| `001_exception_management.sql` | GRC exception tables |
| `002_findings_and_compliance.sql` | Findings + compliance schema |
| `003_operations_and_agents.sql` | Agent + operations tables |
| `004_seed_data.sql` | Initial seed data |
| `005_tenant_isolation.sql` | Adds `tenant_id`/`tenant_name` columns (ADR-019) |
| `006_graph_support.sql` | Creates `resources` table (PuppyGraph vertex source) + backfill |

## Scripts

| Script | Purpose |
|--------|---------|
| `aegis-seed.mjs` | 800-line Node.js seed pipeline: dedup, taxonomy, synthetic padding → 20K findings |
| `seed-postgres.mjs` | Streams findings into Postgres via batched INSERT |
| `seed-resources.mjs` | Generates resources table SQL from seed data |
| `generate-jwt.mjs` | Creates HS256 JWT for demo auth (VITE_STATIC_TOKEN) |
| `enrich-findings-bedrock.mjs` | Bedrock AI enrichment for finding descriptions |
| `load-findings-to-postgres.mjs` | Legacy findings loader |
| `transform-real-findings.mjs` | Sanitization pipeline for real finding exports |
| `merge-findings.py` | Merges multi-export NDJSON files |
| `export-securityhub.py` | AWS SecurityHub finding exporter |

## Diagrams (`docs/core/diagrams/`)

| Source (.mmd) | SVG | Figma Export | README |
|---------------|-----|-------------|--------|
| `architecture.mmd` | `architecture.svg` | `architecture-figma.svg/.png` | PNG |
| `compliance-deployment-models.mmd` | `compliance-deployment-models.svg` | — | SVG |
| `dual-opa-architecture.mmd` | `dual-opa-architecture.svg` | `dual-opa-architecture-figma.svg/.png` | PNG |
| `failover-sequence.mmd` | `failover-sequence.svg` | — | SVG |
| `global-deployment-architecture.mmd` | `global-deployment-architecture.svg` | `global-deployment-figma.svg/.png` | PNG |
| `iac-deploy-pipeline.mmd` | `iac-deploy-pipeline.svg` | — | SVG |
| `remediation-dispatcher-flow.mmd` | `remediation-dispatcher-flow.svg` | — | SVG |
| `risk-intelligence-pipeline.mmd` | `risk-intelligence-pipeline.svg` | `risk-pipeline-figma.svg/.png` | PNG |

CSPM diagrams (`docs/cspm/diagrams/`): `hld_architecture.svg`, `dfd_scoring_pipeline.svg`, `dfd_priority_matrix.svg` (SVG-only, no .mmd sources).

Render: `mmdc -i <file>.mmd -o <file>.svg -w 2400`. Figma Design file: key `2l5XrS7QRy5MYFI9PwcPmK` (pages CF.1-CF.9).

Docs-site gallery: `docs/core/diagrams/gallery.md` — served at `/diagrams`.

## Command Center (`frontend/src/components/ops/`)

| Component | Purpose |
|-----------|---------|
| `DataLayersPanel` | Left sidebar — faceted layer toggles (severity, provider, environment) |
| `EntityDetailPanel` | Right sidebar — finding/attack-path detail with collapsible sections + AI enrich button |
| `FindingsSummaryChart` | Recharts stacked bar charts — severity by provider + workflow status |
| `FindingsTreemap` | Recharts treemap — severity heatmap grouped by provider/category |
| `ShortcutOverlay` | Fixed modal showing keyboard shortcuts (Esc, L, D, 1, 2, ?) |
| `StatusBar` | Bottom bar — severity indicators, date range filter, finding counts, ? hint |

## CommandCenterContext State Shape

```ts
{
  selectedEntity: SelectedEntity | null    // finding or attack-path
  activeLayers: Record<string, boolean>    // "severity:CRITICAL" → true
  selectedPathId: string | null            // attack path graph view
  leftPanelOpen: boolean                   // data layers sidebar
  centerView: 'charts' | 'treemap'        // center pane mode
  dateRange: { start: string | null; end: string | null }
  showShortcutOverlay: boolean
}
```

Actions: `SELECT_ENTITY`, `TOGGLE_LAYER`, `SET_LAYERS`, `SELECT_PATH`, `TOGGLE_LEFT_PANEL`, `SET_CENTER_VIEW`, `SET_DATE_RANGE`, `TOGGLE_SHORTCUT_OVERLAY`

Layer key format: `"group:value"` — parsed via `parseLayerKey()`, built via `layerKey()`.

## Server Architecture (`cmd/server/`)

- **Server struct**: composition root with ~25 fields — domain services, singletons, middleware
- **DataStore**: embeds MockData + 4 O(1) lookup maps (FindingsByID, AgentsByID, TracesByAgentID, RemediationsByID)
- **EnrichmentService**: AI provider + cache + singleflight.Group for dedup
- **AttackPathService**: computed attack paths + RWMutex for concurrent access
- **IntegrationHandler**: ticket routing + Asana/Jira/ADO/Mock providers + webhook delivery
- **TerminalHandler**: xterm.js WebSocket with ticket nonce auth (SA-002), command whitelist
- **GraphHandler**: PuppyGraph Gremlin/Cypher query proxy
- **Handler files**: `handlers_api.go`, `handlers_grc.go`, `handlers_attackpath.go`, `handlers_nlq.go`, `handlers_containers.go`, `handlers_integration.go`, `handlers_terminal.go` (via internal/terminal), `handlers_graph.go`, `handlers_finops.go`, `handlers_secrets.go`, `handlers_secrets_orgscan.go`, `handlers_waf.go`, `handlers_identity.go`, `handlers_webhooks.go`, `handlers_rql.go`, `handlers_asm.go`, `handlers_deploy.go`, `handlers_search.go`, `handlers_ingest.go`, `handlers_compliance.go`, `handlers_config.go`, `handlers_comments.go`, `handlers_workflow.go`, `service_enrichment.go`, `service_identity.go`, `mockdata.go`
- **Routes**: gorilla/mux with auth → tenant → rate-limit → RBAC middleware chain (65 routes, 89 operations per OpenAPI spec)
- **Tenant middleware**: resolves from JWT `tenant_id` → X-Tenant-ID header → subdomain
- **Config endpoint**: `GET /api/v1/config` + `/config.json` (unauthenticated, tenant-aware branding)

## API Surface (65 routes / 89 operations)

| Domain | Endpoints | Auth | Notes |
|--------|-----------|------|-------|
| System | 4 | No | /health, /healthz, /ready, /metrics |
| Config | 3 | No | /api/v1/config, /config.json, /api/v1/providers |
| Findings | 7 | JWT | list, stats, query, search, ingest, enrich, get |
| Comments | 3 | JWT | list, add, delete (per-finding) |
| Compliance | 3 | JWT | frameworks, posture, controls |
| Exceptions (GRC) | 9 | JWT | CRUD + pending/expiring/mine/withdraw/approve + validate |
| Agents | 3 | JWT | list, get, traces |
| Costs | 1 | JWT | summary (computed) |
| Remediations | 4 | JWT | list, execute, get, patch |
| Integration | 5 | JWT | remediate, ticket get/sync, comments get/add |
| Attack Paths | 4 | JWT | list, stats, analysis, get |
| Graph | 1 | JWT | Gremlin/Cypher query proxy |
| Containers | 4 | JWT | list, get, scan, admission |
| Secrets | 5 | JWT | list, scan, upload, get, org-scan |
| WAF | 2 | JWT | templates, compliance check |
| Identity | 2 | JWT | users, risk score |
| AI/NLQ | 2 | JWT | nlq query, usage |
| Deploy | 2 | JWT | preview, abort |
| Workflows | 3 | JWT | list, get, approve |
| Webhooks | 5 | Mixed | register, list, delete, deliveries + Asana (HMAC) |
| ASM | 2 | JWT | scan, assets |
| Terminal | 2 | Mixed | WS (ticket nonce), issue ticket |
| Admin | 2 | JWT | audit-log, users (admin-only) |
| Catalog | 1 | JWT | modules |
| Policies | 2 | JWT | list, get |
| DSPM | 1 | JWT | data classification assets |

## Key Patterns

1. **Mock fallback chain**: API → R2 bucket (20k findings) → local mock (500 trimmed)
2. **Faceted filtering**: layer key system — flat `Record<string, boolean>` parsed into group→value Sets
3. **Recharts chart pattern**: `ResponsiveContainer` + dark tooltip style (`#161b22` bg, `#1e2330` border)
4. **Auth in dev mode**: `AuthProvider` auto-authenticates as admin, `ProtectedRoute` skips checks
5. **Provider abstraction**: `ai.Provider`, `grc.GRCProvider`, `identity.Provider`, `integrations.TicketProvider` — all behind interfaces
6. **Multi-tenant**: `tenant.Store` → `tenant.Middleware()` → `tenant.FromContext()` chain
7. **Runtime config**: `ConfigProvider` wraps app → `loadRuntimeConfig()` fetches `/config.json` → `useConfig()` hook
8. **Terminal WS auth**: `POST /terminal/ticket` → one-time nonce (60s TTL) → `GET /terminal/ws?ticket=<nonce>` (SA-002)
9. **Graph queries**: Gremlin via WebSocket (:8182), Cypher via HTTP — PuppyGraph backed by RDS JDBC
10. **Ticket routing**: risk-aware router dispatches to Asana/Jira/ADO based on severity + choke-point status

## Roles & RBAC

- Go: `RoleAdmin`, `RoleOperator`, `RoleRequester`, `RoleViewer` (rank 0 — read-only; added Sprint B)
- Frontend: 4 roles including 'viewer' — `deriveRoleFromGroups()` defaults to viewer
- `RoleEnforcer.Require()` wraps handlers; `ScopeGuard` for tenant-scoped data (30 endpoints)
- `ResourceScope` on Claims for ABAC (providers, severities, environments, regions, accounts)
- Admin-only: 9 endpoints (approve, ingest, delete comment, audit-log, users, AI usage, register/delete webhook, org-scan)

## Agent Activation

- `frontend/public/mock/agents.json` — mock agent data with `status: "active"|"idle"|"error"`
- `migrations/004_seed_data.sql` — seeds initial agent configurations
- AI enrichment: `POST /api/v1/findings/{id}/enrich` → `EnrichmentService.Enrich()` → Bedrock

## Test Infrastructure

- **Frontend**: Vitest + jsdom + @testing-library/react, 447 tests across 52 files
- **Backend**: Go standard testing, ~1500 tests across 39 packages, -race clean
- **CI**: GitHub Actions — Frontend Checks, Build & Test, Lint, Security Scan, OPA Policy Test, Cloudflare Pages, SBOM (CycloneDX)
