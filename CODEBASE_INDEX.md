# CloudForge Codebase Index

Compressed context for AI agents. Updated: 2026-03-15.

## Repository Structure

```
cloudforge/
  cmd/
    server/           # Main HTTP server — composition root, routes, handlers
    cspm-aggregator/  # CSPM finding aggregation CLI
    cspm-testgen/     # Test data generator
    remediation-dispatcher/  # Remediation execution runner
  internal/
    ai/               # AI provider abstraction (Bedrock, mock)
    ai-governance/    # OPA policy engine integration
    api/              # Auth middleware, CORS, RBAC (Claims, RoleEnforcer)
      gateway/        # Rate limiter (Redis + local fallback)
    audit/            # AuditLogger interface (Memory + Zap implementations)
    cicd/             # CI/CD + VCS provider abstraction
    compliance/       # Compliance framework mapping
    container/        # Container image scanner
    cspm/             # CSPM modules: scoring, normalizer, contextual, threatintel
    finops/           # FinOps: aggregator, anomaly detection, chargeback, alerting
    grc/              # GRC exception management (memory + Postgres providers)
    identity/         # Identity providers: Okta, Entra ID (real + mock)
    ingestion/        # Finding ingestion + DedupCache
    observability/    # Health checker
    policy/           # OPA evaluation bridge
    remediation/      # Remediation types + state store (AES-256-GCM encrypted)
    secrets/          # Secrets management (memory provider + manager)
    tenant/           # Multi-tenant: Store, MemoryStore, middleware, context helpers
    waf/              # WAF template management
    workflow/         # Workflow orchestration engine
  frontend/
    src/
      components/
        ops/          # Command Center components (see below)
        ui/           # Shared: Badge, ProviderBadge, ProviderIcon
        findings/     # SeverityBadge, SLACountdown, FindingCard
        remediation/  # RemediationTierBadge, DryRunPreview
        compliance/   # ComplianceScore
        finops/       # CostSummaryCard, AnomalyAlertCard
        grc/          # StatusBadge, ExceptionCard
        ai/           # AgentStatusBadge
        auth/         # ProtectedRoute
        layout/       # AppShell, TopNav, ExecutionTracePanel
      contexts/       # CommandCenterContext (useReducer state machine)
      hooks/          # useFindings, useAttackPaths, useRemediations, useEnrichFinding, etc.
      lib/            # api, auth, branding, config-context, runtime-config, severity, utils
      pages/          # Route pages: admin/, ops/, portal/
      types/          # TypeScript types: compliance, attack-path, remediation
    public/           # Static assets, mock data (trimmed 500 findings)
  migrations/         # SQL migration files (001-004)
  policies/           # OPA .rego policy files
  docs/               # ADRs, architecture, threat models, QA codex, sprint docs
  deploy/             # Dockerfile, k8s manifests, Terraform, deploy scripts
  scripts/            # Build scripts (trim-demo-findings.js)
  testdata/           # Test fixtures (CSPM, export scripts)
```

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

- **Server struct**: composition root with ~15-20 fields after God Object refactor (phases 1-3 complete) — domain services, singletons, middleware
- **DataStore**: embeds MockData + 4 O(1) lookup maps (FindingsByID, AgentsByID, TracesByAgentID, RemediationsByID)
- **EnrichmentService**: AI provider + cache + singleflight.Group for dedup
- **AttackPathService**: computed attack paths + mutex for concurrent access
- **Handler files**: `handlers_api.go`, `handlers_grc.go`, `handlers_attackpath.go`, `handlers_nlq.go` (NLQ/AI), `handlers_containers.go` (container security), `service_enrichment.go`, `mockdata.go`
- **Routes**: gorilla/mux with auth → rate-limit → RBAC middleware chain
- **Tenant middleware**: resolves from JWT `tenant_id` → X-Tenant-ID header → subdomain
- **Config endpoint**: `GET /api/v1/config` + `/config.json` (unauthenticated, tenant-aware branding)

## Key Patterns

1. **Mock fallback chain**: API → R2 bucket (20k findings) → local mock (500 trimmed)
2. **Faceted filtering**: layer key system — flat `Record<string, boolean>` parsed into group→value Sets
3. **Recharts chart pattern**: `ResponsiveContainer` + dark tooltip style (`#161b22` bg, `#1e2330` border)
4. **Auth in dev mode**: `AuthProvider` auto-authenticates as admin, `ProtectedRoute` skips checks
5. **Provider abstraction**: `ai.Provider`, `grc.GRCProvider`, `identity.Provider` — all behind interfaces
6. **Multi-tenant**: `tenant.Store` → `tenant.Middleware()` → `tenant.FromContext()` chain
7. **Runtime config**: `ConfigProvider` wraps app → `loadRuntimeConfig()` fetches `/config.json` → `useConfig()` hook

## Roles & RBAC

- Go: `RoleAdmin`, `RoleOperator`, `RoleRequester`, `RoleViewer` (rank 0 — read-only; added Sprint B)
- Frontend: 4 roles including 'viewer'
- `RoleEnforcer.Require()` wraps handlers
- `ResourceScope` on Claims for ABAC (providers, severities, environments, regions, accounts)

## Agent Activation

- `frontend/public/mock/agents.json` — mock agent data with `status: "active"|"idle"|"error"`
- `migrations/004_seed_data.sql` — seeds initial agent configurations
- AI enrichment: `POST /api/v1/findings/{id}/enrich` → `EnrichmentService.Enrich()` → Bedrock

## Test Infrastructure

- **Frontend**: Vitest + jsdom + @testing-library/react, 323 tests across 38 files
- **Backend**: Go standard testing, 1474 tests across 34 packages, -race clean, sync.Once for 42MB LFS fixture
- **CI**: GitHub Actions — Frontend Checks, Build & Test, Lint, Security Scan, OPA Policy Test, Cloudflare Pages
