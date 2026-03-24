# Sprint: Whitelabel Readiness — Provider Selection Layer

**Created:** 2026-03-16
**Status:** DONE
**Goal:** Standardize all 8 stub packages on the GRC factory pattern so CloudForge is config-driven provider selection away from production deployment. No real provider wiring — just the seam.
**Estimated effort:** ~1 week (5-7 sessions)
**Strategic context:** Positioning CloudForge as a whitelabel CSPM for HAEA pilot. Portfolio demo stays unchanged (mock providers selected by default). Production deployment only requires setting env vars.

---

## Reference Pattern: GRC Factory (DO NOT MODIFY — this is the target)

```
internal/grc/factory.go:
  - ProviderType string enum: "memory", "postgres", "archer", "servicenow"
  - Config struct with union of sub-configs
  - NewProvider(cfg Config) (GRCProvider, error) — switch on cfg.Type
  - ProviderFromString(s string) (ProviderType, error) — env var parsing

cmd/server/main.go:
  - Reads GRC_PROVIDER env var
  - Calls grc.ProviderFromString() → grc.NewProvider(cfg)
  - Stores as GRCProvider interface on Server struct
```

Every package below must converge on this exact pattern.

---

## Tier 1: High Priority (identity, container, finops)

### W1. identity/ — Extract factory from inline main.go logic

**Current state:** Real Okta + EntraID implementations exist. Selection logic is 30 lines inlined in `cmd/server/main.go:211-244`. Uses `identity.Provider` interface at server boundary. No factory function.

**Changes:**
- [ ] **W1a: Create `internal/identity/factory.go`**
  - `ProviderType` string enum: `"mock-okta"`, `"mock-entra"`, `"okta"`, `"entra_id"`
  - `Config` struct with `Type ProviderType`, `OktaConfig`, `EntraIDConfig` embedded
  - `NewProvider(cfg Config) (Provider, error)` — switch on type, return mock or real
  - `ProviderFromString(s string) (ProviderType, error)` — validates input
  - Move mock seeding from `main.go` into factory's mock cases
  - ~60 lines

- [ ] **W1b: Simplify `cmd/server/main.go` identity init**
  - Replace 30-line inline block with:
    ```go
    idpType, _ := identity.ProviderFromString(os.Getenv("IDENTITY_PROVIDER"))
    idp, err := identity.NewProvider(identity.Config{Type: idpType, ...})
    ```
  - Store as `identity.Provider` (already the case)
  - ~10 lines changed in main.go

- [ ] **W1c: Add `IDENTITY_PROVIDER` to config documentation**
  - Values: `mock-okta` (default), `mock-entra`, `okta`, `entra_id`
  - Required env vars per provider (OKTA_DOMAIN, ENTRA_TENANT_ID, etc.)

**Verify:** `go test -race ./internal/identity/... ./cmd/server/...`
**Acceptance:** `IDENTITY_PROVIDER=mock-okta go run ./cmd/server` behaves identically to current default.

---

### W2. container/ — Thread config through factory

**Current state:** Factory function `NewScanner(provider string)` exists. `CONTAINER_SCANNER` env var exists. `SecurityScannerConfig` struct exists but isn't used by factory path.

**Changes:**
- [ ] **W2a: Extend factory signature to accept config**
  - Change `NewScanner(provider string) (Scanner, error)` → `NewScanner(cfg ScannerConfig) (Scanner, error)`
  - Add `ScannerConfig` struct: `Type string`, `TrivyConfig` (binary path, severity threshold)
  - Thread `SecurityScannerConfig` fields into `TrivyConfig` where applicable
  - ~30 lines

- [ ] **W2b: Add `ProviderFromString` for consistency**
  - Same validation pattern as GRC
  - ~10 lines

- [ ] **W2c: Update `cmd/server/main.go` to use new config struct**
  - Replace `container.NewScanner(containerScannerProvider())` with config-based call
  - Read `CONTAINER_SCANNER` (already exists) + `TRIVY_SEVERITY_THRESHOLD` (new, optional)
  - ~10 lines

**Verify:** `go test -race ./internal/container/... ./cmd/server/...`
**Acceptance:** `CONTAINER_SCANNER=memory go run ./cmd/server` behaves identically.

---

### W3. finops/ — Introduce factory (biggest gap)

**Current state:** Three interfaces defined (`Aggregator`, `AnomalyDetector`, `ChargebackEngine`) but `finopsService` in `cmd/server/handlers_finops.go` uses concrete types (`*finops.MemoryAggregator`, `*anomaly.Detector`, `*chargeback.Allocator`). No factory, no env var.

**Changes:**
- [ ] **W3a: Create `internal/finops/factory.go`**
  - `ProviderType` string enum: `"memory"`, `"aws"`, `"gcp"`, `"azure"`
  - `Config` struct: `Type`, `AWSConfig { Region, RoleARN }`, `GCPConfig { ProjectID }`, `AzureConfig { SubscriptionID }`
  - `Service` struct bundling all three interfaces:
    ```go
    type Service struct {
        Aggregator      Aggregator
        AnomalyDetector AnomalyDetector
        ChargebackEngine ChargebackEngine
    }
    ```
  - `NewService(cfg Config) (*Service, error)` — returns memory implementations for `"memory"`, placeholder `ErrNotImplemented` for cloud providers
  - ~80 lines

- [ ] **W3b: Change `finopsService` to use interfaces**
  - In `cmd/server/handlers_finops.go`, change:
    ```go
    // Before (concrete)
    aggregator *finops.MemoryAggregator
    // After (interface)
    aggregator finops.Aggregator
    ```
  - Same for `detector` → `finops.AnomalyDetector`, `allocator` → `finops.ChargebackEngine`
  - ~10 lines

- [ ] **W3c: Wire factory in `cmd/server/main.go`**
  - Read `FINOPS_PROVIDER` env var (default: `"memory"`)
  - Call `finops.NewService(cfg)` → assign to `finopsService` fields
  - ~15 lines

**Verify:** `go test -race ./internal/finops/... ./cmd/server/...`
**Acceptance:** `FINOPS_PROVIDER=memory go run ./cmd/server` behaves identically. Setting `FINOPS_PROVIDER=aws` returns clean `ErrNotImplemented` errors (not panics).

---

## Tier 2: Low Effort (workflow, waf, secrets — factories exist, just add env var hooks)

### W4. workflow/ — Add env var hook

**Current state:** `NewEngine(provider string)` factory exists. Hardcoded `"memory"` in main.go.

**Changes:**
- [ ] **W4a: Read `WORKFLOW_ENGINE` env var, default `"memory"`**
  - 3 lines in main.go
- [ ] **W4b: Add `ProviderFromString` for validation**
  - 10 lines in engine.go

**Verify:** `go test -race ./internal/workflow/...`

---

### W5. waf/ — Add env var hook

**Current state:** `NewTemplateManager(provider string)` factory exists. Hardcoded `"memory"` in main.go.

**Changes:**
- [ ] **W5a: Read `WAF_PROVIDER` env var, default `"memory"`**
  - 3 lines in main.go
- [ ] **W5b: Add `ProviderFromString` for validation**
  - 10 lines in manager.go

**Verify:** `go test -race ./internal/waf/...`

---

### W6. secrets/ — Consolidate dual abstractions + add env var

**Current state:** Two parallel interfaces (`Provider` and `Lifecycle`). Server uses concrete `*MemoryProvider`. No factory for the `Provider` interface path.

**Changes:**
- [ ] **W6a: Add `NewProvider(providerType string) (Provider, error)` factory**
  - `"memory"` → `NewMemoryProvider("demo")`
  - `"aws"` / `"azure"` / `"gcp"` → existing stub implementations (return `ErrNotImplemented`)
  - ~20 lines

- [ ] **W6b: Change server to use `Provider` interface**
  - `secretsProvider secrets.Provider` (interface) instead of `*secrets.MemoryProvider` (concrete)
  - Read `SECRETS_PROVIDER` env var
  - ~10 lines

**Verify:** `go test -race ./internal/secrets/... ./cmd/server/...`

---

## Tier 3: Skip (cicd, observability)

| Package | Reason |
|---------|--------|
| cicd/ | Not wired to server at all. 3-4 week effort to build handlers + routes. Not needed for HAEA pilot (they use GitHub Actions, not an in-app CI view). |
| observability/ | Infrastructure-internal (health checks, telemetry). No provider abstraction needed — concrete struct is correct here. |

---

## Cross-Cutting: Config Documentation

### W7. Provider configuration reference

- [ ] **W7a: Create `docs/PROVIDER_CONFIG.md`**
  - Table of all env vars, default values, valid options
  - Per-provider required config (e.g., OKTA_DOMAIN for identity/okta)
  - Example `.env.production` file
  - ~100 lines docs

- [ ] **W7b: Add provider status to `/api/health` endpoint**
  - Extend health check response to include which provider is active per package
  - Shows: `{"identity": "mock-okta", "container": "memory", "finops": "memory", ...}`
  - Useful for operators verifying deployment config
  - ~30 lines in health handler

---

## Dependencies

```
W1 (identity factory) → no deps
W2 (container config)  → no deps
W3 (finops factory)    → no deps
W4 (workflow env var)  → no deps
W5 (waf env var)       → no deps
W6 (secrets factory)   → no deps
W7 (docs + health)     → depends on W1-W6 (needs final env var names)

All W1-W6 are independent — can parallelize across 2-3 sessions.
```

---

## Commit Strategy

| Commit | Items | Message | Gate |
|--------|-------|---------|------|
| 1 | W1a-c | `feat(identity): extract provider factory from inline main.go logic` | `go test -race ./...` |
| 2 | W3a-c | `feat(finops): introduce Service factory + interface-based composition` | `go test -race ./...` |
| 3 | W2a-c | `feat(container): thread ScannerConfig through factory` | `go test -race ./...` |
| 4 | W4-W6 | `feat: add env var hooks for workflow, waf, secrets providers` | `go test -race ./...` |
| 5 | W7a-b | `docs: provider configuration reference + health endpoint status` | `go test -race ./...` |

---

## Acceptance Criteria (Sprint Exit)

- [x] All 6 provider packages (identity, container, finops, workflow, waf, secrets) have:
  - A `NewProvider` or `NewService` factory function
  - A `ProviderFromString` validation function
  - An env var hook read in `cmd/server/main.go`
  - Interface types (not concrete) at the server composition root
- [x] Default behavior unchanged: `go run ./cmd/server` with no env vars behaves identically to pre-sprint
- [x] `FINOPS_PROVIDER=aws go run ./cmd/server` returns clean errors (not panics)
- [x] `GET /api/v1/providers` returns active provider per package (separate endpoint, not /health)
- [x] `docs/PROVIDER_CONFIG.md` documents all env vars
- [x] All existing tests pass: `go test -race -timeout 20m ./...`
- [x] No new test files required (factory functions tested via existing integration paths)

**Completed:** 2026-03-23 (session 9) — 4 commits, 1 session (vs. estimated 5-7 sessions)
**Note:** W4 (workflow) and W5 (waf) were already done before sprint start.

---

## Post-Sprint: HAEA Pilot Path

After this sprint, deploying to HAEA requires only:

1. Set env vars: `IDENTITY_PROVIDER=okta`, `CONTAINER_SCANNER=trivy`, `FINOPS_PROVIDER=aws`
2. Provide credentials: `OKTA_DOMAIN`, `OKTA_API_TOKEN`, `AWS_REGION`, etc.
3. The real provider implementations (Okta, Trivy, AWS Cost Explorer) already exist in identity/ and container/. FinOps AWS provider is the only new code needed (~2 weeks).

No architectural changes. No interface changes. Just config.
