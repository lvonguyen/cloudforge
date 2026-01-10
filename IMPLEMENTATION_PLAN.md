# CloudForge - Standards Alignment Implementation Plan

**Version:** 1.0
**Author:** Claude (AI Assistant)
**Date:** January 2026
**Reference Standards:** DEV_GUIDE.md v2.0, Documentation Standards v2.0, REPO_ORGANIZATION.md v1.0

---

## Table of Contents

| Section | Description |
|---------|-------------|
| [Executive Summary](#executive-summary) | Current state and gap analysis |
| [Standards Compliance Matrix](#standards-compliance-matrix) | Detailed compliance checklist |
| [Phase 1: Repository Structure](#phase-1-repository-structure) | Directory and file organization |
| [Phase 2: Code Quality](#phase-2-code-quality) | Go standards, testing, validation |
| [Phase 3: Security](#phase-3-security) | Auth, secrets, input validation |
| [Phase 4: Documentation](#phase-4-documentation) | HLD/DDD/DR-BC alignment |
| [Phase 5: Infrastructure](#phase-5-infrastructure) | IaC organization |
| [Implementation Order](#implementation-order) | Prioritized task list |

---

## Executive Summary

### Current State

CloudForge is a Go 1.24 Internal Developer Platform (IDP) with solid architectural foundations but significant gaps when measured against portfolio standards.

### Gap Summary

| Category | Compliant | Gaps | Priority |
|----------|-----------|------|----------|
| Repository Structure | 60% | Missing `.claude/`, `scripts/`, `infra/` | HIGH |
| Go Standards | 75% | Missing viper config, incomplete interfaces | MEDIUM |
| Security | 30% | No auth middleware, no input validation | CRITICAL |
| Testing | 0% | Zero test files | CRITICAL |
| Documentation | 70% | Emojis in docs, incomplete DDD | LOW |
| Code Quality | 65% | N+1 queries, incomplete implementations | MEDIUM |

---

## Standards Compliance Matrix

### [/] Repository Structure (REPO_ORGANIZATION.md)

| Requirement | Status | Gap | Action |
|-------------|--------|-----|--------|
| `cmd/` directory | [x] | None | - |
| `internal/` directory | [x] | Wrong sub-structure | Reorganize to domain/service/repository |
| `pkg/` directory | [ ] | Missing | Create if public APIs needed |
| `configs/` directory | [x] | None | - |
| `infra/` directory | [ ] | Missing | Create with aws/azure/gcp/docker/helm |
| `docs/` directory | [x] | None | - |
| `scripts/` directory | [ ] | Missing | Create with build/test/deploy scripts |
| `.claude/` directory | [ ] | Missing | Create with rules.md symlink |
| `Makefile` | [x] | None | - |

### [+] Go Standards (DEV_GUIDE.md)

| Requirement | Status | Gap | Action |
|-------------|--------|-----|--------|
| Standard layout (`cmd/`, `internal/`) | [x] | None | - |
| Interfaces in consumer package | [~] | Partial | Review and relocate |
| Error wrapping with `%w` | [x] | None | - |
| Configuration with viper | [ ] | Uses env vars only | Implement viper |
| AI provider abstraction | [x] | None | - |

### [!] Security Standards (DEV_GUIDE.md)

| Requirement | Status | Gap | Action |
|-------------|--------|-----|--------|
| No hardcoded credentials | [x] | None | - |
| 1Password/secrets integration | [ ] | Missing | Add op-read support |
| Input validation | [ ] | Missing | Add validation layer |
| Authentication middleware | [ ] | Missing | Implement OIDC/JWT |
| Authorization (RBAC) | [ ] | Missing | Implement role checks |
| Rate limiting enforced | [ ] | Built but not wired | Connect middleware |

### [>] Testing Standards (DEV_GUIDE.md)

| Requirement | Status | Gap | Action |
|-------------|--------|-----|--------|
| Unit tests | [ ] | 0% coverage | Add comprehensive tests |
| Before/after comparison | [ ] | Missing | Add baseline tests |
| Dry-run mode for remediation | [ ] | Missing | Add --dry-run flag |

### [*] Documentation Standards

| Requirement | Status | Gap | Action |
|-------------|--------|-----|--------|
| HLD document | [x] | Minor formatting | Remove emojis |
| DDD document | [~] | ADRs exist separately | Consolidate into DDD |
| DR/BC document | [x] | None | - |
| No emojis (ASCII only) | [ ] | Emojis present | Replace with ASCII symbols |
| Georgia font in diagrams | [ ] | Not verified | Update SVG styles |
| Color palette compliance | [ ] | Not verified | Update to standard palette |

---

## Phase 1: Repository Structure

### 1.1 Create Missing Directories

```bash
# Create standard directories
mkdir -p /home/user/cloudforge/.claude/commands
mkdir -p /home/user/cloudforge/.claude/agents
mkdir -p /home/user/cloudforge/scripts
mkdir -p /home/user/cloudforge/infra/{aws,azure,gcp,docker,helm}
```

### 1.2 Create `.claude/rules.md`

Create agent configuration file with project-specific rules.

**File:** `.claude/rules.md`

```markdown
# CloudForge - Agent Rules

## Project Context
- **Type:** Internal Developer Platform (IDP)
- **Language:** Go 1.24
- **Database:** PostgreSQL 16
- **Policy Engine:** OPA/Rego

## Key Commands
- `make build` - Build binary
- `make test` - Run tests
- `make docker-up` - Start local environment
- `make lint` - Run golangci-lint

## Architecture
- Provider pattern for GRC (Memory/Postgres/Archer/ServiceNow)
- AI abstraction for LLM providers (Anthropic/OpenAI)
- Temporal for workflow orchestration
- OPA for policy-as-code

## Critical Files
- `cmd/server/main.go` - API entrypoint
- `internal/grc/provider.go` - GRC interface
- `internal/ai/provider.go` - AI interface
- `migrations/` - Database schema
```

### 1.3 Reorganize Internal Structure

**Current:**
```
internal/
├── ai/
├── api/
├── cicd/
├── compliance/
├── container/
├── grc/
├── identity/
├── observability/
├── policy/
├── waf/
└── workflow/
```

**Target (REPO_ORGANIZATION.md compliant):**
```
internal/
├── domain/           # Business logic and models
│   ├── exception/    # Exception request domain
│   ├── compliance/   # Compliance framework domain
│   └── finding/      # Security finding domain
├── service/          # Application services / use cases
│   ├── grc/          # GRC orchestration
│   ├── ai/           # AI analysis service
│   └── workflow/     # Temporal workflow service
├── repository/       # Data access layer
│   ├── postgres/     # PostgreSQL implementations
│   └── memory/       # In-memory implementations
├── api/              # HTTP handlers
│   ├── handlers/     # Route handlers
│   ├── middleware/   # Auth, logging, rate limit
│   └── gateway/      # API gateway components
├── config/           # Configuration loading
├── providers/        # External provider abstractions
│   ├── ai/           # Anthropic, OpenAI
│   ├── identity/     # Okta, Entra ID
│   ├── grc/          # Archer, ServiceNow
│   └── cloud/        # AWS, Azure, GCP
└── pkg/              # Shared utilities (optional)
```

**[!] Note:** This is a significant refactor. Recommend incremental migration with alias packages to maintain compatibility.

### 1.4 Create Scripts Directory

**File:** `scripts/build.sh`
```bash
#!/bin/bash
set -euo pipefail
go build -o bin/cloudforge ./cmd/server
```

**File:** `scripts/test.sh`
```bash
#!/bin/bash
set -euo pipefail
go test -v -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

**File:** `scripts/lint.sh`
```bash
#!/bin/bash
set -euo pipefail
golangci-lint run ./...
```

---

## Phase 2: Code Quality

### 2.1 Configuration Management (Viper)

**Current:** Environment variables only in `cmd/server/main.go`

**Target:** Viper-based configuration with env var overrides

**File:** `internal/config/config.go`

```go
package config

import (
    "github.com/spf13/viper"
)

type Config struct {
    Server   ServerConfig   `mapstructure:"server"`
    GRC      GRCConfig      `mapstructure:"grc"`
    Database DatabaseConfig `mapstructure:"database"`
    Auth     AuthConfig     `mapstructure:"auth"`
    AI       AIConfig       `mapstructure:"ai"`
}

func Load() (*Config, error) {
    viper.SetConfigName("config")
    viper.SetConfigType("yaml")
    viper.AddConfigPath("./configs")
    viper.AddConfigPath(".")

    viper.AutomaticEnv()
    viper.SetEnvPrefix("CLOUDFORGE")

    if err := viper.ReadInConfig(); err != nil {
        // Config file not found is OK if env vars set
        if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
            return nil, fmt.Errorf("reading config: %w", err)
        }
    }

    var cfg Config
    if err := viper.Unmarshal(&cfg); err != nil {
        return nil, fmt.Errorf("unmarshaling config: %w", err)
    }

    return &cfg, nil
}
```

**Action:** Add `github.com/spf13/viper` to go.mod

### 2.2 Fix N+1 Query Problem

**Location:** `internal/grc/postgres_provider.go:407-416`

**Current (BAD):**
```go
rows, err := p.db.QueryContext(ctx, query, approverEmail)
for rows.Next() {
    var id string
    rows.Scan(&id)
    exc, err := p.GetException(ctx, id)  // N+1 query!
    results = append(results, *exc)
}
```

**Target (GOOD):**
```go
query := `
    SELECT er.*, ra.risk_level, ra.impact, ra.likelihood
    FROM exception_requests er
    LEFT JOIN risk_assessments ra ON er.id = ra.exception_id
    JOIN approval_chain ac ON er.id = ac.exception_id
    WHERE er.status = 'PENDING'
      AND ac.approver_email = $1
      AND ac.decision IS NULL
`
rows, err := p.db.QueryContext(ctx, query, approverEmail)
// Single query with JOIN
```

### 2.3 Add Input Validation Layer

**File:** `internal/api/validation/validator.go`

```go
package validation

import (
    "fmt"
    "net/mail"
    "github.com/yourusername/cloudforge/internal/grc"
)

type ValidationError struct {
    Field   string
    Message string
}

func (e *ValidationError) Error() string {
    return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

func ValidateExceptionRequest(req *grc.ExceptionRequest) error {
    if req.ApplicationID == "" {
        return &ValidationError{Field: "application_id", Message: "required"}
    }

    if req.RequestorEmail == "" {
        return &ValidationError{Field: "requestor_email", Message: "required"}
    }

    if _, err := mail.ParseAddress(req.RequestorEmail); err != nil {
        return &ValidationError{Field: "requestor_email", Message: "invalid email format"}
    }

    if req.BusinessCase == "" {
        return &ValidationError{Field: "business_case", Message: "required"}
    }

    return nil
}
```

### 2.4 Add Unit Tests

**Target Coverage:** 80%+ on critical paths

**File:** `internal/grc/postgres_provider_test.go`

```go
package grc_test

import (
    "context"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "github.com/yourusername/cloudforge/internal/grc"
)

func TestMemoryProvider_CreateException(t *testing.T) {
    provider := grc.NewMemoryGRCProvider()

    req := &grc.ExceptionRequest{
        ApplicationID:  "app-123",
        RequestorEmail: "user@example.com",
        BusinessCase:   "Testing exception workflow",
        RequestType:    grc.RequestTypeOther,
    }

    created, err := provider.CreateException(context.Background(), req)

    require.NoError(t, err)
    assert.NotEmpty(t, created.ID)
    assert.Equal(t, grc.StatusPending, created.Status)
    assert.Equal(t, "app-123", created.ApplicationID)
}

func TestMemoryProvider_GetException_NotFound(t *testing.T) {
    provider := grc.NewMemoryGRCProvider()

    _, err := provider.GetException(context.Background(), "nonexistent-id")

    assert.Error(t, err)
}
```

**Required packages:**
```
go get github.com/stretchr/testify
```

---

## Phase 3: Security

### 3.1 Authentication Middleware

**File:** `internal/api/middleware/auth.go`

```go
package middleware

import (
    "context"
    "net/http"
    "strings"

    "go.uber.org/zap"
)

type AuthMiddleware struct {
    logger     *zap.Logger
    issuerURL  string
    audience   string
    // jwks client for token verification
}

func NewAuthMiddleware(logger *zap.Logger, issuerURL, audience string) *AuthMiddleware {
    return &AuthMiddleware{
        logger:    logger,
        issuerURL: issuerURL,
        audience:  audience,
    }
}

func (m *AuthMiddleware) Authenticate(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
            return
        }

        parts := strings.SplitN(authHeader, " ", 2)
        if len(parts) != 2 || parts[0] != "Bearer" {
            http.Error(w, `{"error":"invalid authorization format"}`, http.StatusUnauthorized)
            return
        }

        token := parts[1]
        claims, err := m.verifyToken(token)
        if err != nil {
            m.logger.Warn("token verification failed", zap.Error(err))
            http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
            return
        }

        // Add claims to context
        ctx := context.WithValue(r.Context(), "user_id", claims.Subject)
        ctx = context.WithValue(ctx, "user_email", claims.Email)
        ctx = context.WithValue(ctx, "roles", claims.Roles)

        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

func (m *AuthMiddleware) verifyToken(token string) (*Claims, error) {
    // TODO: Implement OIDC token verification
    // Use go-oidc library or manual JWKS verification
    return nil, nil
}
```

### 3.2 Authorization (RBAC)

**File:** `internal/api/middleware/authz.go`

```go
package middleware

import (
    "net/http"
)

type Role string

const (
    RoleDeveloper     Role = "developer"
    RoleSecurityAdmin Role = "security_admin"
    RolePlatformAdmin Role = "platform_admin"
)

func RequireRole(roles ...Role) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            userRoles, ok := r.Context().Value("roles").([]string)
            if !ok {
                http.Error(w, `{"error":"unauthorized"}`, http.StatusForbidden)
                return
            }

            for _, required := range roles {
                for _, userRole := range userRoles {
                    if string(required) == userRole {
                        next.ServeHTTP(w, r)
                        return
                    }
                }
            }

            http.Error(w, `{"error":"insufficient permissions"}`, http.StatusForbidden)
        })
    }
}
```

### 3.3 Wire Up Rate Limiting

**Current:** Rate limiter exists at `internal/api/gateway/ratelimit.go` but not connected.

**Action:** Add to router setup in `cmd/server/main.go`:

```go
func (s *Server) setupRoutes() {
    // Health endpoint (no auth)
    s.router.HandleFunc("/health", s.healthCheck).Methods("GET")

    // API routes with middleware
    api := s.router.PathPrefix("/api/v1").Subrouter()

    // Apply middleware chain
    api.Use(s.loggingMiddleware)
    api.Use(s.rateLimiter.Middleware)  // Add rate limiting
    api.Use(s.authMiddleware.Authenticate)  // Add authentication

    // Exception endpoints
    api.HandleFunc("/exceptions", s.createException).Methods("POST")
    // ...
}
```

---

## Phase 4: Documentation

### 4.1 Remove Emojis from Documentation

Replace all emojis with ASCII symbols per DEV_GUIDE.md:

| Replace | With |
|---------|------|
| Emoji checkmarks | `[x]` |
| Emoji warnings | `[!]` |
| Emoji X marks | `[ ]` |
| Stars/ratings | `[*]` |

**Files to update:**
- `README.md`
- `cloudforge-HLD.md`
- `docs/architecture/HLD.md`
- All runbooks in `docs/runbooks/`

### 4.2 Consolidate DDD

**Current:** ADRs scattered in `docs/adr/`

**Target:** Single DDD document with embedded ADRs per Documentation Standards.

**File:** `docs/architecture/DDD.md`

Structure:
```markdown
# CloudForge - Detailed Design Document (DDD)

## Document Control
| Version | Date | Author | Role |
|---------|------|--------|------|
| 1.0 | January 2026 | Engineering | Platform Team |

## Overview

## Architecture Decision Records (ADRs)
### ADR-001: Programming Language Selection
### ADR-002: Database Selection
### ADR-003: Caching Strategy
### ADR-004: AI Provider Selection
### ADR-005: Rate Limiting Strategy
### ADR-006: Authentication Approach

## API Specifications
### Endpoints
### Request/Response Models
### Error Handling

## Data Models
### Entity Definitions
### Relationships
### Validation Rules

## Service Interfaces
## Configuration Reference
## Testing Strategy
```

### 4.3 Update Diagram Standards

Ensure all SVG diagrams use:
- Georgia font family
- Standard color palette (AWS orange, Azure blue, GCP green)
- Branding badge in bottom-left

---

## Phase 5: Infrastructure

### 5.1 Create Infrastructure Directory

```
infra/
├── aws/
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   └── backend.tf
├── azure/
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   └── backend.tf
├── gcp/
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   └── backend.tf
├── docker/
│   └── docker-compose.yml  # Move from root
└── helm/
    └── cloudforge/
        ├── Chart.yaml
        ├── values.yaml
        └── templates/
```

### 5.2 Move Docker Compose

Move `docker-compose.yml` from root to `infra/docker/` and update Makefile references.

---

## Implementation Order

### [!] Critical (Do First)

| # | Task | Effort | Impact |
|---|------|--------|--------|
| 1 | Add authentication middleware | 4h | CRITICAL |
| 2 | Add input validation layer | 2h | HIGH |
| 3 | Wire rate limiting to routes | 1h | HIGH |
| 4 | Add unit tests (80% coverage) | 8h | CRITICAL |
| 5 | Fix N+1 query problem | 2h | MEDIUM |

### [+] High Priority

| # | Task | Effort | Impact |
|---|------|--------|--------|
| 6 | Create `.claude/` directory | 30m | MEDIUM |
| 7 | Create `scripts/` directory | 1h | MEDIUM |
| 8 | Implement viper configuration | 3h | MEDIUM |
| 9 | Remove emojis from docs | 1h | LOW |

### [*] Medium Priority

| # | Task | Effort | Impact |
|---|------|--------|--------|
| 10 | Create `infra/` directory structure | 2h | MEDIUM |
| 11 | Consolidate DDD document | 4h | LOW |
| 12 | Reorganize internal/ structure | 8h | MEDIUM |
| 13 | Update diagram standards | 2h | LOW |

### [/] Low Priority (Future)

| # | Task | Effort | Impact |
|---|------|--------|--------|
| 14 | Complete Okta provider | 8h | LOW |
| 15 | Complete Entra ID provider | 8h | LOW |
| 16 | Add integration tests | 8h | MEDIUM |
| 17 | Add E2E tests | 8h | LOW |

---

## Validation Checklist

Before considering implementation complete, verify:

- [ ] All API endpoints require authentication (except `/health`)
- [ ] Input validation on all request bodies
- [ ] Rate limiting enforced on all endpoints
- [ ] Test coverage >= 80% on critical paths
- [ ] No emojis in any documentation
- [ ] `.claude/rules.md` exists and is accurate
- [ ] `scripts/` directory with build/test/lint scripts
- [ ] `infra/` directory with cloud provider structure
- [ ] Viper-based configuration with env var overrides
- [ ] All ADRs consolidated in DDD document

---

## Appendix: Standards Quick Reference

### Go Error Handling Pattern
```go
if err != nil {
    return fmt.Errorf("doing operation X: %w", err)
}
```

### ASCII Symbols
```
[+] Success/Addition
[-] Failure/Removal
[!] Warning/Critical
[*] Important/Note
[/] In-progress/Partial
[x] Completed
[ ] Incomplete
```

### Color Palette
```
AWS:         #f59e0b (Orange)
Azure:       #3b82f6 (Blue)
GCP:         #22c55e (Green)
Core:        #1e40af (Dark Blue)
AI/ML:       #8b5cf6 (Purple)
DR/Failover: #ef4444 (Red)
```
