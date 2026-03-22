# ADR-013: Resource-Scoped RBAC

## Status

Accepted

## Date

2026-03-12

## Context

Cloud Aegis implements role-based access control (RBAC) with four roles: `admin`, `operator`, `requester`, and `viewer`. This model works for small teams (5-10 users) but breaks down at enterprise scale (100+ operators across multiple business units).

### Current RBAC Model

| Role | Permissions |
|------|-------------|
| `admin` | Full access: manage users, execute all tiers of remediation, view all findings |
| `operator` | Execute T1-T2 remediation, view findings, cannot manage users |
| `requester` | View findings, request remediation, cannot execute |
| `viewer` | Read-only access to findings and dashboards (least-privilege default) |

### Problem Statement

In a large organization with 50+ cloud accounts across different business units (payments, infrastructure, data platform), operators should only access findings and execute remediation for their assigned scope. Current implementation grants all operators global access.

**Example Scenario**:
- Alice (operator, payments team) should only see findings for `account-123456` (payments prod) and `account-789012` (payments staging)
- Bob (operator, infra team) should only see findings for shared infrastructure accounts
- Current system: Both Alice and Bob see ALL findings across all accounts

### Requirements

1. **Business Unit Scoping**: Operators limited to specific accounts, regions, or resource tags
2. **Environment Scoping**: Separate permissions for prod vs non-prod
3. **Multi-Dimensional Scoping**: Combine business unit + environment (e.g., "payments + prod only")
4. **Backwards Compatibility**: Existing JWTs without scope claims should continue working
5. **Dynamic Enforcement**: Scope enforcement at API layer (not UI-only filtering)

## Decision

RBAC is extended with **attribute-based access control (ABAC)** using JWT custom claims for resource scoping.

### 1. JWT Claim Structure

Extend JWT payload with a `scope` claim containing an array of attribute filters:

```json
{
  "sub": "alice@company.com",
  "groups": ["operator"],
  "scope": {
    "business_units": ["payments", "platform"],
    "environments": ["prod", "staging"],
    "regions": ["us-east-1", "us-west-2"],
    "account_ids": ["123456789012", "987654321098"]
  },
  "iat": 1710259200,
  "exp": 1710262800
}
```

**Scope Semantics**:
- **Empty array** (e.g., `"business_units": []`) → no access to this dimension
- **Missing field** (e.g., no `regions` key) → no filter on this dimension (access all regions)
- **Wildcard** (e.g., `"environments": ["*"]`) → explicit full access

### 2. Scope Enforcement Logic

Add `ScopeFilter` to `RoleEnforcer.Require()` middleware:

```go
// pkg/rbac/enforcer.go
type ScopeFilter struct {
    BusinessUnits []string
    Environments  []string
    Regions       []string
    AccountIDs    []string
}

func (e *RoleEnforcer) EnforceScope(finding *Finding, userScope ScopeFilter) error {
    // Missing scope = admin (legacy behavior)
    if userScope.IsEmpty() {
        return nil
    }

    // Check account ID
    if len(userScope.AccountIDs) > 0 && !contains(userScope.AccountIDs, finding.AccountID) {
        return ErrScopeDenied
    }

    // Check region
    if len(userScope.Regions) > 0 && !contains(userScope.Regions, finding.Region) {
        return ErrScopeDenied
    }

    // Check environment (requires resource tagging)
    if len(userScope.Environments) > 0 {
        env := extractEnvTag(finding.ResourceID) // e.g., "prod" from tags
        if !contains(userScope.Environments, env) {
            return ErrScopeDenied
        }
    }

    // Check business unit (requires resource tagging)
    if len(userScope.BusinessUnits) > 0 {
        bu := extractBusinessUnitTag(finding.ResourceID)
        if !contains(userScope.BusinessUnits, bu) {
            return ErrScopeDenied
        }
    }

    return nil
}
```

### 3. API Endpoint Changes

#### 3.1 List Endpoints (e.g., `GET /api/findings`)

Apply scope as **SQL WHERE clause** or **post-query filter**:

```go
// cmd/server/handlers_grc.go
func (s *server) handleGetFindings(w http.ResponseWriter, r *http.Request) {
    userScope := extractScopeFromJWT(r)

    // Option A: SQL filter (preferred for large datasets)
    findings, err := s.findingRepo.ListWithScope(ctx, userScope)

    // Option B: Post-query filter (simpler, less efficient)
    allFindings, err := s.findingRepo.List(ctx)
    findings := filterByScope(allFindings, userScope)

    // Return only scoped findings
    respondJSON(w, findings)
}
```

#### 3.2 Single-Resource Endpoints (e.g., `GET /api/findings/{id}`)

Check scope **before returning resource**:

```go
func (s *server) handleGetFinding(w http.ResponseWriter, r *http.Request) {
    findingID := mux.Vars(r)["id"]
    finding, err := s.findingRepo.Get(ctx, findingID)
    if err != nil {
        respondError(w, http.StatusNotFound, "Finding not found")
        return
    }

    // Enforce scope
    userScope := extractScopeFromJWT(r)
    if err := s.rbac.EnforceScope(finding, userScope); err != nil {
        respondError(w, http.StatusForbidden, "Access denied: resource outside scope")
        return
    }

    respondJSON(w, finding)
}
```

### 4. Identity Provider Integration

#### Okta Configuration

Add custom claims to JWT via Okta Authorization Server:

```json
{
  "name": "scope",
  "value": {
    "business_units": "user.profile.businessUnits",
    "environments": "user.profile.environments",
    "account_ids": "user.profile.accountIds"
  }
}
```

Users' profiles must include attributes: `businessUnits`, `environments`, `accountIds`.

#### Entra ID Configuration

Use Microsoft Graph API to set `extensionAttribute1`, `extensionAttribute2`, etc. on user objects:

```json
{
  "extensionAttribute1": "payments,platform",
  "extensionAttribute2": "prod,staging",
  "extensionAttribute3": "123456789012,987654321098"
}
```

Map these to JWT claims via Entra ID app registration (API permissions + token configuration).

## Consequences

### Positive

1. **Enterprise-Ready**: Supports large organizations with 100+ operators across multiple business units
2. **Least Privilege**: Operators only access findings relevant to their scope
3. **Compliance**: Meets SOC 2 access control requirements (principle of least privilege)
4. **Audit Trail**: Scope decisions logged in structured logs (`zap.Logger`)
5. **Dynamic**: No code changes needed to add new scopes (modify JWT claims only)

### Negative

1. **JWT Size Bloat**: Scopes add ~200 bytes to JWT (mitigate with JWT compression or reference tokens)
2. **IDP Dependency**: Requires custom claim configuration in Okta/Entra ID (setup complexity)
3. **Tagging Requirement**: Business unit and environment scoping requires consistent resource tagging

### Mitigations

1. **JWT Size**: Use opaque tokens + introspection endpoint if JWT exceeds 4KB (Okta limit)
2. **IDP Setup**: Provide Terraform modules for Okta/Entra ID configuration
3. **Tagging**: Enforce tagging policy via Service Control Policies (SCPs) or Azure Policy

## Alternatives Considered

### Alternative 1: Open Policy Agent (OPA)

Externalize authorization logic to OPA with Rego policies.

**Pros**:
- Centralized policy management
- Complex policies (e.g., time-based access, geo-fencing)
- Policy versioning and testing

**Cons**:
- Additional infrastructure component (OPA sidecar or server)
- Increased latency (network call for each authz decision)
- Learning curve (Rego language)

**Rejected because**: Adds significant operational complexity for a problem solvable with JWT claims.

---

### Alternative 2: Per-Resource ACLs

Store access control list (ACL) per finding: `{"finding_id": "123", "allowed_users": ["alice", "bob"]}`.

**Pros**:
- Granular control (per-resource permissions)
- No JWT size concerns

**Cons**:
- Requires ACL database table (storage overhead)
- ACL management UI needed
- Doesn't scale: 1M findings × 10 users/finding = 10M ACL rows

**Rejected because**: Too granular for the Cloud Aegis use case (business unit scoping is sufficient).

---

### Alternative 3: Team-Based Namespacing

Create isolated namespaces per team: `findings/payments/`, `findings/infra/`.

**Pros**:
- Simple conceptual model
- No JWT changes needed

**Cons**:
- Rigid: users on multiple teams require duplicate accounts
- Cross-team collaboration difficult (e.g., shared infrastructure)
- Doesn't support environment-based scoping

**Rejected because**: Too rigid for enterprise org structures (matrix organizations).

---

## Implementation Plan

### Phase 1: JWT Claim Extraction (Week 1)

- [ ] Add `scope` field to `User` struct in `internal/auth/user.go`
- [ ] Parse `scope` claim from JWT in `auth.Middleware()`
- [ ] Unit tests for scope extraction

### Phase 2: Scope Enforcement (Week 2)

- [ ] Implement `EnforceScope()` in `pkg/rbac/enforcer.go`
- [ ] Add `ScopeFilter` to all `GET /api/findings/*` endpoints
- [ ] Integration tests for scoped access

### Phase 3: IDP Configuration (Week 3)

- [ ] Document Okta custom claims setup
- [ ] Document Entra ID extension attributes setup
- [ ] Terraform modules for IDP config

### Phase 4: Audit & Monitoring (Week 4)

- [ ] Log all scope denial events (`zap.Info("scope denied", zap.String("user", ...), zap.String("resource", ...))`)
- [ ] Add Prometheus metrics: `aegis_rbac_scope_denials_total`
- [ ] Dashboard for scope violations (Grafana)

## Migration Path

### Backwards Compatibility

Existing JWTs without `scope` claim continue to work as **admin-level access** (no scoping). This ensures zero downtime during rollout.

```go
func (e *RoleEnforcer) EnforceScope(finding *Finding, userScope ScopeFilter) error {
    // Missing scope = legacy admin behavior
    if userScope.IsEmpty() {
        return nil
    }
    // ... rest of scope logic
}
```

### Gradual Rollout

1. **Week 1-2**: Deploy code with scope enforcement (feature flag OFF)
2. **Week 3**: Enable for 10% of users (canary group)
3. **Week 4**: Enable for all non-admin operators
4. **Week 5**: Enable for all users (including admins with explicit `"*"` scopes)

## Related Decisions

- **ADR-006**: Authentication Strategy — defines JWT structure and middleware
- **ADR-009**: Remediation Dispatcher — tier-based access control (orthogonal to resource scoping)

## References

- [NIST ABAC Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-162.pdf)
- [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
- [Okta Custom Claims Documentation](https://developer.okta.com/docs/guides/customize-tokens-returned-from-okta/main/)
- [Entra ID Extension Attributes](https://learn.microsoft.com/en-us/graph/extensibility-overview)
