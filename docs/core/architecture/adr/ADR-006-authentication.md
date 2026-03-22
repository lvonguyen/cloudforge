# ADR-006: Authentication and Authorization

## Status

Accepted

## Date

2026-01-05

## Context

Secure authentication and authorization is required for:
- Multi-tenant SaaS access
- Enterprise SSO integration
- API access for automation
- Role-based access to findings and reports

### Requirements

- Support for enterprise identity providers (Entra ID, Okta)
- API key authentication for automation
- RBAC with fine-grained permissions
- MFA enforcement for privileged operations
- Zero Trust network access model

## Decision

**OIDC/SAML federation** for human users and **API keys with scopes** for machine access were selected, with role-based access control.

## Identity Providers

### Supported Providers

| Provider | Protocol | Priority |
|----------|----------|----------|
| Microsoft Entra ID | OIDC/SAML | Primary |
| Okta | OIDC/SAML | Primary |
| Google Workspace | OIDC | Secondary |
| Custom OIDC | OIDC | Custom |

### Provider Selection Rationale

- Entra ID: Most enterprise customers use M365
- Okta: Leading independent identity provider
- Both support SCIM for user provisioning

## RBAC Model

### Roles

| Role | Constant | Rank | Description | Findings | Reports | Config | Users |
|------|----------|------|-------------|----------|---------|--------|-------|
| viewer | `RoleViewer` | 0 | Read-only access | Read | - | - | - |
| requester | `RoleRequester` | 1 | Request resources | Read | Read | - | - |
| operator | `RoleOperator` | 2 | SecOps team | Read/Update | Create | Read | - |
| admin | `RoleAdmin` | 3 | Tenant admin | Full | Full | Full | Manage |

> **Note (updated Sprint B, 2026-03-16):** `RoleViewer` was added to the Go backend in Sprint B with rank 0 (lowest privilege). The viewer role has a read-only surface covering `/findings`, `/compliance/frameworks`, `/agents` + traces. 13+ RBAC tests verify viewer access controls. The `groupRoleMap` maps `aegis-viewer` group claims to `RoleViewer`. Fine-grained per-resource viewer scoping is not yet enforced.

### Permissions

```go
type Permission string

const (
    PermFindingsRead    Permission = "findings:read"
    PermFindingsWrite   Permission = "findings:write"
    PermFindingsDelete  Permission = "findings:delete"
    PermReportsCreate   Permission = "reports:create"
    PermReportsExport   Permission = "reports:export"
    PermConfigRead      Permission = "config:read"
    PermConfigWrite     Permission = "config:write"
    PermUsersManage     Permission = "users:manage"
    PermAuditRead       Permission = "audit:read"
)
```

### Attribute-Based Access (ABAC)

Beyond roles, support ABAC for:
- Finding visibility by business line (LoB)
- Environment restrictions (prod-only access)
- Time-based access (working hours only)

## API Authentication

### API Keys

- Scoped permissions (subset of user permissions)
- Automatic rotation every 90 days
- Rate limit tied to key tier
- Audit logging of all API key usage

### JWT Format

```json
{
  "sub": "user123",
  "iss": "aegis",
  "aud": "aegis-api",
  "exp": 1704456789,
  "iat": 1704453189,
  "groups": ["aegis-operator"],
  "tenant_id": "tenant456",
  "permissions": ["findings:read", "findings:write"],
  "lob": ["engineering", "security"],
  "mfa_verified": true
}
```

## Zero Trust Controls

- No implicit trust based on network location
- Every request authenticated and authorized
- Continuous validation of device posture (future)
- Just-In-Time (JIT) access for privileged operations

## Consequences

### Positive
- Enterprise-grade SSO support
- Granular access control
- Audit trail for compliance
- Scalable multi-tenancy

### Negative
- Initial complexity for identity setup
- Dependency on external identity providers
- Key rotation management overhead

### Mitigations
- Self-service identity provider configuration
- Automated key rotation with notification
- Graceful fallback if IdP unavailable

## Related Decisions

- ADR-005: Rate Limiting (per-client enforcement)
- ADR-007: GRC Integration Pattern

