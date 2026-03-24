# ADR-019: Multi-Tenant Data Isolation at the Database Layer

## Status

Accepted

## Date

2026-03-23

## Context

Cloud Aegis supports multi-tenancy via a middleware layer that resolves the tenant from JWT claims, HTTP headers, or subdomain, and injects a `tenant.Config` into the request context. However, **no database query enforces tenant isolation**. All SQL queries operate without a `WHERE tenant_id = ?` filter, meaning:

1. A compromised or misconfigured middleware allows full cross-tenant data access.
2. Internal service calls that bypass HTTP middleware (background jobs, event handlers) have no tenant boundary.
3. A bug in the tenant resolution logic silently serves data from the wrong tenant.

The architecture grill assessment scored the resilience pillar at 2.8/5 and security pillar at 3.9/5, partly due to this gap. The red team confirmed that middleware-only tenant isolation is insufficient for a multi-tenant SaaS deployment.

### Decision Drivers

- **Compliance**: SOC 2 Type II and ISO 27001 require demonstrable data isolation controls.
- **Defense in depth**: Middleware is a single layer; database-layer enforcement provides a second barrier.
- **Whitelabel readiness**: HAEA deployment serves multiple business units (HMA, KNA, HMNA, HMGNA) — each needs data isolation.

## Decision

Add a `tenant_id` column (with denormalized `tenant_name` for auditability) to all query-scoped database tables and enforce `WHERE tenant_id = $N` in every SQL query. The tenant ID is extracted from request context at the data access layer, with a fallback to `"default"` for backward-compatible single-tenant operation.

### Implementation Details

1. **Migration 005** adds `tenant_id VARCHAR(50) NOT NULL DEFAULT 'default'` and `tenant_name VARCHAR(255)` to all tables.
2. **`tenantFromCtx(ctx)`** helper extracts `(id, name)` from `tenant.FromContext(ctx)`.
3. Every `SELECT`, `INSERT`, `UPDATE` in `postgres_provider.go` includes `tenant_id` in the query.
4. Indexes on `(tenant_id, created_at DESC)` cover the primary query pattern.

### Tables Affected

| Table | tenant_id | tenant_name | Index |
|-------|-----------|-------------|-------|
| exception_requests | yes | yes | `(tenant_id, created_at DESC)` |
| approval_chain | yes | no | via exception FK |
| exception_audit_log | yes | no | via exception FK |
| risk_assessments | yes | no | via exception FK |
| compensating_controls | yes | no | via exception FK |
| findings | yes | yes | `(tenant_id)` |
| compliance_frameworks | yes | no | reference data |
| ai_agents | yes | no | - |
| agent_traces | yes | no | `(tenant_id)` |
| remediations | yes | yes | `(tenant_id)` |
| cost_summaries | yes | no | `(tenant_id)` |
| audit_log | yes | yes | `(tenant_id, timestamp DESC)` |

## Consequences

### Positive

- Cross-tenant data access is structurally impossible at the SQL layer.
- Background jobs and internal calls inherit tenant context, preventing accidental leaks.
- `tenant_name` denormalization eliminates join lookups for audit/export use cases.
- `DEFAULT 'default'` preserves backward compatibility for single-tenant deployments.

### Negative

- Every SQL query now has an additional `AND tenant_id = $N` clause (minor performance cost, offset by index).
- Developers must remember to pass context through to data access methods.
- Migration adds columns to all tables (one-time schema change, handled by `IF NOT EXISTS`).

### Risks

- If `tenantFromCtx` returns `"default"` when it shouldn't (context not propagated), queries will return empty results rather than cross-tenant data. This is a fail-safe default.

## Alternatives Considered

1. **Row-Level Security (RLS)**: PostgreSQL RLS policies could enforce tenant isolation transparently. Rejected because: (a) requires `SET LOCAL` per connection, complicating connection pooling; (b) less visible in code reviews; (c) harder to test.
2. **Schema-per-tenant**: Separate schemas per tenant. Rejected because: (a) migration complexity scales linearly with tenants; (b) cross-tenant reporting requires schema-qualified queries.
3. **Middleware-only (status quo)**: Rejected per red team findings — single layer, no defense in depth.
