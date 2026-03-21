# Cloud Aegis API Reference

Base URL: `/api/v1` (all endpoints require JWT authentication unless noted)

## Pagination Contract

List endpoints accept query parameters:
- `page` (default: 1) — 1-indexed page number
- `per_page` (default: 50, max: 200) — items per page

Response envelope:
```json
{
  "data": [...],
  "page": 1,
  "per_page": 50,
  "total": 247,
  "total_pages": 5
}
```

## Error Response Format

All errors return:
```json
{
  "code": "FINDING_NOT_FOUND",
  "message": "finding not found",
  "status": 404
}
```

Error codes: `BAD_REQUEST`, `FORBIDDEN`, `NOT_FOUND`, `{RESOURCE}_NOT_FOUND`, `CONFLICT`, `RATE_LIMITED`, `SERVICE_UNAVAILABLE`, `INTERNAL_ERROR`.

## Endpoints

### Health (Unauthenticated)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Full health check (components + status) |
| GET | `/healthz` | Liveness probe (always 200) |
| GET | `/ready` | Readiness probe (checks dependencies) |
| GET | `/metrics` | Prometheus metrics endpoint |

### Config (Unauthenticated)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/config` | Tenant branding + feature flags |
| GET | `/config.json` | Alias for config (frontend SPA) |

### Findings

| Method | Path | Roles | Paginated | Description |
|--------|------|-------|-----------|-------------|
| GET | `/api/v1/findings` | viewer, operator, admin | Yes | List findings (filters: severity, provider, status) |
| GET | `/api/v1/findings/query` | viewer, operator, admin | Yes | RQL-based finding query |
| POST | `/api/v1/findings/ingest` | operator, admin | No | Ingest new finding (dedup cache) |
| GET | `/api/v1/findings/{id}` | viewer, operator, admin | No | Get finding by ID (scope-enforced) |
| POST | `/api/v1/findings/{id}/enrich` | operator, admin | No | AI + threat intel enrichment |
| GET | `/api/v1/findings/{id}/comments` | viewer, requester, operator, admin | No | List finding comments |
| POST | `/api/v1/findings/{id}/comments` | operator, admin | No | Add comment to finding |
| DELETE | `/api/v1/findings/{id}/comments/{commentId}` | operator, admin | No | Delete finding comment |
| POST | `/api/v1/findings/{id}/remediate` | operator, admin | No | Create remediation ticket (integration layer) |
| GET | `/api/v1/findings/{id}/ticket` | operator, admin | No | Get linked ticket status |

### Compliance

| Method | Path | Roles | Paginated | Description |
|--------|------|-------|-----------|-------------|
| GET | `/api/v1/compliance/frameworks` | viewer, operator, admin | Yes | List compliance frameworks |
| GET | `/api/v1/compliance/posture` | viewer, operator, admin | No | Aggregated compliance posture |
| GET | `/api/v1/compliance/controls/{fw}` | viewer, operator, admin | No | Controls for a framework |

### Agents

| Method | Path | Roles | Paginated | Description |
|--------|------|-------|-----------|-------------|
| GET | `/api/v1/agents` | viewer, operator, admin | Yes | List security agents |
| GET | `/api/v1/agents/{id}` | viewer, operator, admin | No | Get agent by ID |
| GET | `/api/v1/agents/{id}/traces` | viewer, operator, admin | No | List agent execution traces |

### Remediations

| Method | Path | Roles | Paginated | Description |
|--------|------|-------|-----------|-------------|
| GET | `/api/v1/remediations` | viewer, operator, admin | Yes | List remediations (filters: status, tier) |
| GET | `/api/v1/remediations/{id}` | viewer, operator, admin | No | Get remediation by ID |
| POST | `/api/v1/remediations/{id}/execute` | operator, admin | No | Execute remediation |
| PATCH | `/api/v1/remediations/{id}` | operator, admin | No | Update remediation status |

### GRC / Exceptions

| Method | Path | Roles | Paginated | Description |
|--------|------|-------|-----------|-------------|
| GET | `/api/v1/exceptions/pending` | operator, admin | No | List pending exception approvals |
| GET | `/api/v1/exceptions/expiring` | operator, admin | No | List expiring exceptions |
| GET | `/api/v1/exceptions/mine` | requester, operator, admin | No | List user's own exceptions |
| GET | `/api/v1/exceptions/{id}` | operator, admin | No | Get exception by ID |
| POST | `/api/v1/exceptions` | admin | No | Create new exception request |
| POST | `/api/v1/exceptions/{id}/approve` | admin | No | Submit approval decision |
| POST | `/api/v1/exceptions/{id}/withdraw` | requester, operator, admin | No | Withdraw exception |
| GET | `/api/v1/applications/{appId}/exceptions` | operator, admin | No | List exceptions by app (ownership-scoped) |
| POST | `/api/v1/validate/exception` | operator, admin | No | Validate exception against policy |

### Policies

| Method | Path | Roles | Paginated | Description |
|--------|------|-------|-----------|-------------|
| GET | `/api/v1/policies` | viewer, operator, admin | Yes | List policies (filters: status, category) |
| GET | `/api/v1/policies/{id}` | viewer, operator, admin | No | Get policy by ID |

### Attack Paths

| Method | Path | Roles | Paginated | Description |
|--------|------|-------|-----------|-------------|
| GET | `/api/v1/attack-paths` | viewer, operator, admin | Yes (20/page, max 100) | List computed attack paths |
| GET | `/api/v1/attack-paths/stats` | viewer, operator, admin | No | Attack path statistics |
| GET | `/api/v1/attack-paths/{id}` | viewer, operator, admin | No | Get attack path by ID |
| GET | `/api/v1/attack-paths/{id}/analysis` | viewer, operator, admin | No | AI analysis of attack path |

### Costs (FinOps)

| Method | Path | Roles | Paginated | Description |
|--------|------|-------|-----------|-------------|
| GET | `/api/v1/costs/summary` | viewer, operator, admin | No | Computed cost summary (all providers) |

### Identity & Zero Trust

| Method | Path | Roles | Paginated | Description |
|--------|------|-------|-----------|-------------|
| GET | `/api/v1/identity/users` | viewer, operator, admin | No | List identity users (Okta/Entra ID) |
| GET | `/api/v1/identity/users/{id}/risk` | viewer, operator, admin | No | Get user risk score |
| GET | `/api/v1/users` | admin | Yes | List platform users |

### Audit

| Method | Path | Roles | Paginated | Description |
|--------|------|-------|-----------|-------------|
| GET | `/api/v1/audit-log` | admin | Yes | Audit log (filters: result, actor) |

### AI

| Method | Path | Roles | Paginated | Description |
|--------|------|-------|-----------|-------------|
| POST | `/api/v1/ai/nlq` | operator, admin | No | Natural language query |
| GET | `/api/v1/ai/usage` | admin | No | AI usage/budget status |

### Container Security

| Method | Path | Roles | Paginated | Description |
|--------|------|-------|-----------|-------------|
| GET | `/api/v1/containers` | viewer, operator, admin | No | List container workloads |
| GET | `/api/v1/containers/{id}` | viewer, operator, admin | No | Get container details |
| GET | `/api/v1/container/scan` | operator, admin | No | Scan container image |
| GET | `/api/v1/container/admission` | operator, admin | No | Admission policy check |

### Secrets Management

| Method | Path | Roles | Paginated | Description |
|--------|------|-------|-----------|-------------|
| GET | `/api/v1/secrets` | operator, admin | No | List secrets |
| POST | `/api/v1/secrets/scan` | operator, admin | No | Scan content for secrets |
| GET | `/api/v1/secrets/{path}` | operator, admin | No | Get secret by path |
| POST | `/api/v1/secrets/org-scan` | operator, admin | No | Org-wide secrets scan |

### WAF

| Method | Path | Roles | Paginated | Description |
|--------|------|-------|-----------|-------------|
| GET | `/api/v1/waf/templates` | viewer, operator, admin | No | List WAF rule templates |
| GET | `/api/v1/waf/compliance/{templateId}` | viewer, operator, admin | No | Validate WAF compliance |

### Webhooks

| Method | Path | Roles | Paginated | Description |
|--------|------|-------|-----------|-------------|
| POST | `/api/v1/webhooks` | operator, admin | No | Register webhook |
| GET | `/api/v1/webhooks` | operator, admin | No | List webhooks |
| DELETE | `/api/v1/webhooks/{id}` | operator, admin | No | Delete webhook |
| GET | `/api/v1/webhooks/{id}/deliveries` | operator, admin | No | List webhook deliveries |

### Workflows

| Method | Path | Roles | Paginated | Description |
|--------|------|-------|-----------|-------------|
| GET | `/api/v1/workflows` | operator, admin | No | List workflows |
| GET | `/api/v1/workflows/{id}` | operator, admin | No | Get workflow by ID |
| POST | `/api/v1/workflows/{id}/approve` | operator, admin | No | Approve workflow |

### Deploy Preview

| Method | Path | Roles | Paginated | Description |
|--------|------|-------|-----------|-------------|
| POST | `/api/v1/deploy/preview` | operator, admin | No | Start deploy preview |
| POST | `/api/v1/deploy/preview/{id}/abort` | operator, admin | No | Abort deploy preview |

### Data Classification (DSPM)

| Method | Path | Roles | Paginated | Description |
|--------|------|-------|-----------|-------------|
| GET | `/api/v1/data-classification/assets` | viewer, operator, admin | No | List data assets with sensitivity |

### ASM (Attack Surface Management)

| Method | Path | Roles | Paginated | Description |
|--------|------|-------|-----------|-------------|
| POST | `/api/v1/asm/scan` | operator, admin | No | Trigger ASM scan |
| GET | `/api/v1/asm/assets` | operator, admin | No | List discovered assets |

### Catalog

| Method | Path | Roles | Paginated | Description |
|--------|------|-------|-----------|-------------|
| GET | `/api/v1/catalog/modules` | viewer, operator, admin | Yes | List Terraform modules (filters: provider, category, search) |

### Graph Query

| Method | Path | Roles | Paginated | Description |
|--------|------|-------|-----------|-------------|
| POST | `/api/v1/graph/query` | operator, admin | No | PuppyGraph Gremlin query proxy |

### Integration Webhooks (Unauthenticated, HMAC-verified)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/webhooks/asana` | Asana webhook receiver |

## RBAC Roles

| Role | Rank | Description |
|------|------|-------------|
| `viewer` | 0 | Read-only access to findings, compliance, agents |
| `requester` | 1 | Viewer + exception request/withdraw |
| `operator` | 2 | Requester + write operations (remediate, enrich, scan) |
| `admin` | 3 | Full access (audit log, user management, approvals) |

All endpoints require at minimum `viewer` role. The `Require()` middleware enforces minimum role rank — e.g., `Require(RoleOperator, RoleAdmin)` allows operator and admin but denies viewer and requester.

**Note:** `DELETE /findings/{id}/comments/{commentId}` has an additional in-handler admin-only check beyond the RBAC middleware — non-admin callers receive 403 even though the middleware passes them.

## RBAC Authorization Matrix (from integration tests)

| Endpoint | Unauthenticated | Requester | Operator | Admin |
|----------|-----------------|-----------|----------|-------|
| GET /api/v1/findings | 401 | 403 | 200 | 200 |
| GET /api/v1/exceptions/mine | 401 | 200 | 200 | 200 |
| GET /api/v1/exceptions/{id} | 401 | 403 | 200 | 200 |
| POST /api/v1/exceptions | 401 | 403 | 200 | 201 |
| GET /api/v1/agents | 401 | 403 | 200 | 200 |
| GET /api/v1/audit-log | 401 | 403 | 200 | 200 |
| GET /api/v1/users | 401 | 403 | 200 | 200 |
| GET /api/v1/identity/users | 401 | 403 | 200 | 200 |
| GET /api/v1/workflows | 401 | 403 | 200 | 200 |
| GET /api/v1/secrets | 401 | 403 | 200 | 200 |
| DELETE /findings/{id}/comments/{cid} | 401 | 403 | 403 | 204 |
