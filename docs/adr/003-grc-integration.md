# ADR-003: GRC Integration Pattern

## Status
Accepted

## Context

CloudForge needs to integrate with enterprise GRC (Governance, Risk, Compliance) platforms to manage policy exceptions. When users request cloud resources that violate policy (e.g., unapproved region, oversized instance), they must submit exception requests that go through a risk assessment and approval workflow.

Different organizations use different GRC tools:
- **RSA Archer** - Common in large enterprises, especially financial services
- **ServiceNow GRC** - Popular for organizations already using ServiceNow ITSM
- **Smaller organizations** - May not have enterprise GRC tools at all

We need an architecture that:
1. Supports multiple GRC backends
2. Allows organizations to swap providers without code changes
3. Provides a fallback for orgs without enterprise GRC
4. Maintains a consistent API for the rest of CloudForge

## Decision

We will implement a **Provider Pattern** with the following components:

### 1. GRCProvider Interface

A Go interface that defines all GRC operations:
- `CreateException` - Submit new exception request
- `GetException` - Retrieve exception details
- `UpdateException` - Modify existing exception
- `ValidateException` - Check if valid exception exists (called by OPA)
- `SubmitApproval` - Record approver decision
- `GetPendingApprovals` - List exceptions awaiting approval
- `GetExceptionsByApplication` - Audit trail per application
- `GetExpiringExceptions` - Proactive renewal notifications

### 2. Provider Implementations

| Provider | Use Case | Persistence | Production Ready |
|----------|----------|-------------|------------------|
| `MemoryGRCProvider` | Development, demos, testing | None | No |
| `PostgresGRCProvider` | Small/medium orgs without enterprise GRC | PostgreSQL | Yes |
| `ArcherGRCProvider` | Enterprise Archer deployments | RSA Archer | Stub only |
| `ServiceNowGRCProvider` | Enterprise ServiceNow deployments | ServiceNow | Stub only |

### 3. Provider Factory

A factory function that creates the appropriate provider based on configuration:

```go
provider, err := grc.NewProvider(grc.Config{
    Type: grc.ProviderTypePostgres,
    Postgres: db,
})
```

### 4. Configuration

Provider selection via environment variable or config file:

```yaml
grc:
  provider: postgres  # or: memory, archer, servicenow
  postgres:
    connection_string: "postgres://..."
  archer:
    base_url: "https://archer.company.com"
    module_id: 123
  servicenow:
    instance_url: "https://company.service-now.com"
```

## Consequences

### Positive

- **Flexibility**: Organizations can use their existing GRC tools
- **Testability**: In-memory provider enables fast unit/integration tests
- **Gradual adoption**: Start with Postgres, migrate to enterprise GRC later
- **Consistent API**: Core CloudForge code doesn't change regardless of GRC backend

### Negative

- **Abstraction overhead**: Some GRC-specific features may not map cleanly to interface
- **Stub implementations**: Archer and ServiceNow providers need real-world testing
- **Field mapping complexity**: Enterprise GRC tools use custom field IDs that vary by deployment

### Risks

- **Archer field IDs**: RSA Archer uses numeric field IDs that vary per installation. Implementation requires per-deployment configuration.
- **ServiceNow customization**: ServiceNow GRC module can be heavily customized. May need org-specific adapters.
- **Sync issues**: If exception status changes in GRC tool outside CloudForge, we need reconciliation.

## Alternatives Considered

### 1. Direct GRC Integration Only
Build only for one GRC platform (e.g., ServiceNow).

**Rejected because**: Limits addressable market, no option for orgs without enterprise GRC.

### 2. Webhook-Based Integration
GRC tools call CloudForge webhooks on status changes.

**Partially adopted**: This could complement the provider pattern for real-time sync, but doesn't replace the need to create/query exceptions.

### 3. GRC Abstraction Service
Separate microservice that handles all GRC integration.

**Deferred**: Adds operational complexity. Can extract later if the abstraction proves valuable.

## References

- [RSA Archer REST API Documentation](https://community.rsa.com/t5/archer-documentation/archer-rest-api-guide/ta-p/569842)
- [ServiceNow REST API](https://docs.servicenow.com/bundle/tokyo-application-development/page/integrate/inbound-rest/concept/c_RESTAPI.html)
- [Provider Pattern in Go](https://blog.golang.org/examples)
