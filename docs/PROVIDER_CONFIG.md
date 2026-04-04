# Provider Configuration Reference

CloudForge uses a factory pattern for all provider packages. Each provider is
configured via an environment variable that selects the implementation.

## Provider Selection

| Package | Env Var | Default | Valid Values | Notes |
|---------|---------|---------|--------------|-------|
| GRC | `GRC_PROVIDER` | `memory` | `memory`, `postgres`, `archer`, `servicenow` | Compliance/risk management backend |
| Identity | `OKTA_DOMAIN` / `ENTRA_TENANT_ID` | mock providers | auto-detected from credentials | Real provider activates when credentials are set |
| FinOps | `FINOPS_PROVIDER` | `memory` | `memory`, `aws`, `gcp`*, `azure`* | Cost aggregation source |
| Container | `CONTAINER_SCANNER` | `memory` | `memory`, `trivy` | Image vulnerability scanner |
| Workflow | `WORKFLOW_ENGINE` | `memory` | `memory` | Workflow orchestration engine |
| WAF | `WAF_PROVIDER` | `memory` | `memory` | WAF golden template manager |
| Secrets | `SECRETS_PROVIDER` | `memory` | `memory`, `aws`*, `azure`*, `gcp`* | Secrets vault provider |

\* = Stub implementation (returns `ErrNotImplemented`). Real provider to be
implemented when needed for production use.

## Per-Provider Configuration

### GRC

| Env Var | Required When | Description |
|---------|---------------|-------------|
| `GRC_PROVIDER` | always | Provider type |
| `AEGIS_DATABASE_URL` | `postgres` | PostgreSQL connection string |

### Identity

Identity providers are selected automatically based on available credentials.
Both Okta and Entra ID can be active simultaneously.

| Env Var | Required When | Description |
|---------|---------------|-------------|
| `OKTA_DOMAIN` | Okta | Okta org domain (e.g., `dev-12345.okta.com`) |
| `OKTA_API_TOKEN` | Okta | Okta API token (env var name, not value) |
| `ENTRA_TENANT_ID` | Entra ID | Azure AD tenant ID |
| `ENTRA_CLIENT_ID` | Entra ID | Azure AD app client ID |
| `ENTRA_CLIENT_SECRET` | Entra ID | Azure AD app client secret |

### FinOps

| Env Var | Required When | Description |
|---------|---------------|-------------|
| `FINOPS_PROVIDER` | always | Provider type |
| `FINOPS_AWS_REGION` | `aws` | AWS region for Cost Explorer (default: `us-east-1`) |

### Container

| Env Var | Required When | Description |
|---------|---------------|-------------|
| `CONTAINER_SCANNER` | always | Scanner type |

### Secrets

| Env Var | Required When | Description |
|---------|---------------|-------------|
| `SECRETS_PROVIDER` | always | Provider type |
| `SECRETS_AWS_REGION` | `SECRETS_PROVIDER=aws` | AWS region for Secrets Manager (falls back to `AWS_REGION` if set) |
| `SECRETS_AZURE_KEY_VAULT_URL` | `SECRETS_PROVIDER=azure` | Key Vault URL (for example `https://<vault>.vault.azure.net`) |
| `SECRETS_GCP_PROJECT_ID` | `SECRETS_PROVIDER=gcp` | GCP project ID for Secret Manager |

## Example: Production `.env`

```bash
# Core
PORT=8080
GRC_PROVIDER=postgres
AEGIS_DATABASE_URL=postgres://user:pass@host:5432/aegis?sslmode=require

# Identity (real providers)
OKTA_DOMAIN=haea.okta.com
OKTA_API_TOKEN=xxxxxxxxxxxx
ENTRA_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
ENTRA_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
ENTRA_CLIENT_SECRET=xxxxxxxxxxxx

# FinOps
FINOPS_PROVIDER=aws
FINOPS_AWS_REGION=us-east-1

# Container
CONTAINER_SCANNER=trivy

# Secrets
SECRETS_PROVIDER=memory

# Workflow / WAF (memory-only for now)
WORKFLOW_ENGINE=memory
WAF_PROVIDER=memory
```

## Health Endpoint

`GET /health` returns the active provider for each package:

```json
{
  "status": "healthy",
  "providers": {
    "grc": "memory",
    "identity": ["okta", "entra_id"],
    "finops": "memory",
    "container": "memory",
    "workflow": "memory",
    "waf": "memory",
    "secrets": "memory"
  }
}
```
