# Cloud Aegis Configuration Reference

All configuration is via environment variables. Defaults are tuned for local development.

## Server

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `PORT` | `8080` | No | HTTP listen port |
| `APP_ENV` | `production` | No | Environment (`development` enables pprof, dev CORS, RoleSwitcher) |
| `GRC_PROVIDER` | `memory` | No | GRC backend (`memory`, `postgres`, `archer`, `servicenow`) |
| `CORS_ALLOWED_ORIGINS` | *(empty)* | No | Comma-separated allowed CORS origins |

## Auth / JWT

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `JWT_SECRET_ENV` | `AEGIS_JWT_SECRET` | No | Name of env var containing HMAC secret |
| `AEGIS_JWT_SECRET` | *(none)* | Prod | HS256 signing key (or use JWKS for RS256) |
| `AEGIS_JWKS_URL` | *(auto-derived)* | No | JWKS endpoint URL (auto-set from `OKTA_DOMAIN` if empty) |
| `JWT_ISSUER` | *(empty)* | No | Expected `iss` claim value |
| `JWT_AUDIENCE` | *(empty)* | No | Expected `aud` claim value |
| `TLS_CERT_FILE` | *(empty)* | No | Path to TLS certificate (enables HTTPS) |
| `TLS_KEY_FILE` | *(empty)* | No | Path to TLS private key |

## AI / Enrichment

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `AEGIS_AI_ENABLED` | `false` | No | Enable Bedrock AI enrichment |
| `AEGIS_AI_REGION` | `us-east-1` | No | AWS region for Bedrock |
| `AEGIS_AI_MODEL` | *(Sonnet)* | No | Bedrock model ID override |
| `ANTHROPIC_API_KEY` | *(empty)* | If Anthropic | Anthropic API key (direct provider, bypasses Bedrock) |
| `AWS_ACCESS_KEY_ID` | *(chain)* | If AI enabled | AWS credential (or use IAM role/SSO) |
| `AWS_SECRET_ACCESS_KEY` | *(chain)* | If AI enabled | AWS credential |

## Identity Providers

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `OKTA_DOMAIN` | *(empty)* | No | Okta org domain (e.g., `dev-12345.okta.com`). Enables real Okta provider |
| `OKTA_API_TOKEN` | *(empty)* | If Okta | Okta API token for user management |
| `ENTRA_TENANT_ID` | *(empty)* | No | Azure Entra ID tenant. Enables real Entra provider |
| `ENTRA_CLIENT_ID` | *(empty)* | If Entra | Entra app registration client ID |
| `ENTRA_CLIENT_SECRET` | *(empty)* | If Entra | Entra app registration client secret |

## Threat Intelligence

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `GREYNOISE_API_KEY` | *(empty)* | No | GreyNoise Community/Enterprise API key |
| `HIBP_API_KEY` | *(empty)* | No | Have I Been Pwned API key |
| `OTX_API_KEY` | *(empty)* | No | AlienVault OTX API key |

EPSS and KEV feeds are public (no key required).

## Redis / Rate Limiting

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `RATE_LIMIT_ENABLED` | `true` | No | Enable API rate limiting |
| `REDIS_ADDR` | `localhost:6379` | No | Redis address (rate limiter + health check) |
| `REDIS_PASSWORD_ENV` | `AEGIS_REDIS_PASSWORD` | No | Name of env var containing Redis password |
| `AEGIS_REDIS_PASSWORD` | *(empty)* | No | Redis auth password |

Falls back to local (in-memory) rate limiting when Redis is unavailable.

## Database

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `AEGIS_DATABASE_URL` | *(empty)* | No | PostgreSQL connection string for the Postgres GRC backend and `FINDINGS_SOURCE=postgres` (`postgres://user:pass@host:5432/db?sslmode=require`) |

When unset, audit logging stays in-memory. If `GRC_PROVIDER=postgres` or `FINDINGS_SOURCE=postgres`, startup requires this variable.

## Provider Selection

These variables control which provider implementation each subsystem uses. All default to `memory` (in-memory mock). See [PROVIDER_CONFIG.md](../PROVIDER_CONFIG.md) for per-provider required configuration.

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `WORKFLOW_ENGINE` | `memory` | No | Workflow engine backend (`temporal` for real workflows) |
| `WAF_PROVIDER` | `memory` | No | WAF backend (`aws`, `cloudflare` for real WAF rules) |
| `SECRETS_PROVIDER` | `memory` | No | Secrets scanner backend (`aws`, `azure`, `gcp` for real vault scanning) |
| `SECRETS_AWS_REGION` | *(empty)* | If `SECRETS_PROVIDER=aws` | AWS region for Secrets Manager (falls back to `AWS_REGION` if set) |
| `SECRETS_AZURE_KEY_VAULT_URL` | *(empty)* | If `SECRETS_PROVIDER=azure` | Azure Key Vault URL (`https://<vault>.vault.azure.net`) |
| `SECRETS_GCP_PROJECT_ID` | *(empty)* | If `SECRETS_PROVIDER=gcp` | GCP project ID for Secret Manager |

## Graph Database

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `PUPPYGRAPH_URL` | *(empty)* | No | PuppyGraph endpoint URL. Enables graph query proxy |
| `SECGRAPH_AUTO_TICKETS` | `false` | No | Automatically create routed tickets for newly materialized secgraph issues during startup sync when PostgreSQL is enabled |

## WebSocket / SSE

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `WS_SERVER_URL` | *(empty)* | No | ws-server URL for SSE event publishing |
| `WS_PUBLISH_KEY` | *(empty)* | No | X-API-Key for ws-server /api/publish |

## Container Security

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `CONTAINER_SCANNER` | `memory` | No | Container scanner backend (`trivy` for real scans) |
| `TRIVY_OUTPUT_PATH` | *(empty)* | No | Path to Trivy K8s JSON output; replaces mock topology |

## FinOps

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `FINOPS_PROVIDER` | `memory` | No | FinOps backend (`aws` for real Cost Explorer) |
| `FINOPS_AWS_REGION` | `us-east-1` | No | AWS region for Cost Explorer API |

## Encryption / Remediation

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `AEGIS_STATE_ENCRYPTION_KEY` | *(none)* | If encrypted rollback | AES-256-GCM key as 64-char hex string (32 bytes) |
| `AEGIS_ROLLBACK_TOKEN` | *(none)* | If rollback dispatcher | Authorization token for rollback ops (min 16 chars) |

## Integrations

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `JIRA_URL` | *(empty)* | No | Jira instance URL. Enables ticket provider |
| `JIRA_USERNAME` | *(empty)* | If Jira | Jira username (email for Jira Cloud) |
| `JIRA_API_TOKEN` | *(empty)* | If Jira | Jira REST API token |
| `JIRA_PROJECT_KEY` | *(empty)* | No | Default Jira project key |
| `JIRA_ISSUE_TYPE` | `Task` | No | Default issue type for created tickets |
| `ASANA_PAT` | *(empty)* | If Asana | Asana Personal Access Token |
| `ASANA_WORKSPACE_GID` | *(empty)* | No | Asana workspace GID |
| `ASANA_DEFAULT_PROJECT_GID` | *(empty)* | No | Default Asana project for ticket creation |
| `ASANA_WEBHOOK_TOKEN` | *(empty)* | If Asana webhooks | Pre-shared token for Asana webhook handshake auth |
| `GITLEAKS_LICENSE` | *(empty)* | CI only | Gitleaks license key (CI action) |

## GRC Provider Credentials

When `GRC_PROVIDER` is not `memory`, the selected backend requires credentials:

| Variable | Required For | Description |
|----------|-------------|-------------|
| `AEGIS_DB_PASSWORD` | `postgres` | PostgreSQL password (name configurable via `password_env` in config) |
| `ARCHER_PASSWORD` | `archer` | RSA Archer API password |
| `SERVICENOW_PASSWORD` | `servicenow` | ServiceNow API password |
| `SERVICENOW_CLIENT_ID` | `servicenow` (OAuth) | ServiceNow OAuth client ID |
| `SERVICENOW_CLIENT_SECRET` | `servicenow` (OAuth) | ServiceNow OAuth client secret |

## CSPM Aggregator

These variables configure the standalone CSPM aggregator binary (`cmd/cspm-aggregator`).

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `AWS_ROLE_ARN` | *(empty)* | If AWS | OIDC role ARN for cross-account CSPM reader access |
| `AZURE_TENANT_ID` | *(empty)* | If Azure | Azure tenant ID for CSPM aggregator (distinct from `ENTRA_TENANT_ID`) |
| `GCP_ORG_ID` | *(empty)* | If GCP | GCP organization ID for aggregator scans |
| `GCP_WIF_CONFIG_PATH` | *(empty)* | If GCP | Path to GCP Workload Identity Federation config file |
| `ASANA_PROJECT_GID` | *(empty)* | No | Asana project GID for aggregator notifications |
| `MAIL_SENDER_ADDRESS` | *(empty)* | No | Email sender address for aggregator notification emails |

## Deployment (fly.toml defaults)

These are set in `fly.toml` for the Fly.io deployment:

| Variable | Value | Description |
|----------|-------|-------------|
| `PORT` | `8080` | HTTP listen port |
| `GRC_PROVIDER` | `memory` | In-memory GRC backend |
| `APP_ENV` | `production` | Production mode |
| `RATE_LIMIT_ENABLED` | `true` | Rate limiting on |
| `CORS_ALLOWED_ORIGINS` | `https://cloudaegis-demo.lvonguyen.com` | Cloudflare Pages domain |

## Observability / Tracing

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `AEGIS_TRACING_ENABLED` | `false` | No | Enable OpenTelemetry distributed tracing |
| `AEGIS_OTLP_ENDPOINT` | `localhost:4317` | No | OTLP collector gRPC endpoint |
| `AEGIS_SAMPLING_RATE` | `1.0` | No | Trace sampling rate (0.0–1.0) |

## Feature Flags

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `AEGIS_RUST_PATHS` | `false` | No | Enable Rust FFI attack path engine (requires `rust` build tag; falls back to pure-Go engine) |

## Frontend (Vite Build-Time)

These variables are embedded at build time via Vite's `import.meta.env`:

| Variable | Default | Description |
|----------|---------|-------------|
| `VITE_API_URL` | `/api/v1` | API base URL override (e.g., `http://localhost:8080`) |
| `VITE_DEMO_MODE` | *(empty)* | Set `true` to enable demo access and mock fallbacks |
| `VITE_OKTA_ISSUER` | *(empty)* | Okta OIDC issuer URL for frontend auth |
| `VITE_OKTA_CLIENT_ID` | *(empty)* | Okta OIDC client ID |
| `VITE_WS_URL` | *(empty)* | WebSocket server URL for SSE events |
| `VITE_DEV_TOKEN` | *(empty)* | Dev-mode auth token override |
| `VITE_COMPANY_NAME` | `Contoso` | White-label company name |
| `VITE_PRODUCT_NAME` | `Cloud Aegis` | White-label product name |
| `VITE_LOGO_PATH` | `/icons/aegis-logo.svg` | Path to logo SVG |
| `VITE_EMAIL_DOMAIN` | `contoso.dev` | Domain used in demo email addresses |
| `VITE_REPO_PREFIX` | `github.com/contoso` | Repository URL prefix |
| `VITE_ENABLED_MODULES` | `aegis,cspm-aggregator` | Comma-separated enabled module list |
| `VITE_STORAGE_PREFIX` | `aegis` | sessionStorage/localStorage key prefix |
| `VITE_BRAND_PRIMARY` | *(empty)* | Primary brand color override (hex) |
| `VITE_BRAND_SECONDARY` | *(empty)* | Secondary brand color override (hex) |
| `VITE_BRAND_ACCENT` | *(empty)* | Accent brand color override (hex) |
| `VITE_THEME` | *(empty)* | Default theme (`light`, `dark`) |
| `VITE_DEMO_ACCESS_ENABLED` | *(empty)* | Set `true` to enable demo access button |

## Graceful Degradation

When optional services are unavailable, the server degrades gracefully:

| Missing | Behavior |
|---------|----------|
| Redis | Local in-memory rate limiting |
| AI credentials | Enrichment endpoint returns 503 |
| Okta/Entra env vars | Mock identity providers |
| PuppyGraph URL | Graph query endpoint disabled |
| Threat intel API keys | Respective feed skipped |
| ws-server URL | Deploy preview SSE disabled |
| Jira URL | Mock ticket provider |
| `AEGIS_DATABASE_URL` | In-memory audit logging only unless postgres-backed GRC/findings are explicitly enabled; those modes require this variable and fail fast when it is missing |
| `WORKFLOW_ENGINE` | In-memory workflow stubs |
| `WAF_PROVIDER` | In-memory WAF stubs |
| `SECRETS_PROVIDER` | In-memory secrets scanner |
