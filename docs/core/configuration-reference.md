# Cloud Aegis Configuration Reference

All configuration is via environment variables. Defaults are tuned for local development.

## Server

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `PORT` | `8080` | No | HTTP listen port |
| `APP_ENV` | `production` | No | Environment (`development` enables pprof, dev CORS, RoleSwitcher) |
| `GRC_PROVIDER` | `memory` | No | GRC backend (`memory`, `archer`, `servicenow`) |
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

## Graph Database

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `PUPPYGRAPH_URL` | *(empty)* | No | PuppyGraph endpoint URL. Enables graph query proxy |

## WebSocket / SSE

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `WS_SERVER_URL` | *(empty)* | No | ws-server URL for SSE event publishing |
| `WS_PUBLISH_KEY` | *(empty)* | No | X-API-Key for ws-server /api/publish |

## Integrations

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `JIRA_URL` | *(empty)* | No | Jira server URL. Enables ticket provider |
| `JIRA_USER` | *(empty)* | If Jira | Jira username |
| `JIRA_TOKEN` | *(empty)* | If Jira | Jira API token |
| `GITLEAKS_LICENSE` | *(empty)* | CI only | Gitleaks license key (CI action) |

## Deployment (fly.toml defaults)

These are set in `fly.toml` for the Fly.io deployment:

| Variable | Value | Description |
|----------|-------|-------------|
| `PORT` | `8080` | HTTP listen port |
| `GRC_PROVIDER` | `memory` | In-memory GRC backend |
| `APP_ENV` | `production` | Production mode |
| `RATE_LIMIT_ENABLED` | `true` | Rate limiting on |
| `CORS_ALLOWED_ORIGINS` | `https://cloudaegis-demo.lvonguyen.com` | Cloudflare Pages domain |

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
