# Runbook: Secrets Rotation

## Overview

This runbook covers rotating secrets used by Aegis, including:
- JWT signing keys
- Cloud provider credentials (AWS, Azure, GCP)
- Database connection strings
- Redis authentication
- AI provider API keys (Anthropic, OpenAI)
- Identity provider secrets (Okta, Entra ID)

## Rotation Sequence

![Secrets Rotation Sequence](../diagrams/secrets-rotation.svg)

> Runtime note (April 1, 2026): the public demo uses 1Password as the source of truth and syncs runtime secrets into Fly with `scripts/fly-sync-runtime-secrets.sh`. Kubernetes examples below are legacy guidance for a future self-managed deployment.

## Prerequisites

- [ ] Access to cloud provider secret stores (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager)
- [ ] `flyctl` authenticated against the `personal` org
- [ ] Database admin access (for connection string rotation)
- [ ] 1Password vault access for development secrets

## Secret Inventory

| Secret | Storage | Rotation Frequency | Auto-Rotation |
|--------|---------|-------------------|---------------|
| JWT signing key | 1Password + Fly secret | 90 days | No |
| PostgreSQL DSN | 1Password + Fly secret | 90 days | No |
| Redis AUTH token | Secrets Manager | 90 days | ElastiCache: Yes |
| Anthropic API key | Secrets Manager | 180 days | No |
| OpenAI API key | Secrets Manager | 180 days | No |
| Okta API token | Secrets Manager | 90 days | No |
| Entra ID client secret | Azure Key Vault | 365 days | No |
| AWS IAM access keys | IAM | 90 days | No (use OIDC/WIF) |

## JWT Signing Key Rotation

### Step 1: Generate New Key

```bash
# For HS256 (symmetric)
openssl rand -base64 64 > new-jwt-secret.txt

# For RS256 (asymmetric)
openssl genrsa -out new-jwt-private.pem 2048
openssl rsa -in new-jwt-private.pem -pubout -out new-jwt-public.pem
```

### Step 2: Store New Key

```bash
# Update the 1Password item backing AEGIS_JWT_SECRET
# Current Development ref:
op read op://Development/aegis-personal-jwt-secret/credential >/dev/null
```

### Step 3: Deploy with Dual-Key Support

During rotation, both old and new keys must be accepted for a grace period (default: 24h). In the live demo, update the 1Password item and re-sync Fly secrets:

```bash
./scripts/fly-sync-runtime-secrets.sh --include-postgres --include-integrations --include-threat-intel --apply

# If a staged dual-key rollout is required, set the temporary previous key directly
fly secrets set JWT_PREVIOUS_SIGNING_KEY="<old-key>" -a cloudforge-api
```

### Step 4: Remove Old Key (after grace period)

```bash
fly secrets unset JWT_PREVIOUS_SIGNING_KEY -a cloudforge-api
```

### Step 5: Clean Up

```bash
rm new-jwt-secret.txt new-jwt-private.pem new-jwt-public.pem
```

## Database Password Rotation

### AWS RDS (Auto-Rotation)

```bash
# Enable auto-rotation (90-day cycle)
aws secretsmanager rotate-secret \
  --secret-id aegis/db-password \
  --rotation-rules AutomaticallyAfterDays=90

# Manual rotation trigger
aws secretsmanager rotate-secret \
  --secret-id aegis/db-password

# Verify new password works
aws secretsmanager get-secret-value \
  --secret-id aegis/db-password \
  --query 'SecretString' --output text | \
  psql "postgresql://aegis:PASSWORD@aegis-db.xxx.rds.amazonaws.com/aegis" -c "SELECT 1;"
```

### Manual Rotation

```bash
# 1. Generate new password
NEW_PASSWORD=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 32)

# 2. Update the live database user/password or DSN target
psql "$AEGIS_DATABASE_URL" -c "ALTER USER aegis PASSWORD '$NEW_PASSWORD';"

# 3. Update the 1Password item referenced by AEGIS_DATABASE_URL_REF
# 4. Re-sync Fly runtime secrets
./scripts/fly-sync-runtime-secrets.sh --include-postgres --apply

# 5. Verify connectivity
curl -sf https://api.cloudforge.lvonguyen.com/health | jq '.components.postgres'
```

## AI Provider API Key Rotation

### Anthropic Claude

```bash
# 1. Generate new key in Anthropic console
# https://console.anthropic.com/settings/keys

# 2. Update the 1Password item backing the runtime ref
# 3. Re-sync Fly runtime secrets
./scripts/fly-sync-runtime-secrets.sh --include-threat-intel --include-integrations --apply

# 4. Verify AI provider health
curl -sf https://api.cloudforge.lvonguyen.com/health | jq '.components.ai_provider'

# 5. Revoke old key in Anthropic console
```

### OpenAI (Fallback)

```bash
# Same process, different 1Password item/ref
./scripts/fly-sync-runtime-secrets.sh --include-integrations --apply
```

## Identity Provider Secret Rotation

### Okta API Token

```bash
# 1. Create new token in Okta Admin Console
# Security > API > Tokens > Create Token

# 2. Update the 1Password item/ref
# 3. Re-sync Fly secrets and verify protected API access
./scripts/fly-sync-runtime-secrets.sh --include-integrations --apply
curl -sf https://api.cloudforge.lvonguyen.com/api/v1/providers \
  -H "Authorization: Bearer $API_TOKEN" | jq .

# 4. Revoke old token in Okta Admin Console
```

### Entra ID Client Secret

```bash
# 1. Create new client secret in Azure Portal
# App registrations > CloudForge > Certificates & secrets > New client secret

# 2. Update the 1Password item/ref
# 3. Re-sync Fly secrets and verify protected API access
./scripts/fly-sync-runtime-secrets.sh --include-integrations --apply
```

## Development Secrets

Development JWT secrets are stored in 1Password (`aegis-personal-jwt-secret`) and referenced via `op://Development/aegis-personal-jwt-secret/credential`.

```bash
# Rotate dev JWT secret
# 1. Generate new secret
openssl rand -base64 64

# 2. Update the 1Password vault item
# 3. Refresh any local env file or shell export that references it
# 4. Restart dev server
```

## Verification

After any secret rotation:

```bash
# 1. Health check
curl -sf https://api.cloudforge.lvonguyen.com/health | jq .

# 2. Verify no auth errors in logs (wait 5 minutes)
fly logs -a cloudforge-api --no-tail | \
  grep -i "auth.*error\|unauthorized\|forbidden" | head -20

# 3. Run smoke test
curl -sf https://api.cloudforge.lvonguyen.com/api/v1/findings \
  -H "Authorization: Bearer $API_TOKEN" | jq '.total'
```

## Escalation

| Condition | Action |
|-----------|--------|
| Rotation causes auth failures | Rollback to previous secret, investigate |
| Secret leaked in logs/git | Immediate rotation + security incident (Runbook 02) |
| Auto-rotation fails | Manual rotation, fix Lambda/function |
| Database password rotation breaks connections | Restart all pods, verify PgBouncer |

## Contact Information

- On-Call: PagerDuty
- Platform Team: #platform-support (Slack)
- Security Team: #security-ops (Slack)
