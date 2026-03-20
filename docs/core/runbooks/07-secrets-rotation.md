# Runbook: Secrets Rotation

## Overview

This runbook covers rotating secrets used by CloudForge, including:
- JWT signing keys
- Cloud provider credentials (AWS, Azure, GCP)
- Database connection strings
- Redis authentication
- AI provider API keys (Anthropic, OpenAI)
- Identity provider secrets (Okta, Entra ID)

## Prerequisites

- [ ] Access to cloud provider secret stores (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager)
- [ ] kubectl access to the CloudForge cluster
- [ ] Database admin access (for connection string rotation)
- [ ] 1Password vault access for development secrets

## Secret Inventory

| Secret | Storage | Rotation Frequency | Auto-Rotation |
|--------|---------|-------------------|---------------|
| JWT signing key | Env var / Secrets Manager | 90 days | No |
| PostgreSQL password | Secrets Manager / Key Vault | 90 days | RDS: Yes |
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
# AWS Secrets Manager
aws secretsmanager update-secret \
  --secret-id cloudforge/jwt-signing-key \
  --secret-string "$(cat new-jwt-secret.txt)" \
  --region us-east-1

# Azure Key Vault
az keyvault secret set \
  --vault-name cloudforge-kv \
  --name jwt-signing-key \
  --value "$(cat new-jwt-secret.txt)"
```

### Step 3: Deploy with Dual-Key Support

During rotation, both old and new keys must be accepted for a grace period (default: 24h). Update the configmap:

```bash
kubectl edit configmap cloudforge-config -n cloudforge
# Add: jwt.previous_signing_key = <old-key>
# Update: jwt.signing_key = <new-key>

kubectl rollout restart deployment/cloudforge-api -n cloudforge
kubectl rollout status deployment/cloudforge-api -n cloudforge
```

### Step 4: Remove Old Key (after grace period)

```bash
kubectl edit configmap cloudforge-config -n cloudforge
# Remove: jwt.previous_signing_key

kubectl rollout restart deployment/cloudforge-api -n cloudforge
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
  --secret-id cloudforge/db-password \
  --rotation-rules AutomaticallyAfterDays=90

# Manual rotation trigger
aws secretsmanager rotate-secret \
  --secret-id cloudforge/db-password

# Verify new password works
aws secretsmanager get-secret-value \
  --secret-id cloudforge/db-password \
  --query 'SecretString' --output text | \
  psql "postgresql://cloudforge:PASSWORD@cloudforge-db.xxx.rds.amazonaws.com/cloudforge" -c "SELECT 1;"
```

### Manual Rotation

```bash
# 1. Generate new password
NEW_PASSWORD=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 32)

# 2. Update database password
psql $DATABASE_URL -c "ALTER USER cloudforge PASSWORD '$NEW_PASSWORD';"

# 3. Update secret store
aws secretsmanager update-secret \
  --secret-id cloudforge/db-password \
  --secret-string "$NEW_PASSWORD"

# 4. Restart API pods to pick up new credentials
kubectl rollout restart deployment/cloudforge-api -n cloudforge
kubectl rollout status deployment/cloudforge-api -n cloudforge

# 5. Verify connectivity
kubectl exec -n cloudforge deployment/cloudforge-api -- \
  ./cloudforge health | grep database
```

## AI Provider API Key Rotation

### Anthropic Claude

```bash
# 1. Generate new key in Anthropic console
# https://console.anthropic.com/settings/keys

# 2. Update secret store
aws secretsmanager update-secret \
  --secret-id cloudforge/anthropic-api-key \
  --secret-string "$NEW_ANTHROPIC_KEY"

# 3. Restart API pods
kubectl rollout restart deployment/cloudforge-api -n cloudforge

# 4. Verify AI provider health
curl -sf https://api.cloudforge.io/health | jq '.components.ai_provider'

# 5. Revoke old key in Anthropic console
```

### OpenAI (Fallback)

```bash
# Same process, different secret ID
aws secretsmanager update-secret \
  --secret-id cloudforge/openai-api-key \
  --secret-string "$NEW_OPENAI_KEY"

kubectl rollout restart deployment/cloudforge-api -n cloudforge
```

## Identity Provider Secret Rotation

### Okta API Token

```bash
# 1. Create new token in Okta Admin Console
# Security > API > Tokens > Create Token

# 2. Update secret
aws secretsmanager update-secret \
  --secret-id cloudforge/okta-api-token \
  --secret-string "$NEW_OKTA_TOKEN"

# 3. Restart and verify
kubectl rollout restart deployment/cloudforge-api -n cloudforge
curl -sf https://api.cloudforge.io/health | jq '.components.identity_provider'

# 4. Revoke old token in Okta Admin Console
```

### Entra ID Client Secret

```bash
# 1. Create new client secret in Azure Portal
# App registrations > CloudForge > Certificates & secrets > New client secret

# 2. Update Key Vault
az keyvault secret set \
  --vault-name cloudforge-kv \
  --name entra-client-secret \
  --value "$NEW_ENTRA_SECRET"

# 3. Restart and verify
kubectl rollout restart deployment/cloudforge-api -n cloudforge
```

## Development Secrets

Development JWT secrets are stored in 1Password (`cloudforge-dev-jwt-secret` vault item) and referenced in `frontend/.env.development` (gitignored).

```bash
# Rotate dev JWT secret
# 1. Generate new secret
openssl rand -base64 64

# 2. Update 1Password vault item
# 3. Update frontend/.env.development with new VITE_DEV_TOKEN
# 4. Restart dev server
```

## Verification

After any secret rotation:

```bash
# 1. Health check
curl -sf https://api.cloudforge.io/health | jq .

# 2. Verify no auth errors in logs (wait 5 minutes)
kubectl logs -n cloudforge -l app=cloudforge-api --since=5m | \
  grep -i "auth.*error\|unauthorized\|forbidden" | head -20

# 3. Run smoke test
curl -sf https://api.cloudforge.io/api/v1/findings \
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
