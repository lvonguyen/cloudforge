# Runbook: Identity Provider Setup

## Overview

This runbook covers configuring identity providers for CloudForge authentication, including:
- Okta OIDC setup and configuration
- Microsoft Entra ID setup and configuration
- JWT validation configuration
- Mock provider for development
- Troubleshooting authentication issues

## Prerequisites

- [ ] Admin access to Okta Admin Console or Azure Portal (Entra ID)
- [ ] kubectl access to the CloudForge cluster
- [ ] CloudForge configuration access (configmap or environment variables)

## Architecture

CloudForge uses config-driven identity provider selection:

```
OKTA_DOMAIN set    --> Okta provider activated
ENTRA_TENANT_ID set --> Entra ID provider activated
Neither set        --> Mock provider (development mode)
```

The server stores active providers in `Server.identityProviders` (`map[string]identity.Provider`). The JWT auth middleware validates tokens against the configured provider's JWKS endpoint.

Relevant code:
- `cmd/server/main.go` — Provider initialization
- `internal/identity/provider.go` — Provider interface
- `internal/identity/okta.go` — Okta implementation
- `internal/identity/entra_id.go` — Entra ID implementation
- `internal/identity/mock.go` — Mock provider for development

## Okta OIDC Setup

### Step 1: Create Okta Application

1. Go to Okta Admin Console > Applications > Create App Integration
2. Select: OIDC - OpenID Connect
3. Application type: Web Application
4. Settings:
   - App name: `CloudForge`
   - Grant type: Authorization Code
   - Sign-in redirect URIs: `https://app.cloudforge.io/callback`
   - Sign-out redirect URIs: `https://app.cloudforge.io`
   - Controlled access: Limit to specific groups

5. Note the following values:
   - Client ID
   - Client Secret
   - Okta Domain (e.g., `dev-12345.okta.com`)

### Step 2: Configure Groups and Roles

Map Okta groups to CloudForge roles:

| Okta Group | CloudForge Role |
|------------|----------------|
| `cloudforge-admin` | admin |
| `cloudforge-operator` | operator |
| `cloudforge-requester` | requester |

Configure group claim in Okta:
1. Security > API > Authorization Servers > default
2. Claims > Add Claim:
   - Name: `groups`
   - Include in token type: ID Token (Always)
   - Value type: Groups
   - Filter: Starts with `cloudforge-`

### Step 3: Configure CloudForge

```bash
# Set environment variables
kubectl set env deployment/cloudforge-api -n cloudforge \
  OKTA_DOMAIN="dev-12345.okta.com" \
  OKTA_CLIENT_ID="0oa..." \
  OKTA_CLIENT_SECRET="xxx"

# Or update configmap
kubectl edit configmap cloudforge-config -n cloudforge
# Add:
#   identity:
#     okta:
#       domain: "dev-12345.okta.com"
#       client_id: "0oa..."
#       client_secret: "xxx"

# Restart to pick up changes
kubectl rollout restart deployment/cloudforge-api -n cloudforge
kubectl rollout status deployment/cloudforge-api -n cloudforge
```

### Step 4: Verify

```bash
# Check health endpoint
curl -sf https://api.cloudforge.io/health | jq '.components.identity_provider'
# Expected: {"okta": "ok"}

# Test token validation
curl -sf https://api.cloudforge.io/api/v1/findings \
  -H "Authorization: Bearer $OKTA_TOKEN" | jq '.total'
```

## Microsoft Entra ID Setup

### Step 1: Register Application

1. Azure Portal > Entra ID > App registrations > New registration
2. Settings:
   - Name: `CloudForge`
   - Supported account types: Single tenant (or multi-tenant for MSP)
   - Redirect URI: Web > `https://app.cloudforge.io/callback`

3. Note: Application (client) ID, Directory (tenant) ID

### Step 2: Configure Authentication

1. Authentication > Add platform > Web
   - Redirect URIs: `https://app.cloudforge.io/callback`
   - ID tokens: Check
   - Access tokens: Check

2. Certificates & secrets > New client secret
   - Note the secret value (store in Key Vault)

### Step 3: Configure Token Claims

1. Token configuration > Add groups claim
   - Group types: Security groups
   - Customize token properties: Group ID

2. App roles > Create app role:
   - Display name: `CloudForge Admin`
   - Value: `admin`
   - Allowed member types: Users/Groups

   Repeat for `operator` and `requester`.

### Step 4: Configure CloudForge

```bash
# Set environment variables
kubectl set env deployment/cloudforge-api -n cloudforge \
  ENTRA_TENANT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
  ENTRA_CLIENT_ID="yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy" \
  ENTRA_CLIENT_SECRET="zzz"

# Restart
kubectl rollout restart deployment/cloudforge-api -n cloudforge
kubectl rollout status deployment/cloudforge-api -n cloudforge
```

### Step 5: Verify

```bash
# Check health endpoint
curl -sf https://api.cloudforge.io/health | jq '.components.identity_provider'
# Expected: {"entra_id": "ok"}
```

## Development Mode (Mock Provider)

When neither `OKTA_DOMAIN` nor `ENTRA_TENANT_ID` is set, CloudForge falls back to the mock provider.

In development mode:
- `AuthProvider` component auto-authenticates as admin
- `ProtectedRoute` skips auth checks when `import.meta.env.DEV` is true
- The dev JWT token is stored in `frontend/.env.development` (gitignored)
- The JWT signing secret is sourced from 1Password (`cloudforge-dev-jwt-secret`)

```bash
# Verify mock mode
curl -sf http://localhost:8080/health | jq '.components.identity_provider'
# Expected: {"mock": "ok"}

# Use dev header override for role testing
curl -sf http://localhost:8080/api/v1/findings \
  -H "X-CloudForge-Role: operator"
```

## JWT Validation Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `JWT_SIGNING_KEY` | HS256 symmetric key | Required (no default) |
| `JWT_ISSUER` | Expected `iss` claim | `cloudforge` |
| `JWT_AUDIENCE` | Expected `aud` claim | `cloudforge-api` |
| `JWKS_URL` | JWKS endpoint for RS256 | Auto-configured from IdP |
| `JWKS_CACHE_TTL` | JWKS cache duration | 1 hour |

## Troubleshooting

### Token Validation Fails

**Symptoms**: 401 Unauthorized on all API calls

**Diagnosis**:
```bash
kubectl logs -n cloudforge -l app=cloudforge-api --tail=100 | grep -i "jwt\|auth\|token"
```

**Common causes**:
1. **Expired token**: Check `exp` claim with `jwt.io`
2. **Wrong issuer**: Token `iss` doesn't match configured issuer
3. **Wrong audience**: Token `aud` doesn't match configured audience
4. **JWKS unreachable**: Network issue reaching IdP's JWKS endpoint
5. **Clock skew**: Server time differs from IdP time by more than allowed leeway

### Groups Claim Missing

**Symptoms**: Authenticated but 403 Forbidden (role not assigned)

**Diagnosis**:
```bash
# Decode token and check groups claim
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq '.groups'
```

**Resolution**:
1. Verify groups claim is configured in IdP (see setup steps above)
2. Verify user is assigned to the correct group/role in IdP
3. Check that group names match expected patterns (`cloudforge-admin`, etc.)

### JWKS Cache Stale

**Symptoms**: Tokens from one provider validate, but newly issued tokens fail

**Diagnosis**:
```bash
kubectl logs -n cloudforge -l app=cloudforge-api | grep "jwks\|key rotation"
```

**Resolution**:
```bash
# Force JWKS cache refresh by restarting pods
kubectl rollout restart deployment/cloudforge-api -n cloudforge
```

## Escalation

| Condition | Action |
|-----------|--------|
| All auth failing after IdP change | Check IdP status page, verify JWKS endpoint |
| Token validation intermittent | Check JWKS cache, verify clock sync |
| Role mapping incorrect | Review group claim configuration in IdP |
| Mock provider active in production | Immediately set OKTA_DOMAIN or ENTRA_TENANT_ID |

## Contact Information

- On-Call: PagerDuty
- Identity Team: #identity-platform (Slack)
- Security Team: #security-ops (Slack)
