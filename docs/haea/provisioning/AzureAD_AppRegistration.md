# Azure AD App Registration — HAEA Cloud Guard (v2)

| Property | Value |
|----------|-------|
| Version | 2.0 |
| Author | Liem Vo-Nguyen |
| Team | HAEA Security TFT |
| Date | March 2026 |
| Status | Active |
| Owner | M365/AD Team |

---

## 1. Overview

The Azure AD (Entra ID) app registration provides Cloud Guard with read-only access to Azure Security Center and subscription resources. In v2, compute runs on AWS ECS — Azure AD is used solely for Azure API authentication, not as a compute identity.

**Changed from v1:**
- v1: App registration was the central identity for cross-cloud federation (ACI managed identity)
- v2: App registration is Azure-only — used for Azure Security Reader access from AWS ECS

---

## 2. App Registration Details

| Property | Value |
|----------|-------|
| Display Name | haea-cloud-guard |
| Application Type | Web application |
| Supported Account Types | Single tenant (HMGNA) |
| Azure AD Tenant | HMGNA tenant (52 subscriptions) |
| Authentication | Client secret (stored in AWS Secrets Manager) |

---

## 3. Architecture — AWS-to-Azure Authentication

```
ECS Task (AWS, 831926608679)
  |
  | HTTPS request with Bearer token
  | (obtained via client_credentials grant)
  v
Azure AD / Entra ID (HMGNA tenant)
  | Validates client_id + client_secret
  | Issues access token with Security Reader scope
  v
Azure Resource Manager / Security Center APIs
  | Security Reader + Reader at subscription scope
  v
Findings: Defender for Cloud, Policy Compliance, Advisor
```

**Why client credentials (not federated)?**
- AWS→Azure AD WIF is not natively supported (unlike AWS→GCP)
- Client secret stored in AWS Secrets Manager with automatic rotation
- Simpler than setting up a custom OIDC provider in Azure AD
- Security Reader is read-only — blast radius is minimal

---

## 4. Required Configuration

### 4.1 API Permissions

| API | Permission | Type | Purpose |
|-----|------------|------|---------|
| Microsoft Graph | Directory.Read.All | Application | Read tenant structure |
| Azure Service Management | user_impersonation | Delegated | (Optional — not needed for client credentials) |

**Note:** Most Azure security APIs use ARM tokens, not Graph tokens. The app registration needs the `Security Reader` RBAC role assigned at subscription scope, not Graph API permissions.

### 4.2 Client Secret

| Property | Value |
|----------|-------|
| Description | Cloud Guard — Azure Security Reader |
| Expiry | 24 months |
| Storage | AWS Secrets Manager: `haea-cg-prod-azure-client-secret` |
| Rotation | 60-day advance calendar reminder |

### 4.3 RBAC Role Assignments

Assign at each target subscription (52 subscriptions under HMGNA tenant):

| Role | Scope | Purpose |
|------|-------|---------|
| Security Reader | Subscription | Read Defender for Cloud findings, security scores, alerts |
| Reader | Subscription | Read resource inventory, network topology, policy compliance |

---

## 5. One-Shot Provisioning Checklist

### Prerequisites

- [ ] Azure CLI authenticated with Global Admin or Application Administrator
- [ ] Target subscription IDs listed (52 under HMGNA)
- [ ] AWS Secrets Manager access for storing client secret

### Step 5.1: Create App Registration

```bash
TENANT_ID="REPLACE_WITH_HMGNA_TENANT_ID"

az ad app create \
  --display-name "haea-cloud-guard" \
  --sign-in-audience "AzureADMyOrg"

APP_ID=$(az ad app list --display-name "haea-cloud-guard" --query "[0].appId" -o tsv)
echo "Application (client) ID: $APP_ID"
```

### Step 5.2: Create Service Principal

```bash
az ad sp create --id "$APP_ID"

SP_OBJECT_ID=$(az ad sp show --id "$APP_ID" --query "id" -o tsv)
echo "Service Principal Object ID: $SP_OBJECT_ID"
```

### Step 5.3: Create Client Secret

```bash
SECRET=$(az ad app credential reset \
  --id "$APP_ID" \
  --display-name "Cloud Guard Azure Reader" \
  --years 2 \
  --query "password" -o tsv)

echo "Client Secret: $SECRET"
echo "[!] Store in AWS Secrets Manager immediately — this value cannot be retrieved again"
```

### Step 5.4: Assign Security Reader + Reader (per subscription)

```bash
# For each subscription:
SUBSCRIPTION_ID="REPLACE_WITH_SUB_ID"

az role assignment create \
  --assignee "$SP_OBJECT_ID" \
  --role "Security Reader" \
  --scope "/subscriptions/$SUBSCRIPTION_ID"

az role assignment create \
  --assignee "$SP_OBJECT_ID" \
  --role "Reader" \
  --scope "/subscriptions/$SUBSCRIPTION_ID"
```

**For all 52 subscriptions (batch):**
```bash
for SUB_ID in $(az account list --query "[].id" -o tsv); do
  echo "Assigning roles to subscription: $SUB_ID"
  az role assignment create --assignee "$SP_OBJECT_ID" --role "Security Reader" --scope "/subscriptions/$SUB_ID" 2>/dev/null
  az role assignment create --assignee "$SP_OBJECT_ID" --role "Reader" --scope "/subscriptions/$SUB_ID" 2>/dev/null
done
```

### Step 5.5: Store Credentials in AWS Secrets Manager

```bash
aws secretsmanager create-secret \
  --name "haea-cg-prod-azure-client-secret" \
  --description "Azure AD client secret for Cloud Guard Security Reader" \
  --secret-string "{\"client_id\":\"$APP_ID\",\"client_secret\":\"$SECRET\",\"tenant_id\":\"$TENANT_ID\"}"
```

### Step 5.6: Validation

```bash
# Acquire token
TOKEN=$(az account get-access-token \
  --resource "https://management.azure.com" \
  --query accessToken -o tsv)

# Test Security Center access
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/providers/Microsoft.Security/assessments?api-version=2021-06-01" \
  | jq '.value | length'

# Test resource inventory
az resource list --subscription "$SUBSCRIPTION_ID" --query "length(@)"
```

---

## 6. Validated Test Results (2026-03-24)

| Test | Environment | Result |
|------|-------------|--------|
| App registration creation | sub-lvn-dev (PVD Solutions) | PASS |
| Service principal creation | sub-lvn-dev | PASS |
| Security Reader assignment | sub-lvn-dev | PASS |
| Reader assignment | sub-lvn-dev | PASS |
| Defender for Cloud API | sub-lvn-dev | PASS |
| Resource inventory API | sub-lvn-dev | PASS |
| Policy compliance API | sub-lvn-dev | PASS |
| Security score API | sub-lvn-dev | PASS |
| Advisor recommendations | sub-lvn-dev | PASS |
| Network topology | sub-lvn-dev | PASS |

**Result: 10/10 PASS.** Test resources in sub-lvn-dev. Calendar reminder April 20 to teardown.

---

## 7. Environment Variables (ECS Task)

| Variable | Source | Description |
|----------|--------|-------------|
| `AZURE_TENANT_ID` | Hardcoded | HMGNA tenant ID |
| `AZURE_CLIENT_ID` | AWS Secrets Manager | App registration client ID |
| `AZURE_CLIENT_SECRET` | AWS Secrets Manager | App registration client secret |

Cloud Guard uses the `azidentity.NewClientSecretCredential()` SDK call with these values.

---

## 8. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `AADSTS700016` (app not found) | Wrong tenant or app ID | Verify `AZURE_TENANT_ID` and `AZURE_CLIENT_ID` |
| `AADSTS7000215` (invalid secret) | Expired or wrong secret | Rotate secret (step 5.3), update Secrets Manager |
| `AuthorizationFailed` on ARM API | Missing RBAC role on subscription | Verify Security Reader + Reader assigned (step 5.4) |
| Empty Defender findings | Defender plans not enabled | Enable Defender for Cloud on the subscription |
| `Forbidden` on specific sub | SP not assigned to that sub | Run role assignment for the missing subscription |

---

## 9. Security Considerations

- Client secret stored in AWS Secrets Manager (not Azure Key Vault) — single secrets plane
- 24-month expiry with 60-day rotation reminder
- Security Reader + Reader = read-only (no write, no delete, no policy changes)
- Service principal has no interactive sign-in capability
- Conditional Access can restrict SP to VPN-only IP ranges if needed
- All authentications logged in Azure AD sign-in logs

---

## Contact

| Property | Value |
|----------|-------|
| Primary Contact | Liem Vo-Nguyen (liem.vo-nguyen@haeaus.com) |
| Backup Contact | Seungwoo Son (seungwooson@haeaus.com) |
| Team | HAEA Security TFT |
