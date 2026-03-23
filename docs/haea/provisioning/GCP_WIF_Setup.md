# GCP Workload Identity Federation - HAEA Cloud Security Automation

| Property | Value |
|----------|-------|
| Version | 1.0 |
| Author | Liem Vo-Nguyen |
| Team | HAEA Security TFT |
| Date | December 2025 |
| Status | Draft |
| Owner | GCP Team |

---

## 1. Overview

This document describes the GCP Workload Identity Federation (WIF) configuration required for the Cross-Cloud CSPM Automation Platform. WIF allows Azure Container Instance to authenticate to GCP without storing service account keys.

---

## 2. Account Context

| Property | Value |
|----------|-------|
| GCP Organization | haea.com |
| Security Project | prj-haea-security |
| Service Account | sa-cspm-automation@prj-haea-security.iam.gserviceaccount.com |
| WIF Pool | haea-azure-federation |
| WIF Provider | azure-oidc |

---

## 3. How WIF Works

```
Azure Container Instance
  → Request token from Azure AD (audience: api://{client-id})
  → Present token to GCP STS (token exchange)
  → GCP validates token against WIF provider
  → GCP issues short-lived credentials for service account
  → Access Security Command Center API
```

**Benefits:**
- No service account keys to manage or rotate
- Short-lived credentials (1 hour default)
- Audit trail of all token exchanges
- Centralized identity in Azure AD

---

## 4. Prerequisites

| Requirement | Value | Status |
|-------------|-------|--------|
| Azure AD App Registration | haea-cloud-security-automation | Pending AD team |
| Application ID URI | api://{client-id} | Pending AD team |
| Azure AD Tenant | bd29b3ab-aaa2-425a-b882-9e7f73283ca6 | Existing |
| Service Account | sa-cspm-automation | Existing or create |

---

## 5. WIF Pool Configuration

### 5.1 Create Workload Identity Pool

```bash
# Set project
gcloud config set project prj-haea-security

# Create WIF pool
gcloud iam workload-identity-pools create haea-azure-federation \
  --location="global" \
  --display-name="HAEA Azure Federation" \
  --description="WIF pool for Azure AD authentication"
```

### 5.2 Create WIF Provider

```bash
# Create OIDC provider
gcloud iam workload-identity-pools providers create-oidc azure-oidc \
  --location="global" \
  --workload-identity-pool="haea-azure-federation" \
  --display-name="Azure AD OIDC" \
  --issuer-uri="https://sts.windows.net/bd29b3ab-aaa2-425a-b882-9e7f73283ca6/" \
  --allowed-audiences="api://{client-id}" \
  --attribute-mapping="google.subject=assertion.sub,attribute.tid=assertion.tid"
```

### 5.3 Grant Service Account Impersonation

```bash
# Allow WIF pool to impersonate service account
gcloud iam service-accounts add-iam-policy-binding \
  sa-cspm-automation@prj-haea-security.iam.gserviceaccount.com \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/{project-number}/locations/global/workloadIdentityPools/haea-azure-federation/attribute.tid/bd29b3ab-aaa2-425a-b882-9e7f73283ca6"
```

---

## 6. Service Account Permissions

### 6.1 Organization-Level Roles

| Role | Purpose |
|------|---------|
| Security Center Findings Viewer | Read SCC findings |
| Security Center Sources Viewer | Read SCC sources |

```bash
# Grant at organization level
gcloud organizations add-iam-policy-binding {org-id} \
  --member="serviceAccount:sa-cspm-automation@prj-haea-security.iam.gserviceaccount.com" \
  --role="roles/securitycenter.findingsViewer"

gcloud organizations add-iam-policy-binding {org-id} \
  --member="serviceAccount:sa-cspm-automation@prj-haea-security.iam.gserviceaccount.com" \
  --role="roles/securitycenter.sourcesViewer"
```

### 6.2 Project-Level Roles (Optional)

If project-specific access is needed:

| Role | Purpose |
|------|---------|
| Viewer | Read project resources |
| Security Reviewer | Read IAM policies |

---

## 7. Credential Configuration File

Create credential configuration for the Go binary:

```json
{
  "type": "external_account",
  "audience": "//iam.googleapis.com/projects/{project-number}/locations/global/workloadIdentityPools/haea-azure-federation/providers/azure-oidc",
  "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "token_url": "https://sts.googleapis.com/v1/token",
  "credential_source": {
    "file": "/var/run/secrets/azure/token",
    "format": {
      "type": "text"
    }
  },
  "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/sa-cspm-automation@prj-haea-security.iam.gserviceaccount.com:generateAccessToken"
}
```

Save as `gcp-wif-config.json` and set environment variable:

```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/gcp-wif-config.json
```

---

## 8. Provisioning Checklist

### 8.1 Service Account

- [ ] Create service account `sa-cspm-automation` (or use existing)
- [ ] Note service account email
- [ ] Grant `securitycenter.findingsViewer` at org level
- [ ] Grant `securitycenter.sourcesViewer` at org level

### 8.2 Workload Identity Pool

- [ ] Create WIF pool `haea-azure-federation`
- [ ] Note pool ID and project number

### 8.3 WIF Provider

- [ ] Get Application ID URI from AD team
- [ ] Create OIDC provider `azure-oidc`
- [ ] Configure issuer URI (Azure AD tenant)
- [ ] Configure allowed audiences (App ID URI)
- [ ] Configure attribute mapping

### 8.4 IAM Binding

- [ ] Grant `workloadIdentityUser` role to WIF pool principal
- [ ] Restrict to Azure AD tenant ID attribute

### 8.5 Credential Config

- [ ] Generate credential configuration JSON
- [ ] Provide to Security TFT for container configuration

### 8.6 Validation

- [ ] Test token exchange from Azure
- [ ] Test SCC API access
- [ ] Verify audit logs show WIF authentication

---

## 9. Usage Examples

### 9.1 List Findings

```bash
# Using gcloud with WIF credentials
export GOOGLE_APPLICATION_CREDENTIALS=gcp-wif-config.json

gcloud scc findings list organizations/{org-id} \
  --filter="state=\"ACTIVE\" AND severity=\"CRITICAL\""
```

### 9.2 Programmatic Access (Go)

```go
import (
    "context"
    securitycenter "cloud.google.com/go/securitycenter/apiv1"
)

// Client auto-discovers credentials from GOOGLE_APPLICATION_CREDENTIALS
client, err := securitycenter.NewClient(context.Background())
```

---

## 10. Troubleshooting

### 10.1 Token Exchange Failures

```bash
# Check WIF pool exists
gcloud iam workload-identity-pools describe haea-azure-federation \
  --location="global"

# Check provider configuration
gcloud iam workload-identity-pools providers describe azure-oidc \
  --location="global" \
  --workload-identity-pool="haea-azure-federation"
```

### 10.2 Permission Denied

```bash
# Verify service account roles
gcloud projects get-iam-policy prj-haea-security \
  --flatten="bindings[].members" \
  --filter="bindings.members:sa-cspm-automation"

# Check organization-level bindings
gcloud organizations get-iam-policy {org-id} \
  --flatten="bindings[].members" \
  --filter="bindings.members:sa-cspm-automation"
```

---

## 11. Security Considerations

- WIF eliminates need for service account keys
- Short-lived tokens (1 hour) limit blast radius
- Attribute mapping restricts to specific Azure AD tenant
- All authentications logged in Cloud Audit Logs
- Service account has read-only access (no write permissions)

---

## Contact

| Property | Value |
|----------|-------|
| Requestor | Liem Vo-Nguyen (liem.vo-nguyen@haeaus.com) |
| Team | HAEA Security TFT |
