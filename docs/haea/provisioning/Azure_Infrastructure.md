# Azure Infrastructure - HAEA Cloud Security Automation

| Property | Value |
|----------|-------|
| Version | 1.0 |
| Author | Liem Vo-Nguyen |
| Team | HAEA Security TFT |
| Date | December 2025 |
| Status | Draft |
| Owner | Azure Team |

---

## 1. Overview

This document describes the Azure infrastructure required for the Cross-Cloud CSPM Automation Platform. The platform uses Azure Container Instance for execution, Logic App for scheduling, Key Vault for secrets, and Blob Storage for state management.

---

## 2. Resource Summary

| Resource | Name | Resource Group | Purpose |
|----------|------|----------------|---------|
| Container Instance | aci-haea-cspm | rg-haea-security | Run Go binary |
| Logic App | la-haea-cspm-schedule | rg-haea-security | Monthly trigger |
| Key Vault | haeasecuritytftkv | rg-haea-security | Secrets storage |
| Storage Account | sthaeacspmstate | rg-haea-security | State + reports |
| Container Registry | crhaeacspm | rg-haea-security | Container images |
| Log Analytics | law-haea-security | rg-haea-security | Logging |

---

## 3. Resource Group

| Property | Value |
|----------|-------|
| Name | rg-haea-security |
| Subscription | HAEA Security |
| Location | West US 2 |
| Tags | Environment=Production, Team=SecurityTFT |

---

## 4. Container Instance

### 4.1 Configuration

| Property | Value |
|----------|-------|
| Name | aci-haea-cspm |
| Image | crhaeacspm.azurecr.io/cspm-reporter:latest |
| OS Type | Linux |
| CPU | 1 core |
| Memory | 1.5 GB |
| Restart Policy | Never |
| Identity | System-assigned Managed Identity |

### 4.2 Environment Variables

| Variable | Source | Description |
|----------|--------|-------------|
| AZURE_TENANT_ID | Hardcoded | Azure AD tenant |
| AZURE_CLIENT_ID | Hardcoded | App registration client ID |
| KEY_VAULT_NAME | Hardcoded | haeasecuritytftkv |
| STORAGE_ACCOUNT | Hardcoded | sthaeacspmstate |
| AWS_ROLE_ARN | Hardcoded | arn:aws:iam::831926608679:role/haea-cs-read-automation |
| GCP_WIF_PROVIDER | Hardcoded | projects/{project}/locations/global/workloadIdentityPools/{pool}/providers/{provider} |

### 4.3 Managed Identity Permissions

| Resource | Role | Scope |
|----------|------|-------|
| Key Vault | Key Vault Secrets User | haeasecuritytftkv |
| Storage Account | Storage Blob Data Contributor | sthaeacspmstate |
| Management Group | Reader | mg-haea-root |
| Container Registry | AcrPull | crhaeacspm |

---

## 5. Logic App

### 5.1 Configuration

| Property | Value |
|----------|-------|
| Name | la-haea-cspm-schedule |
| Type | Consumption |
| Trigger | Recurrence |
| Schedule | 1st of month, 8:00 AM PST |

### 5.2 Workflow

```
Trigger (Recurrence)
  → Start Container Group (aci-haea-cspm)
  → Wait for completion (optional)
  → Send notification on failure (optional)
```

### 5.3 Managed Identity Permissions

| Resource | Role | Scope |
|----------|------|-------|
| Container Instance | Contributor | aci-haea-cspm |

---

## 6. Key Vault

### 6.1 Configuration

| Property | Value |
|----------|-------|
| Name | haeasecuritytftkv |
| SKU | Standard |
| Soft Delete | Enabled (90 days) |
| Purge Protection | Enabled |

### 6.2 Secrets

| Secret Name | Description | Rotation |
|-------------|-------------|----------|
| graph-client-secret | MS Graph API client secret | 24 months |
| asana-pat | Asana Personal Access Token | 12 months |

### 6.3 Access Policies

| Principal | Permissions |
|-----------|-------------|
| aci-haea-cspm (MI) | Get, List secrets |
| HAEA Security TFT | All secret operations |

---

## 7. Storage Account

### 7.1 Configuration

| Property | Value |
|----------|-------|
| Name | sthaeacspmstate |
| Kind | StorageV2 |
| Replication | LRS |
| Access Tier | Hot |
| Minimum TLS | 1.2 |

### 7.2 Containers

| Container | Purpose | Access |
|-----------|---------|--------|
| state | Previous findings state (JSON) | Private |
| reports | Generated HTML/CSV reports | Private |

---

## 8. Container Registry

### 8.1 Configuration

| Property | Value |
|----------|-------|
| Name | crhaeacspm |
| SKU | Basic |
| Admin User | Disabled |
| Anonymous Pull | Disabled |

### 8.2 Images

| Image | Tag | Description |
|-------|-----|-------------|
| cspm-reporter | latest | Current production |
| cspm-reporter | {version} | Versioned releases |

---

## 9. Provisioning Checklist

### 9.1 Resource Group

- [ ] Create resource group `rg-haea-security`
- [ ] Apply tags (Environment, Team)

### 9.2 Key Vault

- [ ] Create Key Vault `haeasecuritytftkv`
- [ ] Enable soft delete and purge protection
- [ ] Store `graph-client-secret` (from AD team)
- [ ] Store `asana-pat`
- [ ] Configure access policies

### 9.3 Storage Account

- [ ] Create storage account `sthaeacspmstate`
- [ ] Create `state` container
- [ ] Create `reports` container
- [ ] Configure firewall (allow Azure services)

### 9.4 Container Registry

- [ ] Create container registry `crhaeacspm`
- [ ] Disable admin user
- [ ] Configure retention policy

### 9.5 Container Instance

- [ ] Create ACI `aci-haea-cspm` (initially stopped)
- [ ] Enable system-assigned Managed Identity
- [ ] Configure environment variables
- [ ] Assign RBAC roles to Managed Identity
- [ ] Test manual start

### 9.6 Logic App

- [ ] Create Logic App `la-haea-cspm-schedule`
- [ ] Configure recurrence trigger (1st of month, 8:00 AM PST)
- [ ] Add "Start Container Group" action
- [ ] Enable Managed Identity
- [ ] Assign Contributor role on ACI
- [ ] Test manual trigger

### 9.7 Monitoring

- [ ] Create Log Analytics workspace (or use existing)
- [ ] Configure ACI diagnostic settings
- [ ] Create alert for container failures
- [ ] Create alert for secret expiry (60 days)

---

## 10. Terraform Reference

Infrastructure as Code templates are available at:

```
infrastructure/azure-automation/
├── main.tf
├── variables.tf
├── outputs.tf
└── modules/
    ├── container-instance/
    ├── logic-app/
    ├── key-vault/
    └── storage/
```

---

## Contact

| Property | Value |
|----------|-------|
| Requestor | Liem Vo-Nguyen (liem.vo-nguyen@haeaus.com) |
| Team | HAEA Security TFT |
