# Azure AD App Registration - HAEA Cloud Security Automation

| Property | Value |
|----------|-------|
| Version | 1.0 |
| Author | Liem Vo-Nguyen |
| Team | HAEA Security TFT |
| Date | December 2025 |
| Status | Draft |
| Owner | AD Team |

---

## 1. Overview

This document describes the Azure AD App Registration required for the Cross-Cloud CSPM Automation Platform. The app registration serves as the central identity for cross-cloud authentication.

---

## 2. App Registration Details

| Property | Value |
|----------|-------|
| Display Name | haea-cloud-security-automation |
| Application Type | Web application |
| Supported Account Types | Single tenant |
| Azure AD Tenant | bd29b3ab-aaa2-425a-b882-9e7f73283ca6 |

---

## 3. Required Configuration

### 3.1 Application ID URI

```
api://{client-id}
```

This URI is used as the audience claim in OIDC tokens for AWS and GCP federation.

### 3.2 API Permissions

| API | Permission | Type | Purpose |
|-----|------------|------|---------|
| Microsoft Graph | Mail.Send | Application | Send email reports |
| Microsoft Graph | User.Read | Delegated | Basic profile (optional) |

### 3.3 Client Secret

| Property | Value |
|----------|-------|
| Description | CSPM Automation - Graph API |
| Expiry | 24 months |
| Storage | Azure Key Vault (haeasecuritytftkv) |
| Secret Name | graph-client-secret |

**Note:** Set calendar reminder for rotation 60 days before expiry.

### 3.4 Federated Credentials (for Managed Identity)

Add federated credential to allow Azure Container Instance's Managed Identity to request tokens:

| Property | Value |
|----------|-------|
| Name | aci-haea-cspm-federation |
| Issuer | https://login.microsoftonline.com/{tenant-id}/v2.0 |
| Subject | {managed-identity-object-id} |
| Audience | api://AzureADTokenExchange |

---

## 4. Provisioning Checklist

### 4.1 App Registration

- [ ] Create App Registration in Azure AD
- [ ] Set display name: `haea-cloud-security-automation`
- [ ] Configure as single-tenant
- [ ] Note Application (client) ID
- [ ] Note Directory (tenant) ID

### 4.2 Application ID URI

- [ ] Set Application ID URI: `api://{client-id}`
- [ ] Expose an API scope (optional, for future use)

### 4.3 API Permissions

- [ ] Add Microsoft Graph → Mail.Send (Application)
- [ ] Grant admin consent for Mail.Send

### 4.4 Client Secret

- [ ] Create client secret (24 month expiry)
- [ ] Store in Key Vault: `haeasecuritytftkv`
- [ ] Secret name: `graph-client-secret`
- [ ] Set rotation reminder (60 days before expiry)

### 4.5 Handoff to Other Teams

Provide the following to requesting teams:

| Team | Information Needed |
|------|-------------------|
| AWS Team | Application ID URI (`api://{client-id}`) |
| GCP Team | Application ID URI, Tenant ID |
| Azure Team | Client ID, Tenant ID |
| Security TFT | All of the above |

---

## 5. Token Claims

The app registration issues tokens with the following claims for cross-cloud federation:

### 5.1 AWS OIDC Token

```json
{
  "iss": "https://sts.windows.net/{tenant-id}/",
  "aud": "api://{client-id}",
  "sub": "{service-principal-object-id}",
  "oid": "{service-principal-object-id}",
  "tid": "{tenant-id}"
}
```

### 5.2 GCP WIF Token

```json
{
  "iss": "https://sts.windows.net/{tenant-id}/",
  "aud": "api://{client-id}",
  "sub": "{service-principal-object-id}"
}
```

---

## 6. Security Considerations

- App registration has **no interactive sign-in** capability
- Client secret stored only in Key Vault (never in code)
- Mail.Send permission limited to sending from automation account
- Audit logs enabled for all token issuances

---

## 7. Validation

### 7.1 Test Token Acquisition

```bash
# Using Azure CLI (from ACI with Managed Identity)
az account get-access-token \
  --resource api://{client-id} \
  --query accessToken -o tsv
```

### 7.2 Verify Token Claims

```bash
# Decode JWT (header.payload.signature)
echo $TOKEN | cut -d'.' -f2 | base64 -d | jq
```

---

## Contact

| Property | Value |
|----------|-------|
| Requestor | Liem Vo-Nguyen (liem.vo-nguyen@haeaus.com) |
| Team | HAEA Security TFT |
