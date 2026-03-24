# Azure Infrastructure — HAEA Cloud Guard (v2)

| Property | Value |
|----------|-------|
| Version | 2.0 |
| Author | Liem Vo-Nguyen |
| Team | HAEA Security TFT |
| Date | March 2026 |
| Status | Active |
| Owner | Azure Team / M365 Team |

---

## 1. Overview

In v2, Cloud Guard runs on **AWS ECS Fargate** — not Azure. Azure's role is limited to:

1. **Identity:** App registration for Azure Security API access (see [AzureAD_AppRegistration.md](AzureAD_AppRegistration.md))
2. **Reader access:** Security Reader + Reader on 52 HMGNA subscriptions
3. **DNS:** Internal DNS record (`cloudguard.haeaus.com`) pointing to AWS ALB via AD DNS

**Removed from v1:** ACI, Logic App, Key Vault, Storage Account, Container Registry, Log Analytics. All replaced by AWS equivalents in `deploy/terraform/environments/haea/main.tf`.

---

## 2. Architecture Comparison

### v1 (December 2025) — RETIRED
```
Azure Container Instance (aci-haea-cspm)
  → Azure Key Vault (secrets)
  → Azure Storage (state + reports)
  → Logic App (monthly scheduler)
  → Azure AD Managed Identity (cross-cloud auth)
  → Container Registry (crhaeacspm)
```

### v2 (March 2026) — CURRENT
```
AWS ECS Fargate (haea-cg-prod)
  → AWS Secrets Manager (secrets)
  → AWS RDS PostgreSQL (state + audit log)
  → AWS ElastiCache Redis (rate limiting + cache)
  → GitLab OIDC (CI/CD federation)
  → GitLab Container Registry (images)

Azure (read-only access only):
  → App Registration: haea-cloud-guard
  → RBAC: Security Reader + Reader on 52 subscriptions
  → DNS: cloudguard.haeaus.com → AWS ALB (internal)
```

---

## 3. Azure Resources Required (v2)

| Resource | Purpose | Owner |
|----------|---------|-------|
| App Registration | Client credentials for Azure API access | M365/AD Team |
| RBAC Role Assignments | Security Reader + Reader per subscription | Azure Team |
| AD DNS Record | `cloudguard.haeaus.com` → AWS ALB internal IP | AD/DNS Team |
| Conditional Access Policy | Restrict app SP to VPN IP ranges (optional) | M365 Team |

**That's it.** No Azure compute, storage, or scheduling resources.

---

## 4. DNS Configuration

### 4.1 Internal DNS Record

| Property | Value |
|----------|-------|
| Record | `cloudguard.haeaus.com` |
| Type | CNAME (to AWS ALB) or A (to ALB IP) |
| Zone | haeaus.com (AD-integrated DNS) |
| Access | VPN-only (not publicly resolvable) |

```powershell
# On AD DNS server (or via RSAT):
Add-DnsServerResourceRecordCName `
  -ZoneName "haeaus.com" `
  -Name "cloudguard" `
  -HostNameAlias "haea-cg-prod-alb-XXXXXXXX.us-east-1.elb.amazonaws.com"
```

### 4.2 Conditional Access (Optional)

Restrict the `haea-cloud-guard` service principal to corporate IP ranges:

| Property | Value |
|----------|-------|
| Policy Name | CG-Restrict-SP-to-VPN |
| Target | Service principal: haea-cloud-guard |
| Condition | Named location: NOT Corporate VPN |
| Grant | Block access |

This prevents the client credentials from being used outside the corporate network.

---

## 5. Provisioning Checklist (v2)

### 5.1 App Registration + RBAC

See [AzureAD_AppRegistration.md](AzureAD_AppRegistration.md) for full steps:

- [ ] Create app registration `haea-cloud-guard`
- [ ] Create service principal
- [ ] Create client secret (store in AWS Secrets Manager)
- [ ] Assign Security Reader to all 52 HMGNA subscriptions
- [ ] Assign Reader to all 52 HMGNA subscriptions
- [ ] Validate API access (10/10 test points)

### 5.2 DNS

- [ ] Create CNAME record `cloudguard.haeaus.com` → AWS ALB
- [ ] Verify resolution from VPN: `nslookup cloudguard.haeaus.com`
- [ ] Verify NOT resolvable from public DNS: `dig cloudguard.haeaus.com @8.8.8.8`

### 5.3 Conditional Access (Optional)

- [ ] Create named location for corporate VPN IP ranges
- [ ] Create CA policy restricting SP to named location
- [ ] Test: API call from VPN succeeds
- [ ] Test: API call from external IP is blocked

### 5.4 Monitoring

- [ ] Enable Azure AD sign-in logs for the service principal
- [ ] Create alert for failed sign-ins (possible credential compromise)
- [ ] Create alert for sign-ins from unexpected locations

---

## 6. Decommissioned Resources (from v1)

The following resources from v1 should be removed if they were provisioned:

| Resource | v1 Name | Action |
|----------|---------|--------|
| Container Instance | aci-haea-cspm | Delete |
| Logic App | la-haea-cspm-schedule | Delete |
| Key Vault | haeasecuritytftkv | Delete (after migrating secrets to AWS SM) |
| Storage Account | sthaeacspmstate | Delete (after migrating state to RDS) |
| Container Registry | crhaeacspm | Delete (images now in GitLab CR) |
| Log Analytics | law-haea-security | Keep (useful for Azure AD logs) |
| Resource Group | rg-haea-security | Keep (holds AD logs workspace) |

---

## 7. Cost Impact

| Item | v1 (Azure) | v2 (Azure portion) |
|------|------------|-------------------|
| ACI | ~$30/mo | $0 (removed) |
| Logic App | ~$5/mo | $0 (removed) |
| Key Vault | ~$3/mo | $0 (removed) |
| Storage | ~$5/mo | $0 (removed) |
| Container Registry | ~$5/mo | $0 (removed) |
| App Registration | $0 | $0 |
| RBAC assignments | $0 | $0 |
| **Total Azure cost** | **~$48/mo** | **$0/mo** |

All compute costs moved to AWS. See [cost-forecast-20260325.md](../cost-forecast-20260325.md) for full breakdown.

---

## 8. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| DNS not resolving | Record not in AD DNS zone | Add CNAME via RSAT or AD DNS console |
| DNS resolves but connection refused | ALB security group blocks source IP | Add VPN CIDR to ALB SG inbound rules |
| CA policy blocks legitimate access | VPN IP not in named location | Update named location with current VPN egress IPs |
| API returns 403 on specific sub | Missing RBAC assignment | Run `az role assignment create` for that subscription |

---

## Contact

| Property | Value |
|----------|-------|
| Primary Contact | Liem Vo-Nguyen (liem.vo-nguyen@haeaus.com) |
| Backup Contact | Seungwoo Son (seungwooson@haeaus.com) |
| Team | HAEA Security TFT |
