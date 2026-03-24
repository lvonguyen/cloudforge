# HAEA Cloud Guard — Provisioning Guides

**Version:** 2.0
**Updated:** 2026-03-24
**Author:** Liem Vo-Nguyen

## Architecture (v2 — Two-Hop Model)

```
GitLab CI/CD (haea-sec/cloudguard)
  → OIDC token (GitLab issuer)
  → AWS STS AssumeRoleWithWebIdentity
  → Central app role: haea-cg-{env}-app (account 831926608679)
  → STS AssumeRole (cross-account)
  → Per-tenant reader: haea-cs-read-automation (in each member account)
  → SecurityHub / Config / GuardDuty / IAM / CloudTrail read-only
```

**Compute:** ECS Fargate on AWS (Go API + OPA sidecar)
**Identity:** GitLab OIDC federation (NOT Azure AD — changed from v1)
**Access:** Internal only — AD DNS record + VPN, no public endpoint

## Document Status

| Document | Version | Status | Notes |
|----------|---------|--------|-------|
| [AWS_OIDC_Setup.md](AWS_OIDC_Setup.md) | **v2** | **Current** | Rewritten for two-hop model (2026-03-23) |
| [GCP_WIF_Setup.md](GCP_WIF_Setup.md) | v1 | **Stale** | Still references ACI + Azure AD federation — needs rewrite for GitLab OIDC |
| [AzureAD_AppRegistration.md](AzureAD_AppRegistration.md) | v1 | **Stale** | Still references ACI compute — needs update for ECS + internal DNS approach |
| [Azure_Infrastructure.md](Azure_Infrastructure.md) | v1 | **Stale** | References ACI, Logic App, Key Vault — architecture moved to AWS ECS |
| [HAEA_CS_Read_Automation_Config.docx](HAEA_CS_Read_Automation_Config.docx) | v1 | Partial | Reader role config — policy updated to 12 statements, 95 actions |
| [SecurityTFT_Validation.docx](SecurityTFT_Validation.docx) | v1 | **Stale** | Needs rewrite for v2 validation steps |

## Provisioning Order (v2)

1. **M365/AD Team** — Azure AD App Registration + internal DNS record + Conditional Access
2. **AWS Team (per org)** — OIDC provider + `haea-cs-read-automation` reader role
3. **GCP Team** — WIF pool + service account with SCC/IAM reader roles
4. **Security TFT** — Deploy ECS stack, validate end-to-end, onboard first accounts

## Validated Configurations (2026-03-24)

All reader policies validated against live APIs in test environments:

| Cloud | Test Account | Result | Policy |
|-------|-------------|--------|--------|
| AWS | lvn-personal (431330216246) | **21/21 PASS** + two-hop chain | 12 statements, 95 read-only actions |
| GCP | lvn-dev-483106 | **4 roles bound**, WIF ACTIVE | SCC Viewer, IAM Reviewer, Compute Viewer, Cloud Asset Viewer |
| Azure | sub-lvn-dev (PVD Solutions) | **10/10 PASS** | Security Reader + Reader at subscription scope |

## Related Documents

- [smart-kpi-bullets-20260325.md](../smart-kpi-bullets-20260325.md) — SMART objectives for Jordan meeting
- [cost-forecast-20260325.md](../cost-forecast-20260325.md) — Infrastructure cost forecast ($368-$1,665/mo)
- `deploy/terraform/environments/haea/` — Terraform modules (backend, variables, main, cspm-readers)
- `scripts/cloud-env-login.sh` — Multi-cloud auth script (all 7 tenants)
