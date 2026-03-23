# Provisioning Guides

This directory contains team-specific provisioning checklists for the Cross-Cloud CSPM Automation Platform.

## Documents

| Document | Owner | Purpose |
|----------|-------|---------|
| [AWS_OIDC_Setup.md](AWS_OIDC_Setup.md) | AWS Team | OIDC provider + haea-cs-read-automation role |
| [Azure_Infrastructure.md](Azure_Infrastructure.md) | Azure Team | ACI, Logic App, Key Vault, Storage |
| [AzureAD_AppRegistration.md](AzureAD_AppRegistration.md) | AD Team | App registration for cross-cloud federation |
| [GCP_WIF_Setup.md](GCP_WIF_Setup.md) | GCP Team | Workload Identity Federation + SCC access |
| [SecurityTFT_Validation.md](SecurityTFT_Validation.md) | HAEA Security TFT | End-to-end validation checklist |

## Provisioning Order

1. **AD Team** - Create App Registration (prerequisite for all clouds)
2. **Azure Team** - Deploy infrastructure (ACI, Logic App, Key Vault)
3. **AWS Team** - Configure OIDC provider and IAM role
4. **GCP Team** - Configure WIF pool and service account
5. **Security TFT** - Validate end-to-end and deploy Go binary

## Related Documents

- [CSPM_Automation_HLD.md](../architecture/CSPM_Automation_HLD.md) - High-level architecture
- [infrastructure/](../../infrastructure/) - Terraform/IaC templates
