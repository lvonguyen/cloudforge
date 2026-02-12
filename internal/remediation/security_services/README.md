# Security Services Remediation Domain

Enables cloud-native threat detection and security monitoring services.
These are Tier 1 handlers -- enabling a monitoring service carries no data loss
risk and does not disrupt running workloads.

## Handlers

| Handler | Finding Type | Tier | CSPs | Description |
|---------|-------------|------|------|-------------|
| `GuardDutyRemediator` | `GuardDuty.1` | 1 | AWS | Creates a GuardDuty detector with S3 and EKS protection enabled |
| `AzureDefenderStorageRemediator` | `Defender.Storage` | 1 | Azure | Enables Azure Defender for Storage (stub -- Azure SDK pending) |

## Handler Details

### GuardDutyRemediator (Tier 1 -- Auto-safe)

- **Action**: Calls `CreateDetector` with S3 log monitoring and EKS audit log monitoring enabled; sets finding publishing frequency to 15 minutes
- **Validation**: Lists detectors, gets detector details, confirms `Status == ENABLED`
- **Dry-run**: Reports planned actions and cost estimate; checks if GuardDuty is already enabled
- **Rollback**: `aws guardduty delete-detector --detector-id <id> --region <region>`
- **Cost**: ~$4.60/month base + $1/GB CloudTrail analysis

### AzureDefenderStorageRemediator (Tier 1 -- Stub)

- **Status**: Azure SDK (`github.com/Azure/azure-sdk-for-go`) not yet in go.mod
- **Planned action**: Enable `Microsoft.Security/pricings` for StorageAccounts with `DefenderForStorageV2` sub-plan
- **All methods** (Remediate, Validate, DryRun) return stub responses indicating SDK integration is pending
- **Cost**: ~$10/storage account/month

## Integration

The dispatcher registers these handlers via:

```go
executor.Register("GuardDuty.1", security_services.NewGuardDutyRemediator())
// executor.Register("Defender.Storage", security_services.NewAzureDefenderStorageRemediator())
```

The Azure Defender handler is currently commented out in the dispatcher pending SDK integration.

## Safety Considerations

- [*] Enabling monitoring services is inherently safe -- no impact on running workloads
- [*] GuardDuty is fully implemented and production-ready
- [!] GuardDuty incurs ongoing costs (~$4.60/month base per account per region)
- [!] Azure Defender handler will fail until Azure SDK is added to go.mod
- [>] Check if GuardDuty is already enabled before running to avoid duplicate detector errors
