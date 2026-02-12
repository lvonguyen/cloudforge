# Storage Remediation Domain

Remediates cloud storage security findings, focusing on preventing public data exposure.
Operates at the account level via S3 Public Access Block settings.

## Handlers

| Handler | Finding Type | Tier | CSPs | Description |
|---------|-------------|------|------|-------------|
| `BlockPublicS3Remediator` | `S3_PUBLIC_ACCESS` | 1 | AWS | Enables all four S3 account-level public access block settings |

## Handler Details

### BlockPublicS3Remediator (Tier 1 -- Auto-safe)

- **Action**: Calls `PutPublicAccessBlock` on the account with all four settings enabled:
  - `BlockPublicAcls = true`
  - `BlockPublicPolicy = true`
  - `IgnorePublicAcls = true`
  - `RestrictPublicBuckets = true`
- **Validation**: Calls `GetPublicAccessBlock` and confirms all four settings are `true`
- **Dry-run**: Lists the four settings that would be enabled and warns about static site breakage
- **Rollback**: `aws s3api delete-public-access-block --bucket <bucket-name>`

## Integration

The dispatcher registers this handler via:

```go
executor.Register("S3_PUBLIC_ACCESS", storage.NewBlockPublicS3Remediator())
```

Uses the finding's `AccountID` field to apply the block at the account level
via the `s3control` service (not per-bucket `s3` API).

## Safety Considerations

- [*] Blocking public access is safe for most workloads
- [!] S3-hosted static websites will break -- these require public read access
- [!] This applies at the ACCOUNT level, affecting all buckets in the account
- [>] Identify any S3 static website buckets before executing
- [>] Consider per-bucket remediation if account-level is too broad
