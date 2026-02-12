# Compute Remediation Domain

Remediates security findings related to EC2 instances and compute infrastructure.
Focuses on instance metadata hardening and compute-layer attack surface reduction.

## Handlers

| Handler | Finding Type | Tier | CSPs | Description |
|---------|-------------|------|------|-------------|
| `EnforceIMDSv2Remediator` | `EC2_IMDSV1_ENABLED` | 1 | AWS | Sets `HttpTokens=required` on EC2 instances to enforce IMDSv2, mitigating SSRF-based credential theft |

## Handler Details

### EnforceIMDSv2Remediator (Tier 1 -- Auto-safe)

- **Action**: Calls `ModifyInstanceMetadataOptions` with `HttpTokens=required`
- **Validation**: Describes instance and checks `MetadataOptions.HttpTokens == required`
- **Dry-run**: Reports planned action and compatibility impact
- **Rollback**: `aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens optional`

## Integration

The dispatcher registers this handler via:

```go
executor.Register("EC2_IMDSV1_ENABLED", compute.NewEnforceIMDSv2Remediator())
```

Findings arrive as JSON in the `auto_remediation/` directory, written by the aggregator.
The handler extracts the instance ID from either an ARN (`arn:aws:ec2:...:instance/i-xxx`)
or a plain instance ID (`i-xxx`).

## Safety Considerations

- [*] IMDSv2 is backwards compatible with AWS SDK v2+ and session-token-aware code
- [!] Legacy applications using IMDSv1 (raw HTTP GET to 169.254.169.254) will break
- [>] Run dry-run first to assess impact; check application SDK versions before executing
- [>] No downtime -- metadata service remains available, only the auth mechanism changes
