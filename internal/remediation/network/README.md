# Network Remediation Domain

Remediates network security findings related to overly permissive ingress rules.
Targets publicly exposed management ports (SSH/RDP) on security groups and firewall rules.

## Handlers

| Handler | Finding Type | Tier | CSPs | Description |
|---------|-------------|------|------|-------------|
| `BlockPublicSSHRemediator` | `OPEN_SSH_PORT` | 1 | AWS, GCP*, Azure* | Revokes `0.0.0.0/0:22` ingress from security groups |
| `BlockPublicSSHRemediator` | `OPEN_RDP_PORT` | 1 | AWS, GCP*, Azure* | Same handler, also registered for RDP findings |
| `BlockPublicSSHRemediator` | `AWS.EC2.SecurityGroup.SSH` | 1 | AWS | Alternate finding type for the same remediation |

(*) GCP and Azure implementations are stubs -- AWS is fully implemented.

## Handler Details

### BlockPublicSSHRemediator (Tier 1 -- Auto-safe)

- **Action**: Calls `RevokeSecurityGroupIngress` to remove `0.0.0.0/0:22` (TCP) from the target security group
- **Multi-CSP routing**: Inspects `finding.Source` to dispatch to AWS, GCP, or Azure remediation paths
- **Validation**: Describes the security group and verifies no `0.0.0.0/0:22` ingress rules remain
- **Dry-run**: Reports planned action; detects bastion host security groups by name heuristic and flags them
- **Rollback**: `aws ec2 authorize-security-group-ingress --group-id <sg-id> --protocol tcp --port 22 --cidr 0.0.0.0/0`

### Bastion Detection

The dry-run checks if the resource ID contains "bastion" (case-insensitive). If detected,
`WouldSucceed` is set to `false` to prevent auto-remediation of intentionally public bastion hosts.

## Integration

The dispatcher registers this handler for multiple finding types:

```go
executor.Register("OPEN_SSH_PORT", network.NewBlockPublicSSHRemediator())
executor.Register("OPEN_RDP_PORT", network.NewBlockPublicSSHRemediator())
```

The handler extracts the security group ID from ARN format
(`arn:aws:ec2:...:security-group/sg-xxx`) or plain ID (`sg-xxx`).

## Safety Considerations

- [*] Blocking public SSH/RDP is safe for non-bastion security groups
- [!] Bastion hosts require public SSH -- the handler detects and skips these
- [>] Ensure VPN or bastion connectivity exists before blocking public SSH
- [>] GCP and Azure paths return errors until SDK integration is complete
- [-] Only removes `0.0.0.0/0` CIDR -- does not affect private IP range rules
