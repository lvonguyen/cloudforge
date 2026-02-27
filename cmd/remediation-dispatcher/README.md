# Remediation Dispatcher

Consumes auto-remediation findings (from cspm-aggregator) and executes remediation handlers with built-in rollback capability.

## Architecture

```
aggregator (read-only) → findings/*.json → dispatcher (write-enabled) → Asana
                                              ↓
                                         state/*.json (rollback snapshots)
```

## Handler Registry

All 10 handlers are registered in `registerHandlers()` in `main.go`.

| Finding Type | Handler | Domain | Tier | CSPs | Status |
|-------------|---------|--------|------|------|--------|
| `GuardDuty.1` | `GuardDutyRemediator` | security_services | 1 | AWS | Active |
| `OPEN_SSH_PORT` | `BlockPublicSSHRemediator` | network | 1 | AWS | Active |
| `OPEN_RDP_PORT` | `BlockPublicSSHRemediator` | network | 1 | AWS | Active |
| `AWS.EC2.SecurityGroup.SSH` | `BlockPublicSSHRemediator` | network | 1 | AWS | Active |
| `S3_PUBLIC_ACCESS` | `BlockPublicS3Remediator` | storage | 1 | AWS | Active |
| `IAM_OLD_ACCESS_KEY` | `RotateIAMKeysRemediator` | identity | 2 | AWS | Active |
| `EC2_IMDSV1_ENABLED` | `EnforceIMDSv2Remediator` | compute | 1 | AWS | Active |
| `Defender.Storage` | `AzureDefenderStorageRemediator` | security_services | 1 | Azure | Stub |
| `EXPOSED_SECRET` | `RotateExposedSecretRemediator` | secrets | 2 | All | No-op |
| `OS_PATCH_MISSING` | `OSPatchRemediator` | patching | 3 | AWS | Query-only |

### Tier Definitions

| Tier | Label | Behavior |
|------|-------|----------|
| 1 | Auto-safe | Can be executed without human review |
| 2 | Requires verification | Must be reviewed before production execution |
| 3 | Requires change window | Needs scheduled downtime and approval |

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--findings-dir` | `./findings/auto_remediation` | Directory containing auto-remediation findings JSON |
| `--execute` | `false` | Execute remediations (default: dry-run) |
| `--max-concurrency` | `5` | Max concurrent remediations per run |
| `--rollback` | `""` | Rollback a specific remediation by ID |
| `--rollback-all` | `false` | Rollback ALL remediations from the last run |
| `--state-dir` | `./state/remediation` | Directory for rollback state snapshots |

## Usage

### Dry-Run (Default)
```bash
./remediation-dispatcher --findings-dir ./findings/auto_remediation
```

Shows what would be remediated without making changes.

### Execute Remediations
```bash
./remediation-dispatcher --findings-dir ./findings/auto_remediation --execute
```

**Safety Features**:
- Max 5 concurrent remediations (configurable with `--max-concurrency`)
- Captures pre-state snapshots for rollback
- 48-hour rollback window
- Rollback scripts generated automatically

### Rollback Scenarios

#### Scenario 1: "You broke our SSH access!"

**Dev Team**: "We can't SSH to prod-bastion anymore!"

**You**:
```bash
# List recent remediations
ls -lh state/remediation/

# Rollback specific finding
./remediation-dispatcher --rollback 20260211-143052-finding-12345

# Output:
# Rolling back: finding-12345
# Handler: OPEN_SSH_PORT
# Timestamp: 2026-02-11 14:30:52
#
# Rollback commands:
# aws ec2 authorize-security-group-ingress --group-id sg-abc123 --protocol tcp --port 22 --cidr 0.0.0.0/0 --region us-east-1
#
# Execute these commands manually to rollback.
```

#### Scenario 2: "Everything broke after last run!"

**Panicked Dev Team**: "Production is down! What changed?!"

**You**:
```bash
# Rollback ALL remediations from the last run
./remediation-dispatcher --rollback-all

# Output:
# Rolling back all remediations from run: 20260211-143052
# Rolled back 12 remediations
```

#### Scenario 3: "Can we test before production?"

**Cautious Dev Team**: "Let's test in staging first."

**You**:
```bash
# Dry-run to see what would happen
./remediation-dispatcher --findings-dir ./findings/auto_remediation

# Review output, then execute
./remediation-dispatcher --findings-dir ./findings/auto_remediation --execute
```

## Rollback State Format

Each successful remediation creates a rollback state file:

```json
{
  "finding_id": "finding-12345",
  "handler": "OPEN_SSH_PORT",
  "timestamp": "2026-02-11T14:30:52Z",
  "pre_state": {
    "resource_id": "sg-abc123",
    "resource_type": "AWS::EC2::SecurityGroup",
    "region": "us-east-1",
    "account_id": "123456789012",
    "finding_type": "OPEN_SSH_PORT"
  },
  "result": {
    "finding_id": "finding-12345",
    "success": true,
    "message": "Blocked public SSH access on security group: sg-abc123",
    "actions": ["Revoked 0.0.0.0/0:22 ingress from security group: sg-abc123"]
  },
  "rollback_script": "aws ec2 authorize-security-group-ingress --group-id sg-abc123 --protocol tcp --port 22 --cidr 0.0.0.0/0 --region us-east-1",
  "expires_at": "2026-02-13T14:30:52Z"
}
```

## Rollback Window

**48-hour window**: Rollback state is retained for 48 hours after remediation. After expiry:
- Rollback files are automatically cleaned up (future: implement cleanup cron)
- Manual rollback still possible via cloud console

## Integration with Aggregator

### Step 1: Aggregator Outputs Findings
```go
// In cspm-aggregator
if finding.AutoRemediationReady {
    writeToFile(finding, "./findings/auto_remediation/")
}
```

### Step 2: Dispatcher Consumes Findings
```bash
# Cron job (every 4 hours)
0 */4 * * * /usr/local/bin/remediation-dispatcher --findings-dir /data/findings/auto_remediation --execute >> /var/log/remediation.log 2>&1
```

### Step 3: Asana Integration (Future)
```bash
# Results are written to results/remediation/*.json
# Asana sync script picks them up and updates tasks
```

## Safety Gates (from remediation-agents rules)

| Gate | Implementation | Override |
|------|----------------|----------|
| Max 5 concurrent/account | `--max-concurrency 5` | `--max-concurrency N` |
| Dry-run first | Default mode | `--execute` required |
| Rollback window | 48 hours | N/A |
| Human checkpoint | Manual `--execute` | N/A |

## Credentials

**Required**: Write-enabled cloud credentials

```bash
# AWS
export AWS_PROFILE=acme-remediation  # SecurityAdmin role

# Azure
export AZURE_CLIENT_ID=<contributor-sp>
export AZURE_CLIENT_SECRET=<secret>
export AZURE_TENANT_ID=<tenant>

# GCP
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
```

## Monitoring

### Check Last Run Status
```bash
cat results/remediation/results-latest.json | jq '.[] | select(.success == false)'
```

### List Available Rollbacks
```bash
find state/remediation -name "*.json" -mtime -2 | while read f; do
    echo "$(basename $f .json): $(jq -r '.handler + " - " + .timestamp' $f)"
done
```

### Audit Trail
```bash
# All remediations in last 7 days
find state/remediation -name "*.json" -mtime -7 | xargs jq -r '.finding_id + "," + .handler + "," + .timestamp + "," + (.result.success|tostring)'
```

## Common Issues

### "Rollback window expired"
**Cause**: Trying to rollback after 48 hours.
**Solution**: Manual rollback via cloud console, or re-run aggregator to regenerate finding.

### "No automated rollback available"
**Cause**: Handler doesn't have rollback script implemented.
**Solution**: Manual intervention required. Check handler documentation for manual steps.

### "Failed to capture rollback state"
**Cause**: Remediation succeeded but state saving failed.
**Impact**: No rollback capability for this remediation.
**Solution**: Check disk space and permissions on `--state-dir`.

## Development

### Adding a New Handler

1. Implement handler in `internal/remediation/{domain}/`
2. Register in `registerHandlers()` function
3. Add rollback script in `generateRollbackScript()`
4. Test with dry-run before executing

### Testing Rollback

```bash
# Execute a remediation
./remediation-dispatcher --findings-dir ./test-findings --execute

# Verify it worked
# (check cloud console)

# Rollback
./remediation-dispatcher --rollback 20260211-XXXXXX-finding-test

# Verify rollback worked
# (check cloud console again)
```

## Future Enhancements

- [ ] Automated rollback script execution (currently manual)
- [ ] Slack/PagerDuty notifications on remediation failures
- [ ] Automatic cleanup of expired rollback state
- [ ] Pre-remediation validation (check if resource is in use)
- [ ] Remediation approval workflow (interactive mode)
- [ ] Rollback state backup to S3/Blob for durability
