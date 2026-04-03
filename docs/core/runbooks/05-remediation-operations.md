# Runbook: Remediation Operations

## Overview

This runbook covers operating Aegis's remediation dispatcher, including:
- Dispatcher architecture and executor model
- Starting and monitoring remediation batches
- Per-handler operations (network, storage, compute, identity, security services)
- Rollback procedures
- Emergency stop
- Troubleshooting common failures
- Reporting and SLA compliance

> Runtime note (April 1, 2026): the public demo runs on Fly.io + Cloudflare Pages. Use `flyctl`, the Aegis API, and 1Password-backed secret refs for live operations. Any `kubectl` examples below apply only to a future self-managed deployment.

## Prerequisites

- [ ] Write-access cloud credentials for the target account/subscription
- [ ] `flyctl` authenticated against the `personal` org
- [ ] Aegis API token with `remediation:execute` scope
- [ ] Runbook 02-incident-response.md reviewed if remediating an active incident
- [ ] Change management approval for production remediations

## Dispatcher Architecture

The public demo executes remediation flows from the main `cloudforge-api` Fly app and exposes a tiered execution model. Self-managed deployments can break this out into a dedicated remediation worker if isolation is required.

| Tier | Handler Types | Concurrency | Timeout |
|------|--------------|-------------|---------|
| T1 (Fast) | Network, Storage ACLs | 10 parallel | 30s |
| T2 (Standard) | Compute config, IAM | 5 parallel | 120s |
| T3 (Slow) | Patching, Key rotation | 2 parallel | 600s |

State snapshots are written to S3/GCS before every remediation. The rollback window is 48h.

## Starting a Remediation Batch

### Step 1: Dry Run (Required)

Always run dry-run first to preview changes.

```bash
# Dry run against a specific finding set
curl -s -X POST https://api.cloudforge.lvonguyen.com/api/v1/remediations \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "finding_ids": ["f-abc123", "f-def456"],
    "dry_run": true,
    "executor_tier": "T1"
  }' | jq '{batch_id, actions_preview, estimated_duration_s}'

# Or via CLI
./aegis remediate --finding-ids f-abc123,f-def456 --dry-run
```

Review the `actions_preview` list. Confirm each action is expected before proceeding.

### Step 2: Execute Batch

```bash
# Execute with the batch_id from dry run
curl -s -X POST https://api.cloudforge.lvonguyen.com/api/v1/remediations \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "batch_id": "batch-20260226-001",
    "finding_ids": ["f-abc123", "f-def456"],
    "dry_run": false,
    "executor_tier": "T1"
  }' | jq '{batch_id, status, started_at}'
```

### Step 3: Monitor Progress

```bash
# Poll batch status
watch -n 10 'curl -sf https://api.cloudforge.lvonguyen.com/api/v1/remediations/batch-20260226-001 | \
  jq "{status, completed, failed, pending, elapsed_s}"'

# Stream dispatcher logs in the live demo
fly logs -a cloudforge-api | grep "batch-20260226-001"

# Self-managed alternative
kubectl logs -n aegis -l app=aegis-remediation -f | grep "batch-20260226-001"
```

## Monitoring Active Remediations

### Prometheus Metrics

```promql
# Active remediation count by tier
aegis_remediations_active by (tier)

# Success rate over 1h
rate(aegis_remediations_total{status="success"}[1h])
/ rate(aegis_remediations_total[1h])

# Avg duration by handler type
histogram_quantile(0.95, rate(aegis_remediation_duration_seconds_bucket[1h])) by (handler)

# Error rate
rate(aegis_remediations_total{status="failed"}[5m])
```

### Log-Based Monitoring

```bash
# All remediation errors in the last hour
fly logs -a cloudforge-api --no-tail | grep '"level":"error"' | jq '{handler, finding_id, error}'

# Successful remediations
fly logs -a cloudforge-api --no-tail | grep '"status":"success"' | \
  jq -r '[.handler, .finding_id, .resource_id] | @tsv'
```

## Per-Handler Operations

### Network: BlockPublicSSH

Blocks inbound SSH (22) and RDP (3389) from 0.0.0.0/0 and ::/0.

```bash
# Trigger manually for a specific security group
curl -s -X POST https://api.cloudforge.lvonguyen.com/api/v1/remediations/handlers/block-public-ssh \
  -H "Authorization: Bearer $API_TOKEN" \
  -d '{"resource_id": "sg-0abc123def456789", "provider": "aws", "dry_run": true}'

# Direct AWS CLI equivalent (for verification)
aws ec2 revoke-security-group-ingress \
  --group-id sg-0abc123def456789 \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0

# Verify rule removed
aws ec2 describe-security-groups \
  --group-ids sg-0abc123def456789 \
  --query 'SecurityGroups[0].IpPermissions[?FromPort==`22`]'
```

### Storage: S3 Public Access Blocking

```bash
# Trigger for a specific S3 bucket
curl -s -X POST https://api.cloudforge.lvonguyen.com/api/v1/remediations/handlers/s3-block-public-access \
  -H "Authorization: Bearer $API_TOKEN" \
  -d '{"resource_id": "my-bucket", "provider": "aws", "dry_run": true}'

# Direct AWS CLI equivalent
aws s3api put-public-access-block \
  --bucket my-bucket \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Verify
aws s3api get-public-access-block --bucket my-bucket
```

### Compute: IMDSv2 Enforcement

```bash
# Trigger for a specific EC2 instance
curl -s -X POST https://api.cloudforge.lvonguyen.com/api/v1/remediations/handlers/enforce-imdsv2 \
  -H "Authorization: Bearer $API_TOKEN" \
  -d '{"resource_id": "i-0abc123def456789", "provider": "aws", "dry_run": true}'

# Direct AWS CLI equivalent
aws ec2 modify-instance-metadata-options \
  --instance-id i-0abc123def456789 \
  --http-tokens required \
  --http-endpoint enabled

# Verify
aws ec2 describe-instances \
  --instance-ids i-0abc123def456789 \
  --query 'Reservations[0].Instances[0].MetadataOptions'
```

### Identity: IAM Key Rotation

Deactivates keys older than the configured threshold (default: 90 days).

```bash
# Trigger key rotation check for a user
curl -s -X POST https://api.cloudforge.lvonguyen.com/api/v1/remediations/handlers/rotate-iam-keys \
  -H "Authorization: Bearer $API_TOKEN" \
  -d '{"resource_id": "arn:aws:iam::123456789012:user/svc-aegis", "provider": "aws", "dry_run": true}'

# Direct AWS CLI: deactivate stale key
aws iam update-access-key \
  --access-key-id AKIAIOSFODNN7EXAMPLE \
  --status Inactive \
  --user-name svc-aegis

# Verify
aws iam list-access-keys \
  --user-name svc-aegis \
  --query 'AccessKeyMetadata[].{KeyId:AccessKeyId,Status:Status,Created:CreateDate}'
```

### Security Services: GuardDuty Enablement

```bash
# Enable GuardDuty in a region
curl -s -X POST https://api.cloudforge.lvonguyen.com/api/v1/remediations/handlers/enable-guardduty \
  -H "Authorization: Bearer $API_TOKEN" \
  -d '{"resource_id": "123456789012", "region": "us-east-1", "provider": "aws", "dry_run": true}'

# Direct AWS CLI equivalent
aws guardduty create-detector \
  --enable \
  --finding-publishing-frequency FIFTEEN_MINUTES \
  --region us-east-1

# Verify
aws guardduty list-detectors --region us-east-1
```

### Patching: SSM Compliance Queries

```bash
# Check SSM patch compliance for an instance
aws ssm describe-instance-patch-states \
  --instance-ids i-0abc123def456789 \
  --query 'InstancePatchStates[0].{Missing:MissingCount,Failed:FailedCount,Installed:InstalledCount}'

# Trigger SSM patch run
aws ssm send-command \
  --instance-ids i-0abc123def456789 \
  --document-name "AWS-RunPatchBaseline" \
  --parameters "Operation=Install" \
  --timeout-seconds 600

# Poll command status
aws ssm get-command-invocation \
  --command-id <command-id> \
  --instance-id i-0abc123def456789 \
  --query '{Status:Status,StatusDetails:StatusDetails}'
```

## Rollback Procedures

The dispatcher snapshots resource state before every change. Rollbacks are available for 48h.

```bash
# List available snapshots for a batch
curl -sf https://api.cloudforge.lvonguyen.com/api/v1/remediations/batch-20260226-001/snapshots | \
  jq '.[] | {snapshot_id, resource_id, handler, taken_at}'

# Dry-run rollback
curl -s -X POST https://api.cloudforge.lvonguyen.com/api/v1/remediations/batch-20260226-001/rollback \
  -H "Authorization: Bearer $API_TOKEN" \
  -d '{"snapshot_id": "snap-001", "dry_run": true}'

# Execute rollback
curl -s -X POST https://api.cloudforge.lvonguyen.com/api/v1/remediations/batch-20260226-001/rollback \
  -H "Authorization: Bearer $API_TOKEN" \
  -d '{"snapshot_id": "snap-001", "dry_run": false}'

# Verify rollback
curl -sf https://api.cloudforge.lvonguyen.com/api/v1/remediations/batch-20260226-001 | jq .rollback_status
```

### Manual Rollback (if dispatcher unavailable)

Snapshots are stored in S3 at `s3://aegis-snapshots/remediations/<batch-id>/`.

```bash
# Retrieve snapshot
aws s3 cp s3://aegis-snapshots/remediations/batch-20260226-001/snap-001.json .

# Inspect and apply manually using the appropriate CSP CLI
cat snap-001.json | jq .previous_state
```

## Emergency Stop

To halt all running remediations immediately:

```bash
# Kill dispatcher pods (restarts automatically but drains queue)
kubectl delete pod -l app=aegis-remediation -n aegis

# Suspend the remediation queue (prevents new work from dequeuing)
kubectl patch deployment aegis-remediation -n aegis \
  --type='json' \
  -p='[{"op": "replace", "path": "/spec/replicas", "value": 0}]'

# Verify stopped
kubectl get pods -n aegis -l app=aegis-remediation

# Resume after investigation
kubectl patch deployment aegis-remediation -n aegis \
  --type='json' \
  -p='[{"op": "replace", "path": "/spec/replicas", "value": 2}]'
```

## Troubleshooting Common Failures

### Permission Denied

**Symptoms**: `remediation failed: AccessDenied` or `403 Forbidden`

**Diagnosis**:
```bash
kubectl logs -n aegis -l app=aegis-remediation | \
  grep '"error":"AccessDenied"' | jq '{finding_id, resource_id, action}'
```

**Resolution**:
1. Verify IAM role/service principal has required policy attached
2. Check for Service Control Policies (SCPs) blocking the action
3. Confirm resource is in scope (correct account, region)
4. Check if resource has a resource-based policy denying the action

### Resource Locked

**Symptoms**: `ConflictException`, `ResourceInUse`, or `resource is being modified`

**Diagnosis**:
```bash
# Check if resource has pending operations
aws ec2 describe-instance-status \
  --instance-ids i-0abc123def456789 \
  --query 'InstanceStatuses[0].InstanceState'
```

**Resolution**:
1. Wait 60s and retry — most locks are transient
2. If persistent, check for concurrent automation (other tools, AWS automation)
3. Manually verify the resource state and complete or cancel the competing operation

### Dependency Conflict

**Symptoms**: Remediation succeeds but finding remains open; re-scan immediately re-flags the resource

**Diagnosis**:
```bash
# Get finding details to identify root resource vs dependent resource
curl -sf https://api.cloudforge.lvonguyen.com/api/v1/findings/f-abc123 | jq .dependencies
```

**Resolution**:
1. Check if a parent resource (e.g., Launch Template) is propagating the misconfiguration
2. Remediate the root resource, not the derived one
3. If an IaC pipeline is overwriting changes, add a policy exception and fix the IaC source

## Remediation Reporting

```bash
# Success/failure rates for last 7 days
curl -sf "https://api.cloudforge.lvonguyen.com/api/v1/remediations/report?period=7d" | \
  jq '{total, succeeded, failed, success_rate, sla_compliance_pct}'

# Breakdown by handler
curl -sf "https://api.cloudforge.lvonguyen.com/api/v1/remediations/report?period=7d&group_by=handler" | \
  jq '.[] | {handler, total, success_rate, avg_duration_s}'

# SLA compliance (target: 95% of T1 remediations complete within 5 min)
curl -s 'http://prometheus:9090/api/v1/query?query=
  sum(rate(aegis_remediations_total{tier="T1",status="success",duration_bucket=~"[0-9]+"}[7d]))
  / sum(rate(aegis_remediations_total{tier="T1"}[7d]))' | jq .
```

## Post-Batch Checklist

1. [ ] Batch status shows no failed items
2. [ ] Re-scan triggered to verify finding closure
3. [ ] Rollback snapshots confirmed in S3 (for audit)
4. [ ] Change management ticket updated with results
5. [ ] Metrics reviewed in Grafana

## Escalation

| Condition | Action |
|-----------|--------|
| Batch failure rate >20% | Stop batch, investigate permissions |
| Rollback fails | Manual remediation, engage Platform Team |
| Emergency stop needed | Scale replicas to 0, page on-call |
| SLA compliance <90% | Page on-call, review dispatcher capacity |

## Contact Information

- On-Call: PagerDuty
- Platform Team: #platform-support (Slack)
- Security Team: #security-ops (Slack)
