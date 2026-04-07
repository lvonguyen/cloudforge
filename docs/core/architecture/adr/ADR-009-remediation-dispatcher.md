# ADR-009: Remediation Dispatcher Architecture

## Status

Accepted

## Date

2026-02-11

## Context

CloudForge aggregates findings from multiple cloud security tools (Security Hub, Defender for Cloud, SCC). Once findings are identified, the next step is automated remediation. Manual remediation at enterprise scale (10K+ findings) is impractical.

The architecture must:
1. Support multiple remediation types across cloud providers
2. Provide safe execution with dry-run and rollback
3. Control concurrency to avoid overwhelming cloud APIs
4. Separate low-risk auto-fixes from high-risk changes requiring approval

### Requirements

- Dry-run mode for every remediation (preview before execution)
- State snapshot before every change (rollback capability)
- Tiered execution model (auto-safe vs approval-required)
- Handler isolation (each remediation type is independent)
- Cloud-native API calls (not shell scripts or Terraform)

## Decision

A **tiered remediation dispatcher** was selected with the following architecture:

### 1. Handler Interface

Every remediation type implements a common interface:

```go
type Handler interface {
    Remediate(ctx context.Context, finding Finding) (*Result, error)
    Validate(ctx context.Context, finding Finding) error
    DryRun(ctx context.Context, finding Finding) (*DryRunResult, error)
    Tier() ExecutionTier
}
```

### 2. Tiered Execution Model

| Tier | Risk Level | Concurrency | Timeout | Approval |
|------|-----------|-------------|---------|----------|
| T1 (Auto-Safe) | Low | 10 parallel | 30s | None |
| T2 (Verify) | Medium | 5 parallel | 120s | Post-execution check |
| T3 (Change Window) | High | 2 parallel | 600s | Pre-execution approval |

### 3. Executor Engine

The executor (`pkg/remediation/`) manages:
- Semaphore-controlled concurrent batch execution
- Per-finding state snapshots to S3/GCS before changes
- 48-hour rollback window
- Structured logging via zap for audit trail

### 4. Handlers (18 across 12 domains)

| Domain | Handler | Tier | Cloud Provider |
|--------|---------|------|---------------|
| Network | BlockPublicSSH | T1 | AWS (EC2 Security Groups) |
| Network | BlockOpenPort | T1 | AWS (EC2 Security Groups) |
| Network | RestrictDefaultSG | T1 | AWS (EC2 Security Groups) |
| Network | EnforceSSL | T2 | AWS (RDS/ELB) |
| Storage | BlockPublicS3 | T1 | AWS (S3) |
| Compute | EnforceIMDSv2 | T2 | AWS (EC2) |
| Identity | RotateIAMKeys | T2 | AWS (IAM) |
| Identity | RestrictExcessivePerms | T2 | AWS (IAM) |
| Security Services | GuardDutyEnablement | T1 | AWS (GuardDuty) |
| Security Services | AzureDefender | T1 | Azure (Defender for Storage, stub) |
| Monitoring | EnableCloudTrail | T2 | AWS (CloudTrail) |
| Monitoring | EnableGCPAuditLogs | T2 | GCP (Cloud Audit Logs) |
| Config | EnableAWSConfig | T2 | AWS (Config) |
| Container | DisablePrivilegedPods | T2 | Kubernetes |
| Database | EnableRDSEncryption | T3 | AWS (RDS) |
| Encryption | RotateKMSKey | T3 | AWS (KMS) |
| Secrets | RotateExposedSecret | T3 | Multi-cloud (manual guidance) |
| Patching | OSPatch | T3 | AWS (SSM, query-only) |

## Consequences

### Positive

- **Safety**: Dry-run + rollback means changes are reversible
- **Auditability**: Every action logged with finding ID, handler, result, and duration
- **Extensibility**: New handlers implement the interface without changing the executor
- **Controlled blast radius**: Tier-based concurrency limits prevent API throttling

### Negative

- **Cloud-specific handlers**: Each CSP needs its own handler implementation
- **Stub implementations**: Azure/GCP handlers are stubs in this version
- **No cross-account orchestration**: Handlers operate within a single account context

### Mitigations

- Use injectable cloud SDK clients for testability
- Document handler interface clearly for future CSP expansion
- Plan for cross-account execution via STS AssumeRole in production

## Alternatives Considered

### 1. Terraform-Based Remediation

Apply Terraform plans to fix misconfigurations.

**Rejected because**: Terraform requires state management per resource, is slow for individual fixes, and cannot handle ephemeral resources. Direct API calls are faster and more precise.

### 2. AWS Systems Manager Automation

Use SSM documents for all remediations.

**Rejected because**: AWS-only, limits multi-cloud support. SSM automation documents are also complex to author and test.

### 3. Single-Tier Execution (All Auto)

No tier distinction, all remediations execute automatically.

**Rejected because**: IAM changes and OS patching carry material risk. A single misconfigured IAM key rotation could lock out service accounts. Tiered execution provides a safety gradient.

## Implementation Update (2026-04-03)

Since this ADR was accepted, handler coverage expanded from 10 to 18 across 12 domains (up from 8). Key additions:

- **Network** grew from 1 handler (SSH) to 4 (SSH, open port, default SG, SSL enforcement)
- **Identity** added `RestrictExcessivePerms` for IAM policy right-sizing
- **Monitoring** added CloudTrail and GCP Audit Logs enablement
- **Config** added AWS Config enablement
- **Container** added Kubernetes privileged pod remediation
- **Database** added RDS encryption enforcement
- **Encryption** added KMS key rotation
- **Private cloud** handlers (ESXi SSH, K8s privileged pods) are designed but not yet implemented — see `internal/remediation/private_cloud/README.md`

The `AzureDefender` and multi-cloud `RotateExposedSecret` handlers remain stubs pending production Azure tenant access. All other handlers have full dry-run, validation, and rollback support.

## References

- `pkg/remediation/` — Executor engine, Remediator interface, types
- `internal/remediation/` — Domain handler implementations (12 active subdirectories + private_cloud planned)
- Runbook: [05-remediation-operations.md](../../runbooks/05-remediation-operations.md)
- State machine diagram: [`remediation-dispatcher-flow.svg`](../../../core/diagrams/remediation-dispatcher-flow.svg) ([Mermaid source](../../../core/diagrams/remediation-dispatcher-flow.mmd))
