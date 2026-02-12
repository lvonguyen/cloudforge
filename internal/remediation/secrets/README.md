# Secrets Remediation Domain

Handles findings for exposed secrets and credentials. This domain intentionally
does NOT auto-rotate secrets -- it documents the exposure and recommends manual
rotation steps to prevent cascading failures.

## Handlers

| Handler | Finding Type | Tier | CSPs | Description |
|---------|-------------|------|------|-------------|
| `RotateExposedSecretRemediator` | `EXPOSED_SECRET` | 2 | All | Logs the finding and outputs manual rotation instructions (no-op handler) |

## Handler Details

### RotateExposedSecretRemediator (Tier 2 -- Manual intervention required)

This is a **no-op handler** by design. Secret rotation is not automated because:

- Secrets may be embedded across multiple systems
- Rotation requires coordinated updates across all consumers
- Automated rotation without consumer updates causes cascading failures

**Remediate**: Returns `Success=false` with manual rotation steps:
1. Identify secret type and all consumers
2. Generate new secret via provider (1Password CLI, Secrets Manager, Key Vault)
3. Update all consumers with the new secret
4. Invalidate the old secret
5. Remove secret from git history if committed (git-filter-repo or BFG)

**Validate**: Always returns `IsCompliant=false` -- manual verification is required.

**Dry-run**: Lists the 6-step manual rotation procedure with impact warnings.

## Integration

This handler is registered but does not perform cloud API calls:

```go
executor.Register("EXPOSED_SECRET", secrets.NewRotateExposedSecretRemediator())
```

The handler creates an audit trail in the results JSON, documenting that the
exposure was detected and what manual steps are needed.

## Safety Considerations

- [*] This handler never modifies cloud resources -- safe to run in any mode
- [!] The actual rotation must be performed manually to avoid breaking consumers
- [>] Use 1Password CLI (`op rotate`) or cloud-native secret managers for rotation
- [>] After rotation, verify no secrets remain in git history
- [-] Automated secret rotation may be added in future with consumer-dependency mapping
