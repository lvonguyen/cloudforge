# Identity Remediation Domain

Remediates IAM and access management findings across cloud accounts.
Targets credential hygiene -- specifically stale access keys that increase blast radius on compromise.

## Handlers

| Handler | Finding Type | Tier | CSPs | Description |
|---------|-------------|------|------|-------------|
| `RotateIAMKeysRemediator` | `IAM_OLD_ACCESS_KEY` | 2 | AWS | Deactivates IAM access keys older than 90 days |

## Handler Details

### RotateIAMKeysRemediator (Tier 2 -- Requires verification)

- **Action**: Lists access keys for the IAM user, deactivates any active keys older than 90 days
- **Validation**: Re-lists keys and confirms no active keys exceed the age threshold
- **Dry-run**: Reports which keys would be deactivated with age details
- **Rollback**: `aws iam update-access-key --access-key-id <key-id> --status Active --user-name <user>`

## Integration

The dispatcher registers this handler via:

```go
executor.Register("IAM_OLD_ACCESS_KEY", identity.NewRotateIAMKeysRemediator())
```

The handler uses the finding's `ResourceID` as the IAM user name. The 90-day
threshold is set at construction time via `maxAgeDays`.

## Safety Considerations

- [!] Deactivating access keys will break any application, CI/CD pipeline, or service using them
- [!] This is Tier 2 -- requires human verification before production execution
- [>] Always run dry-run first to identify affected keys and their age
- [>] Coordinate with application owners to provision replacement keys before deactivating old ones
- [-] Does NOT delete keys -- only sets status to Inactive, allowing reactivation if needed
