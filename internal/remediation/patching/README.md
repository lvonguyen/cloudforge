# Patching Remediation Domain

Reports OS patch compliance status via AWS Systems Manager (SSM). This domain
queries patch state but does NOT auto-apply patches -- patching requires explicit
change windows and approval due to reboot/downtime risk.

## Handlers

| Handler | Finding Type | Tier | CSPs | Description |
|---------|-------------|------|------|-------------|
| `OSPatchRemediator` | `OS_PATCH_MISSING` | 3 | AWS (SSM) | Queries SSM Patch Manager for missing/failed patches and generates patching commands |

## Handler Details

### OSPatchRemediator (Tier 3 -- Requires change window)

- **Action**: Calls `DescribeInstancePatchStates` to query patch compliance; reports missing/failed/installed counts. Does NOT apply patches.
- **Validation**: Re-queries patch state and confirms `MissingCount == 0 && FailedCount == 0`
- **Dry-run**: Reports that patch compliance would be queried; warns about reboot requirements
- **Output**: Generates an `aws ssm send-command` invocation for `AWS-RunPatchBaseline` that operators can run manually during a change window

### Why Tier 3?

OS patching is the highest-risk remediation tier because:
- Patches may require instance reboots (5-15 min downtime)
- Kernel updates can cause application compatibility issues
- Must be coordinated with application owners and change management

## Integration

The dispatcher registers this handler via:

```go
executor.Register("OS_PATCH_MISSING", patching.NewOSPatchRemediator())
```

The handler extracts instance IDs from ARN format or plain `i-xxx` IDs.
Requires the SSM agent to be installed and running on target instances.

## Safety Considerations

- [*] This handler only READS patch state -- it never applies patches
- [!] Actual patching must be scheduled via change windows with application owner approval
- [>] Verify SSM agent is installed before relying on patch data
- [>] Create instance snapshots/AMIs before applying patches
- [-] Instances without SSM agent return "No patch data available"
