// Package patching provides remediation handlers for OS and software patching findings.
package patching

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

	"cloudforge/internal/findings"
	"cloudforge/pkg/remediation"
)

// OSPatchRemediator checks and reports OS patch compliance via AWS SSM.
//
// Finding Type: OS_PATCH_MISSING
// Tier: 3 (Requires change window - OS patching can cause downtime/reboots)
// Impact: Queries patch status; does NOT auto-patch (requires explicit change window)
// CSPs: AWS (via SSM Patch Manager)
type OSPatchRemediator struct {
	tier int
}

// NewOSPatchRemediator creates a new handler for OS patch compliance.
func NewOSPatchRemediator() *OSPatchRemediator {
	return &OSPatchRemediator{tier: 3}
}

// Tier returns the complexity tier (3 = requires change window).
func (o *OSPatchRemediator) Tier() int {
	return o.tier
}

// Remediate queries SSM for patch compliance status and reports missing patches.
// It does NOT auto-apply patches -- that requires a change window and explicit approval.
func (o *OSPatchRemediator) Remediate(ctx context.Context, finding *findings.PrioritizedFinding) (*remediation.RemediationResult, error) {
	startTime := time.Now()

	result := &remediation.RemediationResult{
		FindingID:  finding.Finding.ID,
		ResourceID: finding.Finding.ResourceID,
		StartedAt:  startTime,
		Actions:    []string{},
	}

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(finding.Finding.Region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := ssm.NewFromConfig(cfg)
	instanceID := extractInstanceID(finding.Finding.ResourceID)

	// Query patch compliance status
	patchOutput, err := client.DescribeInstancePatchStates(ctx, &ssm.DescribeInstancePatchStatesInput{
		InstanceIds: []string{instanceID},
	})
	if err != nil {
		result.CompletedAt = time.Now()
		result.Duration = time.Since(startTime).String()
		result.Error = err.Error()
		return result, fmt.Errorf("failed to describe patch states: %w", err)
	}

	if len(patchOutput.InstancePatchStates) == 0 {
		result.CompletedAt = time.Now()
		result.Duration = time.Since(startTime).String()
		result.Success = false
		result.Message = fmt.Sprintf("No patch data available for instance: %s (SSM agent may not be installed)", instanceID)
		return result, nil
	}

	state := patchOutput.InstancePatchStates[0]
	missingCount := state.MissingCount
	failedCount := state.FailedCount

	result.Actions = append(result.Actions,
		fmt.Sprintf("Queried patch compliance for instance: %s", instanceID),
		fmt.Sprintf("Missing patches: %d", missingCount),
		fmt.Sprintf("Failed patches: %d", failedCount),
		fmt.Sprintf("Installed patches: %d", state.InstalledCount),
	)

	result.CompletedAt = time.Now()
	result.Duration = time.Since(startTime).String()
	result.Success = false
	result.Message = fmt.Sprintf(
		"Instance %s has %d missing and %d failed patches. "+
			"Schedule patching via: aws ssm send-command --document-name AWS-RunPatchBaseline --targets Key=instanceids,Values=%s",
		instanceID, missingCount, failedCount, instanceID,
	)

	return result, nil
}

// Validate checks current patch compliance status.
func (o *OSPatchRemediator) Validate(ctx context.Context, finding *findings.PrioritizedFinding) (*remediation.ValidationResult, error) {
	validation := &remediation.ValidationResult{
		FindingID:   finding.Finding.ID,
		ValidatedAt: time.Now(),
		Evidence:    []string{},
	}

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(finding.Finding.Region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := ssm.NewFromConfig(cfg)
	instanceID := extractInstanceID(finding.Finding.ResourceID)

	patchOutput, err := client.DescribeInstancePatchStates(ctx, &ssm.DescribeInstancePatchStatesInput{
		InstanceIds: []string{instanceID},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe patch states: %w", err)
	}

	if len(patchOutput.InstancePatchStates) == 0 {
		validation.IsCompliant = false
		validation.Message = "No patch data available (SSM agent may not be installed)"
		return validation, nil
	}

	state := patchOutput.InstancePatchStates[0]

	validation.Evidence = append(validation.Evidence,
		fmt.Sprintf("Instance: %s", instanceID),
		fmt.Sprintf("Installed: %d", state.InstalledCount),
		fmt.Sprintf("Missing: %d", state.MissingCount),
		fmt.Sprintf("Failed: %d", state.FailedCount),
		fmt.Sprintf("Operation: %s", state.Operation),
	)

	if state.MissingCount == 0 && state.FailedCount == 0 {
		validation.IsCompliant = true
		validation.Message = fmt.Sprintf("Instance %s is fully patched (%d patches installed)", instanceID, state.InstalledCount)
	} else {
		validation.IsCompliant = false
		validation.Message = fmt.Sprintf("Instance %s has %d missing and %d failed patches",
			instanceID, state.MissingCount, state.FailedCount)
	}

	return validation, nil
}

// DryRun reports patch status and estimated remediation impact.
func (o *OSPatchRemediator) DryRun(ctx context.Context, finding *findings.PrioritizedFinding) (*remediation.DryRunResult, error) {
	instanceID := extractInstanceID(finding.Finding.ResourceID)

	return &remediation.DryRunResult{
		FindingID:        finding.Finding.ID,
		WouldSucceed:     false,
		PrerequisitesMet: true,
		PlannedActions: []string{
			fmt.Sprintf("Would query patch compliance for instance: %s", instanceID),
			"Would identify missing security and critical patches",
			"Would generate aws ssm send-command for AWS-RunPatchBaseline",
			"Actual patching requires explicit change window approval",
		},
		EstimatedImpact: "OS patching may require instance reboot (estimated 5-15 min downtime).",
		Warnings: []string{
			"WARNING: OS patching requires a change window -- this handler does NOT auto-patch",
			"Coordinate with application owners before scheduling patch operations",
			"Ensure instance snapshots/AMIs are created before patching",
		},
	}, nil
}

// extractInstanceID extracts the EC2 instance ID from a resource ARN or ID.
func extractInstanceID(resourceID string) string {
	if strings.Contains(resourceID, "instance/") {
		parts := strings.Split(resourceID, "instance/")
		if len(parts) > 1 {
			return parts[1]
		}
	}
	if strings.HasPrefix(resourceID, "i-") {
		return resourceID
	}
	return resourceID
}
