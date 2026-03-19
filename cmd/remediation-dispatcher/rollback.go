package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/s3control"

	cspmscoring "aegis/internal/cspm/scoring"
	"aegis/pkg/remediation"
)

// RollbackFunc executes a rollback for a specific handler type using captured state.
type RollbackFunc func(ctx context.Context, state *remediation.RollbackState) (*remediation.RollbackResult, error)

// rollbackRegistry maps finding types to their rollback functions.
var rollbackRegistry = map[string]RollbackFunc{}

func init() {
	registerRollbackHandlers()
}

// registerRollbackHandlers populates the rollback registry.
// Only handlers with deterministic, safe rollback paths are registered.
func registerRollbackHandlers() {
	rollbackRegistry["GuardDuty.1"] = rollbackGuardDuty
	rollbackRegistry["S3_PUBLIC_ACCESS"] = rollbackBlockPublicS3
	rollbackRegistry["IAM_OLD_ACCESS_KEY"] = rollbackRotateIAMKeys
	rollbackRegistry["EC2_IMDSV1_ENABLED"] = rollbackEnforceIMDS

	// No rollback for:
	// - OPEN_SSH_PORT / AWS.EC2.SecurityGroup.SSH (not yet implemented)
	// - EXPOSED_SECRET (manual rotation cannot be undone)
	// - OS_PATCH_MISSING (uninstalling patches is dangerous)
	// - Defender.Storage (Azure stub, nothing to rollback)
}

// rollbackGuardDuty deletes the GuardDuty detector that was created during remediation.
func rollbackGuardDuty(ctx context.Context, state *remediation.RollbackState) (*remediation.RollbackResult, error) {
	result := &remediation.RollbackResult{
		FindingID:    state.FindingID,
		RolledBackAt: time.Now(),
	}

	detectorID, ok := state.PreState["detector_id"].(string)
	if !ok || detectorID == "" {
		return nil, fmt.Errorf("no detector_id in rollback state for finding %s", state.FindingID)
	}

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(state.Region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := guardduty.NewFromConfig(cfg)
	_, err = client.DeleteDetector(ctx, &guardduty.DeleteDetectorInput{
		DetectorId: aws.String(detectorID),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to delete GuardDuty detector %s: %w", detectorID, err)
	}

	result.Success = true
	result.Message = fmt.Sprintf("Deleted GuardDuty detector %s in %s", detectorID, state.Region)
	result.Actions = []string{fmt.Sprintf("Deleted detector %s", detectorID)}
	return result, nil
}

// rollbackBlockPublicS3 removes the account-level public access block that was applied.
// This restores the previous settings if captured, or removes the block entirely.
func rollbackBlockPublicS3(ctx context.Context, state *remediation.RollbackState) (*remediation.RollbackResult, error) {
	result := &remediation.RollbackResult{
		FindingID:    state.FindingID,
		RolledBackAt: time.Now(),
	}

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(state.Region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := s3control.NewFromConfig(cfg)

	// The forward path sets all 4 flags to true at the account level.
	// Rollback removes the block entirely, restoring the account default.
	_, err = client.DeletePublicAccessBlock(ctx, &s3control.DeletePublicAccessBlockInput{
		AccountId: aws.String(state.AccountID),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to remove public access block on account %s: %w", state.AccountID, err)
	}

	result.Success = true
	result.Message = fmt.Sprintf("Removed account-level S3 public access block on %s", state.AccountID)
	result.Actions = []string{
		fmt.Sprintf("Deleted PublicAccessBlock for account %s", state.AccountID),
	}
	return result, nil
}

// rollbackRotateIAMKeys re-activates access keys that were deactivated during remediation.
func rollbackRotateIAMKeys(ctx context.Context, state *remediation.RollbackState) (*remediation.RollbackResult, error) {
	result := &remediation.RollbackResult{
		FindingID:    state.FindingID,
		RolledBackAt: time.Now(),
	}

	// Extract deactivated key IDs from the captured state.
	keyIDsRaw, ok := state.PreState["deactivated_key_ids"].([]interface{})
	if !ok || len(keyIDsRaw) == 0 {
		return nil, fmt.Errorf("no deactivated_key_ids in rollback state for finding %s", state.FindingID)
	}

	userName := state.ResourceID

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(state.Region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := iam.NewFromConfig(cfg)
	var actions []string

	for _, raw := range keyIDsRaw {
		keyID, ok := raw.(string)
		if !ok || keyID == "" {
			continue
		}

		_, err = client.UpdateAccessKey(ctx, &iam.UpdateAccessKeyInput{
			AccessKeyId: aws.String(keyID),
			Status:      iamtypes.StatusTypeActive,
			UserName:    aws.String(userName),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to re-activate access key %s for user %s: %w", keyID, userName, err)
		}
		actions = append(actions, fmt.Sprintf("Re-activated access key %s", keyID))
	}

	result.Success = true
	result.Message = fmt.Sprintf("Re-activated %d access key(s) for user %s", len(actions), userName)
	result.Actions = actions
	return result, nil
}

// rollbackEnforceIMDS reverts IMDSv2 enforcement back to optional (IMDSv1 allowed).
func rollbackEnforceIMDS(ctx context.Context, state *remediation.RollbackState) (*remediation.RollbackResult, error) {
	result := &remediation.RollbackResult{
		FindingID:    state.FindingID,
		RolledBackAt: time.Now(),
	}

	instanceID := extractInstanceIDFromState(state.ResourceID)

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(state.Region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := ec2.NewFromConfig(cfg)
	_, err = client.ModifyInstanceMetadataOptions(ctx, &ec2.ModifyInstanceMetadataOptionsInput{
		InstanceId: aws.String(instanceID),
		HttpTokens: ec2types.HttpTokensStateOptional,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to revert IMDS to optional on %s: %w", instanceID, err)
	}

	result.Success = true
	result.Message = fmt.Sprintf("Reverted IMDSv2 enforcement on %s (HttpTokens=optional)", instanceID)
	result.Actions = []string{fmt.Sprintf("Set HttpTokens=optional on %s", instanceID)}
	return result, nil
}

// extractInstanceIDFromState extracts an EC2 instance ID from an ARN or plain ID.
func extractInstanceIDFromState(resourceID string) string {
	if strings.Contains(resourceID, "instance/") {
		parts := strings.Split(resourceID, "instance/")
		if len(parts) > 1 {
			return parts[1]
		}
	}
	return resourceID
}

// captureHandlerPreState captures handler-specific state after remediation.
// This provides the data needed for rollback (detector IDs, key IDs, SG IDs).
func captureHandlerPreState(finding *cspmscoring.PrioritizedFinding, result *remediation.RemediationResult) map[string]interface{} {
	preState := map[string]interface{}{
		"resource_id": finding.Finding.ResourceID,
		"region":      finding.Finding.Region,
		"account_id":  finding.Finding.AccountID,
	}

	switch finding.Finding.FindingType {
	case "GuardDuty.1":
		// Parse detector ID from "Enabled GuardDuty detector: det-xxx"
		for _, action := range result.Actions {
			if strings.Contains(action, "detector:") {
				parts := strings.SplitAfter(action, "detector: ")
				if len(parts) > 1 {
					preState["detector_id"] = strings.TrimSpace(parts[1])
				}
			}
		}

	case "OPEN_SSH_PORT", "AWS.EC2.SecurityGroup.SSH":
		preState["security_group_id"] = extractSGIDFromResource(finding.Finding.ResourceID)

	case "S3_PUBLIC_ACCESS":
		// Account-level operation, AccountID is the key identifier
		preState["account_id"] = finding.Finding.AccountID

	case "IAM_OLD_ACCESS_KEY":
		// Parse deactivated key IDs from "Deactivated key AKIA... (age: N days)"
		var keyIDs []string
		for _, action := range result.Actions {
			if strings.Contains(action, "Deactivated key ") {
				parts := strings.SplitAfter(action, "Deactivated key ")
				if len(parts) > 1 {
					keyID := strings.Fields(parts[1])[0]
					keyIDs = append(keyIDs, keyID)
				}
			}
		}
		if len(keyIDs) > 0 {
			preState["deactivated_key_ids"] = keyIDs
		}

	case "EC2_IMDSV1_ENABLED":
		preState["instance_id"] = extractInstanceIDFromState(finding.Finding.ResourceID)
	}

	return preState
}

// extractSGIDFromResource extracts an SG ID from an ARN or plain ID.
func extractSGIDFromResource(resourceID string) string {
	if strings.Contains(resourceID, "security-group/") {
		parts := strings.Split(resourceID, "security-group/")
		if len(parts) > 1 {
			return parts[1]
		}
	}
	if strings.HasPrefix(resourceID, "sg-") {
		return resourceID
	}
	return resourceID
}
