// Package identity provides remediation handlers for identity and access management findings.
package identity

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	cspmscoring "cloudforge/internal/cspm/scoring"
	"cloudforge/pkg/remediation"
)

// iamAPI is the subset of IAM operations needed by this remediator.
// Unexported — implementation detail for testability.
type iamAPI interface {
	ListAccessKeys(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
	UpdateAccessKey(ctx context.Context, params *iam.UpdateAccessKeyInput, optFns ...func(*iam.Options)) (*iam.UpdateAccessKeyOutput, error)
}

// RotateIAMKeysRemediator deactivates IAM access keys older than 90 days.
//
// Finding Type: IAM_OLD_ACCESS_KEY
// Tier: 2 (Requires verification - deactivating keys can break applications)
// Impact: Deactivates stale access keys; applications using them will fail
// CSPs: AWS
type RotateIAMKeysRemediator struct {
	tier          int
	maxAgeDays    int
	clientFactory func(ctx context.Context, region string) (iamAPI, error)
}

// NewRotateIAMKeysRemediator creates a new handler for IAM key rotation.
func NewRotateIAMKeysRemediator() *RotateIAMKeysRemediator {
	return &RotateIAMKeysRemediator{
		tier:       2,
		maxAgeDays: 90,
		clientFactory: func(ctx context.Context, region string) (iamAPI, error) {
			cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
			if err != nil {
				return nil, err
			}
			return iam.NewFromConfig(cfg), nil
		},
	}
}

// newRotateIAMKeysRemediatorForTest creates a remediator with an injected
// IAM client factory. Unexported — test-only.
func newRotateIAMKeysRemediatorForTest(factory func(ctx context.Context, region string) (iamAPI, error)) *RotateIAMKeysRemediator {
	return &RotateIAMKeysRemediator{tier: 2, maxAgeDays: 90, clientFactory: factory}
}

// Tier returns the complexity tier (2 = requires verification before PROD).
func (r *RotateIAMKeysRemediator) Tier() int {
	return r.tier
}

// Remediate deactivates IAM access keys older than the configured threshold.
func (r *RotateIAMKeysRemediator) Remediate(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.RemediationResult, error) {
	startTime := time.Now()

	result := &remediation.RemediationResult{
		FindingID:  finding.Finding.ID,
		ResourceID: finding.Finding.ResourceID,
		StartedAt:  startTime,
		Actions:    []string{},
	}

	client, err := r.clientFactory(ctx, finding.Finding.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to create IAM client: %w", err)
	}

	// Extract IAM user name from resource ID
	userName := finding.Finding.ResourceID

	// List access keys for the user
	listOutput, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
		UserName: aws.String(userName),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list access keys for %s: %w", userName, err)
	}

	deactivated := 0
	for _, key := range listOutput.AccessKeyMetadata {
		if key.Status != iamtypes.StatusTypeActive {
			continue
		}

		if key.CreateDate == nil {
			continue
		}
		age := time.Since(*key.CreateDate)
		if age.Hours()/24 < float64(r.maxAgeDays) {
			continue
		}

		_, err := client.UpdateAccessKey(ctx, &iam.UpdateAccessKeyInput{
			UserName:    aws.String(userName),
			AccessKeyId: key.AccessKeyId,
			Status:      iamtypes.StatusTypeInactive,
		})
		if err != nil {
			result.Error = fmt.Sprintf("failed to deactivate key %s: %v", maskKeyID(key.AccessKeyId), err)
			result.CompletedAt = time.Now()
			result.Duration = time.Since(startTime).String()
			return result, fmt.Errorf("failed to deactivate key: %w", err)
		}

		result.Actions = append(result.Actions,
			fmt.Sprintf("Deactivated key %s (age: %d days)", maskKeyID(key.AccessKeyId), int(age.Hours()/24)),
		)
		deactivated++
	}

	result.CompletedAt = time.Now()
	result.Duration = time.Since(startTime).String()

	if deactivated == 0 {
		result.Success = true
		result.Message = fmt.Sprintf("No keys older than %d days found for user: %s", r.maxAgeDays, userName)
	} else {
		result.Success = true
		result.Message = fmt.Sprintf("Deactivated %d stale access key(s) for user: %s", deactivated, userName)
	}

	return result, nil
}

// Validate verifies no active keys exceed the age threshold.
func (r *RotateIAMKeysRemediator) Validate(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.ValidationResult, error) {
	validation := &remediation.ValidationResult{
		FindingID:   finding.Finding.ID,
		ValidatedAt: time.Now(),
		Evidence:    []string{},
	}

	client, err := r.clientFactory(ctx, finding.Finding.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to create IAM client: %w", err)
	}

	userName := finding.Finding.ResourceID

	listOutput, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
		UserName: aws.String(userName),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list access keys: %w", err)
	}

	staleKeys := 0
	for _, key := range listOutput.AccessKeyMetadata {
		if key.Status != iamtypes.StatusTypeActive {
			continue
		}
		age := time.Since(*key.CreateDate)
		if age.Hours()/24 >= float64(r.maxAgeDays) {
			staleKeys++
			validation.Evidence = append(validation.Evidence,
				fmt.Sprintf("Active key %s is %d days old", *key.AccessKeyId, int(age.Hours()/24)),
			)
		}
	}

	if staleKeys > 0 {
		validation.IsCompliant = false
		validation.Message = fmt.Sprintf("%d active key(s) still exceed %d-day threshold", staleKeys, r.maxAgeDays)
	} else {
		validation.IsCompliant = true
		validation.Message = fmt.Sprintf("All active keys for %s are within %d-day threshold", userName, r.maxAgeDays)
	}

	return validation, nil
}

// DryRun simulates key rotation without making changes.
func (r *RotateIAMKeysRemediator) DryRun(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.DryRunResult, error) {
	dryRun := &remediation.DryRunResult{
		FindingID:        finding.Finding.ID,
		WouldSucceed:     true,
		PrerequisitesMet: true,
		PlannedActions: []string{
			fmt.Sprintf("Would list access keys for user: %s", finding.Finding.ResourceID),
			fmt.Sprintf("Would deactivate keys older than %d days", r.maxAgeDays),
		},
		EstimatedImpact: "Applications using deactivated keys will lose access. Ensure replacement keys are provisioned first.",
		Warnings: []string{
			"WARNING: Deactivating access keys may break applications using these credentials",
			"Verify no CI/CD pipelines or services depend on these keys before executing",
		},
	}

	return dryRun, nil
}

// maskKeyID masks an IAM access key ID for safe logging [SEC-007].
func maskKeyID(keyID *string) string {
	if keyID == nil {
		return "<nil>"
	}
	k := *keyID
	if len(k) <= 4 {
		return "****"
	}
	return "****" + k[len(k)-4:]
}
