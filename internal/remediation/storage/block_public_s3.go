// Package storage provides remediation handlers for cloud storage security findings.
package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3controltypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"

	"cloudforge/internal/findings"
	"cloudforge/pkg/remediation"
)

// BlockPublicS3Remediator blocks all public access on S3 buckets.
//
// Finding Type: S3_PUBLIC_ACCESS
// Tier: 1 (Auto-safe - blocking public access is always safe for non-static-site buckets)
// Impact: Blocks all public access via PutPublicAccessBlock
// CSPs: AWS
type BlockPublicS3Remediator struct {
	tier int
}

// NewBlockPublicS3Remediator creates a new handler for blocking S3 public access.
func NewBlockPublicS3Remediator() *BlockPublicS3Remediator {
	return &BlockPublicS3Remediator{tier: 1}
}

// Tier returns the complexity tier (1 = auto-safe).
func (b *BlockPublicS3Remediator) Tier() int {
	return b.tier
}

// Remediate enables the S3 account-level public access block.
func (b *BlockPublicS3Remediator) Remediate(ctx context.Context, finding *findings.PrioritizedFinding) (*remediation.RemediationResult, error) {
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

	client := s3control.NewFromConfig(cfg)

	_, err = client.PutPublicAccessBlock(ctx, &s3control.PutPublicAccessBlockInput{
		AccountId: &finding.Finding.AccountID,
		PublicAccessBlockConfiguration: &s3controltypes.PublicAccessBlockConfiguration{
			BlockPublicAcls:       aws.Bool(true),
			BlockPublicPolicy:     aws.Bool(true),
			IgnorePublicAcls:      aws.Bool(true),
			RestrictPublicBuckets: aws.Bool(true),
		},
	})

	if err != nil {
		result.CompletedAt = time.Now()
		result.Duration = time.Since(startTime).String()
		result.Error = err.Error()
		return result, fmt.Errorf("failed to put public access block: %w", err)
	}

	result.Actions = append(result.Actions,
		fmt.Sprintf("Enabled BlockPublicAcls on account: %s", finding.Finding.AccountID),
		"Enabled BlockPublicPolicy",
		"Enabled IgnorePublicAcls",
		"Enabled RestrictPublicBuckets",
	)
	result.CompletedAt = time.Now()
	result.Duration = time.Since(startTime).String()
	result.Success = true
	result.Message = fmt.Sprintf("All public access blocked for account: %s", finding.Finding.AccountID)

	return result, nil
}

// Validate verifies the public access block is enabled.
func (b *BlockPublicS3Remediator) Validate(ctx context.Context, finding *findings.PrioritizedFinding) (*remediation.ValidationResult, error) {
	validation := &remediation.ValidationResult{
		FindingID:   finding.Finding.ID,
		ValidatedAt: time.Now(),
		Evidence:    []string{},
	}

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(finding.Finding.Region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := s3control.NewFromConfig(cfg)

	output, err := client.GetPublicAccessBlock(ctx, &s3control.GetPublicAccessBlockInput{
		AccountId: &finding.Finding.AccountID,
	})
	if err != nil {
		validation.IsCompliant = false
		validation.Message = fmt.Sprintf("Failed to get public access block: %v", err)
		return validation, nil
	}

	pab := output.PublicAccessBlockConfiguration
	deref := func(b *bool) bool { return b != nil && *b }
	allBlocked := deref(pab.BlockPublicAcls) && deref(pab.BlockPublicPolicy) &&
		deref(pab.IgnorePublicAcls) && deref(pab.RestrictPublicBuckets)

	if !allBlocked {
		validation.IsCompliant = false
		validation.Message = "Not all public access block settings are enabled"
		validation.Evidence = append(validation.Evidence,
			fmt.Sprintf("BlockPublicAcls: %t", deref(pab.BlockPublicAcls)),
			fmt.Sprintf("BlockPublicPolicy: %t", deref(pab.BlockPublicPolicy)),
			fmt.Sprintf("IgnorePublicAcls: %t", deref(pab.IgnorePublicAcls)),
			fmt.Sprintf("RestrictPublicBuckets: %t", deref(pab.RestrictPublicBuckets)),
		)
		return validation, nil
	}

	validation.IsCompliant = true
	validation.Message = fmt.Sprintf("All public access blocked for account: %s", finding.Finding.AccountID)
	validation.Evidence = append(validation.Evidence, "All 4 public access block settings enabled")

	return validation, nil
}

// DryRun simulates blocking public access without making changes.
func (b *BlockPublicS3Remediator) DryRun(ctx context.Context, finding *findings.PrioritizedFinding) (*remediation.DryRunResult, error) {
	return &remediation.DryRunResult{
		FindingID:        finding.Finding.ID,
		WouldSucceed:     true,
		PrerequisitesMet: true,
		PlannedActions: []string{
			fmt.Sprintf("Would enable BlockPublicAcls on account: %s", finding.Finding.AccountID),
			"Would enable BlockPublicPolicy",
			"Would enable IgnorePublicAcls",
			"Would enable RestrictPublicBuckets",
		},
		EstimatedImpact: "S3 buckets will no longer be publicly accessible. Static website hosting via S3 will break.",
	}, nil
}
