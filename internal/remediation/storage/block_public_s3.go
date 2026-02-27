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

// s3ControlAPI defines the s3control operations used by this remediator.
type s3ControlAPI interface {
	PutPublicAccessBlock(ctx context.Context, params *s3control.PutPublicAccessBlockInput, optFns ...func(*s3control.Options)) (*s3control.PutPublicAccessBlockOutput, error)
	GetPublicAccessBlock(ctx context.Context, params *s3control.GetPublicAccessBlockInput, optFns ...func(*s3control.Options)) (*s3control.GetPublicAccessBlockOutput, error)
}

// BlockPublicS3Remediator blocks public access at the AWS account level via S3 Block Public Access.
//
// Finding Type: S3_PUBLIC_ACCESS
// Tier: 1 (Auto-safe - account-level block prevents public access across all buckets)
// Impact: Applies account-level S3 Public Access Block [SEC-003]
// CSPs: AWS
type BlockPublicS3Remediator struct {
	tier   int
	client s3ControlAPI
}

// WithS3ControlClient injects a custom s3control client (used in tests).
func WithS3ControlClient(c s3ControlAPI) func(*BlockPublicS3Remediator) {
	return func(r *BlockPublicS3Remediator) {
		r.client = c
	}
}

// NewBlockPublicS3Remediator creates a new handler for blocking S3 public access.
func NewBlockPublicS3Remediator(opts ...func(*BlockPublicS3Remediator)) *BlockPublicS3Remediator {
	r := &BlockPublicS3Remediator{tier: 1}
	for _, o := range opts {
		o(r)
	}
	return r
}

func (b *BlockPublicS3Remediator) getClient(ctx context.Context, region string) (s3ControlAPI, error) {
	if b.client != nil {
		return b.client, nil
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	return s3control.NewFromConfig(cfg), nil
}

// Tier returns the complexity tier (1 = auto-safe).
func (b *BlockPublicS3Remediator) Tier() int {
	return b.tier
}

// Remediate applies account-level S3 Public Access Block [SEC-003].
func (b *BlockPublicS3Remediator) Remediate(ctx context.Context, finding *findings.PrioritizedFinding) (*remediation.RemediationResult, error) {
	startTime := time.Now()

	result := &remediation.RemediationResult{
		FindingID:  finding.Finding.ID,
		ResourceID: finding.Finding.ResourceID,
		StartedAt:  startTime,
		Actions:    []string{},
	}

	client, err := b.getClient(ctx, finding.Finding.Region)
	if err != nil {
		return nil, err
	}

	accountID := finding.Finding.AccountID

	_, err = client.PutPublicAccessBlock(ctx, &s3control.PutPublicAccessBlockInput{
		AccountId: aws.String(accountID),
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
		return result, fmt.Errorf("failed to put public access block on account %s: %w", accountID, err)
	}

	result.Actions = append(result.Actions,
		fmt.Sprintf("Enabled BlockPublicAcls for account: %s", accountID),
		"Enabled BlockPublicPolicy",
		"Enabled IgnorePublicAcls",
		"Enabled RestrictPublicBuckets",
	)
	result.CompletedAt = time.Now()
	result.Duration = time.Since(startTime).String()
	result.Success = true
	result.Message = fmt.Sprintf("All public access blocked for account: %s", accountID)

	return result, nil
}

// Validate verifies the account-level public access block is enabled.
func (b *BlockPublicS3Remediator) Validate(ctx context.Context, finding *findings.PrioritizedFinding) (*remediation.ValidationResult, error) {
	validation := &remediation.ValidationResult{
		FindingID:   finding.Finding.ID,
		ValidatedAt: time.Now(),
		Evidence:    []string{},
	}

	client, err := b.getClient(ctx, finding.Finding.Region)
	if err != nil {
		return nil, err
	}

	accountID := finding.Finding.AccountID

	output, err := client.GetPublicAccessBlock(ctx, &s3control.GetPublicAccessBlockInput{
		AccountId: aws.String(accountID),
	})
	if err != nil {
		validation.IsCompliant = false
		validation.Message = fmt.Sprintf("Failed to get public access block for account %s: %v", accountID, err)
		return validation, nil
	}

	pab := output.PublicAccessBlockConfiguration
	if pab == nil {
		validation.IsCompliant = false
		validation.Message = fmt.Sprintf("No public access block configured for account %s", accountID)
		return validation, nil
	}
	deref := func(b *bool) bool { return b != nil && *b }
	allBlocked := deref(pab.BlockPublicAcls) && deref(pab.BlockPublicPolicy) &&
		deref(pab.IgnorePublicAcls) && deref(pab.RestrictPublicBuckets)

	if !allBlocked {
		validation.IsCompliant = false
		validation.Message = fmt.Sprintf("Not all public access block settings are enabled for account %s", accountID)
		validation.Evidence = append(validation.Evidence,
			fmt.Sprintf("BlockPublicAcls: %t", deref(pab.BlockPublicAcls)),
			fmt.Sprintf("BlockPublicPolicy: %t", deref(pab.BlockPublicPolicy)),
			fmt.Sprintf("IgnorePublicAcls: %t", deref(pab.IgnorePublicAcls)),
			fmt.Sprintf("RestrictPublicBuckets: %t", deref(pab.RestrictPublicBuckets)),
		)
		return validation, nil
	}

	validation.IsCompliant = true
	validation.Message = fmt.Sprintf("All public access blocked for account: %s", accountID)
	validation.Evidence = append(validation.Evidence, "All 4 public access block settings enabled")

	return validation, nil
}

// DryRun simulates blocking public access without making changes.
func (b *BlockPublicS3Remediator) DryRun(ctx context.Context, finding *findings.PrioritizedFinding) (*remediation.DryRunResult, error) {
	accountID := finding.Finding.AccountID

	return &remediation.DryRunResult{
		FindingID:        finding.Finding.ID,
		WouldSucceed:     true,
		PrerequisitesMet: true,
		PlannedActions: []string{
			fmt.Sprintf("Would enable BlockPublicAcls for account: %s", accountID),
			"Would enable BlockPublicPolicy",
			"Would enable IgnorePublicAcls",
			"Would enable RestrictPublicBuckets",
		},
		EstimatedImpact: fmt.Sprintf("Account %s: all buckets will block public access. static website hosting via S3 will require CloudFront.", accountID),
	}, nil
}
