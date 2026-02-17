// Package storage provides remediation handlers for cloud storage security findings.
package storage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"cloudforge/internal/findings"
	"cloudforge/pkg/remediation"
)

// BlockPublicS3Remediator blocks public access on a specific S3 bucket.
//
// Finding Type: S3_PUBLIC_ACCESS
// Tier: 1 (Auto-safe - blocking public access is always safe for non-static-site buckets)
// Impact: Blocks all public access on the TARGET BUCKET via PutPublicAccessBlock [SEC-003]
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

// Remediate enables the S3 bucket-level public access block [SEC-003].
func (b *BlockPublicS3Remediator) Remediate(ctx context.Context, finding *findings.PrioritizedFinding) (*remediation.RemediationResult, error) {
	startTime := time.Now()

	result := &remediation.RemediationResult{
		FindingID:  finding.Finding.ID,
		ResourceID: finding.Finding.ResourceID,
		StartedAt:  startTime,
		Actions:    []string{},
	}

	bucketName := extractBucketName(finding.Finding.ResourceID)
	if bucketName == "" {
		return nil, fmt.Errorf("could not extract bucket name from resource ID: %s", finding.Finding.ResourceID)
	}

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(finding.Finding.Region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := s3.NewFromConfig(cfg)

	_, err = client.PutPublicAccessBlock(ctx, &s3.PutPublicAccessBlockInput{
		Bucket: aws.String(bucketName),
		PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
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
		return result, fmt.Errorf("failed to put public access block on bucket %s: %w", bucketName, err)
	}

	result.Actions = append(result.Actions,
		fmt.Sprintf("Enabled BlockPublicAcls on bucket: %s", bucketName),
		"Enabled BlockPublicPolicy",
		"Enabled IgnorePublicAcls",
		"Enabled RestrictPublicBuckets",
	)
	result.CompletedAt = time.Now()
	result.Duration = time.Since(startTime).String()
	result.Success = true
	result.Message = fmt.Sprintf("All public access blocked for bucket: %s", bucketName)

	return result, nil
}

// Validate verifies the public access block is enabled on the bucket.
func (b *BlockPublicS3Remediator) Validate(ctx context.Context, finding *findings.PrioritizedFinding) (*remediation.ValidationResult, error) {
	validation := &remediation.ValidationResult{
		FindingID:   finding.Finding.ID,
		ValidatedAt: time.Now(),
		Evidence:    []string{},
	}

	bucketName := extractBucketName(finding.Finding.ResourceID)

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(finding.Finding.Region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := s3.NewFromConfig(cfg)

	output, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		validation.IsCompliant = false
		validation.Message = fmt.Sprintf("Failed to get public access block for bucket %s: %v", bucketName, err)
		return validation, nil
	}

	pab := output.PublicAccessBlockConfiguration
	deref := func(b *bool) bool { return b != nil && *b }
	allBlocked := deref(pab.BlockPublicAcls) && deref(pab.BlockPublicPolicy) &&
		deref(pab.IgnorePublicAcls) && deref(pab.RestrictPublicBuckets)

	if !allBlocked {
		validation.IsCompliant = false
		validation.Message = fmt.Sprintf("Not all public access block settings are enabled for bucket %s", bucketName)
		validation.Evidence = append(validation.Evidence,
			fmt.Sprintf("BlockPublicAcls: %t", deref(pab.BlockPublicAcls)),
			fmt.Sprintf("BlockPublicPolicy: %t", deref(pab.BlockPublicPolicy)),
			fmt.Sprintf("IgnorePublicAcls: %t", deref(pab.IgnorePublicAcls)),
			fmt.Sprintf("RestrictPublicBuckets: %t", deref(pab.RestrictPublicBuckets)),
		)
		return validation, nil
	}

	validation.IsCompliant = true
	validation.Message = fmt.Sprintf("All public access blocked for bucket: %s", bucketName)
	validation.Evidence = append(validation.Evidence, "All 4 public access block settings enabled")

	return validation, nil
}

// DryRun simulates blocking public access without making changes.
func (b *BlockPublicS3Remediator) DryRun(ctx context.Context, finding *findings.PrioritizedFinding) (*remediation.DryRunResult, error) {
	bucketName := extractBucketName(finding.Finding.ResourceID)

	return &remediation.DryRunResult{
		FindingID:        finding.Finding.ID,
		WouldSucceed:     true,
		PrerequisitesMet: true,
		PlannedActions: []string{
			fmt.Sprintf("Would enable BlockPublicAcls on bucket: %s", bucketName),
			"Would enable BlockPublicPolicy",
			"Would enable IgnorePublicAcls",
			"Would enable RestrictPublicBuckets",
		},
		EstimatedImpact: fmt.Sprintf("Bucket %s will no longer be publicly accessible. Static website hosting via S3 will break.", bucketName),
	}, nil
}

// extractBucketName extracts the S3 bucket name from a resource ARN or name.
func extractBucketName(resourceID string) string {
	// Handle ARN format: arn:aws:s3:::bucket-name or arn:aws:s3:::bucket-name/key
	if strings.HasPrefix(resourceID, "arn:") {
		parts := strings.SplitN(resourceID, ":::", 2)
		if len(parts) == 2 {
			bucket := strings.SplitN(parts[1], "/", 2)[0]
			return bucket
		}
	}
	return resourceID
}
