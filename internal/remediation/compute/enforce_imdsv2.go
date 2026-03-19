// Package compute provides remediation handlers for compute security findings.
package compute

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	cspmscoring "aegis/internal/cspm/scoring"
	"aegis/pkg/remediation"
)

// ec2MetadataAPI defines the EC2 operations used by this remediator.
type ec2MetadataAPI interface {
	ModifyInstanceMetadataOptions(ctx context.Context, params *ec2.ModifyInstanceMetadataOptionsInput, optFns ...func(*ec2.Options)) (*ec2.ModifyInstanceMetadataOptionsOutput, error)
	DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
}

// EnforceIMDSv2Remediator enforces IMDSv2 (Instance Metadata Service v2) on EC2 instances.
//
// Finding Type: EC2_IMDSV1_ENABLED
// Tier: 1 (Auto-safe - IMDSv2 is backwards compatible with SDKs using session tokens)
// Impact: Requires all metadata requests to use session tokens, mitigates SSRF attacks
// CSPs: AWS
type EnforceIMDSv2Remediator struct {
	tier   int
	client ec2MetadataAPI
}

// WithEC2MetadataClient injects a custom EC2 client (used in tests).
func WithEC2MetadataClient(c ec2MetadataAPI) func(*EnforceIMDSv2Remediator) {
	return func(r *EnforceIMDSv2Remediator) {
		r.client = c
	}
}

// NewEnforceIMDSv2Remediator creates a new handler for enforcing IMDSv2.
func NewEnforceIMDSv2Remediator(opts ...func(*EnforceIMDSv2Remediator)) *EnforceIMDSv2Remediator {
	r := &EnforceIMDSv2Remediator{tier: 1}
	for _, o := range opts {
		o(r)
	}
	return r
}

func (e *EnforceIMDSv2Remediator) getClient(ctx context.Context, region string) (ec2MetadataAPI, error) {
	if e.client != nil {
		return e.client, nil
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	return ec2.NewFromConfig(cfg), nil
}

// Tier returns the complexity tier (1 = auto-safe).
func (e *EnforceIMDSv2Remediator) Tier() int {
	return e.tier
}

// Remediate sets HttpTokens=required on the EC2 instance to enforce IMDSv2.
func (e *EnforceIMDSv2Remediator) Remediate(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.RemediationResult, error) {
	startTime := time.Now()

	result := &remediation.RemediationResult{
		FindingID:  finding.Finding.ID,
		ResourceID: finding.Finding.ResourceID,
		StartedAt:  startTime,
		Actions:    []string{},
	}

	client, err := e.getClient(ctx, finding.Finding.Region)
	if err != nil {
		return nil, err
	}

	instanceID := extractInstanceID(finding.Finding.ResourceID)

	_, err = client.ModifyInstanceMetadataOptions(ctx, &ec2.ModifyInstanceMetadataOptionsInput{
		InstanceId: aws.String(instanceID),
		HttpTokens: ec2types.HttpTokensStateRequired,
	})
	if err != nil {
		result.CompletedAt = time.Now()
		result.Duration = time.Since(startTime).String()
		result.Error = err.Error()
		return result, fmt.Errorf("failed to modify instance metadata options: %w", err)
	}

	result.Actions = append(result.Actions,
		fmt.Sprintf("Set HttpTokens=required on instance: %s", instanceID),
		"IMDSv1 requests will now be rejected",
	)
	result.CompletedAt = time.Now()
	result.Duration = time.Since(startTime).String()
	result.Success = true
	result.Message = fmt.Sprintf("IMDSv2 enforced on instance: %s", instanceID)

	return result, nil
}

// Validate verifies IMDSv2 is enforced on the instance.
func (e *EnforceIMDSv2Remediator) Validate(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.ValidationResult, error) {
	validation := &remediation.ValidationResult{
		FindingID:   finding.Finding.ID,
		ValidatedAt: time.Now(),
		Evidence:    []string{},
	}

	client, err := e.getClient(ctx, finding.Finding.Region)
	if err != nil {
		return nil, err
	}

	instanceID := extractInstanceID(finding.Finding.ResourceID)

	output, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe instance: %w", err)
	}

	if len(output.Reservations) == 0 || len(output.Reservations[0].Instances) == 0 {
		validation.IsCompliant = false
		validation.Message = "Instance not found"
		return validation, nil
	}

	instance := output.Reservations[0].Instances[0]

	if instance.MetadataOptions == nil ||
		instance.MetadataOptions.HttpTokens != ec2types.HttpTokensStateRequired {
		validation.IsCompliant = false
		validation.Message = fmt.Sprintf("IMDSv2 not enforced on instance: %s", instanceID)
		return validation, nil
	}

	validation.IsCompliant = true
	validation.Message = fmt.Sprintf("IMDSv2 enforced on instance: %s (HttpTokens=required)", instanceID)
	validation.Evidence = append(validation.Evidence,
		fmt.Sprintf("Instance: %s", instanceID),
		fmt.Sprintf("HttpTokens: %s", instance.MetadataOptions.HttpTokens),
	)

	return validation, nil
}

// DryRun simulates enforcing IMDSv2 without making changes.
func (e *EnforceIMDSv2Remediator) DryRun(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.DryRunResult, error) {
	instanceID := extractInstanceID(finding.Finding.ResourceID)

	return &remediation.DryRunResult{
		FindingID:        finding.Finding.ID,
		WouldSucceed:     true,
		PrerequisitesMet: true,
		PlannedActions: []string{
			fmt.Sprintf("Would set HttpTokens=required on instance: %s", instanceID),
			"Would reject all IMDSv1 (non-token) metadata requests",
		},
		EstimatedImpact: "No downtime. Applications using AWS SDK v2+ are compatible. Legacy IMDSv1 calls will fail.",
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
