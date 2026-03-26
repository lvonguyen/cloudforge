// Package monitoring provides remediation handlers for monitoring and logging security findings.
package monitoring

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"

	cspmscoring "aegis/internal/cspm/scoring"
	"aegis/pkg/remediation"
)

// cloudtrailAPI defines the CloudTrail operations used by this remediator.
type cloudtrailAPI interface {
	StartLogging(ctx context.Context, params *cloudtrail.StartLoggingInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.StartLoggingOutput, error)
	GetTrailStatus(ctx context.Context, params *cloudtrail.GetTrailStatusInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error)
}

// EnableCloudTrailRemediator re-enables logging on a stopped CloudTrail trail.
//
// Finding Types: CLOUDTRAIL_DISABLED, AWS.CloudTrail.Logging
// Tier: 1 (Auto-safe — enabling logging has no destructive side effects)
// Impact: Resumes API activity logging to S3/CloudWatch
// CSPs: AWS
type EnableCloudTrailRemediator struct {
	tier   int
	client cloudtrailAPI
}

// WithCloudTrailClient injects a custom CloudTrail client (used in tests).
func WithCloudTrailClient(c cloudtrailAPI) func(*EnableCloudTrailRemediator) {
	return func(r *EnableCloudTrailRemediator) {
		r.client = c
	}
}

// NewEnableCloudTrailRemediator creates a new handler for enabling CloudTrail logging.
func NewEnableCloudTrailRemediator(opts ...func(*EnableCloudTrailRemediator)) *EnableCloudTrailRemediator {
	r := &EnableCloudTrailRemediator{tier: 1}
	for _, o := range opts {
		o(r)
	}
	return r
}

func (e *EnableCloudTrailRemediator) getClient(ctx context.Context, region string) (cloudtrailAPI, error) {
	if e.client != nil {
		return e.client, nil
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	return cloudtrail.NewFromConfig(cfg), nil
}

// Tier returns the complexity tier (1 = auto-safe).
func (e *EnableCloudTrailRemediator) Tier() int {
	return e.tier
}

// Remediate starts logging on the CloudTrail trail.
func (e *EnableCloudTrailRemediator) Remediate(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.RemediationResult, error) {
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

	trailARN := finding.Finding.ResourceID
	_, err = client.StartLogging(ctx, &cloudtrail.StartLoggingInput{
		Name: aws.String(trailARN),
	})
	if err != nil {
		result.CompletedAt = time.Now()
		result.Duration = time.Since(startTime).String()
		result.Error = err.Error()
		return result, fmt.Errorf("starting CloudTrail logging on %s: %w", trailARN, err)
	}

	result.Actions = append(result.Actions, fmt.Sprintf("Started logging on CloudTrail trail: %s", extractTrailName(trailARN)))
	result.CompletedAt = time.Now()
	result.Duration = time.Since(startTime).String()
	result.Success = true
	result.Message = fmt.Sprintf("CloudTrail logging enabled: %s", extractTrailName(trailARN))
	return result, nil
}

// Validate verifies that the trail is actively logging.
func (e *EnableCloudTrailRemediator) Validate(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.ValidationResult, error) {
	validation := &remediation.ValidationResult{
		FindingID:   finding.Finding.ID,
		ValidatedAt: time.Now(),
		Evidence:    []string{},
	}

	client, err := e.getClient(ctx, finding.Finding.Region)
	if err != nil {
		return nil, err
	}

	trailARN := finding.Finding.ResourceID
	status, err := client.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{
		Name: aws.String(trailARN),
	})
	if err != nil {
		return nil, fmt.Errorf("getting trail status: %w", err)
	}

	if !aws.ToBool(status.IsLogging) {
		validation.IsCompliant = false
		validation.Message = fmt.Sprintf("CloudTrail trail %s is not logging", extractTrailName(trailARN))
		return validation, nil
	}

	validation.IsCompliant = true
	validation.Message = fmt.Sprintf("CloudTrail trail %s is actively logging", extractTrailName(trailARN))
	validation.Evidence = append(validation.Evidence, "IsLogging: true")
	if status.LatestDeliveryTime != nil {
		validation.Evidence = append(validation.Evidence,
			fmt.Sprintf("LatestDelivery: %s", status.LatestDeliveryTime.Format(time.RFC3339)))
	}
	return validation, nil
}

// DryRun simulates enabling CloudTrail logging without making changes.
func (e *EnableCloudTrailRemediator) DryRun(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.DryRunResult, error) {
	trailARN := finding.Finding.ResourceID
	return &remediation.DryRunResult{
		FindingID:        finding.Finding.ID,
		WouldSucceed:     true,
		PrerequisitesMet: true,
		PlannedActions: []string{
			fmt.Sprintf("Would start logging on CloudTrail trail: %s", extractTrailName(trailARN)),
		},
		EstimatedImpact: "No downtime. API events will resume delivery to configured S3 bucket and CloudWatch log group.",
	}, nil
}

func extractTrailName(arnOrName string) string {
	if strings.Contains(arnOrName, "/") {
		parts := strings.Split(arnOrName, "/")
		return parts[len(parts)-1]
	}
	return arnOrName
}
