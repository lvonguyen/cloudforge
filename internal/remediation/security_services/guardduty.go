// Package security_services provides remediation handlers for cloud security services.
package security_services

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/guardduty/types"

	"cloudforge/internal/findings"
	"cloudforge/pkg/remediation"
)

// GuardDutyRemediator enables Amazon GuardDuty threat detection.
//
// Finding Type: GuardDuty.1
// Tier: 1 (Auto-safe - simple enable operation, no data loss risk)
// Impact: Enables threat detection, incurs GuardDuty costs (~$4.60/month per account base)
// CSPs: AWS
type GuardDutyRemediator struct {
	tier int
}

// NewGuardDutyRemediator creates a new GuardDuty remediation handler.
func NewGuardDutyRemediator() *GuardDutyRemediator {
	return &GuardDutyRemediator{tier: 1}
}

// Tier returns the complexity tier (1 = auto-safe).
func (g *GuardDutyRemediator) Tier() int {
	return g.tier
}

// Remediate enables GuardDuty in the specified region.
func (g *GuardDutyRemediator) Remediate(ctx context.Context, finding *findings.PrioritizedFinding) (*remediation.RemediationResult, error) {
	startTime := time.Now()

	result := &remediation.RemediationResult{
		FindingID:  finding.Finding.ID,
		ResourceID: finding.Finding.ResourceID,
		StartedAt:  startTime,
		Actions:    []string{},
	}

	// Load AWS config for the finding's region
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(finding.Finding.Region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := guardduty.NewFromConfig(cfg)

	// Enable GuardDuty
	output, err := client.CreateDetector(ctx, &guardduty.CreateDetectorInput{
		Enable: aws.Bool(true),
		FindingPublishingFrequency: types.FindingPublishingFrequencyFifteenMinutes,
		DataSources: &types.DataSourceConfigurations{
			S3Logs: &types.S3LogsConfiguration{
				Enable: aws.Bool(true), // Enable S3 protection
			},
			Kubernetes: &types.KubernetesConfiguration{
				AuditLogs: &types.KubernetesAuditLogsConfiguration{
					Enable: aws.Bool(true), // Enable EKS protection
				},
			},
		},
	})

	if err != nil {
		result.CompletedAt = time.Now()
		result.Duration = time.Since(startTime).String()
		result.Error = err.Error()
		return result, fmt.Errorf("failed to create GuardDuty detector: %w", err)
	}

	result.Actions = append(result.Actions, fmt.Sprintf("Enabled GuardDuty detector: %s", *output.DetectorId))
	result.Actions = append(result.Actions, "Enabled S3 threat detection")
	result.Actions = append(result.Actions, "Enabled EKS audit log monitoring")
	result.Actions = append(result.Actions, "Set finding publishing frequency to 15 minutes")

	result.CompletedAt = time.Now()
	result.Duration = time.Since(startTime).String()
	result.Success = true
	result.Message = fmt.Sprintf("GuardDuty enabled successfully in %s", finding.Finding.Region)

	return result, nil
}

// Validate verifies GuardDuty is enabled and active.
func (g *GuardDutyRemediator) Validate(ctx context.Context, finding *findings.PrioritizedFinding) (*remediation.ValidationResult, error) {
	validation := &remediation.ValidationResult{
		FindingID:   finding.Finding.ID,
		ValidatedAt: time.Now(),
		Evidence:    []string{},
	}

	// Load AWS config
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(finding.Finding.Region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := guardduty.NewFromConfig(cfg)

	// List detectors
	listOutput, err := client.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list GuardDuty detectors: %w", err)
	}

	if len(listOutput.DetectorIds) == 0 {
		validation.IsCompliant = false
		validation.Message = "No GuardDuty detectors found - remediation may have failed"
		return validation, nil
	}

	// Get detector details
	detectorID := listOutput.DetectorIds[0]
	getOutput, err := client.GetDetector(ctx, &guardduty.GetDetectorInput{
		DetectorId: aws.String(detectorID),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get GuardDuty detector details: %w", err)
	}

	// Check if detector is enabled
	if getOutput.Status != types.DetectorStatusEnabled {
		validation.IsCompliant = false
		validation.Message = fmt.Sprintf("GuardDuty detector exists but status is: %s", getOutput.Status)
		return validation, nil
	}

	validation.IsCompliant = true
	validation.Message = fmt.Sprintf("GuardDuty is enabled (detector: %s, status: %s)", detectorID, getOutput.Status)
	validation.Evidence = append(validation.Evidence, fmt.Sprintf("Detector ID: %s", detectorID))
	validation.Evidence = append(validation.Evidence, fmt.Sprintf("Status: %s", getOutput.Status))
	validation.Evidence = append(validation.Evidence, fmt.Sprintf("Finding publishing frequency: %s", getOutput.FindingPublishingFrequency))

	return validation, nil
}

// DryRun simulates enabling GuardDuty without making changes.
func (g *GuardDutyRemediator) DryRun(ctx context.Context, finding *findings.PrioritizedFinding) (*remediation.DryRunResult, error) {
	dryRun := &remediation.DryRunResult{
		FindingID:       finding.Finding.ID,
		WouldSucceed:    true,
		PrerequisitesMet: true,
		PlannedActions: []string{
			fmt.Sprintf("Would enable GuardDuty in region: %s", finding.Finding.Region),
			"Would enable S3 threat detection",
			"Would enable EKS audit log monitoring",
			"Would set finding publishing frequency to 15 minutes",
		},
		EstimatedImpact: "Cost: ~$4.60/month base + $1/GB CloudTrail analysis. No service disruption.",
	}

	// Load AWS config to verify credentials
	_, err := config.LoadDefaultConfig(ctx, config.WithRegion(finding.Finding.Region))
	if err != nil {
		dryRun.WouldSucceed = false
		dryRun.PrerequisitesMet = false
		dryRun.Warnings = append(dryRun.Warnings, fmt.Sprintf("AWS credentials not valid: %v", err))
		return dryRun, nil
	}

	// Check if already enabled (optional pre-check)
	client := guardduty.NewFromConfig(config.Config{Region: finding.Finding.Region})
	listOutput, err := client.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
	if err == nil && len(listOutput.DetectorIds) > 0 {
		dryRun.Warnings = append(dryRun.Warnings, "GuardDuty may already be enabled in this region")
	}

	return dryRun, nil
}
