// Package config provides remediation handlers for cloud configuration findings.
package config

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	configtypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"

	cspmscoring "aegis/internal/cspm/scoring"
	"aegis/pkg/remediation"
)

// configServiceAPI defines the AWS Config operations used by this remediator.
type configServiceAPI interface {
	DescribeConfigurationRecorders(ctx context.Context, params *configservice.DescribeConfigurationRecordersInput, optFns ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecordersOutput, error)
	PutConfigurationRecorder(ctx context.Context, params *configservice.PutConfigurationRecorderInput, optFns ...func(*configservice.Options)) (*configservice.PutConfigurationRecorderOutput, error)
	PutDeliveryChannel(ctx context.Context, params *configservice.PutDeliveryChannelInput, optFns ...func(*configservice.Options)) (*configservice.PutDeliveryChannelOutput, error)
	StartConfigurationRecorder(ctx context.Context, params *configservice.StartConfigurationRecorderInput, optFns ...func(*configservice.Options)) (*configservice.StartConfigurationRecorderOutput, error)
}

// EnableAWSConfigRemediator enables AWS Config recording in accounts where
// it is not active.
//
// Finding Types: Config.1, AWS_CONFIG_NOT_ENABLED
// Tier: 2 (Requires verification — creates resources: recorder + delivery channel)
// Impact: Creates Config recorder and delivery channel; incurs AWS Config charges
// CSPs: AWS only
type EnableAWSConfigRemediator struct {
	tier          int
	recorderName  string
	s3BucketName  string
	roleARN       string
	clientFactory func(ctx context.Context, region string) (configServiceAPI, error)
}

// EnableAWSConfigOption configures the EnableAWSConfigRemediator.
type EnableAWSConfigOption func(*EnableAWSConfigRemediator)

// WithConfigClient injects a custom Config client factory (used in tests).
func WithConfigClient(factory func(ctx context.Context, region string) (configServiceAPI, error)) EnableAWSConfigOption {
	return func(r *EnableAWSConfigRemediator) {
		r.clientFactory = factory
	}
}

// WithS3Bucket sets the S3 bucket for the delivery channel.
func WithS3Bucket(bucket string) EnableAWSConfigOption {
	return func(r *EnableAWSConfigRemediator) {
		r.s3BucketName = bucket
	}
}

// WithRoleARN sets the IAM role ARN for the configuration recorder.
func WithRoleARN(arn string) EnableAWSConfigOption {
	return func(r *EnableAWSConfigRemediator) {
		r.roleARN = arn
	}
}

// NewEnableAWSConfigRemediator creates a new handler for enabling AWS Config.
func NewEnableAWSConfigRemediator(opts ...EnableAWSConfigOption) *EnableAWSConfigRemediator {
	r := &EnableAWSConfigRemediator{
		tier:         2,
		recorderName: "default",
		clientFactory: func(ctx context.Context, region string) (configServiceAPI, error) {
			cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
			if err != nil {
				return nil, err
			}
			return configservice.NewFromConfig(cfg), nil
		},
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Tier returns the complexity tier (2 = requires verification).
func (r *EnableAWSConfigRemediator) Tier() int {
	return r.tier
}

// Remediate enables AWS Config recording.
func (r *EnableAWSConfigRemediator) Remediate(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.RemediationResult, error) {
	startTime := time.Now()

	result := &remediation.RemediationResult{
		FindingID:  finding.Finding.ID,
		ResourceID: finding.Finding.ResourceID,
		StartedAt:  startTime,
		Actions:    []string{},
	}

	switch {
	case strings.Contains(finding.Finding.Source, "aws"):
		return r.remediateAWS(ctx, finding, result)
	case strings.Contains(finding.Finding.Source, "gcp"):
		return r.remediateGCP(ctx, finding, result)
	case strings.Contains(finding.Finding.Source, "azure"):
		return r.remediateAzure(ctx, finding, result)
	default:
		result.Error = fmt.Sprintf("Unsupported CSP: %s", finding.Finding.Source)
		return result, fmt.Errorf("unsupported CSP: %s", finding.Finding.Source)
	}
}

func (r *EnableAWSConfigRemediator) remediateAWS(ctx context.Context, finding *cspmscoring.PrioritizedFinding, result *remediation.RemediationResult) (*remediation.RemediationResult, error) {
	client, err := r.clientFactory(ctx, finding.Finding.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to create Config client: %w", err)
	}

	// Check if recorder already exists
	descOutput, err := client.DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{})
	if err != nil {
		result.CompletedAt = time.Now()
		result.Duration = time.Since(result.StartedAt).String()
		result.Error = err.Error()
		return result, fmt.Errorf("failed to describe configuration recorders: %w", err)
	}

	recorderExists := false
	for _, rec := range descOutput.ConfigurationRecorders {
		if rec.Name != nil && *rec.Name == r.recorderName {
			recorderExists = true
			break
		}
	}

	if !recorderExists {
		// Create configuration recorder
		_, err = client.PutConfigurationRecorder(ctx, &configservice.PutConfigurationRecorderInput{
			ConfigurationRecorder: &configtypes.ConfigurationRecorder{
				Name:    aws.String(r.recorderName),
				RoleARN: aws.String(r.roleARN),
				RecordingGroup: &configtypes.RecordingGroup{
					AllSupported: true,
				},
			},
		})
		if err != nil {
			result.CompletedAt = time.Now()
			result.Duration = time.Since(result.StartedAt).String()
			result.Error = err.Error()
			return result, fmt.Errorf("failed to create configuration recorder: %w", err)
		}
		result.Actions = append(result.Actions, fmt.Sprintf("Created configuration recorder: %s", r.recorderName))
	}

	// Create delivery channel
	if r.s3BucketName != "" {
		_, err = client.PutDeliveryChannel(ctx, &configservice.PutDeliveryChannelInput{
			DeliveryChannel: &configtypes.DeliveryChannel{
				Name:         aws.String(r.recorderName),
				S3BucketName: aws.String(r.s3BucketName),
			},
		})
		if err != nil {
			result.CompletedAt = time.Now()
			result.Duration = time.Since(result.StartedAt).String()
			result.Error = err.Error()
			return result, fmt.Errorf("failed to create delivery channel: %w", err)
		}
		result.Actions = append(result.Actions, fmt.Sprintf("Created delivery channel with S3 bucket: %s", r.s3BucketName))
	}

	// Start recording
	_, err = client.StartConfigurationRecorder(ctx, &configservice.StartConfigurationRecorderInput{
		ConfigurationRecorderName: aws.String(r.recorderName),
	})
	if err != nil {
		result.CompletedAt = time.Now()
		result.Duration = time.Since(result.StartedAt).String()
		result.Error = err.Error()
		return result, fmt.Errorf("failed to start configuration recorder: %w", err)
	}
	result.Actions = append(result.Actions, fmt.Sprintf("Started configuration recorder: %s", r.recorderName))

	result.CompletedAt = time.Now()
	result.Duration = time.Since(result.StartedAt).String()
	result.Success = true
	result.Message = fmt.Sprintf("AWS Config recording enabled in %s", finding.Finding.Region)

	return result, nil
}

func (r *EnableAWSConfigRemediator) remediateGCP(_ context.Context, _ *cspmscoring.PrioritizedFinding, result *remediation.RemediationResult) (*remediation.RemediationResult, error) {
	result.Message = "GCP Config remediation not applicable (use Cloud Asset Inventory)"
	result.Success = false
	return result, fmt.Errorf("GCP remediation not implemented")
}

func (r *EnableAWSConfigRemediator) remediateAzure(_ context.Context, _ *cspmscoring.PrioritizedFinding, result *remediation.RemediationResult) (*remediation.RemediationResult, error) {
	result.Message = "Azure Config remediation not applicable (use Azure Policy)"
	result.Success = false
	return result, fmt.Errorf("Azure remediation not implemented")
}

// Validate verifies that AWS Config recording is active.
func (r *EnableAWSConfigRemediator) Validate(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.ValidationResult, error) {
	validation := &remediation.ValidationResult{
		FindingID:   finding.Finding.ID,
		ValidatedAt: time.Now(),
		Evidence:    []string{},
	}

	client, err := r.clientFactory(ctx, finding.Finding.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to create Config client: %w", err)
	}

	descOutput, err := client.DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe configuration recorders: %w", err)
	}

	if len(descOutput.ConfigurationRecorders) == 0 {
		validation.IsCompliant = false
		validation.Message = "No configuration recorders found"
		return validation, nil
	}

	validation.IsCompliant = true
	validation.Message = fmt.Sprintf("AWS Config recorder active in %s", finding.Finding.Region)
	for _, rec := range descOutput.ConfigurationRecorders {
		if rec.Name != nil {
			validation.Evidence = append(validation.Evidence, fmt.Sprintf("Recorder: %s", *rec.Name))
		}
	}

	return validation, nil
}

// DryRun simulates enabling AWS Config without making changes.
func (r *EnableAWSConfigRemediator) DryRun(_ context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.DryRunResult, error) {
	dryRun := &remediation.DryRunResult{
		FindingID:        finding.Finding.ID,
		WouldSucceed:     true,
		PrerequisitesMet: r.roleARN != "" && r.s3BucketName != "",
		PlannedActions: []string{
			fmt.Sprintf("Would create configuration recorder '%s' in %s", r.recorderName, finding.Finding.Region),
			fmt.Sprintf("Would create delivery channel with S3 bucket: %s", r.s3BucketName),
			"Would start configuration recording",
		},
		EstimatedImpact: "AWS Config will begin recording resource configurations. Standard AWS Config pricing applies.",
		Warnings: []string{
			"Requires IAM role with config:* permissions",
			"S3 bucket must exist and allow Config delivery",
		},
	}

	if r.roleARN == "" {
		dryRun.Warnings = append(dryRun.Warnings, "WARNING: No IAM role ARN configured — recorder creation will fail")
	}
	if r.s3BucketName == "" {
		dryRun.Warnings = append(dryRun.Warnings, "WARNING: No S3 bucket configured — delivery channel will not be created")
	}

	return dryRun, nil
}
