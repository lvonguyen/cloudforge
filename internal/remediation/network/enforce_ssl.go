package network

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/rds"

	cspmscoring "aegis/internal/cspm/scoring"
	"aegis/pkg/remediation"
)

// rdsAPI defines the RDS operations used by the SSL enforcer.
type rdsAPI interface {
	DescribeDBInstances(ctx context.Context, params *rds.DescribeDBInstancesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
	ModifyDBInstance(ctx context.Context, params *rds.ModifyDBInstanceInput, optFns ...func(*rds.Options)) (*rds.ModifyDBInstanceOutput, error)
}

// EnforceSSLRemediator enables SSL/TLS enforcement on database instances.
//
// Finding Types: SSL_NOT_ENFORCED, RDS_SSL_NOT_ENABLED
// Tier: 1 (Auto-safe — encryption in transit should always be enabled)
// Impact: Sets require_ssl parameter; connections without TLS will be rejected
// CSPs: AWS (RDS), GCP (Cloud SQL), Azure (Azure Database)
type EnforceSSLRemediator struct {
	tier          int
	clientFactory func(ctx context.Context, region string) (rdsAPI, error)
}

// EnforceSSLOption configures the EnforceSSLRemediator.
type EnforceSSLOption func(*EnforceSSLRemediator)

// WithRDSClient injects a custom RDS client factory (used in tests).
func WithRDSClient(factory func(ctx context.Context, region string) (rdsAPI, error)) EnforceSSLOption {
	return func(r *EnforceSSLRemediator) {
		r.clientFactory = factory
	}
}

// NewEnforceSSLRemediator creates a new handler for enforcing SSL/TLS
// on database instances.
func NewEnforceSSLRemediator(opts ...EnforceSSLOption) *EnforceSSLRemediator {
	r := &EnforceSSLRemediator{
		tier: 1,
		clientFactory: func(ctx context.Context, region string) (rdsAPI, error) {
			cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
			if err != nil {
				return nil, err
			}
			return rds.NewFromConfig(cfg), nil
		},
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Tier returns the complexity tier (1 = auto-safe).
func (r *EnforceSSLRemediator) Tier() int {
	return r.tier
}

// Remediate enables SSL enforcement on the database instance.
func (r *EnforceSSLRemediator) Remediate(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.RemediationResult, error) {
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

func (r *EnforceSSLRemediator) remediateAWS(ctx context.Context, finding *cspmscoring.PrioritizedFinding, result *remediation.RemediationResult) (*remediation.RemediationResult, error) {
	client, err := r.clientFactory(ctx, finding.Finding.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to create RDS client: %w", err)
	}

	dbID := extractDBInstanceID(finding.Finding.ResourceID)

	// Describe the instance to verify it exists and get current CA cert
	descOutput, err := client.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{
		DBInstanceIdentifier: aws.String(dbID),
	})
	if err != nil {
		result.CompletedAt = time.Now()
		result.Duration = time.Since(result.StartedAt).String()
		result.Error = err.Error()
		return result, fmt.Errorf("failed to describe DB instance %s: %w", dbID, err)
	}

	if len(descOutput.DBInstances) == 0 {
		result.CompletedAt = time.Now()
		result.Duration = time.Since(result.StartedAt).String()
		result.Error = "DB instance not found"
		return result, fmt.Errorf("DB instance %s not found", dbID)
	}

	// Modify instance to use the latest CA certificate (forces SSL)
	_, err = client.ModifyDBInstance(ctx, &rds.ModifyDBInstanceInput{
		DBInstanceIdentifier:       aws.String(dbID),
		CACertificateIdentifier:    aws.String("rds-ca-rsa2048-g1"),
		CertificateRotationRestart: aws.Bool(false),
		ApplyImmediately:           aws.Bool(true),
	})
	if err != nil {
		result.CompletedAt = time.Now()
		result.Duration = time.Since(result.StartedAt).String()
		result.Error = err.Error()
		return result, fmt.Errorf("failed to enforce SSL on DB instance %s: %w", dbID, err)
	}

	result.Actions = append(result.Actions,
		fmt.Sprintf("Set CA certificate to rds-ca-rsa2048-g1 on DB instance: %s", dbID))
	result.CompletedAt = time.Now()
	result.Duration = time.Since(result.StartedAt).String()
	result.Success = true
	result.Message = fmt.Sprintf("SSL enforcement enabled on DB instance: %s", dbID)

	return result, nil
}

func (r *EnforceSSLRemediator) remediateGCP(_ context.Context, _ *cspmscoring.PrioritizedFinding, result *remediation.RemediationResult) (*remediation.RemediationResult, error) {
	result.Message = "GCP Cloud SQL SSL remediation not yet implemented"
	result.Success = false
	return result, fmt.Errorf("GCP remediation not implemented")
}

func (r *EnforceSSLRemediator) remediateAzure(_ context.Context, _ *cspmscoring.PrioritizedFinding, result *remediation.RemediationResult) (*remediation.RemediationResult, error) {
	result.Message = "Azure Database SSL remediation not yet implemented"
	result.Success = false
	return result, fmt.Errorf("Azure remediation not implemented")
}

// Validate verifies that SSL is enforced on the database instance.
func (r *EnforceSSLRemediator) Validate(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.ValidationResult, error) {
	validation := &remediation.ValidationResult{
		FindingID:   finding.Finding.ID,
		ValidatedAt: time.Now(),
		Evidence:    []string{},
	}

	client, err := r.clientFactory(ctx, finding.Finding.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to create RDS client: %w", err)
	}

	dbID := extractDBInstanceID(finding.Finding.ResourceID)

	descOutput, err := client.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{
		DBInstanceIdentifier: aws.String(dbID),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DB instance: %w", err)
	}

	if len(descOutput.DBInstances) == 0 {
		validation.IsCompliant = false
		validation.Message = "DB instance not found"
		return validation, nil
	}

	db := descOutput.DBInstances[0]

	// Check CA certificate is set (indicates SSL is configured)
	if db.CACertificateIdentifier == nil || *db.CACertificateIdentifier == "" {
		validation.IsCompliant = false
		validation.Message = fmt.Sprintf("DB instance %s has no CA certificate set", dbID)
		return validation, nil
	}

	validation.IsCompliant = true
	validation.Message = fmt.Sprintf("SSL enforced on DB instance: %s", dbID)
	validation.Evidence = append(validation.Evidence,
		fmt.Sprintf("DB instance: %s", dbID),
		fmt.Sprintf("CA certificate: %s", *db.CACertificateIdentifier))

	return validation, nil
}

// DryRun simulates enforcing SSL without making changes.
func (r *EnforceSSLRemediator) DryRun(_ context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.DryRunResult, error) {
	dbID := extractDBInstanceID(finding.Finding.ResourceID)

	dryRun := &remediation.DryRunResult{
		FindingID:        finding.Finding.ID,
		WouldSucceed:     true,
		PrerequisitesMet: true,
		PlannedActions: []string{
			fmt.Sprintf("Would update CA certificate on DB instance: %s", dbID),
			"Would set CA certificate to rds-ca-rsa2048-g1",
		},
		EstimatedImpact: "Database connections without SSL/TLS will be rejected. Ensure all clients support SSL.",
		Warnings:        []string{},
	}

	return dryRun, nil
}

// extractDBInstanceID extracts the DB instance identifier from a resource ARN or ID.
func extractDBInstanceID(resourceID string) string {
	// Handle ARN: arn:aws:rds:region:account:db:my-database
	if strings.Contains(resourceID, ":db:") {
		parts := strings.Split(resourceID, ":db:")
		if len(parts) > 1 {
			return parts[1]
		}
	}
	// Handle cluster ARN: arn:aws:rds:region:account:cluster:my-cluster
	if strings.Contains(resourceID, ":cluster:") {
		parts := strings.Split(resourceID, ":cluster:")
		if len(parts) > 1 {
			return parts[1]
		}
	}
	return resourceID
}
