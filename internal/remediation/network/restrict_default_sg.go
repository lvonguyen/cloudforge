package network

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"

	cspmscoring "aegis/internal/cspm/scoring"
	"aegis/pkg/remediation"
)

// defaultSGAPI defines the EC2 operations used by the default SG remediator.
type defaultSGAPI interface {
	DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	RevokeSecurityGroupIngress(ctx context.Context, params *ec2.RevokeSecurityGroupIngressInput, optFns ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupIngressOutput, error)
	RevokeSecurityGroupEgress(ctx context.Context, params *ec2.RevokeSecurityGroupEgressInput, optFns ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupEgressOutput, error)
}

// RestrictDefaultSGRemediator removes all ingress and egress rules from
// the VPC default security group. The default SG should never be used;
// all resources should use purpose-built security groups.
//
// Finding Types: EC2.2, CIS 4.3, VPC_DEFAULT_SG_ALLOWS_TRAFFIC
// Tier: 1 (Auto-safe — default SG should have no rules)
// Impact: Removes all ingress/egress rules from default SG
// CSPs: AWS (EC2), GCP (Compute Engine), Azure (NSG)
type RestrictDefaultSGRemediator struct {
	tier   int
	client defaultSGAPI
}

// WithDefaultSGClient injects a custom EC2 client (used in tests).
func WithDefaultSGClient(c defaultSGAPI) func(*RestrictDefaultSGRemediator) {
	return func(r *RestrictDefaultSGRemediator) {
		r.client = c
	}
}

// NewRestrictDefaultSGRemediator creates a new handler for restricting VPC
// default security groups.
func NewRestrictDefaultSGRemediator(opts ...func(*RestrictDefaultSGRemediator)) *RestrictDefaultSGRemediator {
	r := &RestrictDefaultSGRemediator{tier: 1}
	for _, o := range opts {
		o(r)
	}
	return r
}

func (b *RestrictDefaultSGRemediator) getClient(ctx context.Context, region string) (defaultSGAPI, error) {
	if b.client != nil {
		return b.client, nil
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	return ec2.NewFromConfig(cfg), nil
}

// Tier returns the complexity tier (1 = auto-safe).
func (b *RestrictDefaultSGRemediator) Tier() int {
	return b.tier
}

// Remediate removes all ingress and egress rules from the default security group.
func (b *RestrictDefaultSGRemediator) Remediate(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.RemediationResult, error) {
	startTime := time.Now()

	result := &remediation.RemediationResult{
		FindingID:  finding.Finding.ID,
		ResourceID: finding.Finding.ResourceID,
		StartedAt:  startTime,
		Actions:    []string{},
	}

	switch {
	case strings.Contains(finding.Finding.Source, "aws"):
		return b.remediateAWS(ctx, finding, result)
	case strings.Contains(finding.Finding.Source, "gcp"):
		return b.remediateGCP(ctx, finding, result)
	case strings.Contains(finding.Finding.Source, "azure"):
		return b.remediateAzure(ctx, finding, result)
	default:
		result.Error = fmt.Sprintf("Unsupported CSP: %s", finding.Finding.Source)
		return result, fmt.Errorf("unsupported CSP: %s", finding.Finding.Source)
	}
}

func (b *RestrictDefaultSGRemediator) remediateAWS(ctx context.Context, finding *cspmscoring.PrioritizedFinding, result *remediation.RemediationResult) (*remediation.RemediationResult, error) {
	client, err := b.getClient(ctx, finding.Finding.Region)
	if err != nil {
		return nil, err
	}

	sgID := extractSGID(finding.Finding.ResourceID)

	// Describe the SG to get current rules
	descOutput, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		GroupIds: []string{sgID},
	})
	if err != nil {
		result.CompletedAt = time.Now()
		result.Duration = time.Since(result.StartedAt).String()
		result.Error = err.Error()
		return result, fmt.Errorf("failed to describe default security group: %w", err)
	}

	if len(descOutput.SecurityGroups) == 0 {
		result.CompletedAt = time.Now()
		result.Duration = time.Since(result.StartedAt).String()
		result.Error = "security group not found"
		return result, fmt.Errorf("security group %s not found", sgID)
	}

	sg := descOutput.SecurityGroups[0]

	// Revoke all ingress rules
	if len(sg.IpPermissions) > 0 {
		_, err = client.RevokeSecurityGroupIngress(ctx, &ec2.RevokeSecurityGroupIngressInput{
			GroupId:       aws.String(sgID),
			IpPermissions: sg.IpPermissions,
		})
		if err != nil {
			result.CompletedAt = time.Now()
			result.Duration = time.Since(result.StartedAt).String()
			result.Error = err.Error()
			return result, fmt.Errorf("failed to revoke ingress rules: %w", err)
		}
		result.Actions = append(result.Actions, fmt.Sprintf("Revoked %d ingress rule(s) from default SG: %s", len(sg.IpPermissions), sgID))
	}

	// Revoke all egress rules
	if len(sg.IpPermissionsEgress) > 0 {
		_, err = client.RevokeSecurityGroupEgress(ctx, &ec2.RevokeSecurityGroupEgressInput{
			GroupId:       aws.String(sgID),
			IpPermissions: sg.IpPermissionsEgress,
		})
		if err != nil {
			result.CompletedAt = time.Now()
			result.Duration = time.Since(result.StartedAt).String()
			result.Error = err.Error()
			return result, fmt.Errorf("failed to revoke egress rules: %w", err)
		}
		result.Actions = append(result.Actions, fmt.Sprintf("Revoked %d egress rule(s) from default SG: %s", len(sg.IpPermissionsEgress), sgID))
	}

	result.CompletedAt = time.Now()
	result.Duration = time.Since(result.StartedAt).String()
	result.Success = true
	result.Message = fmt.Sprintf("Restricted default security group: %s (all rules removed)", sgID)

	return result, nil
}

func (b *RestrictDefaultSGRemediator) remediateGCP(_ context.Context, _ *cspmscoring.PrioritizedFinding, result *remediation.RemediationResult) (*remediation.RemediationResult, error) {
	result.Message = "GCP default SG remediation not yet implemented"
	result.Success = false
	return result, fmt.Errorf("GCP remediation not implemented")
}

func (b *RestrictDefaultSGRemediator) remediateAzure(_ context.Context, _ *cspmscoring.PrioritizedFinding, result *remediation.RemediationResult) (*remediation.RemediationResult, error) {
	result.Message = "Azure default NSG remediation not yet implemented"
	result.Success = false
	return result, fmt.Errorf("Azure remediation not implemented")
}

// Validate verifies the default SG has no ingress or egress rules.
func (b *RestrictDefaultSGRemediator) Validate(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.ValidationResult, error) {
	validation := &remediation.ValidationResult{
		FindingID:   finding.Finding.ID,
		ValidatedAt: time.Now(),
		Evidence:    []string{},
	}

	client, err := b.getClient(ctx, finding.Finding.Region)
	if err != nil {
		return nil, err
	}

	sgID := extractSGID(finding.Finding.ResourceID)

	output, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		GroupIds: []string{sgID},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe security group: %w", err)
	}

	if len(output.SecurityGroups) == 0 {
		validation.IsCompliant = false
		validation.Message = "Security group not found"
		return validation, nil
	}

	sg := output.SecurityGroups[0]

	if len(sg.IpPermissions) > 0 || len(sg.IpPermissionsEgress) > 0 {
		validation.IsCompliant = false
		validation.Message = fmt.Sprintf("Default SG %s still has %d ingress and %d egress rule(s)",
			sgID, len(sg.IpPermissions), len(sg.IpPermissionsEgress))
		return validation, nil
	}

	validation.IsCompliant = true
	validation.Message = fmt.Sprintf("Default security group %s has no rules", sgID)
	validation.Evidence = append(validation.Evidence, fmt.Sprintf("Security group: %s", sgID))
	validation.Evidence = append(validation.Evidence, "No ingress rules", "No egress rules")

	return validation, nil
}

// DryRun simulates restricting the default SG without making changes.
func (b *RestrictDefaultSGRemediator) DryRun(_ context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.DryRunResult, error) {
	sgID := extractSGID(finding.Finding.ResourceID)

	dryRun := &remediation.DryRunResult{
		FindingID:        finding.Finding.ID,
		WouldSucceed:     true,
		PrerequisitesMet: true,
		PlannedActions: []string{
			fmt.Sprintf("Would revoke all ingress rules from default SG: %s", sgID),
			fmt.Sprintf("Would revoke all egress rules from default SG: %s", sgID),
		},
		EstimatedImpact: "All rules on the VPC default security group will be removed. Resources should use dedicated security groups.",
		Warnings:        []string{},
	}

	return dryRun, nil
}
