// Package network provides remediation handlers for network security findings.
package network

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

// BlockOpenPortRemediator removes 0.0.0.0/0 ingress rules for a specific port
// from security groups. Parameterized by port number.
//
// Finding Types: OPEN_RDP_PORT, OPEN_MYSQL_PORT, OPEN_POSTGRESQL_PORT,
// OPEN_REDIS_PORT, OPEN_MONGODB_PORT, OPEN_FTP_PORT, etc.
// Tier: 1 (Auto-safe — public access to service ports is never intended)
// Impact: Removes 0.0.0.0/0:<port> ingress; requires VPN/bastion for access
// CSPs: AWS (EC2), GCP (Compute Engine), Azure (NSG)
type BlockOpenPortRemediator struct {
	tier     int
	port     int32
	portName string
	client   ec2API
}

// WithOpenPortEC2Client injects a custom EC2 client (used in tests).
func WithOpenPortEC2Client(c ec2API) func(*BlockOpenPortRemediator) {
	return func(r *BlockOpenPortRemediator) {
		r.client = c
	}
}

// NewBlockOpenPortRemediator creates a new handler for blocking public access
// to the specified port. The name parameter is a human-readable label
// (e.g., "RDP", "MySQL", "PostgreSQL").
func NewBlockOpenPortRemediator(port int32, name string, opts ...func(*BlockOpenPortRemediator)) *BlockOpenPortRemediator {
	r := &BlockOpenPortRemediator{
		tier:     1,
		port:     port,
		portName: name,
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

func (b *BlockOpenPortRemediator) getClient(ctx context.Context, region string) (ec2API, error) {
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
func (b *BlockOpenPortRemediator) Tier() int {
	return b.tier
}

// Remediate removes the 0.0.0.0/0:<port> ingress rule from the security group.
func (b *BlockOpenPortRemediator) Remediate(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.RemediationResult, error) {
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

func (b *BlockOpenPortRemediator) remediateAWS(ctx context.Context, finding *cspmscoring.PrioritizedFinding, result *remediation.RemediationResult) (*remediation.RemediationResult, error) {
	client, err := b.getClient(ctx, finding.Finding.Region)
	if err != nil {
		return nil, err
	}

	sgID := extractSGID(finding.Finding.ResourceID)

	_, err = client.RevokeSecurityGroupIngress(ctx, &ec2.RevokeSecurityGroupIngressInput{
		GroupId: aws.String(sgID),
		IpPermissions: []ec2types.IpPermission{
			{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(b.port),
				ToPort:     aws.Int32(b.port),
				IpRanges: []ec2types.IpRange{
					{CidrIp: aws.String("0.0.0.0/0")},
				},
			},
		},
	})

	if err != nil {
		result.CompletedAt = time.Now()
		result.Duration = time.Since(result.StartedAt).String()
		result.Error = err.Error()
		return result, fmt.Errorf("failed to revoke %s ingress: %w", b.portName, err)
	}

	result.Actions = append(result.Actions, fmt.Sprintf("Revoked 0.0.0.0/0:%d (%s) ingress from security group: %s", b.port, b.portName, sgID))
	result.CompletedAt = time.Now()
	result.Duration = time.Since(result.StartedAt).String()
	result.Success = true
	result.Message = fmt.Sprintf("Blocked public %s access on security group: %s", b.portName, sgID)

	return result, nil
}

func (b *BlockOpenPortRemediator) remediateGCP(_ context.Context, _ *cspmscoring.PrioritizedFinding, result *remediation.RemediationResult) (*remediation.RemediationResult, error) {
	result.Message = fmt.Sprintf("GCP %s remediation not yet implemented", b.portName)
	result.Success = false
	return result, fmt.Errorf("GCP remediation not implemented")
}

func (b *BlockOpenPortRemediator) remediateAzure(_ context.Context, _ *cspmscoring.PrioritizedFinding, result *remediation.RemediationResult) (*remediation.RemediationResult, error) {
	result.Message = fmt.Sprintf("Azure %s remediation not yet implemented", b.portName)
	result.Success = false
	return result, fmt.Errorf("Azure remediation not implemented")
}

// Validate verifies the 0.0.0.0/0:<port> rule is removed.
func (b *BlockOpenPortRemediator) Validate(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.ValidationResult, error) {
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

	hasPublicPort := false
	for _, perm := range sg.IpPermissions {
		if perm.IpProtocol == nil || perm.FromPort == nil || perm.ToPort == nil {
			continue
		}
		if *perm.IpProtocol == "tcp" && *perm.FromPort == b.port && *perm.ToPort == b.port {
			for _, ipRange := range perm.IpRanges {
				if ipRange.CidrIp != nil && *ipRange.CidrIp == "0.0.0.0/0" {
					hasPublicPort = true
					break
				}
			}
		}
	}

	if hasPublicPort {
		validation.IsCompliant = false
		validation.Message = fmt.Sprintf("0.0.0.0/0:%d (%s) ingress still exists on security group", b.port, b.portName)
		return validation, nil
	}

	validation.IsCompliant = true
	validation.Message = fmt.Sprintf("Public %s access blocked on security group: %s", b.portName, sgID)
	validation.Evidence = append(validation.Evidence, fmt.Sprintf("Security group: %s", sgID))
	validation.Evidence = append(validation.Evidence, fmt.Sprintf("No 0.0.0.0/0:%d (%s) ingress rules found", b.port, b.portName))

	return validation, nil
}

// DryRun simulates blocking the port without making changes.
func (b *BlockOpenPortRemediator) DryRun(_ context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.DryRunResult, error) {
	sgID := extractSGID(finding.Finding.ResourceID)

	dryRun := &remediation.DryRunResult{
		FindingID:        finding.Finding.ID,
		WouldSucceed:     true,
		PrerequisitesMet: true,
		PlannedActions: []string{
			fmt.Sprintf("Would revoke 0.0.0.0/0:%d (%s) ingress from security group: %s", b.port, b.portName, sgID),
		},
		EstimatedImpact: fmt.Sprintf("%s access will be blocked from the internet. Ensure VPN or bastion is configured.", b.portName),
		Warnings:        []string{},
	}

	return dryRun, nil
}
