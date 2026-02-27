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

	"cloudforge/internal/findings"
	"cloudforge/pkg/remediation"
)

// ec2API defines the EC2 operations used by this remediator.
type ec2API interface {
	RevokeSecurityGroupIngress(ctx context.Context, params *ec2.RevokeSecurityGroupIngressInput, optFns ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupIngressOutput, error)
	DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
}

// BlockPublicSSHRemediator removes 0.0.0.0/0 SSH ingress rules from security groups.
//
// Finding Types: OPEN_SSH_PORT, AWS.EC2.SecurityGroup.SSH, GCP.OPEN_SSH_PORT
// Tier: 1 (Auto-safe - blocking public SSH is always safe in non-bastion SGs)
// Impact: Removes 0.0.0.0/0:22 ingress, may require VPN/bastion for SSH access
// CSPs: AWS (EC2), GCP (Compute Engine), Azure (NSG)
type BlockPublicSSHRemediator struct {
	tier   int
	client ec2API
}

// WithEC2Client injects a custom EC2 client (used in tests).
func WithEC2Client(c ec2API) func(*BlockPublicSSHRemediator) {
	return func(r *BlockPublicSSHRemediator) {
		r.client = c
	}
}

// NewBlockPublicSSHRemediator creates a new handler for blocking public SSH access.
func NewBlockPublicSSHRemediator(opts ...func(*BlockPublicSSHRemediator)) *BlockPublicSSHRemediator {
	r := &BlockPublicSSHRemediator{tier: 1}
	for _, o := range opts {
		o(r)
	}
	return r
}

func (b *BlockPublicSSHRemediator) getClient(ctx context.Context, region string) (ec2API, error) {
	if b.client != nil {
		return b.client, nil
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	return ec2.NewFromConfig(cfg), nil
}

// Tier returns the complexity tier (1 = auto-safe for non-bastion hosts).
func (b *BlockPublicSSHRemediator) Tier() int {
	return b.tier
}

// Remediate removes the 0.0.0.0/0:22 ingress rule from the security group.
func (b *BlockPublicSSHRemediator) Remediate(ctx context.Context, finding *findings.PrioritizedFinding) (*remediation.RemediationResult, error) {
	startTime := time.Now()

	result := &remediation.RemediationResult{
		FindingID:  finding.Finding.ID,
		ResourceID: finding.Finding.ResourceID,
		StartedAt:  startTime,
		Actions:    []string{},
	}

	// Determine CSP from finding source
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

// remediateAWS handles AWS EC2 security groups.
func (b *BlockPublicSSHRemediator) remediateAWS(ctx context.Context, finding *findings.PrioritizedFinding, result *remediation.RemediationResult) (*remediation.RemediationResult, error) {
	client, err := b.getClient(ctx, finding.Finding.Region)
	if err != nil {
		return nil, err
	}

	// Extract security group ID from resource ID (e.g., "arn:aws:ec2:region:account:security-group/sg-123")
	sgID := extractSGID(finding.Finding.ResourceID)

	// Revoke the 0.0.0.0/0:22 ingress rule
	_, err = client.RevokeSecurityGroupIngress(ctx, &ec2.RevokeSecurityGroupIngressInput{
		GroupId: aws.String(sgID),
		IpPermissions: []ec2types.IpPermission{
			{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(22),
				ToPort:     aws.Int32(22),
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
		return result, fmt.Errorf("failed to revoke SSH ingress: %w", err)
	}

	result.Actions = append(result.Actions, fmt.Sprintf("Revoked 0.0.0.0/0:22 ingress from security group: %s", sgID))
	result.CompletedAt = time.Now()
	result.Duration = time.Since(result.StartedAt).String()
	result.Success = true
	result.Message = fmt.Sprintf("Blocked public SSH access on security group: %s", sgID)

	return result, nil
}

// remediateGCP handles GCP firewall rules (stub for now).
func (b *BlockPublicSSHRemediator) remediateGCP(ctx context.Context, finding *findings.PrioritizedFinding, result *remediation.RemediationResult) (*remediation.RemediationResult, error) {
	// TODO: Implement GCP firewall rule remediation
	// Use google.golang.org/api/compute/v1
	result.Message = "GCP SSH remediation not yet implemented"
	result.Success = false
	return result, fmt.Errorf("GCP remediation not implemented")
}

// remediateAzure handles Azure Network Security Groups (stub for now).
func (b *BlockPublicSSHRemediator) remediateAzure(ctx context.Context, finding *findings.PrioritizedFinding, result *remediation.RemediationResult) (*remediation.RemediationResult, error) {
	// TODO: Implement Azure NSG remediation
	// Use github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork
	result.Message = "Azure NSG remediation not yet implemented"
	result.Success = false
	return result, fmt.Errorf("Azure remediation not implemented")
}

// Validate verifies the 0.0.0.0/0:22 rule is removed.
func (b *BlockPublicSSHRemediator) Validate(ctx context.Context, finding *findings.PrioritizedFinding) (*remediation.ValidationResult, error) {
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

	// Describe security group
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

	// Check for 0.0.0.0/0:22 ingress [SEC-008: nil-safe pointer derefs]
	hasPublicSSH := false
	for _, perm := range sg.IpPermissions {
		if perm.IpProtocol == nil || perm.FromPort == nil || perm.ToPort == nil {
			continue
		}
		if *perm.IpProtocol == "tcp" && *perm.FromPort == 22 && *perm.ToPort == 22 {
			for _, ipRange := range perm.IpRanges {
				if ipRange.CidrIp != nil && *ipRange.CidrIp == "0.0.0.0/0" {
					hasPublicSSH = true
					break
				}
			}
		}
	}

	if hasPublicSSH {
		validation.IsCompliant = false
		validation.Message = "0.0.0.0/0:22 ingress still exists on security group"
		return validation, nil
	}

	validation.IsCompliant = true
	validation.Message = fmt.Sprintf("Public SSH access blocked on security group: %s", sgID)
	validation.Evidence = append(validation.Evidence, fmt.Sprintf("Security group: %s", sgID))
	validation.Evidence = append(validation.Evidence, "No 0.0.0.0/0:22 ingress rules found")

	return validation, nil
}

// DryRun simulates blocking SSH without making changes.
func (b *BlockPublicSSHRemediator) DryRun(ctx context.Context, finding *findings.PrioritizedFinding) (*remediation.DryRunResult, error) {
	sgID := extractSGID(finding.Finding.ResourceID)

	dryRun := &remediation.DryRunResult{
		FindingID:        finding.Finding.ID,
		WouldSucceed:     true,
		PrerequisitesMet: true,
		PlannedActions: []string{
			fmt.Sprintf("Would revoke 0.0.0.0/0:22 ingress from security group: %s", sgID),
		},
		EstimatedImpact: "SSH access will be blocked from internet. Ensure VPN or bastion is configured.",
		Warnings:        []string{},
	}

	// Check if this is a bastion security group (heuristic)
	if strings.Contains(strings.ToLower(finding.Finding.ResourceID), "bastion") {
		dryRun.Warnings = append(dryRun.Warnings, "WARNING: This appears to be a bastion host security group. Public SSH may be intentional.")
		dryRun.WouldSucceed = false // Don't auto-remediate bastions
	}

	return dryRun, nil
}

// extractSGID extracts the security group ID from a resource ARN or ID.
func extractSGID(resourceID string) string {
	// Handle ARN: arn:aws:ec2:region:account:security-group/sg-123
	if strings.Contains(resourceID, "security-group/") {
		parts := strings.Split(resourceID, "security-group/")
		if len(parts) > 1 {
			return parts[1]
		}
	}
	// Handle plain ID: sg-123
	if strings.HasPrefix(resourceID, "sg-") {
		return resourceID
	}
	return resourceID
}
