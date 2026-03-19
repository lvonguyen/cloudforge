package network

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	cspmscoring "aegis/internal/cspm/scoring"
)

func makeSSHFinding(id, source, resourceID string) *cspmscoring.PrioritizedFinding {
	return &cspmscoring.PrioritizedFinding{
		Finding: &cspmscoring.Finding{
			ID:          id,
			Source:      source,
			Severity:    "HIGH",
			FindingType: "OPEN_SSH_PORT",
			ResourceID:  resourceID,
			Region:      "us-east-1",
			AccountID:   "123456789012",
		},
	}
}

// mockEC2Client implements EC2API for testing.
type mockEC2Client struct {
	revokeFunc   func(ctx context.Context, params *ec2.RevokeSecurityGroupIngressInput, optFns ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupIngressOutput, error)
	describeFunc func(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
}

func (m *mockEC2Client) RevokeSecurityGroupIngress(ctx context.Context, params *ec2.RevokeSecurityGroupIngressInput, optFns ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupIngressOutput, error) {
	if m.revokeFunc != nil {
		return m.revokeFunc(ctx, params, optFns...)
	}
	return &ec2.RevokeSecurityGroupIngressOutput{}, nil
}

func (m *mockEC2Client) DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	if m.describeFunc != nil {
		return m.describeFunc(ctx, params, optFns...)
	}
	return &ec2.DescribeSecurityGroupsOutput{}, nil
}

func TestBlockPublicSSH_Tier(t *testing.T) {
	r := NewBlockPublicSSHRemediator()
	if got := r.Tier(); got != 1 {
		t.Fatalf("expected tier 1, got %d", got)
	}
}

func TestExtractSGID(t *testing.T) {
	tests := []struct {
		name       string
		resourceID string
		want       string
	}{
		{
			name:       "full ARN",
			resourceID: "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0abc123def456",
			want:       "sg-0abc123def456",
		},
		{
			name:       "plain SG ID",
			resourceID: "sg-0abc123def456",
			want:       "sg-0abc123def456",
		},
		{
			name:       "unknown format passes through",
			resourceID: "some-other-resource-id",
			want:       "some-other-resource-id",
		},
		{
			name:       "ARN with nested path",
			resourceID: "arn:aws:ec2:eu-west-1:999888777666:security-group/sg-multi-part",
			want:       "sg-multi-part",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSGID(tt.resourceID)
			if got != tt.want {
				t.Fatalf("extractSGID(%q) = %q, want %q", tt.resourceID, got, tt.want)
			}
		})
	}
}

func TestBlockPublicSSH_DryRun(t *testing.T) {
	tests := []struct {
		name             string
		resourceID       string
		wantWouldSucceed bool
		wantWarnings     bool
	}{
		{
			name:             "standard security group",
			resourceID:       "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0abc123",
			wantWouldSucceed: true,
			wantWarnings:     false,
		},
		{
			name:             "bastion security group detected",
			resourceID:       "arn:aws:ec2:us-east-1:123456789012:security-group/bastion-sg-0abc123",
			wantWouldSucceed: false,
			wantWarnings:     true,
		},
		{
			name:             "plain SG ID",
			resourceID:       "sg-0abc123",
			wantWouldSucceed: true,
			wantWarnings:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewBlockPublicSSHRemediator()
			finding := makeSSHFinding("ssh-dry-1", "aws-securityhub", tt.resourceID)

			result, err := r.DryRun(context.Background(), finding)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.WouldSucceed != tt.wantWouldSucceed {
				t.Fatalf("expected WouldSucceed=%v, got %v", tt.wantWouldSucceed, result.WouldSucceed)
			}
			if tt.wantWarnings && len(result.Warnings) == 0 {
				t.Fatal("expected warnings for bastion SG")
			}
			if !tt.wantWarnings && len(result.Warnings) != 0 {
				t.Fatalf("expected no warnings, got %v", result.Warnings)
			}
			if len(result.PlannedActions) == 0 {
				t.Fatal("expected non-empty planned actions")
			}
		})
	}
}

func TestBlockPublicSSH_Remediate_CSPRouting(t *testing.T) {
	tests := []struct {
		name       string
		source     string
		wantErrMsg string
	}{
		{
			name:       "GCP returns not implemented",
			source:     "gcp-scc",
			wantErrMsg: "GCP remediation not implemented",
		},
		{
			name:       "Azure returns not implemented",
			source:     "azure-defender",
			wantErrMsg: "Azure remediation not implemented",
		},
		{
			name:       "unknown CSP returns error",
			source:     "oracle-cloud",
			wantErrMsg: "unsupported CSP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewBlockPublicSSHRemediator()
			finding := makeSSHFinding("ssh-csp-1", tt.source, "sg-123")

			_, err := r.Remediate(context.Background(), finding)
			if err == nil {
				t.Fatal("expected error for non-AWS CSP")
			}
			if !strings.Contains(err.Error(), tt.wantErrMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.wantErrMsg, err.Error())
			}
		})
	}
}

func TestBlockPublicSSH_Remediate_AWS(t *testing.T) {
	tests := []struct {
		name        string
		resourceID  string
		revokeErr   error
		wantSuccess bool
		wantErrMsg  string
		wantAction  string
	}{
		{
			name:        "successful revoke",
			resourceID:  "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0abc123",
			wantSuccess: true,
			wantAction:  "Revoked 0.0.0.0/0:22 ingress from security group: sg-0abc123",
		},
		{
			name:        "plain SG ID",
			resourceID:  "sg-0xyz789",
			wantSuccess: true,
			wantAction:  "Revoked 0.0.0.0/0:22 ingress from security group: sg-0xyz789",
		},
		{
			name:       "revoke fails",
			resourceID: "sg-fail",
			revokeErr:  fmt.Errorf("InvalidGroup.NotFound: sg-fail"),
			wantErrMsg: "failed to revoke SSH ingress",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockEC2Client{
				revokeFunc: func(_ context.Context, params *ec2.RevokeSecurityGroupIngressInput, _ ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupIngressOutput, error) {
					// Verify the correct SG ID was passed
					wantSG := extractSGID(tt.resourceID)
					if *params.GroupId != wantSG {
						t.Fatalf("expected GroupId %q, got %q", wantSG, *params.GroupId)
					}
					// Verify SSH rule shape
					if len(params.IpPermissions) != 1 {
						t.Fatalf("expected 1 IpPermission, got %d", len(params.IpPermissions))
					}
					perm := params.IpPermissions[0]
					if *perm.FromPort != 22 || *perm.ToPort != 22 {
						t.Fatalf("expected port 22, got %d-%d", *perm.FromPort, *perm.ToPort)
					}
					if tt.revokeErr != nil {
						return nil, tt.revokeErr
					}
					return &ec2.RevokeSecurityGroupIngressOutput{}, nil
				},
			}

			r := NewBlockPublicSSHRemediator(WithEC2Client(mock))
			finding := makeSSHFinding("ssh-aws-1", "aws-securityhub", tt.resourceID)

			result, err := r.Remediate(context.Background(), finding)

			if tt.wantErrMsg != "" {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErrMsg) {
					t.Fatalf("expected error containing %q, got %q", tt.wantErrMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Success != tt.wantSuccess {
				t.Fatalf("expected success=%v, got %v", tt.wantSuccess, result.Success)
			}
			if tt.wantAction != "" {
				if len(result.Actions) == 0 || result.Actions[0] != tt.wantAction {
					t.Fatalf("expected action %q, got %v", tt.wantAction, result.Actions)
				}
			}
		})
	}
}

func TestBlockPublicSSH_Validate(t *testing.T) {
	tests := []struct {
		name          string
		resourceID    string
		describeSGs   []ec2types.SecurityGroup
		describeErr   error
		wantCompliant bool
		wantErrMsg    string
		wantMsgPart   string
	}{
		{
			name:       "compliant - no public SSH rule",
			resourceID: "sg-clean",
			describeSGs: []ec2types.SecurityGroup{
				{
					GroupId: aws.String("sg-clean"),
					IpPermissions: []ec2types.IpPermission{
						{
							IpProtocol: aws.String("tcp"),
							FromPort:   aws.Int32(443),
							ToPort:     aws.Int32(443),
							IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
						},
					},
				},
			},
			wantCompliant: true,
			wantMsgPart:   "Public SSH access blocked",
		},
		{
			name:       "non-compliant - public SSH still open",
			resourceID: "sg-open",
			describeSGs: []ec2types.SecurityGroup{
				{
					GroupId: aws.String("sg-open"),
					IpPermissions: []ec2types.IpPermission{
						{
							IpProtocol: aws.String("tcp"),
							FromPort:   aws.Int32(22),
							ToPort:     aws.Int32(22),
							IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
						},
					},
				},
			},
			wantCompliant: false,
			wantMsgPart:   "ingress still exists",
		},
		{
			name:          "SG not found",
			resourceID:    "sg-gone",
			describeSGs:   []ec2types.SecurityGroup{},
			wantCompliant: false,
			wantMsgPart:   "not found",
		},
		{
			name:        "describe fails",
			resourceID:  "sg-err",
			describeErr: fmt.Errorf("AccessDenied"),
			wantErrMsg:  "failed to describe security group",
		},
		{
			name:       "SSH on private CIDR only is compliant",
			resourceID: "sg-private",
			describeSGs: []ec2types.SecurityGroup{
				{
					GroupId: aws.String("sg-private"),
					IpPermissions: []ec2types.IpPermission{
						{
							IpProtocol: aws.String("tcp"),
							FromPort:   aws.Int32(22),
							ToPort:     aws.Int32(22),
							IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("10.0.0.0/8")}},
						},
					},
				},
			},
			wantCompliant: true,
			wantMsgPart:   "Public SSH access blocked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockEC2Client{
				describeFunc: func(_ context.Context, params *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
					if tt.describeErr != nil {
						return nil, tt.describeErr
					}
					return &ec2.DescribeSecurityGroupsOutput{
						SecurityGroups: tt.describeSGs,
					}, nil
				},
			}

			r := NewBlockPublicSSHRemediator(WithEC2Client(mock))
			finding := makeSSHFinding("ssh-val-1", "aws-securityhub", tt.resourceID)

			result, err := r.Validate(context.Background(), finding)

			if tt.wantErrMsg != "" {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErrMsg) {
					t.Fatalf("expected error containing %q, got %q", tt.wantErrMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.IsCompliant != tt.wantCompliant {
				t.Fatalf("expected IsCompliant=%v, got %v (msg: %s)", tt.wantCompliant, result.IsCompliant, result.Message)
			}
			if tt.wantMsgPart != "" && !strings.Contains(result.Message, tt.wantMsgPart) {
				t.Fatalf("expected message containing %q, got %q", tt.wantMsgPart, result.Message)
			}
		})
	}
}
