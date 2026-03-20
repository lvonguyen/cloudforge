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

func makeDefaultSGFinding(id, source, resourceID string) *cspmscoring.PrioritizedFinding {
	return &cspmscoring.PrioritizedFinding{
		Finding: &cspmscoring.Finding{
			ID:          id,
			Source:      source,
			Severity:    "MEDIUM",
			FindingType: "VPC_DEFAULT_SG_ALLOWS_TRAFFIC",
			ResourceID:  resourceID,
			Region:      "us-east-1",
			AccountID:   "123456789012",
		},
	}
}

// mockDefaultSGClient implements defaultSGAPI for testing.
type mockDefaultSGClient struct {
	describeFunc      func(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	revokeIngressFunc func(ctx context.Context, params *ec2.RevokeSecurityGroupIngressInput, optFns ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupIngressOutput, error)
	revokeEgressFunc  func(ctx context.Context, params *ec2.RevokeSecurityGroupEgressInput, optFns ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupEgressOutput, error)
}

func (m *mockDefaultSGClient) DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	if m.describeFunc != nil {
		return m.describeFunc(ctx, params, optFns...)
	}
	return &ec2.DescribeSecurityGroupsOutput{}, nil
}

func (m *mockDefaultSGClient) RevokeSecurityGroupIngress(ctx context.Context, params *ec2.RevokeSecurityGroupIngressInput, optFns ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupIngressOutput, error) {
	if m.revokeIngressFunc != nil {
		return m.revokeIngressFunc(ctx, params, optFns...)
	}
	return &ec2.RevokeSecurityGroupIngressOutput{}, nil
}

func (m *mockDefaultSGClient) RevokeSecurityGroupEgress(ctx context.Context, params *ec2.RevokeSecurityGroupEgressInput, optFns ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupEgressOutput, error) {
	if m.revokeEgressFunc != nil {
		return m.revokeEgressFunc(ctx, params, optFns...)
	}
	return &ec2.RevokeSecurityGroupEgressOutput{}, nil
}

func TestRestrictDefaultSG_Tier(t *testing.T) {
	r := NewRestrictDefaultSGRemediator()
	if got := r.Tier(); got != 1 {
		t.Fatalf("expected tier 1, got %d", got)
	}
}

func TestRestrictDefaultSG_DryRun(t *testing.T) {
	r := NewRestrictDefaultSGRemediator()
	finding := makeDefaultSGFinding("dsg-dry-1", "aws-securityhub", "sg-default123")

	result, err := r.DryRun(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.WouldSucceed {
		t.Fatal("expected WouldSucceed=true")
	}
	if len(result.PlannedActions) != 2 {
		t.Fatalf("expected 2 planned actions, got %d", len(result.PlannedActions))
	}
}

func TestRestrictDefaultSG_Remediate_AWS(t *testing.T) {
	tests := []struct {
		name           string
		resourceID     string
		ingressRules   []ec2types.IpPermission
		egressRules    []ec2types.IpPermission
		describeErr    error
		revokeInErr    error
		revokeOutErr   error
		wantSuccess    bool
		wantErrMsg     string
		wantActionsCnt int
	}{
		{
			name:       "removes ingress and egress",
			resourceID: "sg-default123",
			ingressRules: []ec2types.IpPermission{
				{
					IpProtocol: aws.String("-1"),
					IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
				},
			},
			egressRules: []ec2types.IpPermission{
				{
					IpProtocol: aws.String("-1"),
					IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
				},
			},
			wantSuccess:    true,
			wantActionsCnt: 2,
		},
		{
			name:           "already clean SG",
			resourceID:     "sg-clean",
			ingressRules:   []ec2types.IpPermission{},
			egressRules:    []ec2types.IpPermission{},
			wantSuccess:    true,
			wantActionsCnt: 0,
		},
		{
			name:        "describe fails",
			resourceID:  "sg-err",
			describeErr: fmt.Errorf("AccessDenied"),
			wantErrMsg:  "failed to describe default security group",
		},
		{
			name:       "revoke ingress fails",
			resourceID: "sg-ingerr",
			ingressRules: []ec2types.IpPermission{
				{IpProtocol: aws.String("-1")},
			},
			revokeInErr: fmt.Errorf("InvalidPermission"),
			wantErrMsg:  "failed to revoke ingress rules",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockDefaultSGClient{
				describeFunc: func(_ context.Context, _ *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
					if tt.describeErr != nil {
						return nil, tt.describeErr
					}
					return &ec2.DescribeSecurityGroupsOutput{
						SecurityGroups: []ec2types.SecurityGroup{
							{
								GroupId:             aws.String(tt.resourceID),
								IpPermissions:       tt.ingressRules,
								IpPermissionsEgress: tt.egressRules,
							},
						},
					}, nil
				},
				revokeIngressFunc: func(_ context.Context, _ *ec2.RevokeSecurityGroupIngressInput, _ ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupIngressOutput, error) {
					if tt.revokeInErr != nil {
						return nil, tt.revokeInErr
					}
					return &ec2.RevokeSecurityGroupIngressOutput{}, nil
				},
				revokeEgressFunc: func(_ context.Context, _ *ec2.RevokeSecurityGroupEgressInput, _ ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupEgressOutput, error) {
					if tt.revokeOutErr != nil {
						return nil, tt.revokeOutErr
					}
					return &ec2.RevokeSecurityGroupEgressOutput{}, nil
				},
			}

			r := NewRestrictDefaultSGRemediator(WithDefaultSGClient(mock))
			finding := makeDefaultSGFinding("dsg-aws-1", "aws-securityhub", tt.resourceID)

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
			if len(result.Actions) != tt.wantActionsCnt {
				t.Fatalf("expected %d actions, got %d: %v", tt.wantActionsCnt, len(result.Actions), result.Actions)
			}
		})
	}
}

func TestRestrictDefaultSG_Remediate_CSPRouting(t *testing.T) {
	tests := []struct {
		name       string
		source     string
		wantErrMsg string
	}{
		{name: "GCP returns not implemented", source: "gcp-scc", wantErrMsg: "GCP remediation not implemented"},
		{name: "Azure returns not implemented", source: "azure-defender", wantErrMsg: "Azure remediation not implemented"},
		{name: "unknown CSP returns error", source: "oracle-cloud", wantErrMsg: "unsupported CSP"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRestrictDefaultSGRemediator()
			finding := makeDefaultSGFinding("dsg-csp-1", tt.source, "sg-123")

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
