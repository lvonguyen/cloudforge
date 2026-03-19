package compute

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

func makeIMDSFinding(id, resourceID string) *cspmscoring.PrioritizedFinding {
	return &cspmscoring.PrioritizedFinding{
		Finding: &cspmscoring.Finding{
			ID:          id,
			Source:      "aws-securityhub",
			Severity:    "HIGH",
			FindingType: "EC2_IMDSV1_ENABLED",
			ResourceID:  resourceID,
			Region:      "us-east-1",
			AccountID:   "123456789012",
		},
	}
}

type mockEC2MetadataClient struct {
	modifyFunc   func(ctx context.Context, params *ec2.ModifyInstanceMetadataOptionsInput, optFns ...func(*ec2.Options)) (*ec2.ModifyInstanceMetadataOptionsOutput, error)
	describeFunc func(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
}

func (m *mockEC2MetadataClient) ModifyInstanceMetadataOptions(ctx context.Context, params *ec2.ModifyInstanceMetadataOptionsInput, optFns ...func(*ec2.Options)) (*ec2.ModifyInstanceMetadataOptionsOutput, error) {
	if m.modifyFunc != nil {
		return m.modifyFunc(ctx, params, optFns...)
	}
	return &ec2.ModifyInstanceMetadataOptionsOutput{}, nil
}

func (m *mockEC2MetadataClient) DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	if m.describeFunc != nil {
		return m.describeFunc(ctx, params, optFns...)
	}
	return &ec2.DescribeInstancesOutput{}, nil
}

func TestEnforceIMDSv2_Tier(t *testing.T) {
	r := NewEnforceIMDSv2Remediator()
	if got := r.Tier(); got != 1 {
		t.Fatalf("expected tier 1, got %d", got)
	}
}

func TestExtractInstanceID(t *testing.T) {
	tests := []struct {
		name       string
		resourceID string
		want       string
	}{
		{name: "full ARN", resourceID: "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123def456", want: "i-0abc123def456"},
		{name: "plain instance ID", resourceID: "i-0abc123def456", want: "i-0abc123def456"},
		{name: "unknown format passes through", resourceID: "some-other-resource", want: "some-other-resource"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractInstanceID(tt.resourceID)
			if got != tt.want {
				t.Fatalf("extractInstanceID(%q) = %q, want %q", tt.resourceID, got, tt.want)
			}
		})
	}
}

func TestEnforceIMDSv2_DryRun(t *testing.T) {
	tests := []struct {
		name       string
		resourceID string
	}{
		{name: "ARN resource", resourceID: "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123"},
		{name: "plain instance ID", resourceID: "i-0xyz789"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewEnforceIMDSv2Remediator()
			finding := makeIMDSFinding("imds-dry-1", tt.resourceID)

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
		})
	}
}

func TestEnforceIMDSv2_Remediate(t *testing.T) {
	tests := []struct {
		name        string
		resourceID  string
		modifyErr   error
		wantSuccess bool
		wantErrMsg  string
	}{
		{
			name:        "successful enforcement",
			resourceID:  "i-0abc123",
			wantSuccess: true,
		},
		{
			name:        "ARN resource ID",
			resourceID:  "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123",
			wantSuccess: true,
		},
		{
			name:       "modify fails",
			resourceID: "i-fail",
			modifyErr:  fmt.Errorf("IncorrectInstanceState: stopped"),
			wantErrMsg: "failed to modify instance metadata",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockEC2MetadataClient{
				modifyFunc: func(_ context.Context, params *ec2.ModifyInstanceMetadataOptionsInput, _ ...func(*ec2.Options)) (*ec2.ModifyInstanceMetadataOptionsOutput, error) {
					wantID := extractInstanceID(tt.resourceID)
					if *params.InstanceId != wantID {
						t.Fatalf("expected InstanceId %q, got %q", wantID, *params.InstanceId)
					}
					if params.HttpTokens != ec2types.HttpTokensStateRequired {
						t.Fatalf("expected HttpTokens=required, got %v", params.HttpTokens)
					}
					if tt.modifyErr != nil {
						return nil, tt.modifyErr
					}
					return &ec2.ModifyInstanceMetadataOptionsOutput{}, nil
				},
			}

			r := NewEnforceIMDSv2Remediator(WithEC2MetadataClient(mock))
			finding := makeIMDSFinding("imds-rem-1", tt.resourceID)

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
		})
	}
}

func TestEnforceIMDSv2_Validate(t *testing.T) {
	tests := []struct {
		name          string
		resourceID    string
		reservations  []ec2types.Reservation
		describeErr   error
		wantCompliant bool
		wantErrMsg    string
		wantMsgPart   string
	}{
		{
			name:       "compliant - IMDSv2 required",
			resourceID: "i-compliant",
			reservations: []ec2types.Reservation{
				{
					Instances: []ec2types.Instance{
						{
							InstanceId: aws.String("i-compliant"),
							MetadataOptions: &ec2types.InstanceMetadataOptionsResponse{
								HttpTokens: ec2types.HttpTokensStateRequired,
							},
						},
					},
				},
			},
			wantCompliant: true,
			wantMsgPart:   "IMDSv2 enforced",
		},
		{
			name:       "non-compliant - IMDSv1 optional",
			resourceID: "i-noncompliant",
			reservations: []ec2types.Reservation{
				{
					Instances: []ec2types.Instance{
						{
							InstanceId: aws.String("i-noncompliant"),
							MetadataOptions: &ec2types.InstanceMetadataOptionsResponse{
								HttpTokens: ec2types.HttpTokensStateOptional,
							},
						},
					},
				},
			},
			wantCompliant: false,
			wantMsgPart:   "IMDSv2 not enforced",
		},
		{
			name:          "instance not found",
			resourceID:    "i-gone",
			reservations:  []ec2types.Reservation{},
			wantCompliant: false,
			wantMsgPart:   "not found",
		},
		{
			name:       "nil metadata options",
			resourceID: "i-nil",
			reservations: []ec2types.Reservation{
				{
					Instances: []ec2types.Instance{
						{InstanceId: aws.String("i-nil")},
					},
				},
			},
			wantCompliant: false,
			wantMsgPart:   "IMDSv2 not enforced",
		},
		{
			name:        "describe fails",
			resourceID:  "i-err",
			describeErr: fmt.Errorf("InvalidInstanceID.NotFound"),
			wantErrMsg:  "failed to describe instance",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockEC2MetadataClient{
				describeFunc: func(_ context.Context, _ *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
					if tt.describeErr != nil {
						return nil, tt.describeErr
					}
					return &ec2.DescribeInstancesOutput{
						Reservations: tt.reservations,
					}, nil
				},
			}

			r := NewEnforceIMDSv2Remediator(WithEC2MetadataClient(mock))
			finding := makeIMDSFinding("imds-val-1", tt.resourceID)

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
