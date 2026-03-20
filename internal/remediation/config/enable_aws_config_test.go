package config

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	configtypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"

	cspmscoring "aegis/internal/cspm/scoring"
)

func makeConfigFinding(id, source, region string) *cspmscoring.PrioritizedFinding {
	return &cspmscoring.PrioritizedFinding{
		Finding: &cspmscoring.Finding{
			ID:          id,
			Source:      source,
			Severity:    "HIGH",
			FindingType: "AWS_CONFIG_NOT_ENABLED",
			ResourceID:  "account-123456789012",
			Region:      region,
			AccountID:   "123456789012",
		},
	}
}

// mockConfigClient implements configServiceAPI for testing.
type mockConfigClient struct {
	describeFunc func(ctx context.Context, params *configservice.DescribeConfigurationRecordersInput, optFns ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecordersOutput, error)
	putRecFunc   func(ctx context.Context, params *configservice.PutConfigurationRecorderInput, optFns ...func(*configservice.Options)) (*configservice.PutConfigurationRecorderOutput, error)
	putChanFunc  func(ctx context.Context, params *configservice.PutDeliveryChannelInput, optFns ...func(*configservice.Options)) (*configservice.PutDeliveryChannelOutput, error)
	startFunc    func(ctx context.Context, params *configservice.StartConfigurationRecorderInput, optFns ...func(*configservice.Options)) (*configservice.StartConfigurationRecorderOutput, error)
}

func (m *mockConfigClient) DescribeConfigurationRecorders(ctx context.Context, params *configservice.DescribeConfigurationRecordersInput, optFns ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecordersOutput, error) {
	if m.describeFunc != nil {
		return m.describeFunc(ctx, params, optFns...)
	}
	return &configservice.DescribeConfigurationRecordersOutput{}, nil
}

func (m *mockConfigClient) PutConfigurationRecorder(ctx context.Context, params *configservice.PutConfigurationRecorderInput, optFns ...func(*configservice.Options)) (*configservice.PutConfigurationRecorderOutput, error) {
	if m.putRecFunc != nil {
		return m.putRecFunc(ctx, params, optFns...)
	}
	return &configservice.PutConfigurationRecorderOutput{}, nil
}

func (m *mockConfigClient) PutDeliveryChannel(ctx context.Context, params *configservice.PutDeliveryChannelInput, optFns ...func(*configservice.Options)) (*configservice.PutDeliveryChannelOutput, error) {
	if m.putChanFunc != nil {
		return m.putChanFunc(ctx, params, optFns...)
	}
	return &configservice.PutDeliveryChannelOutput{}, nil
}

func (m *mockConfigClient) StartConfigurationRecorder(ctx context.Context, params *configservice.StartConfigurationRecorderInput, optFns ...func(*configservice.Options)) (*configservice.StartConfigurationRecorderOutput, error) {
	if m.startFunc != nil {
		return m.startFunc(ctx, params, optFns...)
	}
	return &configservice.StartConfigurationRecorderOutput{}, nil
}

func mockFactory(client configServiceAPI) func(ctx context.Context, region string) (configServiceAPI, error) {
	return func(_ context.Context, _ string) (configServiceAPI, error) {
		return client, nil
	}
}

func TestEnableAWSConfig_Tier(t *testing.T) {
	r := NewEnableAWSConfigRemediator()
	if got := r.Tier(); got != 2 {
		t.Fatalf("expected tier 2, got %d", got)
	}
}

func TestEnableAWSConfig_DryRun(t *testing.T) {
	tests := []struct {
		name            string
		roleARN         string
		s3Bucket        string
		wantPrereqsMet  bool
		wantWarningsMin int
	}{
		{
			name:            "fully configured",
			roleARN:         "arn:aws:iam::123456789012:role/ConfigRole",
			s3Bucket:        "my-config-bucket",
			wantPrereqsMet:  true,
			wantWarningsMin: 2,
		},
		{
			name:            "missing role and bucket",
			roleARN:         "",
			s3Bucket:        "",
			wantPrereqsMet:  false,
			wantWarningsMin: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := []EnableAWSConfigOption{}
			if tt.roleARN != "" {
				opts = append(opts, WithRoleARN(tt.roleARN))
			}
			if tt.s3Bucket != "" {
				opts = append(opts, WithS3Bucket(tt.s3Bucket))
			}
			r := NewEnableAWSConfigRemediator(opts...)
			finding := makeConfigFinding("cfg-dry-1", "aws-securityhub", "us-east-1")

			result, err := r.DryRun(context.Background(), finding)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.PrerequisitesMet != tt.wantPrereqsMet {
				t.Fatalf("expected PrerequisitesMet=%v, got %v", tt.wantPrereqsMet, result.PrerequisitesMet)
			}
			if len(result.Warnings) < tt.wantWarningsMin {
				t.Fatalf("expected at least %d warnings, got %d: %v", tt.wantWarningsMin, len(result.Warnings), result.Warnings)
			}
			if len(result.PlannedActions) != 3 {
				t.Fatalf("expected 3 planned actions, got %d", len(result.PlannedActions))
			}
		})
	}
}

func TestEnableAWSConfig_Remediate_AWS(t *testing.T) {
	tests := []struct {
		name        string
		recorders   []configtypes.ConfigurationRecorder
		describeErr error
		putRecErr   error
		startErr    error
		wantSuccess bool
		wantErrMsg  string
	}{
		{
			name:        "creates recorder and starts",
			recorders:   []configtypes.ConfigurationRecorder{},
			wantSuccess: true,
		},
		{
			name: "recorder exists, just starts",
			recorders: []configtypes.ConfigurationRecorder{
				{Name: aws.String("default")},
			},
			wantSuccess: true,
		},
		{
			name:        "describe fails",
			describeErr: fmt.Errorf("AccessDenied"),
			wantErrMsg:  "failed to describe configuration recorders",
		},
		{
			name:       "put recorder fails",
			recorders:  []configtypes.ConfigurationRecorder{},
			putRecErr:  fmt.Errorf("InsufficientPermissions"),
			wantErrMsg: "failed to create configuration recorder",
		},
		{
			name:       "start fails",
			recorders:  []configtypes.ConfigurationRecorder{},
			startErr:   fmt.Errorf("NoAvailableDeliveryChannel"),
			wantErrMsg: "failed to start configuration recorder",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockConfigClient{
				describeFunc: func(_ context.Context, _ *configservice.DescribeConfigurationRecordersInput, _ ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecordersOutput, error) {
					if tt.describeErr != nil {
						return nil, tt.describeErr
					}
					return &configservice.DescribeConfigurationRecordersOutput{
						ConfigurationRecorders: tt.recorders,
					}, nil
				},
				putRecFunc: func(_ context.Context, _ *configservice.PutConfigurationRecorderInput, _ ...func(*configservice.Options)) (*configservice.PutConfigurationRecorderOutput, error) {
					if tt.putRecErr != nil {
						return nil, tt.putRecErr
					}
					return &configservice.PutConfigurationRecorderOutput{}, nil
				},
				startFunc: func(_ context.Context, _ *configservice.StartConfigurationRecorderInput, _ ...func(*configservice.Options)) (*configservice.StartConfigurationRecorderOutput, error) {
					if tt.startErr != nil {
						return nil, tt.startErr
					}
					return &configservice.StartConfigurationRecorderOutput{}, nil
				},
			}

			r := NewEnableAWSConfigRemediator(
				WithConfigClient(mockFactory(mock)),
				WithRoleARN("arn:aws:iam::123456789012:role/ConfigRole"),
				WithS3Bucket("my-config-bucket"),
			)
			finding := makeConfigFinding("cfg-aws-1", "aws-securityhub", "us-east-1")

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
			if len(result.Actions) == 0 {
				t.Fatal("expected non-empty actions")
			}
		})
	}
}

func TestEnableAWSConfig_Remediate_CSPRouting(t *testing.T) {
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
			r := NewEnableAWSConfigRemediator()
			finding := makeConfigFinding("cfg-csp-1", tt.source, "us-east-1")

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
