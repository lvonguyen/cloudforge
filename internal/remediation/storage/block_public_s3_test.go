package storage

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3controltypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"

	cspmscoring "aegis/internal/cspm/scoring"
)

func makeS3Finding(id, accountID string) *cspmscoring.PrioritizedFinding {
	return &cspmscoring.PrioritizedFinding{
		Finding: &cspmscoring.Finding{
			ID:          id,
			Source:      "aws-securityhub",
			Severity:    "CRITICAL",
			FindingType: "S3_PUBLIC_ACCESS",
			ResourceID:  "arn:aws:s3:::prod-data-bucket",
			Region:      "us-east-1",
			AccountID:   accountID,
		},
	}
}

type mockS3ControlClient struct {
	putFunc func(ctx context.Context, params *s3control.PutPublicAccessBlockInput, optFns ...func(*s3control.Options)) (*s3control.PutPublicAccessBlockOutput, error)
	getFunc func(ctx context.Context, params *s3control.GetPublicAccessBlockInput, optFns ...func(*s3control.Options)) (*s3control.GetPublicAccessBlockOutput, error)
}

func (m *mockS3ControlClient) PutPublicAccessBlock(ctx context.Context, params *s3control.PutPublicAccessBlockInput, optFns ...func(*s3control.Options)) (*s3control.PutPublicAccessBlockOutput, error) {
	if m.putFunc != nil {
		return m.putFunc(ctx, params, optFns...)
	}
	return &s3control.PutPublicAccessBlockOutput{}, nil
}

func (m *mockS3ControlClient) GetPublicAccessBlock(ctx context.Context, params *s3control.GetPublicAccessBlockInput, optFns ...func(*s3control.Options)) (*s3control.GetPublicAccessBlockOutput, error) {
	if m.getFunc != nil {
		return m.getFunc(ctx, params, optFns...)
	}
	return &s3control.GetPublicAccessBlockOutput{}, nil
}

func TestBlockPublicS3_Tier(t *testing.T) {
	r := NewBlockPublicS3Remediator()
	if got := r.Tier(); got != 1 {
		t.Fatalf("expected tier 1, got %d", got)
	}
}

func TestBlockPublicS3_DryRun(t *testing.T) {
	tests := []struct {
		name      string
		accountID string
	}{
		{name: "standard account", accountID: "123456789012"},
		{name: "different account", accountID: "999888777666"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewBlockPublicS3Remediator()
			finding := makeS3Finding("s3-dry-1", tt.accountID)

			result, err := r.DryRun(context.Background(), finding)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !result.WouldSucceed {
				t.Fatal("expected WouldSucceed=true")
			}
			if len(result.PlannedActions) != 4 {
				t.Fatalf("expected 4 planned actions, got %d", len(result.PlannedActions))
			}
			if !strings.Contains(result.PlannedActions[0], tt.accountID) {
				t.Fatalf("expected first action to reference account %q, got %q", tt.accountID, result.PlannedActions[0])
			}
			if !strings.Contains(strings.ToLower(result.EstimatedImpact), "static website") {
				t.Fatalf("expected impact warning about static websites, got %q", result.EstimatedImpact)
			}
		})
	}
}

func TestBlockPublicS3_Remediate(t *testing.T) {
	tests := []struct {
		name        string
		accountID   string
		putErr      error
		wantSuccess bool
		wantErrMsg  string
		wantActions int
	}{
		{
			name:        "successful block",
			accountID:   "123456789012",
			wantSuccess: true,
			wantActions: 4,
		},
		{
			name:       "put fails",
			accountID:  "123456789012",
			putErr:     fmt.Errorf("AccessDenied: insufficient permissions"),
			wantErrMsg: "failed to put public access block",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockS3ControlClient{
				putFunc: func(_ context.Context, params *s3control.PutPublicAccessBlockInput, _ ...func(*s3control.Options)) (*s3control.PutPublicAccessBlockOutput, error) {
					if *params.AccountId != tt.accountID {
						t.Fatalf("expected AccountId %q, got %q", tt.accountID, *params.AccountId)
					}
					pab := params.PublicAccessBlockConfiguration
					if !*pab.BlockPublicAcls || !*pab.BlockPublicPolicy || !*pab.IgnorePublicAcls || !*pab.RestrictPublicBuckets {
						t.Fatal("expected all 4 block settings to be true")
					}
					if tt.putErr != nil {
						return nil, tt.putErr
					}
					return &s3control.PutPublicAccessBlockOutput{}, nil
				},
			}

			r := NewBlockPublicS3Remediator(WithS3ControlClient(mock))
			finding := makeS3Finding("s3-rem-1", tt.accountID)

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
			if len(result.Actions) != tt.wantActions {
				t.Fatalf("expected %d actions, got %d", tt.wantActions, len(result.Actions))
			}
		})
	}
}

func TestBlockPublicS3_Validate(t *testing.T) {
	tests := []struct {
		name          string
		pab           *s3controltypes.PublicAccessBlockConfiguration
		getErr        error
		wantCompliant bool
		wantMsgPart   string
	}{
		{
			name: "all blocked - compliant",
			pab: &s3controltypes.PublicAccessBlockConfiguration{
				BlockPublicAcls:       aws.Bool(true),
				BlockPublicPolicy:     aws.Bool(true),
				IgnorePublicAcls:      aws.Bool(true),
				RestrictPublicBuckets: aws.Bool(true),
			},
			wantCompliant: true,
			wantMsgPart:   "All public access blocked",
		},
		{
			name: "partial block - not compliant",
			pab: &s3controltypes.PublicAccessBlockConfiguration{
				BlockPublicAcls:       aws.Bool(true),
				BlockPublicPolicy:     aws.Bool(false),
				IgnorePublicAcls:      aws.Bool(true),
				RestrictPublicBuckets: aws.Bool(true),
			},
			wantCompliant: false,
			wantMsgPart:   "Not all public access block",
		},
		{
			name: "nil booleans treated as false",
			pab: &s3controltypes.PublicAccessBlockConfiguration{
				BlockPublicAcls: aws.Bool(true),
				// rest are nil
			},
			wantCompliant: false,
			wantMsgPart:   "Not all public access block",
		},
		{
			name:          "get fails - not compliant",
			getErr:        fmt.Errorf("NoSuchPublicAccessBlockConfiguration"),
			wantCompliant: false,
			wantMsgPart:   "Failed to get public access block",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockS3ControlClient{
				getFunc: func(_ context.Context, _ *s3control.GetPublicAccessBlockInput, _ ...func(*s3control.Options)) (*s3control.GetPublicAccessBlockOutput, error) {
					if tt.getErr != nil {
						return nil, tt.getErr
					}
					return &s3control.GetPublicAccessBlockOutput{
						PublicAccessBlockConfiguration: tt.pab,
					}, nil
				},
			}

			r := NewBlockPublicS3Remediator(WithS3ControlClient(mock))
			finding := makeS3Finding("s3-val-1", "123456789012")

			result, err := r.Validate(context.Background(), finding)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.IsCompliant != tt.wantCompliant {
				t.Fatalf("expected IsCompliant=%v, got %v (msg: %s)", tt.wantCompliant, result.IsCompliant, result.Message)
			}
			if !strings.Contains(result.Message, tt.wantMsgPart) {
				t.Fatalf("expected message containing %q, got %q", tt.wantMsgPart, result.Message)
			}
		})
	}
}
