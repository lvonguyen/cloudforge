package identity

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	cspmscoring "cloudforge/internal/cspm/scoring"
)

// ---------- mock IAM client ----------

type mockIAMClient struct {
	listAccessKeysFn  func(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
	updateAccessKeyFn func(ctx context.Context, params *iam.UpdateAccessKeyInput, optFns ...func(*iam.Options)) (*iam.UpdateAccessKeyOutput, error)
}

func (m *mockIAMClient) ListAccessKeys(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	return m.listAccessKeysFn(ctx, params, optFns...)
}

func (m *mockIAMClient) UpdateAccessKey(ctx context.Context, params *iam.UpdateAccessKeyInput, optFns ...func(*iam.Options)) (*iam.UpdateAccessKeyOutput, error) {
	return m.updateAccessKeyFn(ctx, params, optFns...)
}

// ---------- helpers ----------

func daysAgo(n int) *time.Time {
	t := time.Now().Add(-time.Duration(n) * 24 * time.Hour)
	return &t
}

func testFinding(resourceID, region string) *cspmscoring.PrioritizedFinding {
	return &cspmscoring.PrioritizedFinding{
		Finding: &cspmscoring.Finding{
			ID:          "finding-001",
			Source:      "aws-securityhub",
			Severity:    "HIGH",
			FindingType: "IAM_OLD_ACCESS_KEY",
			ResourceID:  resourceID,
			Region:      region,
			AccountID:   "123456789012",
		},
	}
}

func mockFactory(client iamAPI) func(ctx context.Context, region string) (iamAPI, error) {
	return func(ctx context.Context, region string) (iamAPI, error) {
		return client, nil
	}
}

func errorFactory(msg string) func(ctx context.Context, region string) (iamAPI, error) {
	return func(ctx context.Context, region string) (iamAPI, error) {
		return nil, fmt.Errorf("%s", msg)
	}
}

// ---------- Remediate tests ----------

func TestRemediate_DeactivatesOldKeys(t *testing.T) {
	updatedKeys := []string{}
	client := &mockIAMClient{
		listAccessKeysFn: func(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
			return &iam.ListAccessKeysOutput{
				AccessKeyMetadata: []iamtypes.AccessKeyMetadata{
					{
						AccessKeyId: aws.String("AKIAIOSFODNN7EXAMPLE"),
						UserName:    aws.String("test-user"),
						Status:      iamtypes.StatusTypeActive,
						CreateDate:  daysAgo(120),
					},
				},
			}, nil
		},
		updateAccessKeyFn: func(ctx context.Context, params *iam.UpdateAccessKeyInput, optFns ...func(*iam.Options)) (*iam.UpdateAccessKeyOutput, error) {
			updatedKeys = append(updatedKeys, *params.AccessKeyId)
			if params.Status != iamtypes.StatusTypeInactive {
				t.Errorf("expected status Inactive, got %s", params.Status)
			}
			return &iam.UpdateAccessKeyOutput{}, nil
		},
	}

	r := newRotateIAMKeysRemediatorForTest(mockFactory(client))
	result, err := r.Remediate(context.Background(), testFinding("test-user", "us-east-1"))
	if err != nil {
		t.Fatalf("Remediate: %v", err)
	}
	if !result.Success {
		t.Error("expected success=true")
	}
	if len(updatedKeys) != 1 {
		t.Errorf("expected 1 key deactivated, got %d", len(updatedKeys))
	}
	if !strings.Contains(result.Message, "Deactivated 1") {
		t.Errorf("expected deactivation message, got: %s", result.Message)
	}
	if len(result.Actions) != 1 {
		t.Errorf("expected 1 action, got %d", len(result.Actions))
	}
}

func TestRemediate_NoOldKeys(t *testing.T) {
	client := &mockIAMClient{
		listAccessKeysFn: func(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
			return &iam.ListAccessKeysOutput{
				AccessKeyMetadata: []iamtypes.AccessKeyMetadata{
					{
						AccessKeyId: aws.String("AKIAIOSFODNN7FRESH1"),
						UserName:    aws.String("test-user"),
						Status:      iamtypes.StatusTypeActive,
						CreateDate:  daysAgo(30), // Fresh key
					},
				},
			}, nil
		},
		updateAccessKeyFn: func(ctx context.Context, params *iam.UpdateAccessKeyInput, optFns ...func(*iam.Options)) (*iam.UpdateAccessKeyOutput, error) {
			t.Fatal("UpdateAccessKey should not be called for fresh keys")
			return nil, nil
		},
	}

	r := newRotateIAMKeysRemediatorForTest(mockFactory(client))
	result, err := r.Remediate(context.Background(), testFinding("test-user", "us-east-1"))
	if err != nil {
		t.Fatalf("Remediate: %v", err)
	}
	if !result.Success {
		t.Error("expected success=true")
	}
	if !strings.Contains(result.Message, "No keys older") {
		t.Errorf("expected 'no keys older' message, got: %s", result.Message)
	}
}

func TestRemediate_NoKeysAtAll(t *testing.T) {
	client := &mockIAMClient{
		listAccessKeysFn: func(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
			return &iam.ListAccessKeysOutput{
				AccessKeyMetadata: []iamtypes.AccessKeyMetadata{},
			}, nil
		},
		updateAccessKeyFn: func(ctx context.Context, params *iam.UpdateAccessKeyInput, optFns ...func(*iam.Options)) (*iam.UpdateAccessKeyOutput, error) {
			t.Fatal("UpdateAccessKey should not be called with no keys")
			return nil, nil
		},
	}

	r := newRotateIAMKeysRemediatorForTest(mockFactory(client))
	result, err := r.Remediate(context.Background(), testFinding("test-user", "us-east-1"))
	if err != nil {
		t.Fatalf("Remediate: %v", err)
	}
	if !result.Success {
		t.Error("expected success=true")
	}
}

func TestRemediate_SkipsInactiveKeys(t *testing.T) {
	client := &mockIAMClient{
		listAccessKeysFn: func(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
			return &iam.ListAccessKeysOutput{
				AccessKeyMetadata: []iamtypes.AccessKeyMetadata{
					{
						AccessKeyId: aws.String("AKIAIOSFODNN7INACT1"),
						UserName:    aws.String("test-user"),
						Status:      iamtypes.StatusTypeInactive,
						CreateDate:  daysAgo(120),
					},
				},
			}, nil
		},
		updateAccessKeyFn: func(ctx context.Context, params *iam.UpdateAccessKeyInput, optFns ...func(*iam.Options)) (*iam.UpdateAccessKeyOutput, error) {
			t.Fatal("UpdateAccessKey should not be called for inactive keys")
			return nil, nil
		},
	}

	r := newRotateIAMKeysRemediatorForTest(mockFactory(client))
	result, err := r.Remediate(context.Background(), testFinding("test-user", "us-east-1"))
	if err != nil {
		t.Fatalf("Remediate: %v", err)
	}
	if !result.Success {
		t.Error("expected success=true")
	}
}

func TestRemediate_SkipsNilCreateDate(t *testing.T) {
	client := &mockIAMClient{
		listAccessKeysFn: func(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
			return &iam.ListAccessKeysOutput{
				AccessKeyMetadata: []iamtypes.AccessKeyMetadata{
					{
						AccessKeyId: aws.String("AKIAIOSFODNN7NODATE"),
						UserName:    aws.String("test-user"),
						Status:      iamtypes.StatusTypeActive,
						CreateDate:  nil, // No create date
					},
				},
			}, nil
		},
		updateAccessKeyFn: func(ctx context.Context, params *iam.UpdateAccessKeyInput, optFns ...func(*iam.Options)) (*iam.UpdateAccessKeyOutput, error) {
			t.Fatal("UpdateAccessKey should not be called when CreateDate is nil")
			return nil, nil
		},
	}

	r := newRotateIAMKeysRemediatorForTest(mockFactory(client))
	result, err := r.Remediate(context.Background(), testFinding("test-user", "us-east-1"))
	if err != nil {
		t.Fatalf("Remediate: %v", err)
	}
	if !result.Success {
		t.Error("expected success=true")
	}
}

func TestRemediate_MixedKeys(t *testing.T) {
	deactivated := 0
	client := &mockIAMClient{
		listAccessKeysFn: func(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
			return &iam.ListAccessKeysOutput{
				AccessKeyMetadata: []iamtypes.AccessKeyMetadata{
					{
						AccessKeyId: aws.String("AKIAIOSFODNN7OLD001"),
						UserName:    aws.String("test-user"),
						Status:      iamtypes.StatusTypeActive,
						CreateDate:  daysAgo(120), // Old — should be deactivated
					},
					{
						AccessKeyId: aws.String("AKIAIOSFODNN7FRESH2"),
						UserName:    aws.String("test-user"),
						Status:      iamtypes.StatusTypeActive,
						CreateDate:  daysAgo(30), // Fresh — skip
					},
					{
						AccessKeyId: aws.String("AKIAIOSFODNN7INACT3"),
						UserName:    aws.String("test-user"),
						Status:      iamtypes.StatusTypeInactive,
						CreateDate:  daysAgo(200), // Inactive — skip
					},
					{
						AccessKeyId: aws.String("AKIAIOSFODNN7OLD004"),
						UserName:    aws.String("test-user"),
						Status:      iamtypes.StatusTypeActive,
						CreateDate:  daysAgo(180), // Old — should be deactivated
					},
				},
			}, nil
		},
		updateAccessKeyFn: func(ctx context.Context, params *iam.UpdateAccessKeyInput, optFns ...func(*iam.Options)) (*iam.UpdateAccessKeyOutput, error) {
			deactivated++
			return &iam.UpdateAccessKeyOutput{}, nil
		},
	}

	r := newRotateIAMKeysRemediatorForTest(mockFactory(client))
	result, err := r.Remediate(context.Background(), testFinding("test-user", "us-east-1"))
	if err != nil {
		t.Fatalf("Remediate: %v", err)
	}
	if !result.Success {
		t.Error("expected success=true")
	}
	if deactivated != 2 {
		t.Errorf("expected 2 keys deactivated, got %d", deactivated)
	}
	if !strings.Contains(result.Message, "Deactivated 2") {
		t.Errorf("expected 'Deactivated 2' message, got: %s", result.Message)
	}
}

func TestRemediate_ListAccessKeysError(t *testing.T) {
	client := &mockIAMClient{
		listAccessKeysFn: func(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
			return nil, fmt.Errorf("access denied")
		},
		updateAccessKeyFn: func(ctx context.Context, params *iam.UpdateAccessKeyInput, optFns ...func(*iam.Options)) (*iam.UpdateAccessKeyOutput, error) {
			return nil, nil
		},
	}

	r := newRotateIAMKeysRemediatorForTest(mockFactory(client))
	_, err := r.Remediate(context.Background(), testFinding("test-user", "us-east-1"))
	if err == nil {
		t.Fatal("expected error from ListAccessKeys")
	}
	if !strings.Contains(err.Error(), "access denied") {
		t.Errorf("expected 'access denied' error, got: %v", err)
	}
}

func TestRemediate_UpdateAccessKeyError(t *testing.T) {
	client := &mockIAMClient{
		listAccessKeysFn: func(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
			return &iam.ListAccessKeysOutput{
				AccessKeyMetadata: []iamtypes.AccessKeyMetadata{
					{
						AccessKeyId: aws.String("AKIAIOSFODNN7OLD001"),
						UserName:    aws.String("test-user"),
						Status:      iamtypes.StatusTypeActive,
						CreateDate:  daysAgo(120),
					},
				},
			}, nil
		},
		updateAccessKeyFn: func(ctx context.Context, params *iam.UpdateAccessKeyInput, optFns ...func(*iam.Options)) (*iam.UpdateAccessKeyOutput, error) {
			return nil, fmt.Errorf("throttling exception")
		},
	}

	r := newRotateIAMKeysRemediatorForTest(mockFactory(client))
	result, err := r.Remediate(context.Background(), testFinding("test-user", "us-east-1"))
	if err == nil {
		t.Fatal("expected error from UpdateAccessKey")
	}
	if !strings.Contains(err.Error(), "deactivate key") {
		t.Errorf("expected 'deactivate key' error, got: %v", err)
	}
	// Result should still be returned (non-nil) with error info
	if result == nil {
		t.Fatal("expected non-nil result even on error")
	}
	if result.Error == "" {
		t.Error("expected non-empty Error field in result")
	}
}

func TestRemediate_FactoryError(t *testing.T) {
	r := newRotateIAMKeysRemediatorForTest(errorFactory("config not found"))
	_, err := r.Remediate(context.Background(), testFinding("test-user", "us-east-1"))
	if err == nil {
		t.Fatal("expected error from factory")
	}
	if !strings.Contains(err.Error(), "config not found") {
		t.Errorf("expected 'config not found' error, got: %v", err)
	}
}

// ---------- Validate tests ----------

func TestValidate_AllCompliant(t *testing.T) {
	client := &mockIAMClient{
		listAccessKeysFn: func(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
			return &iam.ListAccessKeysOutput{
				AccessKeyMetadata: []iamtypes.AccessKeyMetadata{
					{
						AccessKeyId: aws.String("AKIAIOSFODNN7FRESH1"),
						UserName:    aws.String("test-user"),
						Status:      iamtypes.StatusTypeActive,
						CreateDate:  daysAgo(30),
					},
					{
						AccessKeyId: aws.String("AKIAIOSFODNN7INACT2"),
						UserName:    aws.String("test-user"),
						Status:      iamtypes.StatusTypeInactive,
						CreateDate:  daysAgo(200), // Old but inactive — compliant
					},
				},
			}, nil
		},
		updateAccessKeyFn: func(ctx context.Context, params *iam.UpdateAccessKeyInput, optFns ...func(*iam.Options)) (*iam.UpdateAccessKeyOutput, error) {
			return nil, nil
		},
	}

	r := newRotateIAMKeysRemediatorForTest(mockFactory(client))
	val, err := r.Validate(context.Background(), testFinding("test-user", "us-east-1"))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !val.IsCompliant {
		t.Error("expected IsCompliant=true")
	}
	if !strings.Contains(val.Message, "within") {
		t.Errorf("expected compliance message, got: %s", val.Message)
	}
}

func TestValidate_StaleKeysFound(t *testing.T) {
	client := &mockIAMClient{
		listAccessKeysFn: func(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
			return &iam.ListAccessKeysOutput{
				AccessKeyMetadata: []iamtypes.AccessKeyMetadata{
					{
						AccessKeyId: aws.String("AKIAIOSFODNN7OLD001"),
						UserName:    aws.String("test-user"),
						Status:      iamtypes.StatusTypeActive,
						CreateDate:  daysAgo(120),
					},
				},
			}, nil
		},
		updateAccessKeyFn: func(ctx context.Context, params *iam.UpdateAccessKeyInput, optFns ...func(*iam.Options)) (*iam.UpdateAccessKeyOutput, error) {
			return nil, nil
		},
	}

	r := newRotateIAMKeysRemediatorForTest(mockFactory(client))
	val, err := r.Validate(context.Background(), testFinding("test-user", "us-east-1"))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if val.IsCompliant {
		t.Error("expected IsCompliant=false")
	}
	if !strings.Contains(val.Message, "exceed") {
		t.Errorf("expected 'exceed' message, got: %s", val.Message)
	}
	if len(val.Evidence) != 1 {
		t.Errorf("expected 1 evidence entry, got %d", len(val.Evidence))
	}
}

func TestValidate_ListAccessKeysError(t *testing.T) {
	client := &mockIAMClient{
		listAccessKeysFn: func(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
			return nil, fmt.Errorf("forbidden")
		},
		updateAccessKeyFn: func(ctx context.Context, params *iam.UpdateAccessKeyInput, optFns ...func(*iam.Options)) (*iam.UpdateAccessKeyOutput, error) {
			return nil, nil
		},
	}

	r := newRotateIAMKeysRemediatorForTest(mockFactory(client))
	_, err := r.Validate(context.Background(), testFinding("test-user", "us-east-1"))
	if err == nil {
		t.Fatal("expected error from ListAccessKeys")
	}
	if !strings.Contains(err.Error(), "forbidden") {
		t.Errorf("expected 'forbidden' error, got: %v", err)
	}
}

func TestValidate_FactoryError(t *testing.T) {
	r := newRotateIAMKeysRemediatorForTest(errorFactory("no credentials"))
	_, err := r.Validate(context.Background(), testFinding("test-user", "us-east-1"))
	if err == nil {
		t.Fatal("expected error from factory")
	}
	if !strings.Contains(err.Error(), "no credentials") {
		t.Errorf("expected 'no credentials' error, got: %v", err)
	}
}

func TestValidate_EmptyKeyList(t *testing.T) {
	client := &mockIAMClient{
		listAccessKeysFn: func(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
			return &iam.ListAccessKeysOutput{
				AccessKeyMetadata: []iamtypes.AccessKeyMetadata{},
			}, nil
		},
		updateAccessKeyFn: func(ctx context.Context, params *iam.UpdateAccessKeyInput, optFns ...func(*iam.Options)) (*iam.UpdateAccessKeyOutput, error) {
			return nil, nil
		},
	}

	r := newRotateIAMKeysRemediatorForTest(mockFactory(client))
	val, err := r.Validate(context.Background(), testFinding("test-user", "us-east-1"))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !val.IsCompliant {
		t.Error("expected IsCompliant=true for empty key list")
	}
}

// ---------- DryRun tests ----------

func TestDryRun_Success(t *testing.T) {
	r := newRotateIAMKeysRemediatorForTest(nil) // Factory not needed for DryRun
	result, err := r.DryRun(context.Background(), testFinding("test-user", "us-east-1"))
	if err != nil {
		t.Fatalf("DryRun: %v", err)
	}
	if !result.WouldSucceed {
		t.Error("expected WouldSucceed=true")
	}
	if !result.PrerequisitesMet {
		t.Error("expected PrerequisitesMet=true")
	}
	if len(result.PlannedActions) != 2 {
		t.Errorf("expected 2 planned actions, got %d", len(result.PlannedActions))
	}
	if len(result.Warnings) < 2 {
		t.Errorf("expected at least 2 warnings, got %d", len(result.Warnings))
	}
	if result.EstimatedImpact == "" {
		t.Error("expected non-empty EstimatedImpact")
	}
}

// ---------- Tier test ----------

func TestTier_Returns2(t *testing.T) {
	r := newRotateIAMKeysRemediatorForTest(nil)
	if r.Tier() != 2 {
		t.Errorf("expected tier 2, got %d", r.Tier())
	}
}

// ---------- maskKeyID (regression, already covered by existing test) ----------

func TestMaskKeyID_Variants(t *testing.T) {
	tests := []struct {
		input *string
		want  string
	}{
		{nil, "<nil>"},
		{aws.String("AB"), "****"},
		{aws.String("ABCD"), "****"},
		{aws.String("AKIAIOSFODNN7EXAMPLE"), "****MPLE"},
	}

	for _, tt := range tests {
		got := maskKeyID(tt.input)
		if got != tt.want {
			t.Errorf("maskKeyID(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
