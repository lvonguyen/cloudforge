package security_services

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/guardduty/types"

	cspmscoring "cloudforge/internal/cspm/scoring"
)

// mockGuardDutyClient implements guardDutyAPI for testing.
type mockGuardDutyClient struct {
	createDetectorFn func(ctx context.Context, params *guardduty.CreateDetectorInput, optFns ...func(*guardduty.Options)) (*guardduty.CreateDetectorOutput, error)
	listDetectorsFn  func(ctx context.Context, params *guardduty.ListDetectorsInput, optFns ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error)
	getDetectorFn    func(ctx context.Context, params *guardduty.GetDetectorInput, optFns ...func(*guardduty.Options)) (*guardduty.GetDetectorOutput, error)
}

func (m *mockGuardDutyClient) CreateDetector(ctx context.Context, params *guardduty.CreateDetectorInput, optFns ...func(*guardduty.Options)) (*guardduty.CreateDetectorOutput, error) {
	return m.createDetectorFn(ctx, params, optFns...)
}

func (m *mockGuardDutyClient) ListDetectors(ctx context.Context, params *guardduty.ListDetectorsInput, optFns ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error) {
	return m.listDetectorsFn(ctx, params, optFns...)
}

func (m *mockGuardDutyClient) GetDetector(ctx context.Context, params *guardduty.GetDetectorInput, optFns ...func(*guardduty.Options)) (*guardduty.GetDetectorOutput, error) {
	return m.getDetectorFn(ctx, params, optFns...)
}

func makeGuardDutyFinding(id, region string) *cspmscoring.PrioritizedFinding {
	return &cspmscoring.PrioritizedFinding{
		Finding: &cspmscoring.Finding{
			ID:          id,
			Source:      "guardduty",
			Severity:    "HIGH",
			FindingType: "GuardDuty.1",
			ResourceID:  "arn:aws:guardduty:us-east-1:123456789012:detector",
			AccountID:   "123456789012",
			Region:      region,
		},
	}
}

func mockFactory(client guardDutyAPI) func(ctx context.Context, region string) (guardDutyAPI, error) {
	return func(ctx context.Context, region string) (guardDutyAPI, error) {
		return client, nil
	}
}

func failingFactory(errMsg string) func(ctx context.Context, region string) (guardDutyAPI, error) {
	return func(ctx context.Context, region string) (guardDutyAPI, error) {
		return nil, fmt.Errorf("%s", errMsg)
	}
}

// ---------------------------------------------------------------------------
// GuardDuty — Tier
// ---------------------------------------------------------------------------

func TestGuardDutyRemediator_Tier(t *testing.T) {
	r := NewGuardDutyRemediator()
	if got := r.Tier(); got != 1 {
		t.Fatalf("Tier() = %d, want 1", got)
	}
}

// ---------------------------------------------------------------------------
// GuardDuty — Remediate
// ---------------------------------------------------------------------------

func TestGuardDutyRemediator_Remediate_Success(t *testing.T) {
	mock := &mockGuardDutyClient{
		createDetectorFn: func(ctx context.Context, params *guardduty.CreateDetectorInput, optFns ...func(*guardduty.Options)) (*guardduty.CreateDetectorOutput, error) {
			return &guardduty.CreateDetectorOutput{
				DetectorId: aws.String("det-abc123"),
			}, nil
		},
	}

	r := newGuardDutyRemediatorForTest(mockFactory(mock))
	finding := makeGuardDutyFinding("gd-1", "us-east-1")

	result, err := r.Remediate(context.Background(), finding)
	if err != nil {
		t.Fatalf("Remediate: %v", err)
	}
	if !result.Success {
		t.Fatal("expected Success=true")
	}
	if result.FindingID != "gd-1" {
		t.Errorf("FindingID = %q, want %q", result.FindingID, "gd-1")
	}
	if len(result.Actions) != 4 {
		t.Errorf("expected 4 actions, got %d", len(result.Actions))
	}
	if result.Duration == "" {
		t.Error("expected non-empty Duration")
	}
}

func TestGuardDutyRemediator_Remediate_CreateDetectorError(t *testing.T) {
	mock := &mockGuardDutyClient{
		createDetectorFn: func(ctx context.Context, params *guardduty.CreateDetectorInput, optFns ...func(*guardduty.Options)) (*guardduty.CreateDetectorOutput, error) {
			return nil, fmt.Errorf("detector already exists")
		},
	}

	r := newGuardDutyRemediatorForTest(mockFactory(mock))
	finding := makeGuardDutyFinding("gd-2", "us-west-2")

	result, err := r.Remediate(context.Background(), finding)
	if err == nil {
		t.Fatal("expected error from CreateDetector")
	}
	if result == nil {
		t.Fatal("expected non-nil result even on error")
	}
	if result.Success {
		t.Fatal("expected Success=false on error")
	}
	if result.Error == "" {
		t.Error("expected non-empty Error field")
	}
}

func TestGuardDutyRemediator_Remediate_FactoryError(t *testing.T) {
	r := newGuardDutyRemediatorForTest(failingFactory("config load failed"))
	finding := makeGuardDutyFinding("gd-3", "eu-west-1")

	_, err := r.Remediate(context.Background(), finding)
	if err == nil {
		t.Fatal("expected error from factory")
	}
}

// ---------------------------------------------------------------------------
// GuardDuty — Validate
// ---------------------------------------------------------------------------

func TestGuardDutyRemediator_Validate_Success(t *testing.T) {
	mock := &mockGuardDutyClient{
		listDetectorsFn: func(ctx context.Context, params *guardduty.ListDetectorsInput, optFns ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error) {
			return &guardduty.ListDetectorsOutput{
				DetectorIds: []string{"det-abc123"},
			}, nil
		},
		getDetectorFn: func(ctx context.Context, params *guardduty.GetDetectorInput, optFns ...func(*guardduty.Options)) (*guardduty.GetDetectorOutput, error) {
			return &guardduty.GetDetectorOutput{
				Status:                     types.DetectorStatusEnabled,
				FindingPublishingFrequency: types.FindingPublishingFrequencyFifteenMinutes,
			}, nil
		},
	}

	r := newGuardDutyRemediatorForTest(mockFactory(mock))
	finding := makeGuardDutyFinding("gd-val-1", "us-east-1")

	result, err := r.Validate(context.Background(), finding)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !result.IsCompliant {
		t.Fatal("expected IsCompliant=true")
	}
	if len(result.Evidence) < 3 {
		t.Errorf("expected at least 3 evidence items, got %d", len(result.Evidence))
	}
}

func TestGuardDutyRemediator_Validate_NoDetectors(t *testing.T) {
	mock := &mockGuardDutyClient{
		listDetectorsFn: func(ctx context.Context, params *guardduty.ListDetectorsInput, optFns ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error) {
			return &guardduty.ListDetectorsOutput{
				DetectorIds: []string{},
			}, nil
		},
	}

	r := newGuardDutyRemediatorForTest(mockFactory(mock))
	finding := makeGuardDutyFinding("gd-val-2", "us-east-1")

	result, err := r.Validate(context.Background(), finding)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result.IsCompliant {
		t.Fatal("expected IsCompliant=false when no detectors found")
	}
}

func TestGuardDutyRemediator_Validate_DetectorDisabled(t *testing.T) {
	mock := &mockGuardDutyClient{
		listDetectorsFn: func(ctx context.Context, params *guardduty.ListDetectorsInput, optFns ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error) {
			return &guardduty.ListDetectorsOutput{
				DetectorIds: []string{"det-disabled"},
			}, nil
		},
		getDetectorFn: func(ctx context.Context, params *guardduty.GetDetectorInput, optFns ...func(*guardduty.Options)) (*guardduty.GetDetectorOutput, error) {
			return &guardduty.GetDetectorOutput{
				Status: types.DetectorStatusDisabled,
			}, nil
		},
	}

	r := newGuardDutyRemediatorForTest(mockFactory(mock))
	finding := makeGuardDutyFinding("gd-val-3", "us-east-1")

	result, err := r.Validate(context.Background(), finding)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result.IsCompliant {
		t.Fatal("expected IsCompliant=false when detector is disabled")
	}
}

func TestGuardDutyRemediator_Validate_ListDetectorsError(t *testing.T) {
	mock := &mockGuardDutyClient{
		listDetectorsFn: func(ctx context.Context, params *guardduty.ListDetectorsInput, optFns ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error) {
			return nil, fmt.Errorf("permission denied")
		},
	}

	r := newGuardDutyRemediatorForTest(mockFactory(mock))
	finding := makeGuardDutyFinding("gd-val-4", "us-east-1")

	_, err := r.Validate(context.Background(), finding)
	if err == nil {
		t.Fatal("expected error from ListDetectors")
	}
}

func TestGuardDutyRemediator_Validate_GetDetectorError(t *testing.T) {
	mock := &mockGuardDutyClient{
		listDetectorsFn: func(ctx context.Context, params *guardduty.ListDetectorsInput, optFns ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error) {
			return &guardduty.ListDetectorsOutput{
				DetectorIds: []string{"det-err"},
			}, nil
		},
		getDetectorFn: func(ctx context.Context, params *guardduty.GetDetectorInput, optFns ...func(*guardduty.Options)) (*guardduty.GetDetectorOutput, error) {
			return nil, fmt.Errorf("throttling exception")
		},
	}

	r := newGuardDutyRemediatorForTest(mockFactory(mock))
	finding := makeGuardDutyFinding("gd-val-5", "us-east-1")

	_, err := r.Validate(context.Background(), finding)
	if err == nil {
		t.Fatal("expected error from GetDetector")
	}
}

func TestGuardDutyRemediator_Validate_FactoryError(t *testing.T) {
	r := newGuardDutyRemediatorForTest(failingFactory("no credentials"))
	finding := makeGuardDutyFinding("gd-val-6", "us-east-1")

	_, err := r.Validate(context.Background(), finding)
	if err == nil {
		t.Fatal("expected error from factory")
	}
}

// ---------------------------------------------------------------------------
// GuardDuty — DryRun
// ---------------------------------------------------------------------------

func TestGuardDutyRemediator_DryRun_Success(t *testing.T) {
	mock := &mockGuardDutyClient{
		listDetectorsFn: func(ctx context.Context, params *guardduty.ListDetectorsInput, optFns ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error) {
			return &guardduty.ListDetectorsOutput{
				DetectorIds: []string{},
			}, nil
		},
	}

	r := newGuardDutyRemediatorForTest(mockFactory(mock))
	finding := makeGuardDutyFinding("gd-dry-1", "us-east-1")

	result, err := r.DryRun(context.Background(), finding)
	if err != nil {
		t.Fatalf("DryRun: %v", err)
	}
	if !result.WouldSucceed {
		t.Fatal("expected WouldSucceed=true")
	}
	if !result.PrerequisitesMet {
		t.Fatal("expected PrerequisitesMet=true")
	}
	if len(result.PlannedActions) < 4 {
		t.Errorf("expected at least 4 planned actions, got %d", len(result.PlannedActions))
	}
}

func TestGuardDutyRemediator_DryRun_CredentialsError(t *testing.T) {
	r := newGuardDutyRemediatorForTest(failingFactory("invalid credentials"))
	finding := makeGuardDutyFinding("gd-dry-2", "us-east-1")

	result, err := r.DryRun(context.Background(), finding)
	if err != nil {
		t.Fatalf("DryRun should not return error: %v", err)
	}
	if result.WouldSucceed {
		t.Fatal("expected WouldSucceed=false when credentials fail")
	}
	if result.PrerequisitesMet {
		t.Fatal("expected PrerequisitesMet=false when credentials fail")
	}
	if len(result.Warnings) == 0 {
		t.Fatal("expected warnings about credentials")
	}
}

func TestGuardDutyRemediator_DryRun_AlreadyEnabled(t *testing.T) {
	mock := &mockGuardDutyClient{
		listDetectorsFn: func(ctx context.Context, params *guardduty.ListDetectorsInput, optFns ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error) {
			return &guardduty.ListDetectorsOutput{
				DetectorIds: []string{"det-existing"},
			}, nil
		},
	}

	r := newGuardDutyRemediatorForTest(mockFactory(mock))
	finding := makeGuardDutyFinding("gd-dry-3", "us-east-1")

	result, err := r.DryRun(context.Background(), finding)
	if err != nil {
		t.Fatalf("DryRun: %v", err)
	}
	if !result.WouldSucceed {
		t.Fatal("expected WouldSucceed=true")
	}
	if len(result.Warnings) == 0 {
		t.Fatal("expected warning about already-enabled GuardDuty")
	}
}

func TestGuardDutyRemediator_DryRun_ListDetectorsError(t *testing.T) {
	mock := &mockGuardDutyClient{
		listDetectorsFn: func(ctx context.Context, params *guardduty.ListDetectorsInput, optFns ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error) {
			return nil, fmt.Errorf("throttled")
		},
	}

	r := newGuardDutyRemediatorForTest(mockFactory(mock))
	finding := makeGuardDutyFinding("gd-dry-4", "us-east-1")

	result, err := r.DryRun(context.Background(), finding)
	if err != nil {
		t.Fatalf("DryRun should not return error: %v", err)
	}
	// When ListDetectors errors, we just don't add the warning; the dry run still succeeds
	if !result.WouldSucceed {
		t.Fatal("expected WouldSucceed=true even when ListDetectors errors")
	}
}

// ---------------------------------------------------------------------------
// GuardDuty — NewGuardDutyRemediator (production constructor)
// ---------------------------------------------------------------------------

func TestNewGuardDutyRemediator_HasFactory(t *testing.T) {
	r := NewGuardDutyRemediator()
	if r.clientFactory == nil {
		t.Fatal("expected non-nil clientFactory")
	}
	if r.tier != 1 {
		t.Errorf("tier = %d, want 1", r.tier)
	}
}
