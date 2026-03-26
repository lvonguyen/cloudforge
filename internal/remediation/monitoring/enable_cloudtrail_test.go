package monitoring

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"

	cspmscoring "aegis/internal/cspm/scoring"
)

type mockCloudTrailClient struct {
	isLogging  bool
	startErr   error
	latestTime *time.Time
}

func (m *mockCloudTrailClient) StartLogging(_ context.Context, _ *cloudtrail.StartLoggingInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.StartLoggingOutput, error) {
	if m.startErr != nil {
		return nil, m.startErr
	}
	m.isLogging = true
	return &cloudtrail.StartLoggingOutput{}, nil
}

func (m *mockCloudTrailClient) GetTrailStatus(_ context.Context, _ *cloudtrail.GetTrailStatusInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error) {
	return &cloudtrail.GetTrailStatusOutput{
		IsLogging:          aws.Bool(m.isLogging),
		LatestDeliveryTime: m.latestTime,
	}, nil
}

func ctTestFinding(id, trailARN string) *cspmscoring.PrioritizedFinding {
	return &cspmscoring.PrioritizedFinding{
		Finding: &cspmscoring.Finding{
			ID:          id,
			FindingType: "CLOUDTRAIL_DISABLED",
			ResourceID:  trailARN,
			Region:      "us-east-1",
			AccountID:   "123456789012",
		},
		AutoRemediationReady: true,
	}
}

func TestEnableCloudTrail_Tier(t *testing.T) {
	r := NewEnableCloudTrailRemediator()
	if r.Tier() != 1 {
		t.Errorf("expected tier 1, got %d", r.Tier())
	}
}

func TestEnableCloudTrail_Remediate(t *testing.T) {
	mock := &mockCloudTrailClient{}
	r := NewEnableCloudTrailRemediator(WithCloudTrailClient(mock))
	finding := ctTestFinding("f-001", "arn:aws:cloudtrail:us-east-1:123456789012:trail/mgmt-trail")

	result, err := r.Remediate(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Errorf("expected success, got: %s", result.Message)
	}
	if !mock.isLogging {
		t.Error("expected logging to be enabled after remediation")
	}
}

func TestEnableCloudTrail_Validate_Compliant(t *testing.T) {
	mock := &mockCloudTrailClient{isLogging: true}
	r := NewEnableCloudTrailRemediator(WithCloudTrailClient(mock))
	finding := ctTestFinding("f-001", "arn:aws:cloudtrail:us-east-1:123456789012:trail/mgmt-trail")

	validation, err := r.Validate(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !validation.IsCompliant {
		t.Errorf("expected compliant, got: %s", validation.Message)
	}
}

func TestEnableCloudTrail_Validate_NonCompliant(t *testing.T) {
	mock := &mockCloudTrailClient{isLogging: false}
	r := NewEnableCloudTrailRemediator(WithCloudTrailClient(mock))
	finding := ctTestFinding("f-001", "arn:aws:cloudtrail:us-east-1:123456789012:trail/mgmt-trail")

	validation, err := r.Validate(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if validation.IsCompliant {
		t.Error("expected non-compliant for trail not logging")
	}
}

func TestEnableCloudTrail_DryRun(t *testing.T) {
	r := NewEnableCloudTrailRemediator(WithCloudTrailClient(&mockCloudTrailClient{}))
	finding := ctTestFinding("f-001", "arn:aws:cloudtrail:us-east-1:123456789012:trail/mgmt-trail")

	dryRun, err := r.DryRun(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !dryRun.WouldSucceed {
		t.Error("expected dry run to succeed")
	}
}

func TestExtractTrailName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"arn:aws:cloudtrail:us-east-1:123456789012:trail/mgmt-trail", "mgmt-trail"},
		{"mgmt-trail", "mgmt-trail"},
	}
	for _, tt := range tests {
		got := extractTrailName(tt.input)
		if got != tt.want {
			t.Errorf("extractTrailName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
