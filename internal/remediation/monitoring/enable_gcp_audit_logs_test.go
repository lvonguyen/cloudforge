package monitoring

import (
	"context"
	"testing"

	cspmscoring "aegis/internal/cspm/scoring"
)

type mockGCPAuditClient struct {
	config *GCPAuditConfig
	setErr error
}

func (m *mockGCPAuditClient) GetAuditLogConfig(_ context.Context, _ string) (*GCPAuditConfig, error) {
	return m.config, nil
}

func (m *mockGCPAuditClient) SetAuditLogConfig(_ context.Context, _ string, config *GCPAuditConfig) error {
	if m.setErr != nil {
		return m.setErr
	}
	m.config = config
	return nil
}

func gcpTestFinding(id, projectID string) *cspmscoring.PrioritizedFinding {
	return &cspmscoring.PrioritizedFinding{
		Finding: &cspmscoring.Finding{
			ID:          id,
			FindingType: "GCP_AUDIT_LOGS_DISABLED",
			ResourceID:  "projects/" + projectID,
			Region:      "us-central1",
			AccountID:   projectID,
		},
		AutoRemediationReady: true,
	}
}

func TestEnableGCPAuditLogs_Tier(t *testing.T) {
	r := NewEnableGCPAuditLogsRemediator()
	if r.Tier() != 1 {
		t.Errorf("expected tier 1, got %d", r.Tier())
	}
}

func TestEnableGCPAuditLogs_Remediate(t *testing.T) {
	mock := &mockGCPAuditClient{
		config: &GCPAuditConfig{ProjectID: "my-project"},
	}
	r := NewEnableGCPAuditLogsRemediator(WithGCPAuditClient(mock))
	finding := gcpTestFinding("f-001", "my-project")

	result, err := r.Remediate(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Errorf("expected success, got: %s", result.Message)
	}
	if !mock.config.AdminReadLogs || !mock.config.DataReadLogs || !mock.config.DataWriteLogs {
		t.Error("expected all audit log types to be enabled after remediation")
	}
}

func TestEnableGCPAuditLogs_Validate_Compliant(t *testing.T) {
	mock := &mockGCPAuditClient{
		config: &GCPAuditConfig{
			ProjectID: "my-project", AdminReadLogs: true, DataReadLogs: true, DataWriteLogs: true,
		},
	}
	r := NewEnableGCPAuditLogsRemediator(WithGCPAuditClient(mock))
	finding := gcpTestFinding("f-001", "my-project")

	validation, err := r.Validate(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !validation.IsCompliant {
		t.Errorf("expected compliant, got: %s", validation.Message)
	}
}

func TestEnableGCPAuditLogs_Validate_NonCompliant(t *testing.T) {
	mock := &mockGCPAuditClient{
		config: &GCPAuditConfig{
			ProjectID: "my-project", AdminReadLogs: true, DataReadLogs: false, DataWriteLogs: true,
		},
	}
	r := NewEnableGCPAuditLogsRemediator(WithGCPAuditClient(mock))
	finding := gcpTestFinding("f-001", "my-project")

	validation, err := r.Validate(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if validation.IsCompliant {
		t.Error("expected non-compliant when DATA_READ is disabled")
	}
}

func TestExtractGCPProjectID(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"projects/my-project", "my-project"},
		{"projects/my-project/locations/us-central1", "my-project"},
		{"my-project", "my-project"},
	}
	for _, tt := range tests {
		got := extractGCPProjectID(tt.input)
		if got != tt.want {
			t.Errorf("extractGCPProjectID(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
