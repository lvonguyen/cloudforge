package identity

import (
	"context"
	"testing"

	cspmscoring "cloudforge/internal/cspm/scoring"
)

func TestCovNewRotateIAMKeysRemediator(t *testing.T) {
	r := NewRotateIAMKeysRemediator()
	if r.Tier() != 2 {
		t.Errorf("Tier() = %d, want 2", r.Tier())
	}
}

func TestCovRotateIAMKeysRemediator_DryRun(t *testing.T) {
	r := NewRotateIAMKeysRemediator()
	finding := &cspmscoring.PrioritizedFinding{
		Finding: &cspmscoring.Finding{
			ID:         "f-1",
			ResourceID: "admin-user",
			Region:     "us-east-1",
		},
	}

	result, err := r.DryRun(context.Background(), finding)
	if err != nil {
		t.Fatalf("DryRun: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.PlannedActions) == 0 {
		t.Error("expected planned actions")
	}
	if len(result.Warnings) == 0 {
		t.Error("expected warnings")
	}
}

func TestCovMaskKeyID(t *testing.T) {
	tests := []struct {
		input *string
		want  string
	}{
		{nil, "<nil>"},
		{strPtr("AB"), "****"},
		{strPtr("AKIAIOSFODNN7EXAMPLE"), "****MPLE"},
	}
	for _, tt := range tests {
		got := maskKeyID(tt.input)
		if got != tt.want {
			t.Errorf("maskKeyID(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func strPtr(s string) *string { return &s }
