package patching

import (
	"context"
	"testing"

	cspmscoring "cloudforge/internal/cspm/scoring"
)

func TestCovNewOSPatchRemediator(t *testing.T) {
	r := NewOSPatchRemediator()
	if r.Tier() != 3 {
		t.Errorf("Tier() = %d, want 3", r.Tier())
	}
}

func TestCovOSPatchRemediator_DryRun(t *testing.T) {
	r := NewOSPatchRemediator()
	finding := &cspmscoring.PrioritizedFinding{
		Finding: &cspmscoring.Finding{
			ID:         "f-1",
			ResourceID: "arn:aws:ec2:us-east-1:123:instance/i-12345",
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

func TestCovExtractInstanceID(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"arn:aws:ec2:us-east-1:123:instance/i-12345", "i-12345"},
		{"i-12345", "i-12345"},
		{"some-other-id", "some-other-id"},
	}
	for _, tt := range tests {
		got := extractInstanceID(tt.input)
		if got != tt.want {
			t.Errorf("extractInstanceID(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
