package security_services

import (
	"context"
	"testing"

	cspmscoring "cloudforge/internal/cspm/scoring"
)

func TestCovNewGuardDutyRemediator(t *testing.T) {
	r := NewGuardDutyRemediator()
	if r.Tier() != 1 {
		t.Errorf("Tier() = %d, want 1", r.Tier())
	}
}

func TestCovGuardDutyRemediator_DryRun(t *testing.T) {
	r := NewGuardDutyRemediator()
	finding := &cspmscoring.PrioritizedFinding{
		Finding: &cspmscoring.Finding{
			ID:     "f-1",
			Region: "us-east-1",
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
}
