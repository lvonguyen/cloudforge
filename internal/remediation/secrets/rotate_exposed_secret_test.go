package secrets

import (
	"context"
	"strings"
	"testing"

	cspmscoring "aegis/internal/cspm/scoring"
)

func makeSecretFinding(id, resourceID string) *cspmscoring.PrioritizedFinding {
	return &cspmscoring.PrioritizedFinding{
		Finding: &cspmscoring.Finding{
			ID:          id,
			Source:      "github-secret-scanning",
			Severity:    "CRITICAL",
			FindingType: "EXPOSED_SECRET",
			ResourceID:  resourceID,
			AccountID:   "acct-123",
			Region:      "us-east-1",
		},
	}
}

func TestRotateExposedSecret_Tier(t *testing.T) {
	r := NewRotateExposedSecretRemediator()
	if got := r.Tier(); got != 2 {
		t.Fatalf("expected tier 2, got %d", got)
	}
}

func TestRotateExposedSecret_Remediate(t *testing.T) {
	tests := []struct {
		name        string
		resourceID  string
		wantSuccess bool
		wantActions int
	}{
		{
			name:        "returns manual rotation guidance",
			resourceID:  "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod-db-password",
			wantSuccess: false,
			wantActions: 4,
		},
		{
			name:        "handles generic secret resource",
			resourceID:  "github.com/org/repo/blob/main/.env",
			wantSuccess: false,
			wantActions: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRotateExposedSecretRemediator()
			finding := makeSecretFinding("sec-"+tt.name, tt.resourceID)

			result, err := r.Remediate(context.Background(), finding)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Success != tt.wantSuccess {
				t.Fatalf("expected success=%v, got %v", tt.wantSuccess, result.Success)
			}
			if len(result.Actions) != tt.wantActions {
				t.Fatalf("expected %d actions, got %d: %v", tt.wantActions, len(result.Actions), result.Actions)
			}
			if !strings.Contains(result.Actions[0], tt.resourceID) {
				t.Fatalf("expected first action to reference resource ID %q, got %q", tt.resourceID, result.Actions[0])
			}
			if !strings.Contains(result.Message, "manual intervention") {
				t.Fatalf("expected message about manual intervention, got %q", result.Message)
			}
		})
	}
}

func TestRotateExposedSecret_Validate(t *testing.T) {
	r := NewRotateExposedSecretRemediator()
	finding := makeSecretFinding("sec-val-1", "secret-resource")

	result, err := r.Validate(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsCompliant {
		t.Fatal("expected IsCompliant=false (manual verification required)")
	}
	if !strings.Contains(result.Message, "Manual verification") {
		t.Fatalf("expected message about manual verification, got %q", result.Message)
	}
	if len(result.Evidence) < 3 {
		t.Fatalf("expected at least 3 evidence items, got %d", len(result.Evidence))
	}
}

func TestRotateExposedSecret_DryRun(t *testing.T) {
	r := NewRotateExposedSecretRemediator()
	finding := makeSecretFinding("sec-dry-1", "secret-resource")

	result, err := r.DryRun(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.WouldSucceed {
		t.Fatal("expected WouldSucceed=false (secrets cannot be auto-rotated)")
	}
	if !result.PrerequisitesMet {
		t.Fatal("expected PrerequisitesMet=true")
	}
	if len(result.PlannedActions) < 6 {
		t.Fatalf("expected at least 6 planned actions (rotation steps), got %d", len(result.PlannedActions))
	}
	if len(result.Warnings) < 2 {
		t.Fatalf("expected at least 2 warnings, got %d", len(result.Warnings))
	}
}
