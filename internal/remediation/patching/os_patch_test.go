package patching

import (
	"context"
	"strings"
	"testing"

	cspmscoring "aegis/internal/cspm/scoring"
)

func makePatchFinding(id, resourceID string) *cspmscoring.PrioritizedFinding {
	return &cspmscoring.PrioritizedFinding{
		Finding: &cspmscoring.Finding{
			ID:          id,
			Source:      "aws-securityhub",
			Severity:    "HIGH",
			FindingType: "OS_PATCH_MISSING",
			ResourceID:  resourceID,
			Region:      "us-east-1",
			AccountID:   "123456789012",
		},
	}
}

func TestOSPatch_Tier(t *testing.T) {
	r := NewOSPatchRemediator()
	if got := r.Tier(); got != 3 {
		t.Fatalf("expected tier 3, got %d", got)
	}
}

func TestExtractInstanceID_Patching(t *testing.T) {
	tests := []struct {
		name       string
		resourceID string
		want       string
	}{
		{
			name:       "full ARN",
			resourceID: "arn:aws:ec2:us-east-1:123456789012:instance/i-patch001",
			want:       "i-patch001",
		},
		{
			name:       "plain instance ID",
			resourceID: "i-patch001",
			want:       "i-patch001",
		},
		{
			name:       "unknown format passes through",
			resourceID: "unknown-resource",
			want:       "unknown-resource",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractInstanceID(tt.resourceID)
			if got != tt.want {
				t.Fatalf("extractInstanceID(%q) = %q, want %q", tt.resourceID, got, tt.want)
			}
		})
	}
}

func TestOSPatch_DryRun(t *testing.T) {
	r := NewOSPatchRemediator()
	finding := makePatchFinding("patch-dry-1", "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123")

	result, err := r.DryRun(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.WouldSucceed {
		t.Fatal("expected WouldSucceed=false (patching requires change window)")
	}
	if !result.PrerequisitesMet {
		t.Fatal("expected PrerequisitesMet=true")
	}
	if len(result.PlannedActions) < 3 {
		t.Fatalf("expected at least 3 planned actions, got %d", len(result.PlannedActions))
	}
	if len(result.Warnings) < 3 {
		t.Fatalf("expected at least 3 warnings, got %d", len(result.Warnings))
	}

	hasChangeWindow := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "change window") {
			hasChangeWindow = true
			break
		}
	}
	if !hasChangeWindow {
		t.Fatal("expected warning about change window requirement")
	}
}
