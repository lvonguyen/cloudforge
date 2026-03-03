package security_services

import (
	"context"
	"testing"

	cspmscoring "cloudforge/internal/cspm/scoring"
)

func makeAzureFinding(id string) *cspmscoring.PrioritizedFinding {
	return &cspmscoring.PrioritizedFinding{
		Finding: &cspmscoring.Finding{
			ID:          id,
			Source:      "azure-defender",
			Severity:    "HIGH",
			FindingType: "Defender.Storage",
			ResourceID:  "/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/prodstorage",
			AccountID:   "sub-123",
			Region:      "eastus",
		},
	}
}

func TestAzureDefenderStorage_Tier(t *testing.T) {
	r := NewAzureDefenderStorageRemediator()
	if got := r.Tier(); got != 1 {
		t.Fatalf("expected tier 1, got %d", got)
	}
}

func TestAzureDefenderStorage_Remediate(t *testing.T) {
	tests := []struct {
		name        string
		finding     *cspmscoring.PrioritizedFinding
		wantSuccess bool
		wantMsgPart string
	}{
		{
			name:        "stub returns not implemented",
			finding:     makeAzureFinding("az-1"),
			wantSuccess: false,
			wantMsgPart: "Azure SDK",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewAzureDefenderStorageRemediator()
			result, err := r.Remediate(context.Background(), tt.finding)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Success != tt.wantSuccess {
				t.Fatalf("expected success=%v, got %v", tt.wantSuccess, result.Success)
			}
			if result.FindingID != tt.finding.Finding.ID {
				t.Fatalf("expected finding ID %q, got %q", tt.finding.Finding.ID, result.FindingID)
			}
			if len(result.Actions) == 0 {
				t.Fatal("expected non-empty actions list")
			}
		})
	}
}

func TestAzureDefenderStorage_Validate(t *testing.T) {
	r := NewAzureDefenderStorageRemediator()
	finding := makeAzureFinding("az-val-1")

	result, err := r.Validate(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsCompliant {
		t.Fatal("expected IsCompliant=false for stub handler")
	}
	if result.FindingID != finding.Finding.ID {
		t.Fatalf("expected finding ID %q, got %q", finding.Finding.ID, result.FindingID)
	}
	if len(result.Evidence) == 0 {
		t.Fatal("expected non-empty evidence")
	}
}

func TestAzureDefenderStorage_DryRun(t *testing.T) {
	r := NewAzureDefenderStorageRemediator()
	finding := makeAzureFinding("az-dry-1")

	result, err := r.DryRun(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.FindingID != finding.Finding.ID {
		t.Fatalf("expected finding ID %q, got %q", finding.Finding.ID, result.FindingID)
	}
	if result.WouldSucceed != true {
		t.Fatal("expected WouldSucceed=true")
	}
	if result.PrerequisitesMet != false {
		t.Fatal("expected PrerequisitesMet=false (Azure SDK not integrated)")
	}
	if len(result.PlannedActions) == 0 {
		t.Fatal("expected non-empty planned actions")
	}
	if len(result.Warnings) == 0 {
		t.Fatal("expected warnings about Azure SDK")
	}
}
