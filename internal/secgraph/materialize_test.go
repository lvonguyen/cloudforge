package secgraph

import (
	"testing"
	"time"

	"aegis/internal/compliance"
	"go.uber.org/zap"
)

func TestBuildControlsFromManager(t *testing.T) {
	manager := compliance.NewManager(zap.NewNop())
	now := time.Date(2026, time.March, 31, 2, 0, 0, 0, time.UTC)

	controls := BuildControlsFromManager(manager, "tenant-a", now)
	if len(controls) == 0 {
		t.Fatal("expected seeded controls")
	}

	if controls[0].TenantID != "tenant-a" {
		t.Fatalf("tenant_id = %q, want tenant-a", controls[0].TenantID)
	}

	found := false
	for _, control := range controls {
		if control.FrameworkID == "cis-benchmarks" {
			found = true
			if control.ID == "" {
				t.Fatal("expected canonical control ID")
			}
			break
		}
	}
	if !found {
		t.Fatal("expected at least one CIS-derived control")
	}
}

func TestMaterializeFindingProducesDeterministicArtifacts(t *testing.T) {
	now := time.Date(2026, time.March, 31, 3, 0, 0, 0, time.UTC)
	finding := &compliance.Finding{
		ID:               "F-001",
		Title:            "Bucket allows public read",
		ResourceID:       "arn:aws:s3:::bucket-a",
		ResourceName:     "bucket-a",
		ResourceType:     compliance.ResourceTypeStorage,
		CloudProvider:    compliance.CloudProviderAWS,
		AccountID:        "123456789012",
		Severity:         "HIGH",
		Category:         compliance.CategoryNetwork,
		ExploitAvailable: true,
		ImpactedResources: []compliance.ImpactedResource{
			{ResourceID: "arn:aws:iam::123456789012:role/Admin", ResourceName: "Admin", ResourceType: "identity"},
			{ResourceID: "arn:aws:rds:us-east-1:123456789012:db/customer", ResourceName: "customer", ResourceType: "database"},
		},
		ComplianceMappings: []compliance.ComplianceMapping{
			{
				FrameworkID:   "cis-benchmarks",
				FrameworkName: "CIS Benchmarks",
				ControlID:     "3.1",
				ControlTitle:  "Data must be protected at rest",
				Severity:      "CRITICAL",
			},
		},
	}

	result := MaterializeFinding(finding, "tenant-a", now)

	if len(result.Controls) != 1 {
		t.Fatalf("controls = %d, want 1", len(result.Controls))
	}
	if len(result.Evaluations) != 1 {
		t.Fatalf("evaluations = %d, want 1", len(result.Evaluations))
	}
	if len(result.Issues) != 1 {
		t.Fatalf("issues = %d, want 1", len(result.Issues))
	}
	if len(result.IssueFindings) != 1 {
		t.Fatalf("issue_findings = %d, want 1", len(result.IssueFindings))
	}
	if len(result.Edges) != 4 {
		t.Fatalf("edges = %d, want 4", len(result.Edges))
	}

	issue := result.Issues[0]
	if issue.Severity != "CRITICAL" {
		t.Fatalf("issue severity = %q, want CRITICAL", issue.Severity)
	}
	if issue.BlastRadius != 2 {
		t.Fatalf("blast_radius = %d, want 2", issue.BlastRadius)
	}
	if issue.ExposurePaths != 3 {
		t.Fatalf("exposure_paths = %d, want 3", issue.ExposurePaths)
	}
	if issue.ID != MaterializeFinding(finding, "tenant-a", now).Issues[0].ID {
		t.Fatal("expected deterministic issue ID")
	}
}

func TestMaterializeFindingDeduplicatesDuplicateMappings(t *testing.T) {
	now := time.Date(2026, time.March, 31, 4, 0, 0, 0, time.UTC)
	finding := &compliance.Finding{
		ID:            "F-002",
		Title:         "Overly permissive IAM policy",
		ResourceID:    "role/admin",
		ResourceName:  "admin",
		ResourceType:  compliance.ResourceTypeIdentity,
		CloudProvider: compliance.CloudProviderAWS,
		Severity:      "MEDIUM",
		Category:      compliance.CategoryIdentity,
		ComplianceMappings: []compliance.ComplianceMapping{
			{FrameworkID: "nist-csf", FrameworkName: "NIST CSF", ControlID: "PR.AC", ControlTitle: "Access Control", Severity: "HIGH"},
			{FrameworkID: "nist-csf", FrameworkName: "NIST CSF", ControlID: "PR.AC", ControlTitle: "Access Control", Severity: "HIGH"},
		},
	}

	result := MaterializeFinding(finding, "tenant-a", now)
	if len(result.Issues) != 1 {
		t.Fatalf("issues = %d, want 1", len(result.Issues))
	}
	if len(result.Evaluations) != 1 {
		t.Fatalf("evaluations = %d, want 1", len(result.Evaluations))
	}
}
