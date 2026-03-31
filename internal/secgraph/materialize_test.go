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
	if issue.RiskScore != 100 {
		t.Fatalf("risk_score = %.2f, want 100.00", issue.RiskScore)
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

func TestMaterializeFindingDerivesResolvedLifecycle(t *testing.T) {
	now := time.Date(2026, time.March, 31, 5, 0, 0, 0, time.UTC)
	resolvedAt := now.Add(-2 * time.Hour)
	slaBreachAt := now.Add(-4 * time.Hour)
	finding := &compliance.Finding{
		ID:             "F-003",
		Title:          "Resolved vulnerability",
		ResourceID:     "i-12345",
		ResourceName:   "i-12345",
		ResourceType:   compliance.ResourceTypeCompute,
		CloudProvider:  compliance.CloudProviderAWS,
		AccountID:      "123456789012",
		Severity:       "HIGH",
		Status:         "resolved",
		WorkflowStatus: compliance.StatusRemediated,
		LastSeenAt:     resolvedAt,
		ResolvedAt:     &resolvedAt,
		SLABreachDate:  &slaBreachAt,
		ComplianceMappings: []compliance.ComplianceMapping{
			{FrameworkID: "nist-csf", FrameworkName: "NIST CSF", ControlID: "PR.1", ControlTitle: "Patch critical vulnerabilities", Severity: "HIGH"},
		},
	}

	result := MaterializeFinding(finding, "tenant-a", now)
	if len(result.Issues) != 1 || len(result.Evaluations) != 1 {
		t.Fatalf("unexpected materialization sizes: %+v", result)
	}

	issue := result.Issues[0]
	if issue.Status != IssueResolved {
		t.Fatalf("issue status = %q, want %q", issue.Status, IssueResolved)
	}
	if issue.ResolvedAt == nil || !issue.ResolvedAt.Equal(resolvedAt) {
		t.Fatalf("resolved_at = %v, want %v", issue.ResolvedAt, resolvedAt)
	}
	if issue.SLABreachAt == nil || !issue.SLABreachAt.Equal(slaBreachAt) {
		t.Fatalf("sla_breach_at = %v, want %v", issue.SLABreachAt, slaBreachAt)
	}
	if result.Evaluations[0].Status != EvalPass {
		t.Fatalf("evaluation status = %q, want %q", result.Evaluations[0].Status, EvalPass)
	}
}

func TestMaterializeFindingDerivesSuppressedLifecycle(t *testing.T) {
	now := time.Date(2026, time.March, 31, 6, 0, 0, 0, time.UTC)
	lastSeenAt := now.Add(-30 * time.Minute)
	finding := &compliance.Finding{
		ID:             "F-004",
		Title:          "Accepted misconfiguration",
		ResourceID:     "db-456",
		ResourceName:   "db-456",
		ResourceType:   compliance.ResourceTypeDatabase,
		CloudProvider:  compliance.CloudProviderAWS,
		AccountID:      "123456789012",
		Severity:       "MEDIUM",
		Suppressed:     true,
		WorkflowStatus: compliance.StatusRiskAccepted,
		LastSeenAt:     lastSeenAt,
		ComplianceMappings: []compliance.ComplianceMapping{
			{FrameworkID: "pci-dss", FrameworkName: "PCI-DSS", ControlID: "REQ.6", ControlTitle: "Review accepted risk", Severity: "MEDIUM"},
		},
	}

	result := MaterializeFinding(finding, "tenant-a", now)
	if len(result.Issues) != 1 || len(result.Evaluations) != 1 {
		t.Fatalf("unexpected materialization sizes: %+v", result)
	}

	issue := result.Issues[0]
	if issue.Status != IssueSuppressed {
		t.Fatalf("issue status = %q, want %q", issue.Status, IssueSuppressed)
	}
	if issue.ResolvedAt == nil || !issue.ResolvedAt.Equal(lastSeenAt) {
		t.Fatalf("resolved_at = %v, want %v", issue.ResolvedAt, lastSeenAt)
	}
	if result.Evaluations[0].Status != EvalNotApplicable {
		t.Fatalf("evaluation status = %q, want %q", result.Evaluations[0].Status, EvalNotApplicable)
	}
}

func TestMergeMaterializationResultsAggregatesSharedIssue(t *testing.T) {
	now := time.Date(2026, time.March, 31, 7, 0, 0, 0, time.UTC)
	sharedMapping := []compliance.ComplianceMapping{
		{FrameworkID: "nist-csf", FrameworkName: "NIST CSF", ControlID: "PR.2", ControlTitle: "Shared issue control", Severity: "HIGH"},
	}

	openFinding := &compliance.Finding{
		ID:                 "F-005",
		Title:              "Active shared finding",
		ResourceID:         "db-999",
		ResourceName:       "db-999",
		ResourceType:       compliance.ResourceTypeDatabase,
		CloudProvider:      compliance.CloudProviderAWS,
		AccountID:          "123456789012",
		Severity:           "HIGH",
		Status:             "open",
		Category:           compliance.CategoryNetwork,
		ExploitAvailable:   true,
		ImpactedResources:  []compliance.ImpactedResource{{ResourceID: "app-1"}},
		ComplianceMappings: sharedMapping,
	}
	resolvedAt := now.Add(-30 * time.Minute)
	resolvedFinding := &compliance.Finding{
		ID:                 "F-006",
		Title:              "Resolved shared finding",
		ResourceID:         "db-999",
		ResourceName:       "db-999",
		ResourceType:       compliance.ResourceTypeDatabase,
		CloudProvider:      compliance.CloudProviderAWS,
		AccountID:          "123456789012",
		Severity:           "MEDIUM",
		Status:             "resolved",
		WorkflowStatus:     compliance.StatusRemediated,
		ResolvedAt:         &resolvedAt,
		ComplianceMappings: sharedMapping,
	}

	openResult := MaterializeFinding(openFinding, "tenant-a", now)
	resolvedResult := MaterializeFinding(resolvedFinding, "tenant-a", now)
	merged := MergeMaterializationResults(openResult, resolvedResult)

	if len(merged.Issues) != 1 {
		t.Fatalf("issues = %d, want 1", len(merged.Issues))
	}
	if len(merged.Evaluations) != 1 {
		t.Fatalf("evaluations = %d, want 1", len(merged.Evaluations))
	}
	if len(merged.IssueFindings) != 2 {
		t.Fatalf("issue_findings = %d, want 2", len(merged.IssueFindings))
	}

	issue := merged.Issues[0]
	if issue.Status != IssueOpen {
		t.Fatalf("issue status = %q, want %q", issue.Status, IssueOpen)
	}
	if issue.Severity != "HIGH" {
		t.Fatalf("issue severity = %q, want HIGH", issue.Severity)
	}
	if issue.RiskScore != openResult.Issues[0].RiskScore {
		t.Fatalf("issue risk_score = %v, want %v", issue.RiskScore, openResult.Issues[0].RiskScore)
	}
	if issue.ResolvedAt != nil {
		t.Fatalf("resolved_at = %v, want nil for active merged issue", issue.ResolvedAt)
	}

	evaluation := merged.Evaluations[0]
	if evaluation.Status != EvalFail {
		t.Fatalf("evaluation status = %q, want %q", evaluation.Status, EvalFail)
	}
	if len(evaluation.Evidence) != 2 {
		t.Fatalf("evaluation evidence = %+v, want 2 findings", evaluation.Evidence)
	}
}

func TestMaterializeFindingUsesAIRiskScoreFloor(t *testing.T) {
	now := time.Date(2026, time.March, 31, 7, 0, 0, 0, time.UTC)
	finding := &compliance.Finding{
		ID:            "F-005",
		Title:         "Low severity but contextually risky",
		ResourceID:    "vm-789",
		ResourceName:  "vm-789",
		ResourceType:  compliance.ResourceTypeCompute,
		CloudProvider: compliance.CloudProviderAWS,
		AccountID:     "123456789012",
		Severity:      "LOW",
		AIRiskScore:   8.5,
		ComplianceMappings: []compliance.ComplianceMapping{
			{FrameworkID: "cis-benchmarks", FrameworkName: "CIS Benchmarks", ControlID: "4.2", ControlTitle: "Protect compute instances", Severity: "LOW"},
		},
	}

	result := MaterializeFinding(finding, "tenant-a", now)
	if len(result.Issues) != 1 {
		t.Fatalf("issues = %d, want 1", len(result.Issues))
	}

	if result.Issues[0].RiskScore != 85 {
		t.Fatalf("risk_score = %.2f, want 85.00", result.Issues[0].RiskScore)
	}
}
