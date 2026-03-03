package compliance

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("creating logger: %v", err)
	}
	return NewManager(logger)
}

func TestManager_LoadsBuiltInFrameworks(t *testing.T) {
	m := newTestManager(t)

	requiredFrameworks := []string{
		"cis-benchmarks", "nist-800-53", "nist-csf", "iso-27001",
		"pci-dss", "hipaa", "fedramp",
	}

	for _, id := range requiredFrameworks {
		t.Run(id, func(t *testing.T) {
			fw, ok := m.GetFramework(id)
			if !ok {
				t.Fatalf("framework %s not loaded", id)
			}
			if fw.Name == "" {
				t.Error("framework name is empty")
			}
			if len(fw.Controls) == 0 {
				t.Errorf("framework %s has no controls", id)
			}
		})
	}
}

func TestManager_GetFrameworksForSector(t *testing.T) {
	m := newTestManager(t)

	tests := []struct {
		name              string
		sector            Sector
		wantMinFrameworks int
		mustContain       []string
	}{
		{
			name:              "healthcare includes HIPAA",
			sector:            SectorHealthcare,
			wantMinFrameworks: 4,
			mustContain:       []string{"hipaa", "hitrust"},
		},
		{
			name:              "finance includes PCI-DSS and SOX",
			sector:            SectorFinance,
			wantMinFrameworks: 6,
			mustContain:       []string{"pci-dss", "sox"},
		},
		{
			name:              "government includes FedRAMP and NIST",
			sector:            SectorGovernment,
			wantMinFrameworks: 4,
			mustContain:       []string{"fedramp", "nist-800-53"},
		},
		{
			name:              "general sector returns baseline",
			sector:            SectorGeneral,
			wantMinFrameworks: 3,
			mustContain:       []string{"cis-benchmarks", "nist-csf"},
		},
		{
			name:              "AI sector includes NIST AI RMF",
			sector:            SectorAI,
			wantMinFrameworks: 4,
			mustContain:       []string{"nist-ai-rmf"},
		},
		{
			name:              "unknown sector falls back to general",
			sector:            Sector("nonexistent"),
			wantMinFrameworks: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frameworks := m.GetFrameworksForSector(tt.sector)

			if len(frameworks) < tt.wantMinFrameworks {
				t.Errorf("got %d frameworks, want at least %d", len(frameworks), tt.wantMinFrameworks)
			}

			fwIDs := make(map[string]bool)
			for _, fw := range frameworks {
				fwIDs[fw.ID] = true
			}

			for _, required := range tt.mustContain {
				if !fwIDs[required] {
					t.Errorf("expected framework %s for sector %s", required, tt.sector)
				}
			}
		})
	}
}

func TestManager_MapFinding(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()

	finding := &Finding{
		ID:              "test-001",
		Title:           "S3 bucket has public read access enabled",
		Description:     "The S3 bucket allows public read access which could expose sensitive data",
		ResourceType:    ResourceTypeStorage,
		ResourceID:      "arn:aws:s3:::my-bucket",
		Type:            FindingTypeMisconfiguration,
		Severity:        "high",
		Source:          "aws-security-hub",
		SourceFindingID: "S3.1",
		CWEs:            []string{"CWE-284"},
		CloudProvider:   CloudProviderAWS,
		FirstFoundAt:    time.Now(),
	}

	mapped, err := m.MapFinding(ctx, finding, SectorGeneral)
	if err != nil {
		t.Fatalf("MapFinding failed: %v", err)
	}

	if len(mapped.ComplianceMappings) == 0 {
		t.Error("expected at least one compliance mapping for public S3 bucket")
	}

	hasFramework := make(map[string]bool)
	for _, cm := range mapped.ComplianceMappings {
		hasFramework[cm.FrameworkID] = true
		if cm.ControlID == "" {
			t.Error("mapping has empty ControlID")
		}
		if cm.FrameworkName == "" {
			t.Error("mapping has empty FrameworkName")
		}
	}
}

func TestManager_MapFinding_CVEEnrichment(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()

	finding := &Finding{
		ID:           "test-cve-001",
		Title:        "Critical vulnerability in openssl",
		Description:  "Buffer overflow in openssl library",
		ResourceType: ResourceTypeCompute,
		ResourceID:   "i-12345",
		Type:         FindingTypeVulnerability,
		CVEs: []CVEReference{
			{ID: "CVE-2024-0001"},
			{ID: "CVE-2024-0002", URL: "https://custom.url/cve"},
		},
		Source:       "inspector",
		FirstFoundAt: time.Now(),
	}

	mapped, err := m.MapFinding(ctx, finding, SectorGeneral)
	if err != nil {
		t.Fatalf("MapFinding failed: %v", err)
	}

	if mapped.CVEs[0].URL == "" {
		t.Error("expected CVE URL to be populated")
	}
	if mapped.CVEs[0].URL != "https://nvd.nist.gov/vuln/detail/CVE-2024-0001" {
		t.Errorf("unexpected CVE URL: %s", mapped.CVEs[0].URL)
	}

	if mapped.CVEs[1].URL != "https://custom.url/cve" {
		t.Error("pre-existing CVE URL should not be overwritten")
	}
}

func TestManager_RegisterAndGetFramework(t *testing.T) {
	m := newTestManager(t)

	custom := &Framework{
		ID:      "custom-fw",
		Name:    "Custom Framework",
		Version: "1.0",
		Controls: map[string]*Control{
			"CTRL-001": {
				ID:       "CTRL-001",
				Title:    "Custom Control",
				Keywords: []string{"encryption"},
			},
		},
	}

	m.RegisterFramework(custom)

	retrieved, ok := m.GetFramework("custom-fw")
	if !ok {
		t.Fatal("expected custom framework to be retrievable")
	}
	if retrieved.Name != "Custom Framework" {
		t.Errorf("got %s, want Custom Framework", retrieved.Name)
	}
	if len(retrieved.Controls) != 1 {
		t.Errorf("got %d controls, want 1", len(retrieved.Controls))
	}
}

func TestManager_DeduplicateFinding_ExactDuplicate(t *testing.T) {
	m := newTestManager(t)

	existing := &Finding{
		ID:              "existing-001",
		ResourceID:      "arn:aws:s3:::my-bucket",
		ResourceType:    ResourceTypeStorage,
		Source:          "security-hub",
		SourceFindingID: "S3.1",
		Title:           "Public S3 bucket",
		FirstFoundAt:    time.Now().Add(-24 * time.Hour),
	}
	existing.DeduplicationKey = existing.GenerateDeduplicationKey()

	duplicate := &Finding{
		ResourceID:      "arn:aws:s3:::my-bucket",
		ResourceType:    ResourceTypeStorage,
		Source:          "security-hub",
		SourceFindingID: "S3.1",
		Title:           "Public S3 bucket",
		FirstFoundAt:    time.Now(),
	}

	_, keep := m.DeduplicateFinding(duplicate, []*Finding{existing})
	if keep {
		t.Error("exact duplicate should not be kept")
	}
}

func TestManager_DeduplicateFinding_EquivalentRules(t *testing.T) {
	m := newTestManager(t)

	existing := &Finding{
		ID:              "existing-001",
		ResourceID:      "arn:aws:s3:::my-bucket",
		ResourceType:    ResourceTypeStorage,
		Source:          "checkov",
		SourceFindingID: "CKV_AWS_19",
		Title:           "Public S3 bucket (checkov)",
		FirstFoundAt:    time.Now().Add(-24 * time.Hour),
	}
	existing.CanonicalRuleID = "checkov:CKV_AWS_19"
	existing.DeduplicationKey = existing.GenerateDeduplicationKey()

	secHubFinding := &Finding{
		ResourceID:      "arn:aws:s3:::my-bucket",
		ResourceType:    ResourceTypeStorage,
		Source:          "security-hub",
		SourceFindingID: "S3.1",
		Title:           "Public S3 bucket (security-hub)",
		FirstFoundAt:    time.Now(),
	}

	result, keep := m.DeduplicateFinding(secHubFinding, []*Finding{existing})
	if !keep {
		t.Error("Security Hub finding (higher priority) should replace Checkov finding")
	}
	if len(result.RelatedRules) == 0 {
		t.Error("expected related rules to include the replaced rule")
	}
}

func TestManager_DeduplicateFinding_DifferentResources(t *testing.T) {
	m := newTestManager(t)

	existing := &Finding{
		ID:              "existing-001",
		ResourceID:      "arn:aws:s3:::bucket-a",
		ResourceType:    ResourceTypeStorage,
		Source:          "security-hub",
		SourceFindingID: "S3.1",
		Title:           "Public S3 bucket",
		FirstFoundAt:    time.Now(),
	}
	existing.DeduplicationKey = existing.GenerateDeduplicationKey()

	different := &Finding{
		ResourceID:      "arn:aws:s3:::bucket-b",
		ResourceType:    ResourceTypeStorage,
		Source:          "security-hub",
		SourceFindingID: "S3.1",
		Title:           "Public S3 bucket",
		FirstFoundAt:    time.Now(),
	}

	_, keep := m.DeduplicateFinding(different, []*Finding{existing})
	if !keep {
		t.Error("findings on different resources should not be deduplicated")
	}
}

func TestDeduplicator_DeduplicateBatch(t *testing.T) {
	d := NewDeduplicator()

	findings := []*Finding{
		{
			ID:              "f1",
			ResourceID:      "arn:aws:s3:::bucket",
			ResourceType:    ResourceTypeStorage,
			Source:          "security-hub",
			SourceFindingID: "S3.1",
			Title:           "Public bucket",
			FirstFoundAt:    time.Now(),
		},
		{
			ID:              "f2",
			ResourceID:      "arn:aws:s3:::bucket",
			ResourceType:    ResourceTypeStorage,
			Source:          "checkov",
			SourceFindingID: "CKV_AWS_19",
			Title:           "Public bucket",
			FirstFoundAt:    time.Now(),
		},
		{
			ID:              "f3",
			ResourceID:      "arn:aws:ec2:us-east-1:123:sg/sg-123",
			ResourceType:    ResourceTypeNetwork,
			Source:          "security-hub",
			SourceFindingID: "EC2.19",
			Title:           "Open security group",
			FirstFoundAt:    time.Now(),
		},
	}

	deduplicated := d.DeduplicateBatch(findings)

	if len(deduplicated) != 2 {
		t.Errorf("expected 2 deduplicated findings, got %d", len(deduplicated))
	}

	resourceIDs := make(map[string]bool)
	for _, f := range deduplicated {
		resourceIDs[f.ResourceID] = true
	}
	if !resourceIDs["arn:aws:s3:::bucket"] {
		t.Error("expected S3 bucket finding to survive dedup")
	}
	if !resourceIDs["arn:aws:ec2:us-east-1:123:sg/sg-123"] {
		t.Error("expected security group finding to survive dedup")
	}
}

func TestDeduplicator_AddRuleEquivalence(t *testing.T) {
	d := NewDeduplicator()

	d.AddRuleEquivalence("custom-rule", []string{"RULE-A", "RULE-B", "RULE-C"})

	if !d.areRulesEquivalent("RULE-A", "RULE-B") {
		t.Error("RULE-A and RULE-B should be equivalent after AddRuleEquivalence")
	}
	if !d.areRulesEquivalent("RULE-A", "RULE-C") {
		t.Error("RULE-A and RULE-C should be equivalent")
	}
	if d.areRulesEquivalent("RULE-A", "RULE-D") {
		t.Error("RULE-A and RULE-D should not be equivalent")
	}
}

func TestDeduplicator_AddRulePriority(t *testing.T) {
	d := NewDeduplicator()

	d.AddRulePriority("CUSTOM-1", 5)
	d.AddRulePriority("CUSTOM-2", 50)

	if p := d.getRulePriority("CUSTOM-1"); p != 5 {
		t.Errorf("expected priority 5, got %d", p)
	}
	if p := d.getRulePriority("CUSTOM-2"); p != 50 {
		t.Errorf("expected priority 50, got %d", p)
	}
	if p := d.getRulePriority("UNKNOWN"); p != 100 {
		t.Errorf("unknown rule should have default priority 100, got %d", p)
	}
}

func TestFinding_GenerateDeduplicationKey(t *testing.T) {
	f1 := &Finding{
		ResourceType: ResourceTypeStorage,
		ResourceID:   "bucket-a",
		Title:        "Public bucket",
	}
	f2 := &Finding{
		ResourceType: ResourceTypeStorage,
		ResourceID:   "bucket-a",
		Title:        "Public bucket",
	}
	f3 := &Finding{
		ResourceType: ResourceTypeStorage,
		ResourceID:   "bucket-b",
		Title:        "Public bucket",
	}

	key1 := f1.GenerateDeduplicationKey()
	key2 := f2.GenerateDeduplicationKey()
	key3 := f3.GenerateDeduplicationKey()

	if key1 != key2 {
		t.Error("identical findings should produce identical dedup keys")
	}
	if key1 == key3 {
		t.Error("different resources should produce different dedup keys")
	}
	if len(key1) != 32 {
		t.Errorf("dedup key should be 32 hex chars, got %d", len(key1))
	}
}

func TestFinding_CalculateSLADueDate(t *testing.T) {
	tests := []struct {
		name        string
		severity    string
		wantDaysOut int
	}{
		{name: "critical SLA is 1 day", severity: "critical", wantDaysOut: 1},
		{name: "high SLA is 7 days", severity: "high", wantDaysOut: 7},
		{name: "medium SLA is 30 days", severity: "medium", wantDaysOut: 30},
		{name: "low SLA is 90 days", severity: "low", wantDaysOut: 90},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Now()
			f := &Finding{
				Severity:     tt.severity,
				FirstFoundAt: now,
			}

			f.CalculateSLADueDate(nil)

			if f.DueDate == nil {
				t.Fatal("DueDate should be set")
			}

			expected := now.AddDate(0, 0, tt.wantDaysOut)
			diff := f.DueDate.Sub(expected)
			if diff < -time.Second || diff > time.Second {
				t.Errorf("expected due date ~%v, got %v", expected, *f.DueDate)
			}
		})
	}
}

func TestFinding_IsOverdue(t *testing.T) {
	past := time.Now().Add(-24 * time.Hour)
	future := time.Now().Add(24 * time.Hour)

	tests := []struct {
		name    string
		finding Finding
		want    bool
	}{
		{
			name:    "no due date is not overdue",
			finding: Finding{Status: "open"},
			want:    false,
		},
		{
			name:    "future due date is not overdue",
			finding: Finding{Status: "open", DueDate: &future},
			want:    false,
		},
		{
			name:    "past due date is overdue",
			finding: Finding{Status: "open", DueDate: &past},
			want:    true,
		},
		{
			name:    "resolved finding is not overdue even with past due date",
			finding: Finding{Status: "resolved", DueDate: &past},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.finding.IsOverdue(); got != tt.want {
				t.Errorf("IsOverdue() = %v, want %v", got, tt.want)
			}
		})
	}
}
