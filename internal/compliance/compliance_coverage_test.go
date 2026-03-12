package compliance

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.uber.org/zap"
)

func covLogger() *zap.Logger {
	l, _ := zap.NewDevelopment()
	return l
}

// --- Coverage for Finding methods not in engine_test.go ---

func TestCovFinding_MarkFalsePositive(t *testing.T) {
	f := &Finding{ID: "test"}
	expires := time.Now().Add(30 * 24 * time.Hour)
	f.MarkFalsePositive("test reason", "test evidence", "analyst@example.com", &expires)

	if f.FalsePositive == nil {
		t.Fatal("expected FalsePositive to be set")
	}
	if !f.FalsePositive.IsFalsePositive {
		t.Error("expected IsFalsePositive = true")
	}
	if f.FalsePositive.Reason != "test reason" {
		t.Error("expected reason to match")
	}
	if f.Status != "suppressed" {
		t.Errorf("status = %q, want %q", f.Status, "suppressed")
	}
	if !f.Suppressed {
		t.Error("expected Suppressed = true")
	}
	if !f.FalsePositive.ReviewRequired {
		t.Error("expected ReviewRequired = true")
	}
}

func TestCovFinding_ApproveFalsePositive(t *testing.T) {
	f := &Finding{ID: "test"}
	f.MarkFalsePositive("reason", "evidence", "analyst", nil)
	f.ApproveFalsePositive("approver@example.com")

	if f.FalsePositive.ApprovedBy != "approver@example.com" {
		t.Error("expected ApprovedBy to be set")
	}
	if f.FalsePositive.ApprovedAt == nil {
		t.Error("expected ApprovedAt to be set")
	}
	if f.FalsePositive.ReviewRequired {
		t.Error("expected ReviewRequired = false after approval")
	}
}

func TestCovFinding_ApproveFalsePositive_NilFP(t *testing.T) {
	f := &Finding{ID: "test"}
	f.ApproveFalsePositive("approver@example.com")
	// Should not panic
}

func TestCovFinding_IsFalsePositiveExpired(t *testing.T) {
	f := &Finding{ID: "test"}

	if f.IsFalsePositiveExpired() {
		t.Error("expected not expired when no FP")
	}

	f.MarkFalsePositive("reason", "evidence", "analyst", nil)
	if f.IsFalsePositiveExpired() {
		t.Error("expected not expired when no expiry date")
	}

	past := time.Now().Add(-24 * time.Hour)
	f.FalsePositive.ExpiresAt = &past
	if !f.IsFalsePositiveExpired() {
		t.Error("expected expired when past expiry")
	}

	future := time.Now().Add(24 * time.Hour)
	f.FalsePositive.ExpiresAt = &future
	if f.IsFalsePositiveExpired() {
		t.Error("expected not expired when future expiry")
	}
}

func TestCovFinding_EnrichCVEReferences(t *testing.T) {
	f := &Finding{
		CVEs: []CVEReference{
			{ID: "CVE-2023-001"},
			{ID: "CVE-2023-002"},
			{ID: ""},
		},
	}
	f.EnrichCVEReferences()

	if f.CVEs[0].NVDUrl == "" {
		t.Error("CVE[0] NVDUrl is empty")
	}
	if f.CVEs[0].MitreURL == "" {
		t.Error("CVE[0] MitreURL is empty")
	}
	// Empty ID should not get URLs
	if f.CVEs[2].NVDUrl != "" {
		t.Error("empty CVE ID should not get NVDUrl")
	}
}

func TestCovCVEReference_BuildCVEURLs(t *testing.T) {
	c := &CVEReference{ID: "CVE-2023-12345"}
	c.BuildCVEURLs()

	if c.NVDUrl != "https://nvd.nist.gov/vuln/detail/CVE-2023-12345" {
		t.Errorf("unexpected NVDUrl: %s", c.NVDUrl)
	}
	if c.MitreURL != "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-12345" {
		t.Errorf("unexpected MitreURL: %s", c.MitreURL)
	}
	if c.URL != c.NVDUrl {
		t.Error("URL should default to NVDUrl")
	}
}

func TestCovCVEReference_BuildCVEURLs_EmptyID(t *testing.T) {
	c := &CVEReference{ID: ""}
	c.BuildCVEURLs()
	if c.NVDUrl != "" || c.MitreURL != "" || c.URL != "" {
		t.Error("empty ID should not produce URLs")
	}
}

func TestCovFinding_GetContextualRiskFactors(t *testing.T) {
	tests := []struct {
		name     string
		finding  Finding
		contains []string
	}{
		{
			"production env",
			Finding{EnvironmentType: EnvProduction},
			[]string{"production_environment"},
		},
		{
			"exploit available",
			Finding{ExploitAvailable: true},
			[]string{"exploit_available"},
		},
		{
			"high EPSS",
			Finding{EPSS: 0.75},
			[]string{"high_epss_score"},
		},
		{
			"network resource",
			Finding{ResourceType: ResourceTypeNetwork},
			[]string{"network_resource"},
		},
		{
			"database resource",
			Finding{ResourceType: ResourceTypeDatabase},
			[]string{"data_resource"},
		},
		{
			"storage resource",
			Finding{ResourceType: ResourceTypeStorage},
			[]string{"data_resource"},
		},
		{
			"toxic combo",
			Finding{ToxicComboDetails: &ToxicComboDetails{}},
			[]string{"toxic_combination"},
		},
		{
			"CISA KEV",
			Finding{CVEs: []CVEReference{{CISAKnownExploited: true}}},
			[]string{"cisa_known_exploited"},
		},
		{
			"low EPSS",
			Finding{EPSS: 0.1},
			nil,
		},
		{
			"empty finding",
			Finding{},
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			factors := tt.finding.GetContextualRiskFactors()
			for _, want := range tt.contains {
				found := false
				for _, f := range factors {
					if f == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected factor %q, got %v", want, factors)
				}
			}
		})
	}
}

func TestCovFinding_CalculateSLADueDate_CustomSLA(t *testing.T) {
	customSLA := map[string]int{
		"critical": 2,
		"high":     14,
	}
	f := &Finding{Severity: "critical", FirstFoundAt: time.Now()}
	f.CalculateSLADueDate(customSLA)
	if f.DueDate == nil {
		t.Fatal("expected DueDate to be set")
	}
	diff := f.DueDate.Sub(f.FirstFoundAt)
	if diff != 2*24*time.Hour {
		t.Errorf("custom SLA diff = %v, want %v", diff, 2*24*time.Hour)
	}
}

func TestCovFinding_CalculateSLADueDate_UnknownSeverity(t *testing.T) {
	f := &Finding{Severity: "unknown", FirstFoundAt: time.Now()}
	f.CalculateSLADueDate(nil)
	if f.DueDate != nil {
		t.Error("expected nil DueDate for unknown severity")
	}
}

func TestCovFinding_CalculateSLADueDate_ZeroFirstFound(t *testing.T) {
	f := &Finding{Severity: "high"}
	f.CalculateSLADueDate(nil)
	if f.FirstFoundAt.IsZero() {
		t.Error("expected FirstFoundAt to be auto-set")
	}
	if f.DueDate == nil {
		t.Fatal("expected DueDate to be set")
	}
}

func TestCovFinding_GenerateDeduplicationKey_WithCVEs(t *testing.T) {
	f1 := &Finding{
		ResourceType: ResourceTypeStorage,
		ResourceID:   "bucket",
		Title:        "Vuln",
		CVEs:         []CVEReference{{ID: "CVE-2023-001"}},
	}
	f2 := &Finding{
		ResourceType: ResourceTypeStorage,
		ResourceID:   "bucket",
		Title:        "Vuln",
		CVEs:         []CVEReference{{ID: "CVE-2023-002"}},
	}

	k1 := f1.GenerateDeduplicationKey()
	k2 := f2.GenerateDeduplicationKey()
	if k1 == k2 {
		t.Error("different CVEs should produce different dedup keys")
	}
}

// --- AIAnalyzer tests ---

type covMockAIProvider struct {
	response string
	err      error
}

func (m *covMockAIProvider) Analyze(_ context.Context, _ string) (string, error) {
	return m.response, m.err
}

func (m *covMockAIProvider) AnalyzeJSON(_ context.Context, _ string, _ interface{}) error {
	return m.err
}

func TestCovNewAIAnalyzer(t *testing.T) {
	a := NewAIAnalyzer(nil, AIAnalyzerConfig{}, covLogger())
	if a == nil {
		t.Fatal("expected non-nil analyzer")
	}
}

func TestCovAIAnalyzer_AnalyzeFinding_Disabled(t *testing.T) {
	a := NewAIAnalyzer(nil, AIAnalyzerConfig{Enabled: false}, covLogger())
	f := &Finding{ID: "test"}
	result, err := a.AnalyzeFinding(context.Background(), f, nil)
	if err != nil {
		t.Fatalf("AnalyzeFinding: %v", err)
	}
	if result.ID != "test" {
		t.Error("expected finding returned unchanged")
	}
}

func TestCovAIAnalyzer_AnalyzeFinding_NilProvider(t *testing.T) {
	a := NewAIAnalyzer(nil, AIAnalyzerConfig{Enabled: true}, covLogger())
	f := &Finding{ID: "test"}
	result, err := a.AnalyzeFinding(context.Background(), f, nil)
	if err != nil {
		t.Fatalf("AnalyzeFinding: %v", err)
	}
	if result.ID != "test" {
		t.Error("expected finding returned unchanged with nil provider")
	}
}

func TestCovAIAnalyzer_AnalyzeFinding_ProviderError(t *testing.T) {
	provider := &covMockAIProvider{err: fmt.Errorf("test error")}
	a := NewAIAnalyzer(provider, AIAnalyzerConfig{Enabled: true}, covLogger())
	f := &Finding{ID: "test"}
	result, err := a.AnalyzeFinding(context.Background(), f, nil)
	if err != nil {
		t.Fatalf("AnalyzeFinding should not return error: %v", err)
	}
	if result.ID != "test" {
		t.Error("expected finding returned on error")
	}
}

func TestCovAIAnalyzer_DetectToxicCombinations_Disabled(t *testing.T) {
	a := NewAIAnalyzer(nil, AIAnalyzerConfig{Enabled: false}, covLogger())
	findings := []*Finding{{ID: "f1"}, {ID: "f2"}}
	result, err := a.DetectToxicCombinations(context.Background(), findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 2 {
		t.Error("expected findings returned unchanged")
	}
}

func TestCovAIAnalyzer_DetectToxicCombinations_Single(t *testing.T) {
	a := NewAIAnalyzer(&covMockAIProvider{}, AIAnalyzerConfig{Enabled: true}, covLogger())
	findings := []*Finding{{ID: "f1"}}
	result, err := a.DetectToxicCombinations(context.Background(), findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 {
		t.Error("expected single finding returned unchanged")
	}
}

func TestCovAIAnalyzer_DetectToxicCombinations_GroupByResource(t *testing.T) {
	provider := &covMockAIProvider{err: fmt.Errorf("mock error")}
	a := NewAIAnalyzer(provider, AIAnalyzerConfig{Enabled: true}, covLogger())
	findings := []*Finding{
		{ID: "f1", ResourceID: "res-1"},
		{ID: "f2", ResourceID: "res-1"},
	}
	result, err := a.DetectToxicCombinations(context.Background(), findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 2 {
		t.Error("expected findings returned even on error")
	}
}

func TestCovAIAnalyzer_DetectToxicCombinations_ImpactedResources(t *testing.T) {
	provider := &covMockAIProvider{err: fmt.Errorf("mock error")}
	a := NewAIAnalyzer(provider, AIAnalyzerConfig{Enabled: true}, covLogger())
	findings := []*Finding{
		{ID: "f1", ResourceID: "res-1", ImpactedResources: []ImpactedResource{{ResourceID: "res-2"}}},
		{ID: "f2", ResourceID: "res-2"},
	}
	result, err := a.DetectToxicCombinations(context.Background(), findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 2 {
		t.Error("expected findings returned")
	}
}

func TestCovAIAnalyzer_BuildRiskAssessmentPrompt(t *testing.T) {
	a := NewAIAnalyzer(nil, AIAnalyzerConfig{}, covLogger())
	f := &Finding{
		Title:         "Test finding",
		Description:   "Test description",
		ResourceName:  "my-resource",
		ResourceType:  ResourceTypeStorage,
		Platform:      PlatformCloud,
		CloudProvider: CloudProviderAWS,
		CVEs:          []CVEReference{{ID: "CVE-2023-001", CVSS: 9.0}},
		ComplianceMappings: []ComplianceMapping{
			{FrameworkName: "CIS", ControlID: "1.1", ControlTitle: "test"},
		},
	}
	related := []*Finding{
		{Severity: "high", Title: "Related", ResourceName: "related-resource"},
	}

	prompt := a.buildRiskAssessmentPrompt(f, related)
	if prompt == "" {
		t.Error("expected non-empty prompt")
	}
}

func TestCovAIAnalyzer_BuildRiskAssessmentPrompt_EmptyRelated(t *testing.T) {
	a := NewAIAnalyzer(nil, AIAnalyzerConfig{}, covLogger())
	f := &Finding{Title: "Test", Description: "Desc"}
	prompt := a.buildRiskAssessmentPrompt(f, nil)
	if prompt == "" {
		t.Error("expected non-empty prompt even without related findings")
	}
}

func TestCovMin(t *testing.T) {
	tests := []struct {
		a, b, want int
	}{
		{3, 5, 3},
		{5, 3, 3},
		{3, 3, 3},
		{0, 1, 0},
		{-1, 0, -1},
	}
	for _, tt := range tests {
		if got := min(tt.a, tt.b); got != tt.want {
			t.Errorf("min(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

// --- controlMatchesFinding ---

func TestCovControlMatchesFinding_Keywords(t *testing.T) {
	m := NewManager(covLogger())
	control := &Control{
		Keywords: []string{"encryption", "s3"},
	}
	finding := &Finding{
		Title:        "S3 bucket encryption missing",
		Description:  "The S3 bucket lacks encryption",
		ResourceType: ResourceTypeStorage,
	}
	findingText := "s3 bucket encryption missing the s3 bucket lacks encryption storage"
	if !m.controlMatchesFinding(control, finding, findingText) {
		t.Error("expected control to match finding via keyword")
	}
}

func TestCovControlMatchesFinding_CWE(t *testing.T) {
	m := NewManager(covLogger())
	control := &Control{
		Mappings: []string{"CWE-284"},
	}
	finding := &Finding{
		CWEs: []string{"CWE-284"},
	}
	if !m.controlMatchesFinding(control, finding, "some text") {
		t.Error("expected control to match finding via CWE mapping")
	}
}

func TestCovControlMatchesFinding_NoMatch(t *testing.T) {
	m := NewManager(covLogger())
	control := &Control{
		Keywords: []string{"kubernetes"},
	}
	finding := &Finding{}
	if m.controlMatchesFinding(control, finding, "some unrelated text") {
		t.Error("expected no match")
	}
}
