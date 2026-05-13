package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"aegis/internal/ai"

	"go.uber.org/zap"
)

// stubAIProvider is a minimal ai.Provider for use in Enabled() tests.
type stubAIProvider struct{}

func (stubAIProvider) Complete(_ context.Context, _ string) (string, error) {
	return "", nil
}

func (stubAIProvider) CompleteWithSystem(_ context.Context, _, _ string) (string, error) {
	return "", nil
}

// verify stubAIProvider satisfies the interface at compile time.
var _ ai.Provider = stubAIProvider{}

// --- parseFindingEnrichment tests ---

func TestParseFindingEnrichment_ValidJSON(t *testing.T) {
	response := `{"root_cause":"Overly permissive IAM policy","impact":"Full S3 read access","remediation":"Restrict to least-privilege","related_controls":["CIS 1.2","NIST AC-3"]}`
	got, err := parseFindingEnrichment("finding-001", response)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.FindingID != "finding-001" {
		t.Errorf("FindingID = %q, want %q", got.FindingID, "finding-001")
	}
	if got.RootCause != "Overly permissive IAM policy" {
		t.Errorf("RootCause = %q, want %q", got.RootCause, "Overly permissive IAM policy")
	}
	if got.Impact != "Full S3 read access" {
		t.Errorf("Impact = %q, want %q", got.Impact, "Full S3 read access")
	}
	if got.Remediation != "Restrict to least-privilege" {
		t.Errorf("Remediation = %q, want %q", got.Remediation, "Restrict to least-privilege")
	}
	if len(got.RelatedControls) != 2 {
		t.Errorf("RelatedControls len = %d, want 2", len(got.RelatedControls))
	}
	if got.EnrichedAt == "" {
		t.Error("EnrichedAt should not be empty")
	}
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}
}

func TestParseFindingEnrichment_EmbeddedJSON(t *testing.T) {
	response := `Here is the analysis: {"root_cause":"Exposed secret in env var","impact":"Credential theft","remediation":"Rotate and use secrets manager","related_controls":["CIS 13.1"]} Hope this helps.`
	got, err := parseFindingEnrichment("finding-002", response)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.RootCause != "Exposed secret in env var" {
		t.Errorf("RootCause = %q, want %q", got.RootCause, "Exposed secret in env var")
	}
	if got.FindingID != "finding-002" {
		t.Errorf("FindingID = %q, want %q", got.FindingID, "finding-002")
	}
}

func TestParseFindingEnrichment_MissingRootCause(t *testing.T) {
	response := `{"root_cause":"","impact":"some impact","remediation":"some fix","related_controls":[]}`
	_, err := parseFindingEnrichment("finding-003", response)
	if err == nil {
		t.Fatal("expected error for missing root_cause, got nil")
	}
	if !strings.Contains(err.Error(), "root_cause") {
		t.Errorf("error %q should mention root_cause", err.Error())
	}
}

func TestParseFindingEnrichment_Garbage(t *testing.T) {
	_, err := parseFindingEnrichment("finding-004", "hello world no json here")
	if err == nil {
		t.Fatal("expected error for garbage input, got nil")
	}
	if !strings.Contains(err.Error(), "no JSON") {
		t.Errorf("error %q should mention 'no JSON'", err.Error())
	}
}

func TestParseFindingEnrichment_InvalidJSON(t *testing.T) {
	_, err := parseFindingEnrichment("finding-005", "{malformed json")
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

func TestParseFindingEnrichment_MissingImpact(t *testing.T) {
	response := `{"root_cause":"something","impact":"","remediation":"fix it","related_controls":[]}`
	_, err := parseFindingEnrichment("finding-006", response)
	if err == nil || !strings.Contains(err.Error(), "missing impact") {
		t.Errorf("expected 'missing impact' error, got: %v", err)
	}
}

func TestParseFindingEnrichment_MissingRemediation(t *testing.T) {
	response := `{"root_cause":"something","impact":"bad","remediation":"","related_controls":[]}`
	_, err := parseFindingEnrichment("finding-007", response)
	if err == nil || !strings.Contains(err.Error(), "missing remediation") {
		t.Errorf("expected 'missing remediation' error, got: %v", err)
	}
}

func TestParseFindingEnrichment_ControlFiltering(t *testing.T) {
	response := `{"root_cause":"open port","impact":"exposure","remediation":"close it","related_controls":["CIS 1.2","NIST AC-3","garbage","SOC 2","unknown-ctrl"]}`
	got, err := parseFindingEnrichment("finding-008", response)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"CIS 1.2", "NIST AC-3", "SOC 2"}
	if len(got.RelatedControls) != len(want) {
		t.Fatalf("controls = %v, want %v", got.RelatedControls, want)
	}
	for i, c := range got.RelatedControls {
		if c != want[i] {
			t.Errorf("control[%d] = %q, want %q", i, c, want[i])
		}
	}
}

func TestTruncateField(t *testing.T) {
	long := strings.Repeat("x", 3000)
	got := truncateField(long, 2000)
	if len(got) != 2000 {
		t.Errorf("truncated length = %d, want 2000", len(got))
	}
	short := "hello"
	if truncateField(short, 2000) != short {
		t.Error("short string should not be truncated")
	}
}

func TestExtractIPsFromText(t *testing.T) {
	text := strings.Join([]string{
		"reachable hosts: 8.8.8.8 and 1.1.1.1",
		"duplicates 8.8.8.8 should collapse",
		"ignore loopback 127.0.0.1 and link-local 169.254.1.10",
		"ignore invalid 999.999.999.999 and broadcast 255.255.255.255",
		"ignore wildcard 0.0.0.0",
	}, "\n")

	got := extractIPsFromText(text)
	want := []string{"8.8.8.8", "1.1.1.1"}
	if len(got) != len(want) {
		t.Fatalf("ips = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ips[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	seen := make(map[string]bool, len(got))
	for _, ip := range got {
		if net.ParseIP(ip) == nil {
			t.Fatalf("returned invalid IP %q", ip)
		}
		if seen[ip] {
			t.Fatalf("returned duplicate IP %q", ip)
		}
		seen[ip] = true
	}
}

func TestExtractFindingCodeToCloud_FromTags(t *testing.T) {
	finding := &Finding{
		ID: "finding-ctc-001",
		Tags: map[string]string{
			"repository_url":   "https://github.com/cloudforge/orders-api",
			"branch":           "main",
			"commit_sha":       "0123456789abcdef",
			"build_system":     "github-actions",
			"pipeline_name":    "deploy-orders",
			"pipeline_run_id":  "4711",
			"pipeline_run_url": "https://github.com/cloudforge/orders-api/actions/runs/4711",
			"artifact":         "ghcr.io/cloudforge/orders-api:2026.04.07",
		},
	}

	got := extractFindingCodeToCloud(finding)
	if got == nil {
		t.Fatal("extractFindingCodeToCloud() = nil, want context")
	}
	if got.RepositoryName != "cloudforge/orders-api" {
		t.Fatalf("repository_name = %q, want cloudforge/orders-api", got.RepositoryName)
	}
	if got.RepositoryProvider != "github" {
		t.Fatalf("repository_provider = %q, want github", got.RepositoryProvider)
	}
	if got.Branch != "main" {
		t.Fatalf("branch = %q, want main", got.Branch)
	}
	if got.PipelineName != "deploy-orders" {
		t.Fatalf("pipeline_name = %q, want deploy-orders", got.PipelineName)
	}
	if got.Artifact == "" {
		t.Fatal("artifact must not be empty when tag is present")
	}
}

func TestExtractFindingCodeToCloud_Empty(t *testing.T) {
	got := extractFindingCodeToCloud(&Finding{ID: "finding-ctc-002"})
	if got != nil {
		t.Fatalf("extractFindingCodeToCloud() = %#v, want nil", got)
	}
}

func TestExtractFindingCodeToCloud_FromSeededFixtureTags(t *testing.T) {
	findings, err := loadTestFindingsFromFile("testdata/findings_test.json")
	if err != nil {
		t.Fatalf("loadTestFindingsFromFile() error = %v", err)
	}

	var tagged *Finding
	for i := range findings {
		if len(findings[i].Tags) > 0 {
			tagged = &findings[i]
			break
		}
	}
	if tagged == nil {
		t.Fatal("expected at least one seeded fixture finding with code-to-cloud tags")
	}

	got := extractFindingCodeToCloud(tagged)
	if got == nil {
		t.Fatal("extractFindingCodeToCloud() = nil, want context from seeded fixture tags")
	}
	if got.RepositoryName == "" {
		t.Fatal("repository_name must not be empty for seeded fixture tags")
	}
	if got.RepositoryProvider == "" {
		t.Fatal("repository_provider must not be empty for seeded fixture tags")
	}
	if got.PipelineName == "" {
		t.Fatal("pipeline_name must not be empty for seeded fixture tags")
	}
	if got.CommitSHA == "" {
		t.Fatal("commit_sha must not be empty for seeded fixture tags")
	}
}

// --- EnrichmentService tests ---

func TestEnrichmentService_Enabled(t *testing.T) {
	nilSvc := &EnrichmentService{Cache: make(map[string]*FindingEnrichment), Logger: zap.NewNop()}
	if nilSvc.Enabled() {
		t.Error("Enabled() = true with nil AI, want false")
	}

	withProvider := &EnrichmentService{
		AI:     stubAIProvider{},
		Cache:  make(map[string]*FindingEnrichment),
		Logger: zap.NewNop(),
	}
	if !withProvider.Enabled() {
		t.Error("Enabled() = false with non-nil AI, want true")
	}
}

func TestEnrichmentService_GetCached_Hit(t *testing.T) {
	svc := &EnrichmentService{Cache: make(map[string]*FindingEnrichment), Logger: zap.NewNop()}
	entry := &FindingEnrichment{
		FindingID: "finding-100",
		RootCause: "cached root cause",
		CreatedAt: time.Now(),
	}
	svc.Cache["finding-100"] = entry

	got, ok := svc.GetCached("finding-100")
	if !ok {
		t.Fatal("GetCached returned false for existing key")
	}
	if got != entry {
		t.Error("GetCached returned a different pointer than inserted")
	}
}

func TestEnrichmentService_GetCached_Miss(t *testing.T) {
	svc := &EnrichmentService{Cache: make(map[string]*FindingEnrichment), Logger: zap.NewNop()}
	_, ok := svc.GetCached("nonexistent")
	if ok {
		t.Error("GetCached returned true for missing key, want false")
	}
}

func TestEnrichmentService_EvictExpired_TTL(t *testing.T) {
	svc := &EnrichmentService{Cache: make(map[string]*FindingEnrichment), Logger: zap.NewNop()}

	// Fresh entry — should survive eviction.
	svc.Cache["fresh"] = &FindingEnrichment{
		FindingID: "fresh",
		RootCause: "recent",
		CreatedAt: time.Now(),
	}
	// Stale entry — 31 minutes old, past the 30-minute TTL.
	svc.Cache["stale"] = &FindingEnrichment{
		FindingID: "stale",
		RootCause: "old",
		CreatedAt: time.Now().Add(-31 * time.Minute),
	}

	svc.evictExpired()

	if _, ok := svc.Cache["stale"]; ok {
		t.Error("stale entry should have been evicted after TTL")
	}
	if _, ok := svc.Cache["fresh"]; !ok {
		t.Error("fresh entry should still be present after eviction")
	}
}

func TestEnrichmentService_EvictExpired_MaxSize(t *testing.T) {
	svc := &EnrichmentService{Cache: make(map[string]*FindingEnrichment), Logger: zap.NewNop()}

	base := time.Now()
	// Insert enrichmentCacheMaxSize + 2 entries, all within TTL but with
	// incrementing CreatedAt so oldest-first eviction is deterministic.
	for i := 0; i < enrichmentCacheMaxSize+2; i++ {
		key := fmt.Sprintf("finding-%05d", i)
		svc.Cache[key] = &FindingEnrichment{
			FindingID: key,
			RootCause: "rc",
			CreatedAt: base.Add(time.Duration(i) * time.Second),
		}
	}

	svc.evictExpired()

	if len(svc.Cache) != enrichmentCacheMaxSize {
		t.Errorf("cache size after eviction = %d, want %d", len(svc.Cache), enrichmentCacheMaxSize)
	}
	// The two oldest entries (index 0 and 1) must have been removed.
	if _, ok := svc.Cache["finding-00000"]; ok {
		t.Error("oldest entry (finding-00000) should have been evicted")
	}
	if _, ok := svc.Cache["finding-00001"]; ok {
		t.Error("second oldest entry (finding-00001) should have been evicted")
	}
}
