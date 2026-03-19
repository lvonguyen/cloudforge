package main

import (
	"context"
	"fmt"
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
