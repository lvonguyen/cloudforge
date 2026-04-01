package main

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// --- Phase 1: BM25 keyword search tests ---

func TestSearchService_BasicSearch(t *testing.T) {
	findings := testFindings()
	svc, err := NewSearchService(findings)
	if err != nil {
		t.Fatalf("NewSearchService: %v", err)
	}

	result, err := svc.Search(context.Background(), "audit logging", 1, 10)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}

	if result.Total == 0 {
		t.Fatal("expected at least one result for 'audit logging'")
	}
	if result.Findings[0].Score <= 0 {
		t.Error("expected positive score")
	}
}

func TestSearchService_TitleBoost(t *testing.T) {
	// Title contains "S3 bucket" — should rank higher than a finding where
	// "S3 bucket" only appears in the description.
	findings := []Finding{
		{
			ID:          "title-match",
			Title:       "S3 bucket public access detected",
			Description: "A storage resource has public access enabled.",
		},
		{
			ID:          "desc-match",
			Title:       "Storage misconfiguration found",
			Description: "An S3 bucket was found with public access enabled.",
		},
	}

	svc, err := NewSearchService(findings)
	if err != nil {
		t.Fatalf("NewSearchService: %v", err)
	}

	result, err := svc.Search(context.Background(), "S3 bucket", 1, 10)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}

	if result.Total == 0 {
		t.Fatal("expected results for 'S3 bucket'")
	}

	// The title-match finding should rank first due to 3x repetition in content.
	if result.Findings[0].Finding.ID != "title-match" {
		t.Errorf("expected title-match to rank first, got %s", result.Findings[0].Finding.ID)
	}
}

func TestSearchService_IncrementalIndex(t *testing.T) {
	findings := testFindings()
	svc, err := NewSearchService(findings)
	if err != nil {
		t.Fatalf("NewSearchService: %v", err)
	}

	// Search for something that doesn't exist yet.
	result, err := svc.Search(context.Background(), "kubernetes_pod_privilege_escalation", 1, 10)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	initialTotal := result.Total

	// Add a new finding.
	newFinding := Finding{
		ID:          "new-k8s-finding",
		Title:       "Kubernetes pod privilege escalation risk",
		Description: "Container running as root with host PID namespace.",
		Category:    "CONTAINER_SECURITY",
	}
	svc.IndexFinding(newFinding)

	// Search again — should find the new finding.
	result, err = svc.Search(context.Background(), "kubernetes pod privilege escalation", 1, 10)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}

	if result.Total <= initialTotal {
		t.Errorf("expected more results after indexing, got %d (was %d)", result.Total, initialTotal)
	}

	found := false
	for _, sf := range result.Findings {
		if sf.Finding.ID == "new-k8s-finding" {
			found = true
			break
		}
	}
	if !found {
		t.Error("newly indexed finding not found in search results")
	}
}

func TestSearchService_EmptyResults(t *testing.T) {
	findings := testFindings()
	svc, err := NewSearchService(findings)
	if err != nil {
		t.Fatalf("NewSearchService: %v", err)
	}

	result, err := svc.Search(context.Background(), "xyznonexistentterm12345", 1, 10)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}

	if result.Total != 0 {
		t.Errorf("expected 0 results, got %d", result.Total)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected empty findings slice, got %d", len(result.Findings))
	}
}

func TestSearchService_Pagination(t *testing.T) {
	findings := testFindings()
	svc, err := NewSearchService(findings)
	if err != nil {
		t.Fatalf("NewSearchService: %v", err)
	}

	// Use a broad query that matches many findings.
	result1, err := svc.Search(context.Background(), "security", 1, 2)
	if err != nil {
		t.Fatalf("Search page 1: %v", err)
	}

	if len(result1.Findings) > 2 {
		t.Errorf("page 1: expected at most 2 results, got %d", len(result1.Findings))
	}

	if result1.Total <= 2 {
		t.Skip("not enough results to test pagination")
	}

	result2, err := svc.Search(context.Background(), "security", 2, 2)
	if err != nil {
		t.Fatalf("Search page 2: %v", err)
	}

	// Page 2 results should differ from page 1.
	if len(result2.Findings) == 0 {
		t.Error("page 2 should have results")
	}
	if len(result1.Findings) > 0 && len(result2.Findings) > 0 {
		if result1.Findings[0].Finding.ID == result2.Findings[0].Finding.ID {
			t.Error("page 1 and page 2 returned the same first result")
		}
	}

	// Total should be consistent.
	if result1.Total != result2.Total {
		t.Errorf("total mismatch: page1=%d, page2=%d", result1.Total, result2.Total)
	}
}

// --- Phase 2: TF-IDF and hybrid search tests ---

func TestEmbeddingService_GenerateEmbedding(t *testing.T) {
	findings := testFindings()
	es := NewEmbeddingService(findings)

	vec, err := es.GenerateEmbedding(context.Background(), "audit logging database")
	if err != nil {
		t.Fatalf("GenerateEmbedding: %v", err)
	}

	if len(vec) == 0 {
		t.Fatal("expected sparse vector to contain non-zero terms")
	}

	for i := 1; i < len(vec); i++ {
		if vec[i-1].index >= vec[i].index {
			t.Fatalf("expected sparse vector to be sorted by index, got %d before %d", vec[i-1].index, vec[i].index)
		}
	}

	var magnitude float64
	for _, component := range vec {
		if component.weight == 0 {
			t.Fatal("expected sparse vector to exclude zero-weight terms")
		}
		magnitude += float64(component.weight * component.weight)
	}
	if magnitude < 0.99 || magnitude > 1.01 {
		t.Fatalf("expected normalized sparse vector, got squared magnitude %.4f", magnitude)
	}
}

func TestCosineSimilarity(t *testing.T) {
	// Identical normalized vectors should have similarity ~1.0.
	a := sparseVector{{index: 1, weight: 0.6}, {index: 3, weight: 0.8}}
	b := sparseVector{{index: 1, weight: 0.6}, {index: 3, weight: 0.8}}
	sim := cosineSimilarity(a, b)
	if sim < 0.99 {
		t.Errorf("identical vectors: expected ~1.0, got %f", sim)
	}

	// Orthogonal vectors should have similarity ~0.0.
	c := sparseVector{{index: 1, weight: 1}}
	d := sparseVector{{index: 2, weight: 1}}
	sim = cosineSimilarity(c, d)
	if sim > 0.01 {
		t.Errorf("orthogonal vectors: expected ~0.0, got %f", sim)
	}

	// Empty vectors should return 0.
	sim = cosineSimilarity(nil, d)
	if sim != 0 {
		t.Errorf("empty vector: expected 0, got %f", sim)
	}
}

func TestEmbeddingService_SearchSimilar(t *testing.T) {
	findings := testFindings()
	es := NewEmbeddingService(findings)

	query, err := es.GenerateEmbedding(context.Background(), "audit logging database")
	if err != nil {
		t.Fatalf("GenerateEmbedding: %v", err)
	}

	results := es.SearchSimilar(query, 5)
	if len(results) == 0 {
		t.Fatal("expected at least one semantic candidate")
	}
	if results[0].score <= 0 {
		t.Fatalf("expected positive similarity score, got %f", results[0].score)
	}
}

func TestRRFFusion(t *testing.T) {
	bm25 := []ScoredFinding{
		{Finding: Finding{ID: "a"}, Score: 10},
		{Finding: Finding{ID: "b"}, Score: 8},
		{Finding: Finding{ID: "c"}, Score: 5},
	}
	semantic := []ScoredFinding{
		{Finding: Finding{ID: "b"}, Score: 0.9},
		{Finding: Finding{ID: "d"}, Score: 0.7},
		{Finding: Finding{ID: "a"}, Score: 0.5},
	}

	fused := rrfFuse(bm25, semantic, 60)

	if len(fused) != 4 {
		t.Fatalf("expected 4 fused results, got %d", len(fused))
	}

	// "a" and "b" appear in both lists — they should have higher fused scores.
	aScore := 0.0
	bScore := 0.0
	dScore := 0.0
	for _, sf := range fused {
		switch sf.Finding.ID {
		case "a":
			aScore = sf.Score
		case "b":
			bScore = sf.Score
		case "d":
			dScore = sf.Score
		}
	}

	// Both "a" and "b" should score higher than "d" (which appears in only one list).
	if aScore <= dScore {
		t.Errorf("expected 'a' (%.4f) > 'd' (%.4f)", aScore, dScore)
	}
	if bScore <= dScore {
		t.Errorf("expected 'b' (%.4f) > 'd' (%.4f)", bScore, dScore)
	}
}

func TestHybridSearch_ReturnsBothSignals(t *testing.T) {
	findings := testFindings()
	svc, err := NewSearchService(findings)
	if err != nil {
		t.Fatalf("NewSearchService: %v", err)
	}
	svc.embedSvc = NewEmbeddingService(findings)

	result, err := svc.HybridSearch(context.Background(), "audit logging", 1, 10)
	if err != nil {
		t.Fatalf("HybridSearch: %v", err)
	}

	if result.Total == 0 {
		t.Fatal("expected at least one hybrid result")
	}
	if result.Findings[0].Score <= 0 {
		t.Error("expected positive fused score")
	}
}

func TestHybridSearch_FallsBackToKeyword(t *testing.T) {
	findings := testFindings()
	svc, err := NewSearchService(findings)
	if err != nil {
		t.Fatalf("NewSearchService: %v", err)
	}
	// No embedSvc — should fall back to keyword-only.

	result, err := svc.HybridSearch(context.Background(), "audit", 1, 10)
	if err != nil {
		t.Fatalf("HybridSearch fallback: %v", err)
	}

	if result.Total == 0 {
		t.Fatal("expected keyword-only fallback results")
	}
}

func TestSemanticSearchMaxFindings_DefaultAndOverride(t *testing.T) {
	t.Setenv("SEMANTIC_SEARCH_MAX_FINDINGS", "")
	if got, want := semanticSearchMaxFindings(), defaultSemanticSearchMaxFindings; got != want {
		t.Fatalf("default limit = %d, want %d", got, want)
	}

	t.Setenv("SEMANTIC_SEARCH_MAX_FINDINGS", "25000")
	if got, want := semanticSearchMaxFindings(), 25000; got != want {
		t.Fatalf("override limit = %d, want %d", got, want)
	}

	t.Setenv("SEMANTIC_SEARCH_MAX_FINDINGS", "invalid")
	if got, want := semanticSearchMaxFindings(), defaultSemanticSearchMaxFindings; got != want {
		t.Fatalf("invalid override limit = %d, want %d", got, want)
	}

	t.Setenv("SEMANTIC_SEARCH_MAX_FINDINGS", strconv.Itoa(0))
	if semanticSearchEnabledForCorpus(10) {
		t.Fatal("expected semantic search to be disabled when limit is zero")
	}
}

func TestSemanticSearchEnabledForCorpus(t *testing.T) {
	t.Setenv("SEMANTIC_SEARCH_MAX_FINDINGS", "100")

	if !semanticSearchEnabledForCorpus(100) {
		t.Fatal("expected semantic search enabled at limit")
	}
	if semanticSearchEnabledForCorpus(101) {
		t.Fatal("expected semantic search disabled above limit")
	}
}

func TestFallbackKeywordSearch_RanksTitlePhraseFirst(t *testing.T) {
	findings := []Finding{
		{
			ID:          "title-match",
			Title:       "S3 bucket public access detected",
			Description: "Public access is enabled on this storage resource.",
		},
		{
			ID:          "description-match",
			Title:       "Storage misconfiguration found",
			Description: "An S3 bucket has public access enabled.",
		},
	}

	result := fallbackKeywordSearch(findings, "S3 bucket", 10)
	if result.Total != 2 {
		t.Fatalf("expected 2 fallback results, got %d", result.Total)
	}
	if got := result.Findings[0].Finding.ID; got != "title-match" {
		t.Fatalf("first fallback result = %s, want title-match", got)
	}
}

func TestFallbackKeywordSearchCandidateLimit(t *testing.T) {
	if got := fallbackKeywordSearchCandidateLimit(1, 10); got != 200 {
		t.Fatalf("limit for small page = %d, want 200", got)
	}
	if got := fallbackKeywordSearchCandidateLimit(5, 50); got != fallbackKeywordSearchMaxCandidates {
		t.Fatalf("limit for large page = %d, want %d", got, fallbackKeywordSearchMaxCandidates)
	}
}

func TestRewriteSearchQuery_ExpandsOperatorShorthand(t *testing.T) {
	rewritten := rewriteSearchQuery("internet exposed rds without mfa")

	for _, expected := range []string{
		"public access",
		"database",
		"multi factor authentication",
	} {
		if !strings.Contains(rewritten, expected) {
			t.Fatalf("rewritten query %q missing %q", rewritten, expected)
		}
	}
}

func TestFallbackKeywordSearch_RewriteImprovesRecall(t *testing.T) {
	findings := []Finding{
		{
			ID:           "db-public-access",
			Title:        "Database instance has public access enabled",
			Description:  "Multi-factor authentication is not enforced for the owning workflow.",
			ResourceName: "db-prod-001",
		},
	}

	raw := fallbackKeywordSearch(findings, "internet exposed rds without mfa", 10)
	if raw.Total != 0 {
		t.Fatalf("expected raw fallback search to miss shorthand query, got %d results", raw.Total)
	}

	rewritten := fallbackKeywordSearch(findings, rewriteSearchQuery("internet exposed rds without mfa"), 10)
	if rewritten.Total == 0 {
		t.Fatal("expected rewritten fallback search to recover a result")
	}
	if rewritten.Findings[0].Finding.ID != "db-public-access" {
		t.Fatalf("first rewritten result = %s, want db-public-access", rewritten.Findings[0].Finding.ID)
	}
}

// --- Handler tests ---

func TestSearchFindings_Handler(t *testing.T) {
	srv, router := testServer(t)

	// Initialize search service for test.
	searchSvc, err := NewSearchService(srv.data.Findings)
	if err != nil {
		t.Fatalf("NewSearchService: %v", err)
	}
	searchSvc.embedSvc = NewEmbeddingService(srv.data.Findings)
	srv.searchSvc = searchSvc

	jwt := adminJWT(t)
	body := `{"query":"audit logging","mode":"keyword","page":1,"per_page":10}`

	rr := doRequest(t, router, "POST", "/api/v1/findings/search", body, jwt)
	assertStatus(t, rr, http.StatusOK)

	var resp searchResponse
	assertJSON(t, rr, &resp)

	if resp.Total == 0 {
		t.Error("expected search results")
	}
	if resp.Mode != "keyword" {
		t.Errorf("expected mode=keyword, got %s", resp.Mode)
	}
}

func TestSearchFindings_EmptyQuery(t *testing.T) {
	srv, router := testServer(t)
	searchSvc, err := NewSearchService(srv.data.Findings)
	if err != nil {
		t.Fatalf("NewSearchService: %v", err)
	}
	srv.searchSvc = searchSvc

	jwt := adminJWT(t)
	rr := doRequest(t, router, "POST", "/api/v1/findings/search", `{"query":""}`, jwt)
	assertStatus(t, rr, http.StatusBadRequest)
}

func TestSearchFindings_InvalidMode(t *testing.T) {
	srv, router := testServer(t)
	searchSvc, err := NewSearchService(srv.data.Findings)
	if err != nil {
		t.Fatalf("NewSearchService: %v", err)
	}
	srv.searchSvc = searchSvc

	jwt := operatorJWT(t)
	rr := doRequest(t, router, "POST", "/api/v1/findings/search", `{"query":"test","mode":"invalid"}`, jwt)
	assertStatus(t, rr, http.StatusBadRequest)
}

func TestSearchFindings_ViewerForbidden(t *testing.T) {
	_, router := testServer(t)
	jwt := viewerJWT(t)

	rr := doRequest(t, router, "POST", "/api/v1/findings/search", `{"query":"test"}`, jwt)
	assertStatus(t, rr, http.StatusForbidden)
}

func TestSearchFindings_Unauthenticated(t *testing.T) {
	_, router := testServer(t)

	rr := doRequest(t, router, "POST", "/api/v1/findings/search", `{"query":"test"}`, "")
	assertStatus(t, rr, http.StatusUnauthorized)
}

func TestSearchFindings_WithFilters(t *testing.T) {
	srv, router := testServer(t)
	searchSvc, err := NewSearchService(srv.data.Findings)
	if err != nil {
		t.Fatalf("NewSearchService: %v", err)
	}
	srv.searchSvc = searchSvc

	jwt := operatorJWT(t)
	body := `{"query":"security","filters":{"severity":["CRITICAL"]},"page":1,"per_page":50}`

	rr := doRequest(t, router, "POST", "/api/v1/findings/search", body, jwt)
	assertStatus(t, rr, http.StatusOK)

	var resp searchResponse
	assertJSON(t, rr, &resp)

	// All returned findings should be CRITICAL severity.
	for _, sf := range resp.Data {
		if !strings.EqualFold(sf.Finding.Severity, "CRITICAL") {
			t.Errorf("expected CRITICAL severity, got %s (finding %s)", sf.Finding.Severity, sf.Finding.ID)
		}
	}
}

func TestSearchFindings_HybridMode(t *testing.T) {
	srv, router := testServer(t)
	searchSvc, err := NewSearchService(srv.data.Findings)
	if err != nil {
		t.Fatalf("NewSearchService: %v", err)
	}
	searchSvc.embedSvc = NewEmbeddingService(srv.data.Findings)
	srv.searchSvc = searchSvc

	jwt := adminJWT(t)
	body := `{"query":"database audit trail","mode":"hybrid","page":1,"per_page":10}`

	rr := doRequest(t, router, "POST", "/api/v1/findings/search", body, jwt)
	assertStatus(t, rr, http.StatusOK)

	var resp searchResponse
	assertJSON(t, rr, &resp)

	if resp.Mode != "hybrid" {
		t.Errorf("expected mode=hybrid, got %s", resp.Mode)
	}
}

func TestSearchFindings_NotInitializedFallsBackToKeyword(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "POST", "/api/v1/findings/search", `{"query":"test"}`, jwt)
	assertStatus(t, rr, http.StatusOK)

	var resp searchResponse
	assertJSON(t, rr, &resp)

	if resp.Mode != "keyword" {
		t.Fatalf("mode = %s, want keyword fallback", resp.Mode)
	}
}

// --- Helpers ---

// testFindings returns a small set of findings for unit tests.
func testFindings() []Finding {
	// Try to load from test fixture.
	if data, err := loadTestFindingsFromFile("testdata/findings_test.json"); err == nil {
		return data
	}

	// Fallback: hardcoded minimal set.
	return []Finding{
		{
			ID:           "f-001",
			Title:        "Missing audit trail for database",
			Description:  "No audit logging configured for administrative actions.",
			Severity:     "MEDIUM",
			Category:     "COMPLIANCE",
			ServiceName:  "RDS",
			ResourceID:   "db-12345",
			ResourceName: "prod-database",
		},
		{
			ID:            "f-002",
			Title:         "S3 bucket public access enabled",
			Description:   "Storage bucket allows public read access.",
			Severity:      "CRITICAL",
			Category:      "DATA_PROTECTION",
			ServiceName:   "S3",
			ResourceID:    "bucket-67890",
			ResourceName:  "data-bucket-prod",
			CloudProvider: "aws",
		},
		{
			ID:            "f-003",
			Title:         "Security group allows unrestricted SSH",
			Description:   "Inbound SSH (port 22) is open to 0.0.0.0/0.",
			Severity:      "HIGH",
			Category:      "NETWORK",
			ServiceName:   "EC2",
			ResourceID:    "sg-abcdef",
			ResourceName:  "web-server-sg",
			CloudProvider: "aws",
		},
		{
			ID:            "f-004",
			Title:         "IAM policy with excessive permissions",
			Description:   "IAM role has AdministratorAccess policy attached.",
			Severity:      "CRITICAL",
			Category:      "IDENTITY",
			ServiceName:   "IAM",
			ResourceID:    "role-admin-123",
			ResourceName:  "admin-role",
			CloudProvider: "aws",
		},
	}
}

// loadTestFindingsFromFile loads findings from a JSON file.
func loadTestFindingsFromFile(path string) ([]Finding, error) {
	var findings []Finding
	if err := loadJSON(path, &findings); err != nil {
		return nil, err
	}
	// Limit to 50 for fast unit tests.
	if len(findings) > 50 {
		findings = findings[:50]
	}
	return findings, nil
}
