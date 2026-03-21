package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fpfnScenario represents a single FPFN test scenario.
type fpfnScenario struct {
	ID           string `json:"id"`
	Sector       string `json:"sector"`
	FindingType  string `json:"finding_type"`
	FindingClass string `json:"finding_class"`
	Scenario     string `json:"scenario"`
	Severity     string `json:"severity_reported"`
}

// loadFPFNScenarios loads all FPFN scenarios from testdata/cspm/fpfn/.
func loadFPFNScenarios(t *testing.T) []fpfnScenario {
	t.Helper()

	fpfnDir := filepath.Join(mockDataDir(), "testdata", "cspm", "fpfn")
	entries, err := os.ReadDir(fpfnDir)
	if err != nil {
		t.Fatalf("reading fpfn dir: %v", err)
	}

	var scenarios []fpfnScenario
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(fpfnDir, entry.Name()))
		if err != nil {
			t.Fatalf("reading %s: %v", entry.Name(), err)
		}
		var batch []fpfnScenario
		if err := json.Unmarshal(raw, &batch); err != nil {
			t.Fatalf("parsing %s: %v", entry.Name(), err)
		}
		scenarios = append(scenarios, batch...)
	}

	if len(scenarios) == 0 {
		t.Fatal("no FPFN scenarios found")
	}
	return scenarios
}

// TestSearchEval_FPFN uses FPFN scenarios as search queries and measures
// whether the scenario's finding_type appears in the top-K results.
// This is an evaluation test, not a correctness test — it reports metrics
// (MRR, Recall@5, Recall@10) without hard-fail thresholds.
func TestSearchEval_FPFN(t *testing.T) {
	scenarios := loadFPFNScenarios(t)

	// Load full test findings.
	mockData, err := loadTestMockData(mockDataDir())
	if err != nil {
		t.Fatalf("loading mock data: %v", err)
	}

	svc, err := NewSearchService(mockData.Findings)
	if err != nil {
		t.Fatalf("NewSearchService: %v", err)
	}

	ctx := context.Background()

	// Build a set of all finding_types in the corpus for fast lookup.
	findingTypeSet := make(map[string]bool)
	for _, f := range mockData.Findings {
		findingTypeSet[strings.ToUpper(f.Type)] = true
	}

	var (
		totalQueries int
		sumRR        float64 // sum of reciprocal ranks
		recall5      int
		recall10     int
	)

	for _, sc := range scenarios {
		// Use the scenario text as the search query.
		query := sc.Scenario
		if len(query) > 500 {
			query = query[:500] // Bleve handles long queries fine, but truncate for speed.
		}

		result, err := svc.Search(ctx, query, 1, 10)
		if err != nil {
			t.Errorf("search for %s: %v", sc.ID, err)
			continue
		}

		totalQueries++

		// Check if the scenario's finding_type appears in results.
		targetType := strings.ToUpper(sc.FindingType)
		found := false
		for rank, sf := range result.Findings {
			resultType := strings.ToUpper(sf.Finding.Type)
			resultTitle := strings.ToUpper(sf.Finding.Title)
			resultCategory := strings.ToUpper(sf.Finding.Category)

			// Match on type, or partial match in title/category.
			if resultType == targetType ||
				strings.Contains(resultTitle, targetType) ||
				strings.Contains(resultCategory, strings.ToUpper(sc.FindingClass)) {
				if !found {
					sumRR += 1.0 / float64(rank+1)
					found = true
				}
				if rank < 5 {
					recall5++
				}
				if rank < 10 {
					recall10++
				}
				break
			}
		}
	}

	// Report metrics.
	if totalQueries == 0 {
		t.Fatal("no queries executed")
	}

	mrr := sumRR / float64(totalQueries)
	r5 := float64(recall5) / float64(totalQueries)
	r10 := float64(recall10) / float64(totalQueries)

	t.Logf("Search Evaluation Metrics (BM25, %d queries):", totalQueries)
	t.Logf("  MRR:       %.4f", mrr)
	t.Logf("  Recall@5:  %.4f (%d/%d)", r5, recall5, totalQueries)
	t.Logf("  Recall@10: %.4f (%d/%d)", r10, recall10, totalQueries)

	// Soft threshold: warn if MRR is very low (indicates search is broken).
	if mrr < 0.01 && totalQueries > 5 {
		t.Logf("WARNING: MRR is very low (%.4f) — search may not be returning relevant results", mrr)
	}
}

// TestSearchEval_FPFN_Hybrid runs the same evaluation with hybrid search.
func TestSearchEval_FPFN_Hybrid(t *testing.T) {
	scenarios := loadFPFNScenarios(t)

	mockData, err := loadTestMockData(mockDataDir())
	if err != nil {
		t.Fatalf("loading mock data: %v", err)
	}

	svc, err := NewSearchService(mockData.Findings)
	if err != nil {
		t.Fatalf("NewSearchService: %v", err)
	}
	svc.embedSvc = NewEmbeddingService(mockData.Findings)

	ctx := context.Background()

	var (
		totalQueries int
		sumRR        float64
		recall5      int
		recall10     int
	)

	for _, sc := range scenarios {
		query := sc.Scenario
		if len(query) > 500 {
			query = query[:500]
		}

		result, err := svc.HybridSearch(ctx, query, 1, 10)
		if err != nil {
			t.Errorf("hybrid search for %s: %v", sc.ID, err)
			continue
		}

		totalQueries++

		targetType := strings.ToUpper(sc.FindingType)
		found := false
		for rank, sf := range result.Findings {
			resultType := strings.ToUpper(sf.Finding.Type)
			resultTitle := strings.ToUpper(sf.Finding.Title)
			resultCategory := strings.ToUpper(sf.Finding.Category)

			if resultType == targetType ||
				strings.Contains(resultTitle, targetType) ||
				strings.Contains(resultCategory, strings.ToUpper(sc.FindingClass)) {
				if !found {
					sumRR += 1.0 / float64(rank+1)
					found = true
				}
				if rank < 5 {
					recall5++
				}
				if rank < 10 {
					recall10++
				}
				break
			}
		}
	}

	if totalQueries == 0 {
		t.Fatal("no queries executed")
	}

	mrr := sumRR / float64(totalQueries)
	r5 := float64(recall5) / float64(totalQueries)
	r10 := float64(recall10) / float64(totalQueries)

	t.Logf("Search Evaluation Metrics (Hybrid, %d queries):", totalQueries)
	t.Logf("  MRR:       %.4f", mrr)
	t.Logf("  Recall@5:  %.4f (%d/%d)", r5, recall5, totalQueries)
	t.Logf("  Recall@10: %.4f (%d/%d)", r10, recall10, totalQueries)
}

// BenchmarkSearch measures BM25 keyword search throughput.
func BenchmarkSearch(b *testing.B) {
	mockData, err := loadTestMockData(mockDataDir())
	if err != nil {
		b.Fatalf("loading mock data: %v", err)
	}

	svc, err := NewSearchService(mockData.Findings)
	if err != nil {
		b.Fatalf("NewSearchService: %v", err)
	}

	queries := []string{
		"S3 bucket public access",
		"IAM excessive permissions",
		"database audit logging",
		"security group SSH",
		"encryption at rest disabled",
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		q := queries[i%len(queries)]
		_, err := svc.Search(ctx, q, 1, 10)
		if err != nil {
			b.Fatalf("search: %v", err)
		}
	}
}

// BenchmarkHybridSearch measures hybrid (BM25 + TF-IDF) search throughput.
func BenchmarkHybridSearch(b *testing.B) {
	mockData, err := loadTestMockData(mockDataDir())
	if err != nil {
		b.Fatalf("loading mock data: %v", err)
	}

	svc, err := NewSearchService(mockData.Findings)
	if err != nil {
		b.Fatalf("NewSearchService: %v", err)
	}
	svc.embedSvc = NewEmbeddingService(mockData.Findings)

	queries := []string{
		"S3 bucket public access",
		"IAM excessive permissions",
		"database audit logging",
		"security group SSH",
		"encryption at rest disabled",
	}

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		q := queries[i%len(queries)]
		_, err := svc.HybridSearch(ctx, q, 1, 10)
		if err != nil {
			b.Fatalf("hybrid search: %v", err)
		}
	}
}

// BenchmarkEmbeddingGeneration measures TF-IDF embedding generation throughput.
func BenchmarkEmbeddingGeneration(b *testing.B) {
	mockData, err := loadTestMockData(mockDataDir())
	if err != nil {
		b.Fatalf("loading mock data: %v", err)
	}

	es := NewEmbeddingService(mockData.Findings)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := es.GenerateEmbedding(ctx, "S3 bucket public access misconfiguration")
		if err != nil {
			b.Fatalf("embedding: %v", err)
		}
	}
}

// BenchmarkIndexBuilding measures the time to build a full BM25 index.
func BenchmarkIndexBuilding(b *testing.B) {
	mockData, err := loadTestMockData(mockDataDir())
	if err != nil {
		b.Fatalf("loading mock data: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		svc, err := NewSearchService(mockData.Findings)
		if err != nil {
			b.Fatalf("NewSearchService: %v", err)
		}
		_ = fmt.Sprintf("%d", len(svc.findings)) // prevent dead-code elimination
	}
}
