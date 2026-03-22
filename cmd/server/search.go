package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blevesearch/bleve/v2"
	"github.com/blevesearch/bleve/v2/mapping"
	"github.com/blevesearch/bleve/v2/search/searcher"
)

// SearchResult holds the output of a search query.
type SearchResult struct {
	Findings []ScoredFinding `json:"findings"`
	Total    int             `json:"total"`
	MaxScore float64         `json:"max_score"`
	Took     time.Duration   `json:"took"`
}

// ScoredFinding wraps a Finding with its relevance score.
type ScoredFinding struct {
	Finding
	Score float64 `json:"score"`
}

// findingDocument is the Bleve-indexable representation of a Finding.
// The Content field concatenates all text with high-value fields repeated
// to simulate field boosting (Bleve v2 FieldMapping lacks a Boost property).
//
// Effective boosting via repetition:
//   - Title: repeated 3x (boost ~3.0)
//   - ResourceID/ResourceName: repeated 2x (boost ~2.0)
//   - Description: 1x (baseline)
//   - Remediation: 1x (slightly diluted by other content)
//   - Other fields: 1x
type findingDocument struct {
	Content string `json:"content"`
}

// SearchService provides BM25 full-text search over findings using Bleve.
type SearchService struct {
	index    bleve.Index
	mu       sync.RWMutex
	findings map[string]*Finding // ID -> Finding pointer for result hydration
	embedSvc *EmbeddingService   // optional: nil when semantic search is disabled
}

// NewSearchService builds an in-memory BM25 index from the given findings.
func NewSearchService(findings []Finding) (*SearchService, error) {
	indexMapping := buildIndexMapping()

	// Set max clause count once at init (not per-query) to avoid data race.
	searcher.DisjunctionMaxClauseCount = 4096

	// Create an in-memory index (no disk persistence).
	index, err := bleve.NewMemOnly(indexMapping)
	if err != nil {
		return nil, fmt.Errorf("creating bleve index: %w", err)
	}

	ss := &SearchService{
		index:    index,
		findings: make(map[string]*Finding, len(findings)),
	}

	// Batch-index all findings.
	batch := index.NewBatch()
	for i := range findings {
		f := &findings[i]
		ss.findings[f.ID] = f
		doc := toFindingDocument(f)
		_ = batch.Index(f.ID, doc) // error is nil for in-memory batch
	}
	if err := index.Batch(batch); err != nil {
		return nil, fmt.Errorf("batch indexing findings: %w", err)
	}

	return ss, nil
}

// buildIndexMapping creates a Bleve index mapping for single-field documents.
// Field boosting is achieved via content repetition in toFindingDocument.
func buildIndexMapping() mapping.IndexMapping {
	contentField := bleve.NewTextFieldMapping()
	contentField.Analyzer = "en"
	contentField.Store = false
	contentField.IncludeTermVectors = false
	contentField.IncludeInAll = true

	docMapping := bleve.NewDocumentMapping()
	docMapping.AddFieldMappingsAt("content", contentField)

	indexMapping := bleve.NewIndexMapping()
	indexMapping.DefaultMapping = docMapping
	indexMapping.DefaultAnalyzer = "en"

	return indexMapping
}

// toFindingDocument converts a Finding into a content-boosted document.
// High-value fields are repeated to increase their BM25 term frequency.
func toFindingDocument(f *Finding) findingDocument {
	var sb strings.Builder

	// Title repeated 3x for ~3.0 boost.
	for range 3 {
		sb.WriteString(f.Title)
		sb.WriteByte(' ')
	}

	// ResourceID and ResourceName repeated 2x for ~2.0 boost.
	for range 2 {
		sb.WriteString(f.ResourceID)
		sb.WriteByte(' ')
		sb.WriteString(f.ResourceName)
		sb.WriteByte(' ')
	}

	// Description 1x (baseline).
	sb.WriteString(f.Description)
	sb.WriteByte(' ')

	// Remediation 1x.
	sb.WriteString(f.Remediation)
	sb.WriteByte(' ')

	// Supplementary fields 1x each.
	for _, s := range []string{
		f.ResourceARN, f.CanonicalRuleID, f.ServiceName,
		f.Category, f.Type, f.AIRiskRationale,
	} {
		if s != "" {
			sb.WriteString(s)
			sb.WriteByte(' ')
		}
	}

	return findingDocument{Content: sb.String()}
}

// Search executes a BM25 keyword search. The query string is parsed as a
// Bleve match query (tokenized, stemmed, scored by TF-IDF/BM25).
func (ss *SearchService) Search(ctx context.Context, query string, page, perPage int) (*SearchResult, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	ss.mu.RLock()
	defer ss.mu.RUnlock()

	q := bleve.NewMatchQuery(query)
	q.SetFuzziness(0) // exact token matching, no fuzzy

	offset := (page - 1) * perPage
	searchReq := bleve.NewSearchRequestOptions(q, perPage, offset, false)

	start := time.Now()
	bleveResult, err := ss.index.SearchInContext(ctx, searchReq)
	if err != nil {
		return nil, fmt.Errorf("bleve search: %w", err)
	}
	took := time.Since(start)

	results := make([]ScoredFinding, 0, len(bleveResult.Hits))
	for _, hit := range bleveResult.Hits {
		if f, ok := ss.findings[hit.ID]; ok {
			results = append(results, ScoredFinding{
				Finding: *f,
				Score:   hit.Score,
			})
		}
	}

	return &SearchResult{
		Findings: results,
		Total:    int(bleveResult.Total), //nolint:gosec // Total is bounded by index size
		MaxScore: bleveResult.MaxScore,
		Took:     took,
	}, nil
}

// IndexFinding adds or updates a single finding in the index.
// Called from ingestFinding for incremental indexing.
func (ss *SearchService) IndexFinding(f Finding) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	// Store a copy so the pointer in our map stays valid.
	fCopy := f
	ss.findings[f.ID] = &fCopy
	doc := toFindingDocument(&fCopy)
	_ = ss.index.Index(f.ID, doc)
}

// Close releases the Bleve index resources. Called during server shutdown.
func (ss *SearchService) Close() error {
	return ss.index.Close()
}

// HybridSearch runs BM25 + cosine similarity in parallel and fuses results
// via Reciprocal Rank Fusion (RRF). Falls back to keyword-only when the
// embedding service is nil.
func (ss *SearchService) HybridSearch(ctx context.Context, query string, page, perPage int) (*SearchResult, error) {
	if ss.embedSvc == nil {
		return ss.Search(ctx, query, page, perPage)
	}

	type rankedResult struct {
		results []ScoredFinding
		err     error
	}

	bm25Ch := make(chan rankedResult, 1)
	semCh := make(chan rankedResult, 1)

	// Run BM25 search in goroutine — fetch enough candidates for fusion.
	go func() {
		res, err := ss.Search(ctx, query, 1, 200) // fetch top-200 for ranking
		if err != nil {
			bm25Ch <- rankedResult{err: err}
			return
		}
		bm25Ch <- rankedResult{results: res.Findings}
	}()

	// Run semantic search in goroutine.
	go func() {
		res, err := ss.semanticSearch(ctx, query, 200)
		if err != nil {
			semCh <- rankedResult{err: err}
			return
		}
		semCh <- rankedResult{results: res}
	}()

	start := time.Now()
	bm25Res := <-bm25Ch
	semRes := <-semCh

	// If both fail, return the BM25 error (more informative).
	if bm25Res.err != nil && semRes.err != nil {
		return nil, bm25Res.err
	}

	// If only one signal is available, use it directly.
	if bm25Res.err != nil {
		return ss.paginateScored(semRes.results, page, perPage, time.Since(start))
	}
	if semRes.err != nil {
		return ss.paginateScored(bm25Res.results, page, perPage, time.Since(start))
	}

	// RRF fusion: score = sum(1/(k + rank_i)) with k=60
	fused := rrfFuse(bm25Res.results, semRes.results, 60)

	return ss.paginateScored(fused, page, perPage, time.Since(start))
}

// semanticSearch performs cosine-similarity search against TF-IDF embeddings.
func (ss *SearchService) semanticSearch(ctx context.Context, query string, topN int) ([]ScoredFinding, error) {
	if ss.embedSvc == nil {
		return nil, fmt.Errorf("embedding service not initialized")
	}

	queryVec, err := ss.embedSvc.GenerateEmbedding(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("generating query embedding: %w", err)
	}

	// Snapshot finding IDs and cached embeddings under RLock, then release
	// to avoid holding the lock during CPU-intensive embedding generation.
	ss.mu.RLock()
	type findingSnapshot struct {
		id  string
		vec []float32
	}
	snapshots := make([]findingSnapshot, 0, len(ss.findings))
	for id := range ss.findings {
		vec, _ := ss.embedSvc.GetCachedEmbedding(id)
		snapshots = append(snapshots, findingSnapshot{id: id, vec: vec})
	}
	ss.mu.RUnlock()

	// Score candidates outside the lock.
	candidates := make([]scoredID, 0, len(snapshots))
	for _, snap := range snapshots {
		var fVec []float32
		if snap.vec != nil {
			fVec = snap.vec
		} else {
			// Generate embedding for uncached finding (rare after init).
			ss.mu.RLock()
			f := ss.findings[snap.id]
			ss.mu.RUnlock()
			if f != nil {
				text := findingSearchText(f)
				if vec, err := ss.embedSvc.GenerateEmbedding(ctx, text); err == nil {
					ss.embedSvc.CacheEmbedding(snap.id, vec)
					fVec = vec
				}
			}
		}
		if fVec != nil {
			sim := cosineSimilarity(queryVec, fVec)
			if sim > 0 {
				candidates = append(candidates, scoredID{id: snap.id, score: sim})
			}
		}
	}

	// Sort by descending similarity.
	sortByScoreDesc(candidates)

	if topN > len(candidates) {
		topN = len(candidates)
	}

	// Hydrate results under RLock to prevent race with IndexFinding.
	ss.mu.RLock()
	results := make([]ScoredFinding, 0, topN)
	for i := 0; i < topN; i++ {
		if f, ok := ss.findings[candidates[i].id]; ok {
			results = append(results, ScoredFinding{
				Finding: *f,
				Score:   candidates[i].score,
			})
		}
	}
	ss.mu.RUnlock()

	return results, nil
}

// scoredID pairs a finding ID with a similarity score for sorting.
type scoredID struct {
	id    string
	score float64
}

func sortByScoreDesc(items []scoredID) {
	sort.Slice(items, func(i, j int) bool {
		return items[i].score > items[j].score
	})
}

// rrfFuse merges two ranked lists using Reciprocal Rank Fusion.
// score_final = sum(1/(k + rank_i)) for each signal where the finding appears.
func rrfFuse(bm25, semantic []ScoredFinding, k int) []ScoredFinding {
	type fusedEntry struct {
		finding ScoredFinding
		score   float64
	}

	seen := make(map[string]*fusedEntry, len(bm25)+len(semantic))

	for rank, sf := range bm25 {
		id := sf.Finding.ID
		if e, ok := seen[id]; ok {
			e.score += 1.0 / float64(k+rank+1)
		} else {
			seen[id] = &fusedEntry{finding: sf, score: 1.0 / float64(k+rank+1)}
		}
	}

	for rank, sf := range semantic {
		id := sf.Finding.ID
		if e, ok := seen[id]; ok {
			e.score += 1.0 / float64(k+rank+1)
		} else {
			seen[id] = &fusedEntry{finding: sf, score: 1.0 / float64(k+rank+1)}
		}
	}

	// Collect and sort by fused score descending.
	results := make([]ScoredFinding, 0, len(seen))
	for _, e := range seen {
		e.finding.Score = e.score
		results = append(results, e.finding)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})

	return results
}

// paginateScored slices a scored result set for the given page.
func (ss *SearchService) paginateScored(results []ScoredFinding, page, perPage int, took time.Duration) (*SearchResult, error) {
	total := len(results)
	offset := (page - 1) * perPage
	if offset >= total {
		return &SearchResult{
			Findings: []ScoredFinding{},
			Total:    total,
			Took:     took,
		}, nil
	}

	end := offset + perPage
	if end > total {
		end = total
	}

	maxScore := 0.0
	if len(results) > 0 {
		maxScore = results[0].Score
	}

	return &SearchResult{
		Findings: results[offset:end],
		Total:    total,
		MaxScore: maxScore,
		Took:     took,
	}, nil
}

// findingSearchText concatenates searchable text fields for embedding generation.
func findingSearchText(f *Finding) string {
	parts := []string{
		f.Title,
		f.Description,
		f.ResourceName,
		f.ResourceID,
		f.ServiceName,
		f.Category,
		f.Type,
	}

	var sb strings.Builder
	for _, p := range parts {
		if p != "" {
			if sb.Len() > 0 {
				sb.WriteByte(' ')
			}
			sb.WriteString(p)
		}
	}
	return sb.String()
}
