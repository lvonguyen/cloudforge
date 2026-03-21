package main

import (
	"context"
	"math"
	"sort"
	"strings"
	"sync"
	"unicode"
)

// EmbeddingService generates and caches TF-IDF sparse vectors for findings.
// This is a pure-Go implementation requiring no external embedding API.
type EmbeddingService struct {
	mu         sync.RWMutex
	vocab      map[string]int       // term -> index in vocabulary
	idf        []float64            // inverse document frequency per term
	embeddings map[string][]float32 // finding ID -> TF-IDF vector
	vocabSize  int                  // capped at maxVocabSize
}

const maxVocabSize = 10_000

// NewEmbeddingService builds a TF-IDF vocabulary from all finding text and
// pre-computes embeddings for each finding.
func NewEmbeddingService(findings []Finding) *EmbeddingService {
	es := &EmbeddingService{
		embeddings: make(map[string][]float32, len(findings)),
	}

	// Build corpus: one document per finding.
	docs := make([]string, len(findings))
	for i := range findings {
		docs[i] = findingSearchText(&findings[i])
	}

	// Build vocabulary and IDF.
	es.buildVocabulary(docs)

	// Pre-compute embeddings for all findings.
	for i := range findings {
		vec := es.tfidfVector(docs[i])
		es.embeddings[findings[i].ID] = vec
	}

	return es
}

// buildVocabulary constructs the term vocabulary and IDF weights from a corpus.
func (es *EmbeddingService) buildVocabulary(docs []string) {
	// Count document frequency for each term.
	df := make(map[string]int) // term -> number of docs containing it
	tf := make(map[string]int) // term -> total frequency (for ranking)

	for _, doc := range docs {
		seen := make(map[string]bool)
		for _, token := range tokenize(doc) {
			tf[token]++
			if !seen[token] {
				df[token]++
				seen[token] = true
			}
		}
	}

	// Rank terms by total frequency, keep top maxVocabSize.
	type termFreq struct {
		term string
		freq int
	}
	ranked := make([]termFreq, 0, len(tf))
	for term, freq := range tf {
		// Filter out very rare terms (appear in <2 docs) and stop words.
		if df[term] >= 2 && len(term) > 1 {
			ranked = append(ranked, termFreq{term: term, freq: freq})
		}
	}
	sort.Slice(ranked, func(i, j int) bool {
		return ranked[i].freq > ranked[j].freq
	})

	vocabSize := len(ranked)
	if vocabSize > maxVocabSize {
		vocabSize = maxVocabSize
	}

	es.vocab = make(map[string]int, vocabSize)
	es.idf = make([]float64, vocabSize)
	es.vocabSize = vocabSize

	n := float64(len(docs))
	for i := 0; i < vocabSize; i++ {
		term := ranked[i].term
		es.vocab[term] = i
		// Standard IDF: log(N / df(t)) + 1 (smoothed)
		es.idf[i] = math.Log(n/float64(df[term])) + 1.0
	}
}

// GenerateEmbedding creates a TF-IDF vector for arbitrary text.
func (es *EmbeddingService) GenerateEmbedding(_ context.Context, text string) ([]float32, error) {
	return es.tfidfVector(text), nil
}

// GetCachedEmbedding returns a pre-computed embedding for a finding ID.
func (es *EmbeddingService) GetCachedEmbedding(id string) ([]float32, bool) {
	es.mu.RLock()
	defer es.mu.RUnlock()
	vec, ok := es.embeddings[id]
	return vec, ok
}

// CacheEmbedding stores an embedding for a finding ID.
func (es *EmbeddingService) CacheEmbedding(id string, vec []float32) {
	es.mu.Lock()
	defer es.mu.Unlock()
	es.embeddings[id] = vec
}

// tfidfVector computes a normalized TF-IDF vector for the given text.
func (es *EmbeddingService) tfidfVector(text string) []float32 {
	tokens := tokenize(text)
	if len(tokens) == 0 {
		return make([]float32, es.vocabSize)
	}

	// Count term frequencies in this document.
	termFreq := make(map[string]int, len(tokens))
	for _, t := range tokens {
		termFreq[t]++
	}

	vec := make([]float32, es.vocabSize)
	maxTF := 0
	for _, count := range termFreq {
		if count > maxTF {
			maxTF = count
		}
	}

	// Compute TF-IDF: augmented TF (0.5 + 0.5 * tf/max_tf) * IDF
	for term, count := range termFreq {
		if idx, ok := es.vocab[term]; ok {
			augTF := 0.5 + 0.5*float64(count)/float64(maxTF)
			vec[idx] = float32(augTF * es.idf[idx])
		}
	}

	// L2-normalize for cosine similarity.
	l2Normalize(vec)

	return vec
}

// tokenize splits text into lowercase tokens, stripping punctuation.
func tokenize(text string) []string {
	lower := strings.ToLower(text)
	words := strings.FieldsFunc(lower, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_'
	})

	tokens := make([]string, 0, len(words))
	for _, w := range words {
		w = strings.Trim(w, "-_")
		if len(w) > 0 {
			tokens = append(tokens, w)
		}
	}
	return tokens
}

// cosineSimilarity computes the cosine similarity between two vectors.
// Both vectors must be L2-normalized for this to equal dot product.
func cosineSimilarity(a, b []float32) float64 {
	if len(a) != len(b) {
		// Mismatched dimensions: degrade to 0.
		return 0
	}
	var dot float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
	}
	return dot
}

// l2Normalize normalizes a vector in-place to unit length.
func l2Normalize(vec []float32) {
	var sum float64
	for _, v := range vec {
		sum += float64(v) * float64(v)
	}
	if sum == 0 {
		return
	}
	norm := float32(math.Sqrt(sum))
	for i := range vec {
		vec[i] /= norm
	}
}
