package main

import (
	"context"
	"math"
	"sort"
	"strings"
	"sync"
	"unicode"
)

// sparseComponent represents a single weighted vocabulary term.
type sparseComponent struct {
	index  int
	weight float32
}

// sparseVector stores only non-zero TF-IDF weights.
type sparseVector []sparseComponent

type weightedDoc struct {
	id     string
	weight float32
}

// EmbeddingService generates sparse TF-IDF vectors and inverted postings.
// This keeps full-corpus semantic search memory-bounded for large finding sets.
type EmbeddingService struct {
	mu         sync.RWMutex
	vocab      map[string]int          // term -> index in vocabulary
	idf        []float64               // inverse document frequency per term
	embeddings map[string]sparseVector // finding ID -> sparse vector
	postings   map[int][]weightedDoc   // term index -> weighted document list
	vocabSize  int                     // capped at maxVocabSize
}

const maxVocabSize = 10_000

// NewEmbeddingService builds a TF-IDF vocabulary from all finding text and
// pre-computes sparse embeddings plus postings for each finding.
func NewEmbeddingService(findings []Finding) *EmbeddingService {
	es := &EmbeddingService{
		embeddings: make(map[string]sparseVector, len(findings)),
		postings:   make(map[int][]weightedDoc, maxVocabSize),
	}

	docs := make([]string, len(findings))
	for i := range findings {
		docs[i] = findingSearchText(&findings[i])
	}

	es.buildVocabulary(docs)

	for i := range findings {
		es.IndexDocument(findings[i].ID, docs[i])
	}

	return es
}

// buildVocabulary constructs the term vocabulary and IDF weights from a corpus.
func (es *EmbeddingService) buildVocabulary(docs []string) {
	df := make(map[string]int)
	tf := make(map[string]int)

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

	type termFreq struct {
		term string
		freq int
	}
	ranked := make([]termFreq, 0, len(tf))
	for term, freq := range tf {
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
		es.idf[i] = math.Log(n/float64(df[term])) + 1.0
	}
}

// GenerateEmbedding creates a sparse TF-IDF vector for arbitrary text.
func (es *EmbeddingService) GenerateEmbedding(_ context.Context, text string) (sparseVector, error) {
	return es.tfidfVector(text), nil
}

// GetCachedEmbedding returns a pre-computed embedding for a finding ID.
func (es *EmbeddingService) GetCachedEmbedding(id string) (sparseVector, bool) {
	es.mu.RLock()
	defer es.mu.RUnlock()
	vec, ok := es.embeddings[id]
	return vec, ok
}

// CacheEmbedding stores an embedding for a finding ID and refreshes postings.
func (es *EmbeddingService) CacheEmbedding(id string, vec sparseVector) {
	es.mu.Lock()
	defer es.mu.Unlock()
	es.removePostingLocked(id)
	es.embeddings[id] = vec
	es.addPostingLocked(id, vec)
}

// IndexDocument tokenizes a finding against the existing vocabulary and updates
// both the sparse embedding cache and inverted postings for semantic search.
func (es *EmbeddingService) IndexDocument(id, text string) {
	vec := es.tfidfVector(text)
	es.CacheEmbedding(id, vec)
}

// SearchSimilar returns the top-N document IDs ranked by cosine similarity.
func (es *EmbeddingService) SearchSimilar(query sparseVector, topN int) []scoredID {
	if topN <= 0 || len(query) == 0 {
		return nil
	}

	es.mu.RLock()
	defer es.mu.RUnlock()

	scores := make(map[string]float64, min(topN*20, len(es.embeddings)))
	for _, term := range query {
		postings := es.postings[term.index]
		for _, doc := range postings {
			scores[doc.id] += float64(term.weight * doc.weight)
		}
	}

	if len(scores) == 0 {
		return nil
	}

	candidates := make([]scoredID, 0, len(scores))
	for id, score := range scores {
		if score > 0 {
			candidates = append(candidates, scoredID{id: id, score: score})
		}
	}

	sortByScoreDesc(candidates)
	if topN < len(candidates) {
		candidates = candidates[:topN]
	}
	return candidates
}

// tfidfVector computes a normalized sparse TF-IDF vector for the given text.
func (es *EmbeddingService) tfidfVector(text string) sparseVector {
	tokens := tokenize(text)
	if len(tokens) == 0 {
		return nil
	}

	termFreq := make(map[int]int, len(tokens))
	maxTF := 0
	for _, token := range tokens {
		if idx, ok := es.vocab[token]; ok {
			termFreq[idx]++
			if termFreq[idx] > maxTF {
				maxTF = termFreq[idx]
			}
		}
	}
	if len(termFreq) == 0 || maxTF == 0 {
		return nil
	}

	vec := make(sparseVector, 0, len(termFreq))
	for idx, count := range termFreq {
		augTF := 0.5 + 0.5*float64(count)/float64(maxTF)
		vec = append(vec, sparseComponent{
			index:  idx,
			weight: float32(augTF * es.idf[idx]),
		})
	}
	sort.Slice(vec, func(i, j int) bool {
		return vec[i].index < vec[j].index
	})
	l2NormalizeSparse(vec)
	return vec
}

func (es *EmbeddingService) removePostingLocked(id string) {
	if old, ok := es.embeddings[id]; ok {
		for _, component := range old {
			postings := es.postings[component.index]
			for i := range postings {
				if postings[i].id == id {
					es.postings[component.index] = append(postings[:i], postings[i+1:]...)
					break
				}
			}
		}
	}
}

func (es *EmbeddingService) addPostingLocked(id string, vec sparseVector) {
	for _, component := range vec {
		es.postings[component.index] = append(es.postings[component.index], weightedDoc{
			id:     id,
			weight: component.weight,
		})
	}
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

// cosineSimilarity computes the cosine similarity between two sparse vectors.
func cosineSimilarity(a, b sparseVector) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}

	var dot float64
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i].index == b[j].index:
			dot += float64(a[i].weight * b[j].weight)
			i++
			j++
		case a[i].index < b[j].index:
			i++
		default:
			j++
		}
	}
	return dot
}

// l2NormalizeSparse normalizes a sparse vector in-place to unit length.
func l2NormalizeSparse(vec sparseVector) {
	var sum float64
	for _, component := range vec {
		sum += float64(component.weight) * float64(component.weight)
	}
	if sum == 0 {
		return
	}
	norm := float32(math.Sqrt(sum))
	for i := range vec {
		vec[i].weight /= norm
	}
}
