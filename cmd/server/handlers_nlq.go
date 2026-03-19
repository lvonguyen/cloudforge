package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"aegis/internal/ai"
	"aegis/internal/api"
)

// nlqRateLimiter tracks per-user NLQ call timestamps to prevent AI budget drain.
var nlqRateLimiter = struct {
	sync.Mutex
	last map[string]time.Time
}{last: make(map[string]time.Time)}

const nlqMinInterval = 3 * time.Second // max ~20 req/min per user

// NLQRequest is the request body for the NLQ endpoint.
type NLQRequest struct {
	Query string `json:"query"`
}

// NLQResponse is the structured filter response from NLQ parsing.
type NLQResponse struct {
	Severity    []string `json:"severity,omitempty"`
	Provider    []string `json:"provider,omitempty"`
	Category    []string `json:"category,omitempty"`
	Status      []string `json:"status,omitempty"`
	Environment []string `json:"environment,omitempty"`
	Text        string   `json:"text,omitempty"`
}

const nlqSystemPrompt = `You are a security query parser. Convert the user's natural language query into a structured JSON filter for a CSPM findings dashboard.

Return ONLY valid JSON with these optional fields:
- "severity": array of "CRITICAL", "HIGH", "MEDIUM", "LOW"
- "provider": array of "aws", "azure", "gcp"
- "category": array of "VULNERABILITY", "MISCONFIGURATION", "DATA_PROTECTION", "IDENTITY", "NETWORK"
- "status": array of "open", "in_progress", "resolved"
- "environment": array of "production", "staging", "development", "sandbox"
- "text": free text search term if nothing else matches

Examples:
- "critical AWS misconfigs" -> {"severity":["CRITICAL"],"provider":["aws"],"category":["MISCONFIGURATION"]}
- "all open high vulns in prod" -> {"severity":["HIGH"],"category":["VULNERABILITY"],"status":["open"],"environment":["production"]}
- "S3 bucket" -> {"text":"S3 bucket"}

Only include fields that are clearly specified. Return {} for ambiguous queries.`

func (s *Server) queryNLQ(w http.ResponseWriter, r *http.Request) {
	if s.enrichmentSvc == nil || s.enrichmentSvc.AI == nil {
		http.Error(w, `{"error":"AI provider not configured"}`, http.StatusServiceUnavailable)
		return
	}

	// Per-user rate limit to prevent AI budget drain
	claims, _ := api.GetClaimsFromContext(r.Context())
	subject := "unknown"
	if claims != nil {
		subject = claims.Subject
	}
	nlqRateLimiter.Lock()
	// Evict stale entries to prevent unbounded map growth
	for k, t := range nlqRateLimiter.last {
		if time.Since(t) > nlqMinInterval*10 {
			delete(nlqRateLimiter.last, k)
		}
	}
	if last, ok := nlqRateLimiter.last[subject]; ok && time.Since(last) < nlqMinInterval {
		nlqRateLimiter.Unlock()
		http.Error(w, `{"error":"rate limit exceeded, try again shortly"}`, http.StatusTooManyRequests)
		return
	}
	nlqRateLimiter.last[subject] = time.Now()
	nlqRateLimiter.Unlock()

	var req NLQRequest
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	query := strings.TrimSpace(req.Query)
	if query == "" {
		http.Error(w, `{"error":"query is required"}`, http.StatusBadRequest)
		return
	}
	if len(query) > 500 {
		http.Error(w, `{"error":"query too long (max 500 chars)"}`, http.StatusBadRequest)
		return
	}

	// Use TierFast for NLQ parsing — cost-optimized
	var result string
	var err error
	if rp, ok := s.enrichmentSvc.AI.(*ai.RoutingProvider); ok {
		result, err = rp.CompleteWithTier(r.Context(), ai.TierFast, nlqSystemPrompt, query)
	} else {
		result, err = s.enrichmentSvc.AI.CompleteWithSystem(r.Context(), nlqSystemPrompt, query)
	}

	if err != nil {
		// Fallback: return query as text search
		resp := NLQResponse{Text: query}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}

	// Parse AI response into structured filter
	var resp NLQResponse
	if err := json.Unmarshal([]byte(result), &resp); err != nil {
		// AI returned unparseable output — fall back to text search
		resp = NLQResponse{Text: query}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// getAIUsage returns AI cost budget status.
func (s *Server) getAIUsage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if s.enrichmentSvc == nil || s.enrichmentSvc.AI == nil {
		json.NewEncoder(w).Encode(map[string]any{
			"monthly_budget_cents": 0,
			"spent_cents":          0,
			"remaining_cents":      0,
			"exhausted":            false,
			"tiers":                []any{},
		})
		return
	}

	rp, ok := s.enrichmentSvc.AI.(*ai.RoutingProvider)
	if !ok {
		// No routing provider — return zero usage
		json.NewEncoder(w).Encode(map[string]any{
			"monthly_budget_cents": 0,
			"spent_cents":          0,
			"remaining_cents":      0,
			"exhausted":            false,
			"tiers":                []any{},
		})
		return
	}

	json.NewEncoder(w).Encode(rp.GetBudgetStatus())
}
