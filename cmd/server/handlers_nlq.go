package main

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"aegis/internal/ai"
	"aegis/internal/api"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/text/unicode/norm"
)

// nlqRateLimiter tracks per-user NLQ call timestamps to prevent AI budget drain.
var nlqRateLimiter = struct {
	sync.Mutex
	last map[string]time.Time
}{last: make(map[string]time.Time)}

const nlqMinInterval = 3 * time.Second // max ~20 req/min per user

// htmlTagPattern strips HTML tags to prevent XSS via AI-reflected content.
// The second alternative catches unclosed tags at end-of-string (e.g. "<script").
var htmlTagPattern = regexp.MustCompile(`<[^>]*>|</?[a-zA-Z][^>]*$`)

// allowedNLQValues whitelists structured filter values, preventing the AI
// from injecting arbitrary strings into the response.
var allowedNLQValues = map[string]map[string]bool{
	"severity":    {"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true},
	"provider":    {"aws": true, "azure": true, "gcp": true},
	"category":    {"VULNERABILITY": true, "MISCONFIGURATION": true, "DATA_PROTECTION": true, "IDENTITY": true, "NETWORK": true},
	"status":      {"open": true, "in_progress": true, "resolved": true},
	"environment": {"production": true, "staging": true, "development": true, "sandbox": true},
}

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
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.queryNLQ")
	defer span.End()
	r = r.WithContext(ctx)

	if s.enrichmentSvc == nil || s.enrichmentSvc.AI == nil {
		writeErrorResponse(w, "AI provider not configured", http.StatusServiceUnavailable)
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
		writeErrorResponse(w, "rate limit exceeded, try again shortly", http.StatusTooManyRequests)
		return
	}
	nlqRateLimiter.last[subject] = time.Now()
	nlqRateLimiter.Unlock()

	var req NLQRequest
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, "invalid request body", http.StatusBadRequest)
		return
	}

	query := strings.TrimSpace(req.Query)
	if query == "" {
		writeErrorResponse(w, "query is required", http.StatusBadRequest)
		return
	}
	if len(query) > 500 {
		writeErrorResponse(w, "query too long (max 500 chars)", http.StatusBadRequest)
		return
	}

	// Sanitize: strip HTML tags and control characters to prevent prompt
	// injection and reflected XSS through AI-mediated content.
	query = sanitizeNLQQuery(query)
	if query == "" {
		writeErrorResponse(w, "query is required", http.StatusBadRequest)
		return
	}

	span.SetAttributes(attribute.Int("nlq.query_length", len(query)))

	// Use TierFast for NLQ parsing — cost-optimized
	var result string
	var err error
	if rp, ok := s.enrichmentSvc.AI.(*ai.RoutingProvider); ok {
		result, err = rp.CompleteWithTier(r.Context(), ai.TierFast, nlqSystemPrompt, query)
	} else {
		result, err = s.enrichmentSvc.AI.CompleteWithSystem(r.Context(), nlqSystemPrompt, query)
	}

	if err != nil {
		// Fallback: return query as text search (still validate for consistency).
		resp := NLQResponse{Text: query}
		validateNLQResponse(&resp)
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

	// Validate: filter structured fields to allowed values only, sanitize text.
	// Prevents the AI from reflecting injected content or hallucinating categories.
	validateNLQResponse(&resp)

	// When NLQ returns a text field but no structured filters, use full-text
	// search to return actual matching findings alongside the NLQ response.
	if resp.Text != "" && len(resp.Severity) == 0 && len(resp.Provider) == 0 &&
		len(resp.Category) == 0 && len(resp.Status) == 0 && len(resp.Environment) == 0 &&
		s.searchSvc != nil {
		if searchResult, err := s.searchSvc.Search(r.Context(), resp.Text, 1, 10); err == nil && searchResult.Total > 0 {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"filters":  resp,
				"findings": searchResult.Findings,
				"total":    searchResult.Total,
			})
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// getAIUsage returns AI cost budget status.
func (s *Server) getAIUsage(w http.ResponseWriter, r *http.Request) {
	_, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.getAIUsage")
	defer span.End()

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

// sanitizeNLQQuery strips HTML tags and control characters from NLQ input.
// NFKC normalization collapses Unicode confusables (e.g., fullwidth U+FF1C '<')
// before the HTML tag regex runs — consistent with handlers_graph.go:88.
func sanitizeNLQQuery(s string) string {
	s = norm.NFKC.String(s)
	s = htmlTagPattern.ReplaceAllString(s, "")
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r != 127 {
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// validateNLQResponse filters AI output to only whitelisted values.
func validateNLQResponse(resp *NLQResponse) {
	resp.Severity = filterAllowed(resp.Severity, allowedNLQValues["severity"])
	resp.Provider = filterAllowed(resp.Provider, allowedNLQValues["provider"])
	resp.Category = filterAllowed(resp.Category, allowedNLQValues["category"])
	resp.Status = filterAllowed(resp.Status, allowedNLQValues["status"])
	resp.Environment = filterAllowed(resp.Environment, allowedNLQValues["environment"])
	if resp.Text != "" {
		resp.Text = sanitizeNLQQuery(resp.Text)
	}
}

// filterAllowed keeps only values present in the allowed set.
func filterAllowed(values []string, allowed map[string]bool) []string {
	if len(values) == 0 {
		return nil
	}
	var result []string
	for _, v := range values {
		if allowed[v] {
			result = append(result, v)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}
