package main

import (
	"aegis/internal/api"
	"encoding/json"
	"net/http"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// searchRequest is the request body for POST /api/v1/findings/search.
type searchRequest struct {
	Query   string        `json:"query"`
	Mode    string        `json:"mode"` // "keyword", "semantic", "hybrid" (default: "hybrid")
	Filters searchFilters `json:"filters"`
	Page    int           `json:"page"`
	PerPage int           `json:"per_page"`
}

// searchFilters are optional structured filters applied after text search.
type searchFilters struct {
	Severity []string `json:"severity,omitempty"`
	Provider []string `json:"provider,omitempty"`
	Status   []string `json:"status,omitempty"`
}

// searchResponse is the paginated search result envelope.
type searchResponse struct {
	Data     []ScoredFinding `json:"data"`
	Total    int             `json:"total"`
	Page     int             `json:"page"`
	PerPage  int             `json:"per_page"`
	MaxScore float64         `json:"max_score"`
	TookMS   int64           `json:"took_ms"`
	Mode     string          `json:"mode"`
}

// searchFindings handles POST /api/v1/findings/search.
// Combines Bleve BM25 text search with optional structured filters.
func (s *Server) searchFindings(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.searchFindings")
	defer span.End()
	r = r.WithContext(ctx)

	if s.searchSvc == nil {
		writeErrorResponse(w, "search service not initialized", http.StatusServiceUnavailable)
		return
	}

	var req searchRequest
	if !s.decodeJSONBody(w, r, &req) {
		return
	}

	query := strings.TrimSpace(req.Query)
	if query == "" {
		writeErrorResponse(w, "query is required", http.StatusBadRequest)
		return
	}
	if len(query) > 1000 {
		writeErrorResponse(w, "query too long (max 1000 chars)", http.StatusBadRequest)
		return
	}

	// Defaults.
	page := req.Page
	if page < 1 {
		page = 1
	}
	perPage := req.PerPage
	if perPage < 1 {
		perPage = 50
	}
	if perPage > 200 {
		perPage = 200
	}

	mode := strings.ToLower(req.Mode)
	if mode == "" {
		mode = "hybrid"
	}
	switch mode {
	case "keyword", "semantic", "hybrid":
		// valid
	default:
		writeErrorResponse(w, "mode must be keyword, semantic, or hybrid", http.StatusBadRequest)
		return
	}

	span.SetAttributes(
		attribute.Int("search.query_length", len(query)),
		attribute.String("search.mode", mode),
		attribute.Int("search.page", page),
		attribute.Int("search.per_page", perPage),
	)

	// Execute search based on mode.
	var result *SearchResult
	var err error

	switch mode {
	case "keyword":
		// Fetch wide window from Bleve — post-filter ABAC + structured filters
		// will reduce the set, so pre-paginating at the index level produces
		// wrong results for scoped users on page 2+.
		result, err = s.searchSvc.Search(ctx, query, 1, 200)
	case "semantic":
		if s.searchSvc.embedSvc == nil {
			writeErrorResponse(w, "semantic search not available", http.StatusServiceUnavailable)
			return
		}
		scored, sErr := s.searchSvc.semanticSearch(ctx, query, 200)
		if sErr != nil {
			s.writeInternalError(w, sErr, "semantic_search")
			return
		}
		result, err = s.searchSvc.paginateScored(scored, page, perPage, 0)
	case "hybrid":
		result, err = s.searchSvc.HybridSearch(ctx, query, page, perPage)
	}

	if err != nil {
		s.writeInternalError(w, err, "search")
		return
	}

	// Enforce ABAC scope — filter out findings outside caller's authorized scope.
	claims, _ := api.GetClaimsFromContext(r.Context())
	scope := api.ScopeFromContext(claims)
	scopedFindings := result.Findings
	if scope != nil {
		scopedFindings = make([]ScoredFinding, 0, len(result.Findings))
		for _, sf := range result.Findings {
			if api.EnforceScope(scope, &sf.Finding) == nil {
				scopedFindings = append(scopedFindings, sf)
			}
		}
	}

	// Apply optional structured filters post-search.
	filtered := applySearchFilters(scopedFindings, req.Filters)

	// Re-paginate after filtering if filters removed results.
	total := len(filtered)
	offset := (page - 1) * perPage
	if offset >= total {
		offset = 0
	}
	end := offset + perPage
	if end > total {
		end = total
	}

	pageData := filtered
	if len(filtered) > 0 && offset < total {
		pageData = filtered[offset:end]
	} else if len(filtered) == 0 {
		pageData = []ScoredFinding{}
	}

	maxScore := 0.0
	if len(filtered) > 0 {
		maxScore = filtered[0].Score
	}

	span.SetAttributes(attribute.Int("search.results", total))

	resp := searchResponse{
		Data:     pageData,
		Total:    total,
		Page:     page,
		PerPage:  perPage,
		MaxScore: maxScore,
		TookMS:   result.Took.Milliseconds(),
		Mode:     mode,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// applySearchFilters filters scored findings by severity, provider, and status.
func applySearchFilters(findings []ScoredFinding, f searchFilters) []ScoredFinding {
	if len(f.Severity) == 0 && len(f.Provider) == 0 && len(f.Status) == 0 {
		return findings
	}

	sevSet := toUpperSet(f.Severity)
	provSet := toLowerSet(f.Provider)
	statusSet := toLowerSet(f.Status)

	filtered := make([]ScoredFinding, 0, len(findings))
	for _, sf := range findings {
		if len(sevSet) > 0 && !sevSet[strings.ToUpper(sf.Finding.Severity)] {
			continue
		}
		if len(provSet) > 0 && !provSet[strings.ToLower(sf.Finding.CloudProvider)] {
			continue
		}
		if len(statusSet) > 0 && !statusSet[strings.ToLower(sf.Finding.Status)] {
			continue
		}
		filtered = append(filtered, sf)
	}
	return filtered
}

func toUpperSet(ss []string) map[string]bool {
	if len(ss) == 0 {
		return nil
	}
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[strings.ToUpper(s)] = true
	}
	return m
}

func toLowerSet(ss []string) map[string]bool {
	if len(ss) == 0 {
		return nil
	}
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[strings.ToLower(s)] = true
	}
	return m
}
