package main

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"aegis/internal/graph"

	"go.uber.org/zap"
)

// graphQueryRequest is the HTTP request body for POST /api/v1/graph/query.
type graphQueryRequest struct {
	Language string `json:"language"` // "gremlin" or "cypher"
	Query    string `json:"query"`
}

// graphQueryResponse is the HTTP response for a graph query.
type graphQueryResponse struct {
	Data    json.RawMessage `json:"data"`
	Elapsed string          `json:"elapsed"`
}

// maxGraphQueryLen caps the query string length to prevent abuse.
const maxGraphQueryLen = 4096

// graphMutationPattern rejects Gremlin/Cypher mutation keywords.
var graphMutationPattern = regexp.MustCompile(`(?i)\b(addV|addE|drop|property\s*\(|CREATE\b|MERGE\b|DELETE\b|DETACH\b|SET\b|REMOVE\b)`)

// handleGraphQuery proxies graph queries to PuppyGraph.
// Feature-flagged: returns 501 when PUPPYGRAPH_URL is not configured.
// Read-only: mutation keywords are rejected.
func (s *Server) handleGraphQuery(w http.ResponseWriter, r *http.Request) {
	if s.graphClient == nil {
		writeErrorResponse(w, "graph query engine not configured (set PUPPYGRAPH_URL)", http.StatusNotImplemented)
		return
	}

	// Limit request body size (consistent with all other POST handlers).
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB

	var req graphQueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Language == "" || req.Query == "" {
		writeErrorResponse(w, "language and query fields are required", http.StatusBadRequest)
		return
	}

	if req.Language != "gremlin" && req.Language != "cypher" {
		writeErrorResponse(w, "language must be gremlin or cypher", http.StatusBadRequest)
		return
	}

	// Enforce query length cap.
	if len(req.Query) > maxGraphQueryLen {
		writeErrorResponse(w, "query exceeds maximum length", http.StatusBadRequest)
		return
	}

	// Block mutation keywords — read-only proxy.
	if graphMutationPattern.MatchString(strings.TrimSpace(req.Query)) {
		writeErrorResponse(w, "mutation queries are not permitted (read-only)", http.StatusForbidden)
		return
	}

	result, err := s.graphClient.Query(r.Context(), graph.QueryRequest{
		Language: req.Language,
		Query:    req.Query,
	})
	if err != nil {
		s.logger.Warn("graph query failed",
			zap.String("language", req.Language),
			zap.Error(err),
		)
		writeErrorResponse(w, "graph query execution failed", http.StatusBadGateway)
		return
	}

	resp := graphQueryResponse{
		Data:    result.Data,
		Elapsed: result.Elapsed.String(),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Warn("encoding graph response", zap.Error(err))
	}
}
