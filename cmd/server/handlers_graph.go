package main

import (
	"encoding/json"
	"net/http"

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

// handleGraphQuery proxies graph queries to PuppyGraph.
// Feature-flagged: returns 501 when PUPPYGRAPH_URL is not configured.
func (s *Server) handleGraphQuery(w http.ResponseWriter, r *http.Request) {
	if s.graphClient == nil {
		http.Error(w, `{"error":"graph query engine not configured (set PUPPYGRAPH_URL)"}`, http.StatusNotImplemented)
		return
	}

	var req graphQueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.Language == "" || req.Query == "" {
		http.Error(w, `{"error":"language and query fields are required"}`, http.StatusBadRequest)
		return
	}

	if req.Language != "gremlin" && req.Language != "cypher" {
		http.Error(w, `{"error":"language must be gremlin or cypher"}`, http.StatusBadRequest)
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
		http.Error(w, `{"error":"graph query execution failed"}`, http.StatusBadGateway)
		return
	}

	resp := graphQueryResponse{
		Data:    result.Data,
		Elapsed: result.Elapsed.String(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
