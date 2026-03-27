package main

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"aegis/internal/graph"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"
	"golang.org/x/text/unicode/norm"
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

// gremlinMutationPattern rejects Gremlin-specific mutation steps.
// Uses [\s\x{00a0}\x{2000}-\x{200b}]* instead of \s* to match Unicode
// whitespace (non-breaking space, em space, etc.) that Go's \s excludes.
var gremlinMutationPattern = regexp.MustCompile(`(?i)\b(addV|addE|mergeV|mergeE|drop|sideEffect|withSideEffect|inject|io|call|choose|program|submit|evaluate|GroovyShell|Eval|property[\s\x{00a0}\x{2000}-\x{200b}]*\(|map[\s\x{00a0}\x{2000}-\x{200b}]*\{|flatMap[\s\x{00a0}\x{2000}-\x{200b}]*\{|sack[\s\x{00a0}\x{2000}-\x{200b}]*\{|aggregate[\s\x{00a0}\x{2000}-\x{200b}]*\(|store[\s\x{00a0}\x{2000}-\x{200b}]*\(|cap[\s\x{00a0}\x{2000}-\x{200b}]*\(|coalesce[\s\x{00a0}\x{2000}-\x{200b}]*\(|withComputer|Runtime|Thread|System|ProcessBuilder|Class\.forName)`)

// cypherMutationPattern rejects Cypher-specific mutation keywords.
var cypherMutationPattern = regexp.MustCompile(`(?i)\b(CREATE|MERGE|DELETE|DETACH|SET|REMOVE|CALL)\b`)

// cypherCommentPattern strips Cypher block and line comments to prevent
// bypass via comment injection (e.g., CR/**/EATE). Applied only to Cypher
// queries — Gremlin has no standard comment syntax and stripping // or --
// would corrupt property values containing those sequences.
var cypherCommentPattern = regexp.MustCompile(`/\*[\s\S]*?\*/|//[^\n]*|--[^\n]*`)

// handleGraphQuery proxies graph queries to PuppyGraph.
// Feature-flagged: returns 501 when PUPPYGRAPH_URL is not configured.
// Read-only: mutation keywords are rejected after comment stripping.
// Defense-in-depth: configure PuppyGraph with a read-only database role.
func (s *Server) handleGraphQuery(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.handleGraphQuery")
	defer span.End()
	r = r.WithContext(ctx)

	if s.graphClient == nil {
		writeErrorResponse(w, "graph query engine not configured", http.StatusNotImplemented)
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

	// Block mutation keywords. For Cypher, strip comments first to prevent
	// bypass via comment injection (e.g., CR/**/EATE). Gremlin has no
	// standard comment syntax — stripping would corrupt property values.
	normalizedQuery := norm.NFKC.String(strings.TrimSpace(req.Query))
	var mutationPattern *regexp.Regexp
	if req.Language == "cypher" {
		normalizedQuery = cypherCommentPattern.ReplaceAllString(normalizedQuery, "")
		mutationPattern = cypherMutationPattern
	} else {
		mutationPattern = gremlinMutationPattern
	}
	if mutationPattern.MatchString(normalizedQuery) {
		writeErrorResponse(w, "mutation queries are not permitted (read-only)", http.StatusForbidden)
		return
	}

	// Block Groovy template injection (${}), which can execute arbitrary code
	// if the Gremlin engine uses Groovy string evaluation.
	if strings.Contains(normalizedQuery, "${") {
		writeErrorResponse(w, "template expressions are not permitted (read-only)", http.StatusForbidden)
		return
	}

	span.SetAttributes(
		attribute.String("graph.language", req.Language),
		attribute.Int("graph.query_length", len(req.Query)),
	)

	result, err := s.graphClient.Query(r.Context(), graph.QueryRequest{
		Language: req.Language,
		Query:    normalizedQuery,
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
