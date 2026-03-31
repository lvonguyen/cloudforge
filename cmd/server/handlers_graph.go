package main

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"aegis/internal/graph"
	"aegis/internal/secgraph"

	"github.com/gorilla/mux"
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

type graphQueryValidationError struct {
	status  int
	message string
}

func (e *graphQueryValidationError) Error() string {
	return e.message
}

// maxGraphQueryLen caps the query string length to prevent abuse.
const maxGraphQueryLen = 4096

// gremlinMutationPattern rejects Gremlin mutation and code-execution steps.
// Ambiguous short names (io, call, etc.) require a preceding dot and opening
// paren to avoid false positives on property names (e.g. "callback_url").
// Read-only steps (choose, coalesce) are intentionally excluded.
// Unicode whitespace class [\s\x{00a0}\x{2000}-\x{200b}]* covers nbsp/em-space
// that Go's \s does not match.
var gremlinMutationPattern = regexp.MustCompile(
	`(?i)` +
		`\b(?:addV|addE|mergeV|mergeE|drop|sideEffect|withSideEffect|withComputer|GroovyShell|ProcessBuilder)\b` +
		`|\bClass\.forName\b` +
		`|\.[\s\x{00a0}\x{2000}-\x{200b}]*(?:inject|io|call|program|submit)[\s\x{00a0}\x{2000}-\x{200b}]*\(` +
		`|\bevaluate[\s\x{00a0}\x{2000}-\x{200b}]*\(` +
		`|\b(?:Runtime|Thread|System|Eval)\.` +
		`|\bproperty[\s\x{00a0}\x{2000}-\x{200b}]*\(` +
		`|\b(?:map|flatMap|sack)[\s\x{00a0}\x{2000}-\x{200b}]*\{` +
		`|\b(?:aggregate|store|cap)[\s\x{00a0}\x{2000}-\x{200b}]*\(`,
)

// cypherMutationPattern rejects Cypher-specific mutation keywords.
var cypherMutationPattern = regexp.MustCompile(`(?i)\b(CREATE|MERGE|DELETE|DETACH|SET|REMOVE|CALL)\b`)

// cypherCommentPattern strips Cypher block and line comments to prevent
// bypass via comment injection (e.g., CR/**/EATE). Applied only to Cypher
// queries — Gremlin has no standard comment syntax and stripping // or --
// would corrupt property values containing those sequences.
var cypherCommentPattern = regexp.MustCompile(`/\*[\s\S]*?\*/|//[^\n]*|--[^\n]*`)

func validateAndNormalizeGraphQuery(language, query string) (string, error) {
	if language == "" || query == "" {
		return "", &graphQueryValidationError{
			status:  http.StatusBadRequest,
			message: "language and query fields are required",
		}
	}

	if language != "gremlin" && language != "cypher" {
		return "", &graphQueryValidationError{
			status:  http.StatusBadRequest,
			message: "language must be gremlin or cypher",
		}
	}

	// Enforce query length cap: rune count for logical length, byte count
	// for payload size (a 4096-rune CJK query is 16KB in UTF-8).
	if utf8.RuneCountInString(query) > maxGraphQueryLen || len(query) > maxGraphQueryLen*4 {
		return "", &graphQueryValidationError{
			status:  http.StatusBadRequest,
			message: "query exceeds maximum length",
		}
	}

	// Block mutation keywords. For Cypher, strip comments first to prevent
	// bypass via comment injection (e.g., CR/**/EATE). Gremlin has no
	// standard comment syntax — stripping would corrupt property values.
	normalizedQuery := norm.NFKC.String(strings.TrimSpace(query))
	// Strip Unicode format characters (Cf: zero-width spaces, joiners, BOM)
	// and Unicode whitespace (Zs: NBSP, em-space, etc.) beyond ASCII space,
	// preventing bypass via NBSP insertion between dot and keyword (e.g.,
	// ".\\u00a0inject(" normalizing to ". inject(" which evades the regex).
	normalizedQuery = strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cf, r) {
			return -1
		}
		if r != ' ' && unicode.Is(unicode.Zs, r) {
			return ' '
		}
		return r
	}, normalizedQuery)
	var mutationPattern *regexp.Regexp
	if language == "cypher" {
		normalizedQuery = cypherCommentPattern.ReplaceAllString(normalizedQuery, "")
		mutationPattern = cypherMutationPattern
	} else {
		mutationPattern = gremlinMutationPattern
	}
	if strings.TrimSpace(normalizedQuery) == "" {
		return "", &graphQueryValidationError{
			status:  http.StatusBadRequest,
			message: "query must not be blank",
		}
	}
	if mutationPattern.MatchString(normalizedQuery) {
		return "", &graphQueryValidationError{
			status:  http.StatusForbidden,
			message: "mutation queries are not permitted (read-only)",
		}
	}

	// Block Groovy template injection (${}), which can execute arbitrary code
	// if the Gremlin engine uses Groovy string evaluation.
	if strings.Contains(normalizedQuery, "${") {
		return "", &graphQueryValidationError{
			status:  http.StatusForbidden,
			message: "template expressions are not permitted (read-only)",
		}
	}

	return normalizedQuery, nil
}

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

	normalizedQuery, err := validateAndNormalizeGraphQuery(req.Language, req.Query)
	if err != nil {
		if validationErr, ok := err.(*graphQueryValidationError); ok {
			writeErrorResponse(w, validationErr.message, validationErr.status)
			return
		}
		s.logger.Warn("graph query validation failed", zap.Error(err))
		writeErrorResponse(w, "graph query validation failed", http.StatusBadRequest)
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

// handleGraphNeighborhood returns the typed subgraph within N hops of a node.
// Uses the Postgres CTE querier (always available when DB is configured).
func (s *Server) handleGraphNeighborhood(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.handleGraphNeighborhood")
	defer span.End()

	if s.graphQuerier == nil {
		writeErrorResponse(w, "graph querier not configured (requires AEGIS_DATABASE_URL)", http.StatusNotImplemented)
		return
	}

	vars := mux.Vars(r)
	nodeType := vars["nodeType"]
	nodeID := vars["nodeId"]

	if nodeType == "" || nodeID == "" {
		writeErrorResponse(w, "nodeType and nodeId path parameters are required", http.StatusBadRequest)
		return
	}

	hops := parseIntParam(r, "hops", 1)
	limit := parseIntParam(r, "limit", 100)

	span.SetAttributes(
		attribute.String("graph.node_type", nodeType),
		attribute.String("graph.node_id", nodeID),
		attribute.Int("graph.hops", hops),
	)

	result, err := s.graphQuerier.Neighborhood(ctx, secgraph.NodeType(nodeType), nodeID, hops, limit)
	if err != nil {
		s.logger.Warn("graph neighborhood query failed",
			zap.String("node_type", nodeType),
			zap.String("node_id", nodeID),
			zap.Error(err),
		)
		writeErrorResponse(w, "graph neighborhood query failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		s.logger.Warn("encoding neighborhood response", zap.Error(err))
	}
}

// handleGraphStats returns vertex and edge counts grouped by type.
func (s *Server) handleGraphStats(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.handleGraphStats")
	defer span.End()

	if s.graphQuerier == nil {
		writeErrorResponse(w, "graph querier not configured (requires AEGIS_DATABASE_URL)", http.StatusNotImplemented)
		return
	}

	stats, err := s.graphQuerier.Stats(ctx)
	if err != nil {
		s.logger.Warn("graph stats query failed", zap.Error(err))
		writeErrorResponse(w, "graph stats query failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		s.logger.Warn("encoding graph stats response", zap.Error(err))
	}
}

// parseIntParam reads an integer query param with a default fallback.
func parseIntParam(r *http.Request, name string, defaultVal int) int {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return defaultVal
	}
	val, err := strconv.Atoi(raw)
	if err != nil || val <= 0 {
		return defaultVal
	}
	return val
}
