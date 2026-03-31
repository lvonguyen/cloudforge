package main

import (
	"encoding/json"
	"net/http"
	"strconv"

	"aegis/internal/secgraph"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"
)

// handleListIssues returns a paginated list of security issues.
// GET /api/v1/issues?severity=HIGH&status=OPEN&page=1&per_page=25
func (s *Server) handleListIssues(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.handleListIssues")
	defer span.End()

	iq, ok := s.graphQuerier.(secgraph.IssueQuerier)
	if !ok || iq == nil {
		writeErrorResponse(w, "issue queries not configured (requires AEGIS_DATABASE_URL)", http.StatusNotImplemented)
		return
	}

	params := secgraph.IssueListParams{
		Severity:  r.URL.Query().Get("severity"),
		Status:    r.URL.Query().Get("status"),
		ControlID: r.URL.Query().Get("control_id"),
		AccountID: r.URL.Query().Get("account_id"),
		Provider:  r.URL.Query().Get("provider"),
		Page:      parseQueryInt(r, "page", 1),
		PerPage:   parseQueryInt(r, "per_page", 25),
	}

	span.SetAttributes(
		attribute.String("issues.severity", params.Severity),
		attribute.String("issues.status", params.Status),
		attribute.Int("issues.page", params.Page),
	)

	result, err := iq.ListIssues(ctx, params)
	if err != nil {
		s.logger.Warn("list issues failed", zap.Error(err))
		writeErrorResponse(w, "failed to list issues", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleGetIssue returns a single issue with related finding IDs.
// GET /api/v1/issues/{id}
func (s *Server) handleGetIssue(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.handleGetIssue")
	defer span.End()

	iq, ok := s.graphQuerier.(secgraph.IssueQuerier)
	if !ok || iq == nil {
		writeErrorResponse(w, "issue queries not configured", http.StatusNotImplemented)
		return
	}

	id := mux.Vars(r)["id"]
	if id == "" {
		writeErrorResponse(w, "issue id is required", http.StatusBadRequest)
		return
	}

	span.SetAttributes(attribute.String("issues.id", id))

	detail, err := iq.GetIssue(ctx, id)
	if err != nil {
		s.logger.Warn("get issue failed", zap.String("id", id), zap.Error(err))
		writeErrorResponse(w, "failed to get issue", http.StatusInternalServerError)
		return
	}
	if detail == nil {
		writeErrorResponse(w, "issue not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(detail)
}

// handleUpdateIssue applies partial updates to an issue.
// PATCH /api/v1/issues/{id}
func (s *Server) handleUpdateIssue(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.handleUpdateIssue")
	defer span.End()

	iq, ok := s.graphQuerier.(secgraph.IssueQuerier)
	if !ok || iq == nil {
		writeErrorResponse(w, "issue queries not configured", http.StatusNotImplemented)
		return
	}

	id := mux.Vars(r)["id"]
	if id == "" {
		writeErrorResponse(w, "issue id is required", http.StatusBadRequest)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<16) // 64KB
	var update secgraph.IssueUpdate
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		writeErrorResponse(w, "invalid request body", http.StatusBadRequest)
		return
	}

	span.SetAttributes(attribute.String("issues.id", id))

	updated, err := iq.UpdateIssue(ctx, id, update)
	if err != nil {
		s.logger.Warn("update issue failed", zap.String("id", id), zap.Error(err))
		writeErrorResponse(w, "failed to update issue", http.StatusInternalServerError)
		return
	}
	if updated == nil {
		writeErrorResponse(w, "issue not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updated)
}

// handleIssueStats returns aggregate issue counts.
// GET /api/v1/issues/stats
func (s *Server) handleIssueStats(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.handleIssueStats")
	defer span.End()

	iq, ok := s.graphQuerier.(secgraph.IssueQuerier)
	if !ok || iq == nil {
		writeErrorResponse(w, "issue queries not configured", http.StatusNotImplemented)
		return
	}

	stats, err := iq.IssueStats(ctx)
	if err != nil {
		s.logger.Warn("issue stats failed", zap.Error(err))
		writeErrorResponse(w, "failed to get issue stats", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func parseQueryInt(r *http.Request, name string, defaultVal int) int {
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
