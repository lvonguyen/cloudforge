package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"aegis/internal/api"
	"aegis/internal/secgraph"
	"aegis/internal/tenant"

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
		TenantID:   issueTenantID(r),
		Severity:   strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("severity"))),
		Status:     strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("status"))),
		ControlID:  strings.TrimSpace(r.URL.Query().Get("control_id")),
		AccountID:  strings.TrimSpace(r.URL.Query().Get("account_id")),
		ResourceID: strings.TrimSpace(r.URL.Query().Get("resource_id")),
		Provider:   strings.ToLower(strings.TrimSpace(r.URL.Query().Get("provider"))),
		SortBy:     strings.ToLower(strings.TrimSpace(r.URL.Query().Get("sort"))),
		SortOrder:  strings.ToLower(strings.TrimSpace(r.URL.Query().Get("order"))),
		Page:       parseQueryInt(r, "page", 1),
		PerPage:    parseQueryInt(r, "per_page", 25),
	}
	if hasTicket, ok := parseIssueTicketedQuery(w, r); !ok {
		return
	} else {
		params.HasTicket = hasTicket
	}
	if claims, ok := api.GetClaimsFromContext(r.Context()); ok && claims != nil {
		if scope := api.ScopeFromContext(claims); scope != nil {
			params.ScopeAccountIDs = append([]string(nil), scope.AccountIDs...)
			params.ScopeRegions = append([]string(nil), scope.Regions...)
			params.ScopeEnvironments = append([]string(nil), scope.Environments...)
			params.ScopeBusinessUnits = append([]string(nil), scope.BusinessUnits...)
		}
	}

	span.SetAttributes(
		attribute.String("issues.severity", params.Severity),
		attribute.String("issues.status", params.Status),
		attribute.Int("issues.page", params.Page),
		attribute.String("tenant.id", params.TenantID),
	)

	result, err := iq.ListIssues(ctx, params)
	if err != nil {
		s.logger.Warn("list issues failed", zap.Error(err))
		writeErrorResponse(w, "failed to list issues", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
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

	span.SetAttributes(
		attribute.String("issues.id", id),
		attribute.String("tenant.id", issueTenantID(r)),
	)

	detail, err := iq.GetIssue(ctx, issueTenantID(r), id)
	if err != nil {
		s.logger.Warn("get issue failed", zap.String("id", id), zap.Error(err))
		writeErrorResponse(w, "failed to get issue", http.StatusInternalServerError)
		return
	}
	if detail == nil {
		writeErrorResponse(w, "issue not found", http.StatusNotFound)
		return
	}

	if claims, ok := api.GetClaimsFromContext(r.Context()); ok && claims != nil {
		if scope := api.ScopeFromContext(claims); scope != nil {
			if err := api.EnforceScope(scope, detail.Issue); err != nil {
				api.LogScopeDenial(s.logger, claims.Subject, detail.Issue.ID, detail.Issue.AccountID, detail.Issue.Region, err.Error())
				writeErrorResponse(w, "forbidden: resource outside authorized scope", http.StatusForbidden)
				return
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(detail)
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

	span.SetAttributes(
		attribute.String("issues.id", id),
		attribute.String("tenant.id", issueTenantID(r)),
	)

	// Fetch the issue first to enforce scope before allowing modification.
	tenantID := issueTenantID(r)
	existing, err := iq.GetIssue(ctx, tenantID, id)
	if err != nil {
		s.logger.Warn("get issue for scope check failed", zap.String("id", id), zap.Error(err))
		writeErrorResponse(w, "failed to get issue", http.StatusInternalServerError)
		return
	}
	if existing == nil {
		writeErrorResponse(w, "issue not found", http.StatusNotFound)
		return
	}

	if claims, ok := api.GetClaimsFromContext(r.Context()); ok && claims != nil {
		if scope := api.ScopeFromContext(claims); scope != nil {
			if scopeErr := api.EnforceScope(scope, existing.Issue); scopeErr != nil {
				api.LogScopeDenial(s.logger, claims.Subject, existing.Issue.ID, existing.Issue.AccountID, existing.Issue.Region, scopeErr.Error())
				writeErrorResponse(w, "forbidden: resource outside authorized scope", http.StatusForbidden)
				return
			}
		}
	}

	updated, err := iq.UpdateIssue(ctx, tenantID, id, update)
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
	_ = json.NewEncoder(w).Encode(updated)
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

	span.SetAttributes(attribute.String("tenant.id", issueTenantID(r)))

	stats, err := iq.IssueStats(ctx, issueTenantID(r))
	if err != nil {
		s.logger.Warn("issue stats failed", zap.Error(err))
		writeErrorResponse(w, "failed to get issue stats", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
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

func parseIssueTicketedQuery(w http.ResponseWriter, r *http.Request) (*bool, bool) {
	raw := strings.TrimSpace(r.URL.Query().Get("ticketed"))
	if raw == "" {
		return nil, true
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		writeErrorResponse(w, "ticketed must be a boolean", http.StatusBadRequest)
		return nil, false
	}
	return &value, true
}

func issueTenantID(r *http.Request) string {
	tenantID, _ := tenant.IDFromContext(r.Context())
	if tenantID == "" {
		return defaultSecgraphTenantID
	}
	return tenantID
}
