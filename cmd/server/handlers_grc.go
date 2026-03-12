package main

import (
	"encoding/json"
	"errors"
	"net/http"

	"cloudforge/internal/api"
	"cloudforge/internal/grc"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"
)

func (s *Server) createException(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.createException")
	defer span.End()
	r = r.WithContext(ctx)

	var req grc.ExceptionRequest
	if !s.decodeJSONBody(w, r, &req) {
		return
	}

	// Validate required fields
	if req.ApplicationID == "" || req.PolicyViolated == "" {
		writeErrorResponse(w, "application_id and policy_violated are required", http.StatusBadRequest)
		return
	}

	// Enforce requestor identity from JWT — caller cannot impersonate another user.
	claims, ok := api.GetClaimsFromContext(r.Context())
	if !ok {
		writeErrorResponse(w, "authentication required", http.StatusUnauthorized)
		return
	}
	if req.RequestorEmail == "" {
		req.RequestorEmail = claims.Email
	} else if req.RequestorEmail != claims.Email {
		s.logger.Warn("identity spoofing attempt on createException",
			zap.String("claimed_email", req.RequestorEmail),
			zap.String("authenticated_email", claims.Email),
		)
		writeErrorResponse(w, "requestor_email must match authenticated user", http.StatusForbidden)
		return
	}

	// Server-authoritative workflow state — ignore client-supplied values.
	req.Status = grc.StatusPending
	req.ApproverChain = nil

	created, err := s.grcProvider.CreateException(r.Context(), &req)
	if err != nil {
		s.writeInternalError(w, err, "create exception")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(created)
}

func (s *Server) getException(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.getException")
	defer span.End()
	r = r.WithContext(ctx)

	vars := mux.Vars(r)
	id := vars["id"]
	span.SetAttributes(attribute.String("exception.id", id))

	exc, err := s.grcProvider.GetException(r.Context(), id)
	if err != nil {
		if errors.Is(err, grc.ErrNotFound) {
			writeErrorResponse(w, "exception not found", http.StatusNotFound)
			return
		}
		s.logger.Error("get exception failed", zap.Error(err))
		writeErrorResponse(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Authorization: require admin/operator role or JWT subject matching the exception's app owner.
	claims, ok := api.GetClaimsFromContext(r.Context())
	if !ok {
		writeErrorResponse(w, "authentication required", http.StatusUnauthorized)
		return
	}
	role := api.RoleFromClaims(claims)
	if role != api.RoleAdmin && role != api.RoleOperator && claims.Subject != exc.ApplicationID {
		writeErrorResponse(w, "forbidden: requires admin/operator role or matching application identity", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(exc)
}

func (s *Server) submitApproval(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.submitApproval")
	defer span.End()
	r = r.WithContext(ctx)

	vars := mux.Vars(r)
	id := vars["id"]
	span.SetAttributes(attribute.String("exception.id", id))

	var approver grc.Approver
	if !s.decodeJSONBody(w, r, &approver) {
		return
	}

	// Enforce that the approver email matches the authenticated JWT identity
	claims, ok := api.GetClaimsFromContext(r.Context())
	if !ok {
		writeErrorResponse(w, "authentication required", http.StatusUnauthorized)
		return
	}
	if approver.Email == "" {
		approver.Email = claims.Email
	} else if approver.Email != claims.Email {
		writeErrorResponse(w, "approver email must match authenticated user", http.StatusForbidden)
		return
	}

	if err := s.grcProvider.SubmitApproval(r.Context(), id, approver); err != nil {
		s.writeInternalError(w, err, "submit approval")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "approval recorded"})
}

func (s *Server) getPendingApprovals(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.getPendingApprovals")
	defer span.End()
	r = r.WithContext(ctx)

	// Enforce that the query matches the authenticated JWT identity
	claims, ok := api.GetClaimsFromContext(r.Context())
	if !ok {
		writeErrorResponse(w, "authentication required", http.StatusUnauthorized)
		return
	}

	email := r.URL.Query().Get("approver_email")
	if email == "" {
		email = claims.Email
	} else if email != claims.Email {
		writeErrorResponse(w, "can only query your own pending approvals", http.StatusForbidden)
		return
	}

	pending, err := s.grcProvider.GetPendingApprovals(r.Context(), email)
	if err != nil {
		s.writeInternalError(w, err, "get pending approvals")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(pending)
}

func (s *Server) getMyExceptions(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.getMyExceptions")
	defer span.End()
	r = r.WithContext(ctx)

	// Extract email from JWT context
	claims, ok := api.GetClaimsFromContext(r.Context())
	if !ok {
		writeErrorResponse(w, "authentication required", http.StatusUnauthorized)
		return
	}

	exceptions, err := s.grcProvider.GetExceptionsByRequestor(r.Context(), claims.Email)
	if err != nil {
		s.writeInternalError(w, err, "get exceptions by requestor")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(exceptions)
}

func (s *Server) getExpiringExceptions(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.getExpiringExceptions")
	defer span.End()
	r = r.WithContext(ctx)

	expiring, err := s.grcProvider.GetExpiringExceptions(r.Context(), 30)
	if err != nil {
		s.writeInternalError(w, err, "get expiring exceptions")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(expiring)
}

func (s *Server) getExceptionsByApp(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.getExceptionsByApp")
	defer span.End()
	r = r.WithContext(ctx)

	vars := mux.Vars(r)
	appID := vars["appId"]
	span.SetAttributes(attribute.String("application.id", appID))

	exceptions, err := s.grcProvider.GetExceptionsByApplication(r.Context(), appID)
	if err != nil {
		s.writeInternalError(w, err, "get exceptions by app")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(exceptions)
}

// ValidateExceptionRequest is the request body for exception validation
type ValidateExceptionRequest struct {
	ApplicationID string `json:"application_id"`
	PolicyCode    string `json:"policy_code"`
}

func (s *Server) validateException(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.validateException")
	defer span.End()
	r = r.WithContext(ctx)

	var req ValidateExceptionRequest
	if !s.decodeJSONBody(w, r, &req) {
		return
	}

	validation, err := s.grcProvider.ValidateException(r.Context(), req.ApplicationID, req.PolicyCode)
	if err != nil {
		s.writeInternalError(w, err, "validate exception")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(validation)
}
