package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"strings"

	"cloudforge/internal/api"
	"cloudforge/internal/audit"
	"cloudforge/internal/grc"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"
)

// GRCHandler encapsulates GRC exception management handlers,
// extracted from Server to reduce God Object field count.
type GRCHandler struct {
	provider    grc.GRCProvider
	logger      *zap.Logger
	auditLogger audit.AuditLogger
}

// decodeBody decodes a JSON request body with size limit.
func (h *GRCHandler) decodeBody(w http.ResponseWriter, r *http.Request, dst interface{}) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		var msg string
		switch {
		case strings.Contains(err.Error(), "http: request body too large"):
			msg = "request body exceeds maximum allowed size"
		case strings.Contains(err.Error(), "unknown field"):
			msg = "request contains unknown fields"
		default:
			msg = "invalid request body"
		}
		h.logger.Warn("JSON decode error", zap.Error(err))
		writeErrorResponse(w, msg, http.StatusBadRequest)
		return false
	}
	return true
}

// writeError logs the actual error and returns a generic message to the client.
func (h *GRCHandler) writeError(w http.ResponseWriter, err error, operation string) {
	h.logger.Error("operation failed", zap.String("operation", operation), zap.Error(err))
	writeErrorResponse(w, "internal server error", http.StatusInternalServerError)
}

// logAudit records an audit event for GRC operations.
func (h *GRCHandler) logAudit(r *http.Request, action, resource, resourceID, result string) {
	if h.auditLogger == nil {
		return
	}
	actor := ""
	actorRole := ""
	if claims, ok := api.GetClaimsFromContext(r.Context()); ok {
		actor = claims.Subject
		actorRole = string(api.RoleFromClaims(claims))
	}
	_ = h.auditLogger.Log(r.Context(), audit.AuditEntry{
		Actor:      actor,
		ActorRole:  actorRole,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Result:     result,
		IP:         r.RemoteAddr,
	})
}

// ValidateExceptionRequest is the request body for exception validation.
type ValidateExceptionRequest struct {
	ApplicationID string `json:"application_id"`
	PolicyCode    string `json:"policy_code"`
}

func (h *GRCHandler) CreateException(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.createException")
	defer span.End()
	r = r.WithContext(ctx)

	var req grc.ExceptionRequest
	if !h.decodeBody(w, r, &req) {
		return
	}

	if req.ApplicationID == "" || req.PolicyViolated == "" {
		writeErrorResponse(w, "application_id and policy_violated are required", http.StatusBadRequest)
		return
	}

	if req.RequestorEmail != "" {
		if _, err := mail.ParseAddress(req.RequestorEmail); err != nil {
			writeErrorResponse(w, "requestor_email is not a valid email address", http.StatusBadRequest)
			return
		}
	}

	claims, ok := api.GetClaimsFromContext(r.Context())
	if !ok {
		writeErrorResponse(w, "authentication required", http.StatusUnauthorized)
		return
	}
	if req.RequestorEmail == "" {
		req.RequestorEmail = claims.Email
	} else if req.RequestorEmail != claims.Email {
		h.logger.Warn("identity spoofing attempt on createException",
			zap.String("claimed_email", req.RequestorEmail),
			zap.String("authenticated_email", claims.Email),
		)
		writeErrorResponse(w, "requestor_email must match authenticated user", http.StatusForbidden)
		return
	}

	req.Status = grc.StatusPending
	req.ApproverChain = nil

	created, err := h.provider.CreateException(r.Context(), &req)
	if err != nil {
		h.writeError(w, err, "create exception")
		return
	}

	h.logAudit(r, "exception.create", "exception", created.ID, "success")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(created)
}

func (h *GRCHandler) GetException(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.getException")
	defer span.End()
	r = r.WithContext(ctx)

	vars := mux.Vars(r)
	id := vars["id"]
	span.SetAttributes(attribute.String("exception.id", id))

	exc, err := h.provider.GetException(r.Context(), id)
	if err != nil {
		if errors.Is(err, grc.ErrNotFound) {
			writeErrorResponse(w, "exception not found", http.StatusNotFound)
			return
		}
		h.logger.Error("get exception failed", zap.Error(err))
		writeErrorResponse(w, "internal server error", http.StatusInternalServerError)
		return
	}

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

func (h *GRCHandler) SubmitApproval(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.submitApproval")
	defer span.End()
	r = r.WithContext(ctx)

	vars := mux.Vars(r)
	id := vars["id"]
	span.SetAttributes(attribute.String("exception.id", id))

	var approver grc.Approver
	if !h.decodeBody(w, r, &approver) {
		return
	}

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

	if err := h.provider.SubmitApproval(r.Context(), id, approver); err != nil {
		h.writeError(w, err, "submit approval")
		return
	}

	h.logAudit(r, "exception.approve", "exception", id, "success")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "approval recorded"})
}

func (h *GRCHandler) GetPendingApprovals(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.getPendingApprovals")
	defer span.End()
	r = r.WithContext(ctx)

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

	pending, err := h.provider.GetPendingApprovals(r.Context(), email)
	if err != nil {
		h.writeError(w, err, "get pending approvals")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(pending)
}

func (h *GRCHandler) GetMyExceptions(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.getMyExceptions")
	defer span.End()
	r = r.WithContext(ctx)

	claims, ok := api.GetClaimsFromContext(r.Context())
	if !ok {
		writeErrorResponse(w, "authentication required", http.StatusUnauthorized)
		return
	}

	exceptions, err := h.provider.GetExceptionsByRequestor(r.Context(), claims.Email)
	if err != nil {
		h.writeError(w, err, "get exceptions by requestor")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(exceptions)
}

func (h *GRCHandler) GetExpiringExceptions(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.getExpiringExceptions")
	defer span.End()
	r = r.WithContext(ctx)

	expiring, err := h.provider.GetExpiringExceptions(r.Context(), 30)
	if err != nil {
		h.writeError(w, err, "get expiring exceptions")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(expiring)
}

func (h *GRCHandler) GetExceptionsByApp(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.getExceptionsByApp")
	defer span.End()
	r = r.WithContext(ctx)

	vars := mux.Vars(r)
	appID := vars["appId"]
	span.SetAttributes(attribute.String("application.id", appID))

	claims, ok := api.GetClaimsFromContext(r.Context())
	if !ok {
		writeErrorResponse(w, "authentication required", http.StatusUnauthorized)
		return
	}
	role := api.RoleFromClaims(claims)
	if role != api.RoleAdmin && claims.Subject != appID {
		writeErrorResponse(w, "forbidden: requires admin role or matching application identity", http.StatusForbidden)
		return
	}

	exceptions, err := h.provider.GetExceptionsByApplication(r.Context(), appID)
	if err != nil {
		h.writeError(w, err, "get exceptions by app")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(exceptions)
}

func (h *GRCHandler) WithdrawException(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.withdrawException")
	defer span.End()
	r = r.WithContext(ctx)

	vars := mux.Vars(r)
	id := vars["id"]
	span.SetAttributes(attribute.String("exception.id", id))

	claims, ok := api.GetClaimsFromContext(r.Context())
	if !ok {
		writeErrorResponse(w, "authentication required", http.StatusUnauthorized)
		return
	}

	exc, err := h.provider.GetException(r.Context(), id)
	if err != nil {
		if errors.Is(err, grc.ErrNotFound) {
			writeErrorResponse(w, "exception not found", http.StatusNotFound)
			return
		}
		h.writeError(w, err, "withdraw exception: get")
		return
	}

	if exc.Status != grc.StatusPending {
		writeErrorResponse(w, "exception is not in PENDING status", http.StatusConflict)
		return
	}

	role := api.RoleFromClaims(claims)
	if claims.Subject != exc.RequestorEmail && role != api.RoleAdmin {
		writeErrorResponse(w, "forbidden: only the requestor or an admin can withdraw", http.StatusForbidden)
		return
	}

	exc.Status = grc.StatusRevoked
	if err := h.provider.UpdateException(r.Context(), exc); err != nil {
		h.writeError(w, err, "withdraw exception: update")
		return
	}

	h.logAudit(r, "exception.withdraw", "exception", id, "success")

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(exc)
}

func (h *GRCHandler) ValidateException(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.validateException")
	defer span.End()
	r = r.WithContext(ctx)

	var req ValidateExceptionRequest
	if !h.decodeBody(w, r, &req) {
		return
	}

	validation, err := h.provider.ValidateException(r.Context(), req.ApplicationID, req.PolicyCode)
	if err != nil {
		h.writeError(w, err, "validate exception")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(validation)
}
