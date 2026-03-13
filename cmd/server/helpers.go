package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"

	"cloudforge/internal/api"
	"cloudforge/internal/audit"

	"go.uber.org/zap"
)

// logAuditEvent records an auditable action. Silently drops the event if the
// audit logger is nil (e.g., in test configurations that don't set it up).
func (s *Server) logAuditEvent(r *http.Request, action, resource, resourceID, result string) {
	if s.auditLogger == nil {
		return
	}
	actor := ""
	actorRole := ""
	if claims, ok := api.GetClaimsFromContext(r.Context()); ok {
		actor = claims.Subject
		actorRole = string(api.RoleFromClaims(claims))
	}
	ip := r.RemoteAddr
	_ = s.auditLogger.Log(r.Context(), audit.AuditEntry{
		Actor:      actor,
		ActorRole:  actorRole,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Result:     result,
		IP:         ip,
	})
}

const (
	// maxRequestBodySize limits request body to 1MB to prevent resource exhaustion
	maxRequestBodySize = 1 << 20 // 1MB
)

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// decodeJSONBody decodes JSON request body with size limit and validation.
func (s *Server) decodeJSONBody(w http.ResponseWriter, r *http.Request, dst interface{}) bool {
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
		s.logger.Warn("JSON decode error", zap.Error(err))
		writeErrorResponse(w, msg, http.StatusBadRequest)
		return false
	}
	return true
}

// writeErrorResponse writes a JSON error response without leaking internal details
func writeErrorResponse(w http.ResponseWriter, msg string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// writeInternalError logs the actual error and returns a generic message to the client
func (s *Server) writeInternalError(w http.ResponseWriter, err error, operation string) {
	s.logger.Error("operation failed", zap.String("operation", operation), zap.Error(err))
	writeErrorResponse(w, "internal server error", http.StatusInternalServerError)
}

// paginatedResponse wraps a paginated JSON response.
type paginatedResponse struct {
	Data       any `json:"data"`
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	Total      int `json:"total"`
	TotalPages int `json:"total_pages"`
}

// parsePagination extracts page and per_page from query params with defaults.
func parsePagination(r *http.Request, defaultPerPage int) (page, perPage int) {
	page = 1
	perPage = defaultPerPage
	if v := r.URL.Query().Get("page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			page = n
		}
	}
	if v := r.URL.Query().Get("per_page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 100 {
			perPage = n
		}
	}
	return page, perPage
}
