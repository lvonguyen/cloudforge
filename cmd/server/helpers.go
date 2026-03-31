package main

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"

	"aegis/internal/api"
	"aegis/internal/audit"

	"go.uber.org/zap"
)

// logAuditEvent is the package-level audit logging function. Silently drops
// the event if the audit logger is nil (e.g., in test configurations).
func logAuditEvent(r *http.Request, logger audit.AuditLogger, action, resource, resourceID, result string) {
	if logger == nil {
		return
	}
	actor := ""
	actorRole := ""
	if claims, ok := api.GetClaimsFromContext(r.Context()); ok {
		actor = claims.Subject
		actorRole = string(api.RoleFromClaims(claims))
	}
	// Strip port from RemoteAddr — PostgreSQL INET rejects "host:port" format.
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		ip = host
	}
	if err := logger.Log(r.Context(), audit.AuditEntry{
		Actor:      actor,
		ActorRole:  actorRole,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Result:     result,
		IP:         ip,
	}); err != nil {
		zap.L().Warn("audit log write failed", zap.String("action", action), zap.Error(err))
	}
}

// logAuditEvent on Server delegates to the package-level function.
func (s *Server) logAuditEvent(r *http.Request, action, resource, resourceID, result string) {
	logAuditEvent(r, s.auditLogger, action, resource, resourceID, result)
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

// parseFloatOrDefault parses a string as float64 and returns the default if parsing fails or s is empty.
func parseFloatOrDefault(s string, defaultValue float64) float64 {
	if s == "" {
		return defaultValue
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return defaultValue
	}
	return v
}

// decodeJSONBody is the package-level JSON body decoder with size limit and validation.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst interface{}, logger *zap.Logger) bool {
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
		if logger != nil {
			logger.Warn("JSON decode error", zap.Error(err))
		}
		writeErrorResponse(w, msg, http.StatusBadRequest)
		return false
	}
	return true
}

// decodeJSONBody on Server delegates to the package-level function.
func (s *Server) decodeJSONBody(w http.ResponseWriter, r *http.Request, dst interface{}) bool {
	return decodeJSONBody(w, r, dst, s.logger)
}

// apiError is the standard error response envelope for all API errors.
type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Status  int    `json:"status"`
}

// errorCodeFromStatus derives a machine-readable error code from status + message.
func errorCodeFromStatus(status int, msg string) string {
	switch status {
	case http.StatusNotFound:
		// Derive resource-specific code from the message prefix.
		for _, prefix := range []string{"finding", "agent", "remediation", "policy", "workflow", "container", "exception"} {
			if strings.Contains(strings.ToLower(msg), prefix) {
				return strings.ToUpper(prefix) + "_NOT_FOUND"
			}
		}
		return "NOT_FOUND"
	case http.StatusBadRequest:
		return "BAD_REQUEST"
	case http.StatusForbidden:
		return "FORBIDDEN"
	case http.StatusServiceUnavailable:
		return "SERVICE_UNAVAILABLE"
	case http.StatusConflict:
		return "CONFLICT"
	case http.StatusTooManyRequests:
		return "RATE_LIMITED"
	default:
		return "INTERNAL_ERROR"
	}
}

// writeErrorResponse writes a standard JSON error response.
func writeErrorResponse(w http.ResponseWriter, msg string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(apiError{
		Code:    errorCodeFromStatus(statusCode, msg),
		Message: msg,
		Status:  statusCode,
	})
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
// maxPerPage caps the per_page value a client can request.
func parsePagination(r *http.Request, defaultPerPage, maxPerPage int) (page, perPage int) {
	page = 1
	perPage = defaultPerPage
	if v := r.URL.Query().Get("page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			page = n
		}
	}
	// Accept both "per_page" and "limit" as the page-size parameter
	ppStr := r.URL.Query().Get("per_page")
	if ppStr == "" {
		ppStr = r.URL.Query().Get("limit")
	}
	if ppStr != "" {
		if n, err := strconv.Atoi(ppStr); err == nil && n > 0 && n <= maxPerPage {
			perPage = n
		}
	}
	return page, perPage
}

// paginateResult slices a result set and wraps it in a paginatedResponse.
func paginateResult[T any](items []T, page, perPage int) paginatedResponse {
	total := len(items)
	totalPages := (total + perPage - 1) / perPage
	if totalPages == 0 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}

	start := (page - 1) * perPage
	end := start + perPage
	if start >= total {
		start = total
		end = total
	} else if end > total {
		end = total
	}

	data := items[start:end]
	if data == nil {
		data = make([]T, 0)
	}

	return paginatedResponse{
		Data:       data,
		Page:       page,
		PerPage:    perPage,
		Total:      total,
		TotalPages: totalPages,
	}
}

// handleProviderStatus returns the active provider type for each subsystem.
// Useful for operators verifying deployment configuration.
func (s *Server) handleProviderStatus(w http.ResponseWriter, _ *http.Request) {
	// Collect identity provider names
	idNames := make([]string, 0)
	if s.identitySvc != nil {
		for name := range s.identitySvc.providers {
			idNames = append(idNames, name)
		}
	}
	sort.Strings(idNames)

	integrationNames := make([]string, 0)
	integrationDefault := "mock"
	integrationStore := "memory"
	asanaWebhook := "disabled"
	if s.integrationHandler != nil {
		if s.integrationHandler.provider != nil {
			integrationDefault = s.integrationHandler.provider.Name()
		}
		if s.integrationHandler.providers != nil {
			for name := range s.integrationHandler.providers {
				integrationNames = append(integrationNames, name)
			}
		}
		if len(integrationNames) == 0 && integrationDefault != "" {
			integrationNames = append(integrationNames, integrationDefault)
		}
		if s.integrationHandler.ticketRepo != nil {
			integrationStore = "durable"
		}
		if strings.TrimSpace(s.integrationHandler.asanaWebhookToken) != "" {
			asanaWebhook = "configured"
		}
	}
	sort.Strings(integrationNames)

	status := map[string]interface{}{
		"grc":      os.Getenv("GRC_PROVIDER"),
		"identity": idNames,
		"integrations": map[string]interface{}{
			"default":       integrationDefault,
			"enabled":       integrationNames,
			"ticket_store":  integrationStore,
			"asana_webhook": asanaWebhook,
		},
		"finops":    getEnv("FINOPS_PROVIDER", "memory"),
		"container": getEnv("CONTAINER_SCANNER", "memory"),
		"workflow":  getEnv("WORKFLOW_ENGINE", "memory"),
		"waf":       getEnv("WAF_PROVIDER", "memory"),
		"secrets":   getEnv("SECRETS_PROVIDER", "memory"),
	}

	// Fill GRC default
	if status["grc"] == "" {
		status["grc"] = "memory"
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}
