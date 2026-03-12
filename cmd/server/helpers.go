package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"go.uber.org/zap"
)

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
