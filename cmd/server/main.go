package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/yourusername/cloudforge/internal/api"
	"github.com/yourusername/cloudforge/internal/grc"
)

const (
	// maxRequestBodySize limits request body to 1MB to prevent resource exhaustion
	maxRequestBodySize = 1 << 20 // 1MB
)

// Config holds application configuration
type Config struct {
	Port         string
	GRCProvider  grc.ProviderType
	JWTSecretEnv string // Environment variable name for JWT secret
	JWTIssuer    string // Expected JWT issuer
	JWTAudience  string // Expected JWT audience
	TLSCertFile  string // Path to TLS certificate file
	TLSKeyFile   string // Path to TLS key file
}

// Server holds the application state
type Server struct {
	config         Config
	grcProvider    grc.GRCProvider
	router         *mux.Router
	authMiddleware *api.AuthMiddleware
}

func main() {
	// Load configuration
	cfg := Config{
		Port:         getEnv("PORT", "8080"),
		GRCProvider:  grc.ProviderType(getEnv("GRC_PROVIDER", "memory")),
		JWTSecretEnv: getEnv("JWT_SECRET_ENV", "CLOUDFORGE_JWT_SECRET"),
		JWTIssuer:    getEnv("JWT_ISSUER", ""),
		JWTAudience:  getEnv("JWT_AUDIENCE", ""),
		TLSCertFile:  getEnv("TLS_CERT_FILE", ""),
		TLSKeyFile:   getEnv("TLS_KEY_FILE", ""),
	}

	// Initialize GRC provider
	grcProvider, err := grc.NewProvider(grc.Config{
		Type: cfg.GRCProvider,
	})
	if err != nil {
		log.Fatalf("Failed to initialize GRC provider: %v", err)
	}

	// Initialize authentication middleware
	authMiddleware, err := api.NewAuthMiddleware(api.AuthConfig{
		JWTSecretEnv: cfg.JWTSecretEnv,
		Issuer:       cfg.JWTIssuer,
		Audience:     cfg.JWTAudience,
		SkipPaths:    []string{"/health"},
	})
	if err != nil {
		log.Fatalf("Failed to initialize auth middleware: %v", err)
	}

	// Create server
	srv := &Server{
		config:         cfg,
		grcProvider:    grcProvider,
		router:         mux.NewRouter(),
		authMiddleware: authMiddleware,
	}

	// Setup routes
	srv.setupRoutes()

	// Create HTTP server with security middleware
	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%s", cfg.Port),
		Handler:      srv.securityHeadersMiddleware(srv.router),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Configure TLS if cert and key are provided
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		httpServer.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		}
	}

	// Start server in goroutine
	go func() {
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			log.Printf("CloudForge API server starting with TLS on port %s", cfg.Port)
			if err := httpServer.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Server error: %v", err)
			}
		} else {
			log.Printf("CloudForge API server starting on port %s (WARNING: TLS not configured)", cfg.Port)
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Server error: %v", err)
			}
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server stopped")
}

func (s *Server) setupRoutes() {
	// Health check (unauthenticated - skipped by middleware)
	s.router.HandleFunc("/health", s.healthCheck).Methods("GET")

	// API v1 routes with authentication middleware
	apiRouter := s.router.PathPrefix("/api/v1").Subrouter()
	apiRouter.Use(s.authMiddleware.Middleware)

	// Exception management
	apiRouter.HandleFunc("/exceptions", s.createException).Methods("POST")
	apiRouter.HandleFunc("/exceptions/{id}", s.getException).Methods("GET")
	apiRouter.HandleFunc("/exceptions/{id}/approve", s.submitApproval).Methods("POST")
	apiRouter.HandleFunc("/exceptions/pending", s.getPendingApprovals).Methods("GET")
	apiRouter.HandleFunc("/exceptions/expiring", s.getExpiringExceptions).Methods("GET")
	apiRouter.HandleFunc("/applications/{appId}/exceptions", s.getExceptionsByApp).Methods("GET")

	// Policy validation (called by Terraform/provisioning)
	apiRouter.HandleFunc("/validate/exception", s.validateException).Methods("POST")
}

func (s *Server) healthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "healthy",
		"version": "0.1.0",
	})
}

func (s *Server) createException(w http.ResponseWriter, r *http.Request) {
	var req grc.ExceptionRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}

	// Validate required fields
	if req.ApplicationID == "" || req.PolicyCode == "" {
		writeErrorResponse(w, "application_id and policy_code are required", http.StatusBadRequest)
		return
	}

	created, err := s.grcProvider.CreateException(r.Context(), &req)
	if err != nil {
		writeInternalError(w, err, "create exception")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(created)
}

func (s *Server) getException(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	exc, err := s.grcProvider.GetException(r.Context(), id)
	if err != nil {
		log.Printf("get exception failed: %v", err)
		writeErrorResponse(w, "exception not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(exc)
}

func (s *Server) submitApproval(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var approver grc.Approver
	if !decodeJSONBody(w, r, &approver) {
		return
	}

	// Validate required fields
	if approver.Email == "" {
		writeErrorResponse(w, "approver email is required", http.StatusBadRequest)
		return
	}

	if err := s.grcProvider.SubmitApproval(r.Context(), id, approver); err != nil {
		writeInternalError(w, err, "submit approval")
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "approval recorded"})
}

func (s *Server) getPendingApprovals(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("approver_email")
	if email == "" {
		writeErrorResponse(w, "approver_email query parameter required", http.StatusBadRequest)
		return
	}

	pending, err := s.grcProvider.GetPendingApprovals(r.Context(), email)
	if err != nil {
		writeInternalError(w, err, "get pending approvals")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(pending)
}

func (s *Server) getExpiringExceptions(w http.ResponseWriter, r *http.Request) {
	expiring, err := s.grcProvider.GetExpiringExceptions(r.Context(), 30)
	if err != nil {
		writeInternalError(w, err, "get expiring exceptions")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(expiring)
}

func (s *Server) getExceptionsByApp(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	appID := vars["appId"]

	exceptions, err := s.grcProvider.GetExceptionsByApplication(r.Context(), appID)
	if err != nil {
		writeInternalError(w, err, "get exceptions by app")
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
	var req ValidateExceptionRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}

	validation, err := s.grcProvider.ValidateException(r.Context(), req.ApplicationID, req.PolicyCode)
	if err != nil {
		writeInternalError(w, err, "validate exception")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(validation)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// securityHeadersMiddleware adds security headers including HSTS
func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		next.ServeHTTP(w, r)
	})
}

// decodeJSONBody decodes JSON request body with size limit and validation.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst interface{}) bool {
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
		log.Printf("JSON decode error: %v", err)
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
func writeInternalError(w http.ResponseWriter, err error, operation string) {
	log.Printf("%s failed: %v", operation, err)
	writeErrorResponse(w, "internal server error", http.StatusInternalServerError)
}
