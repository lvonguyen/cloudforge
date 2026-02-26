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

	"cloudforge/internal/api"
	"cloudforge/internal/api/gateway"
	"cloudforge/internal/grc"

	"github.com/gorilla/mux"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const (
	// maxRequestBodySize limits request body to 1MB to prevent resource exhaustion
	maxRequestBodySize = 1 << 20 // 1MB
)

// Config holds application configuration
type Config struct {
	Port             string
	GRCProvider      grc.ProviderType
	JWTSecretEnv     string // Environment variable name for JWT secret
	JWTIssuer        string // Expected JWT issuer
	JWTAudience      string // Expected JWT audience
	TLSCertFile      string // Path to TLS certificate file
	TLSKeyFile       string // Path to TLS key file
	RedisAddr        string // Redis address for rate limiting
	RedisPasswordEnv string // Environment variable name for Redis password
	RateLimitEnabled bool   // Enable rate limiting
}

// Server holds the application state
type Server struct {
	config         Config
	grcProvider    grc.GRCProvider
	router         *mux.Router
	authMiddleware *api.AuthMiddleware
	rateLimiter    *gateway.RateLimiter
	logger         *zap.Logger
}

func main() {
	// Initialize logger
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer func() { _ = logger.Sync() }()

	// Load configuration
	cfg := Config{
		Port:             getEnv("PORT", "8080"),
		GRCProvider:      grc.ProviderType(getEnv("GRC_PROVIDER", "memory")),
		JWTSecretEnv:     getEnv("JWT_SECRET_ENV", "CLOUDFORGE_JWT_SECRET"),
		JWTIssuer:        getEnv("JWT_ISSUER", ""),
		JWTAudience:      getEnv("JWT_AUDIENCE", ""),
		TLSCertFile:      getEnv("TLS_CERT_FILE", ""),
		TLSKeyFile:       getEnv("TLS_KEY_FILE", ""),
		RedisAddr:        getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPasswordEnv: getEnv("REDIS_PASSWORD_ENV", "CLOUDFORGE_REDIS_PASSWORD"),
		RateLimitEnabled: getEnv("RATE_LIMIT_ENABLED", "true") == "true",
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
	}, logger)
	if err != nil {
		log.Fatalf("Failed to initialize auth middleware: %v", err)
	}

	// Initialize rate limiter (optional, depends on Redis availability)
	var rateLimiter *gateway.RateLimiter
	if cfg.RateLimitEnabled {
		redisPassword := os.Getenv(cfg.RedisPasswordEnv)
		redisClient := redis.NewClient(&redis.Options{
			Addr:     cfg.RedisAddr,
			Password: redisPassword,
			DB:       0,
		})

		// Test Redis connection
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := redisClient.Ping(ctx).Err(); err != nil {
			logger.Warn("Redis connection failed, rate limiting will use local fallback",
				zap.Error(err),
				zap.String("redis_addr", cfg.RedisAddr),
			)
		} else {
			logger.Info("Redis connected for rate limiting",
				zap.String("redis_addr", cfg.RedisAddr),
			)
		}
		cancel()

		rateLimiter = gateway.NewRateLimiter(redisClient, gateway.DefaultConfig(), logger)
		logger.Info("Rate limiter initialized")
	}

	// Create server
	srv := &Server{
		config:         cfg,
		grcProvider:    grcProvider,
		router:         mux.NewRouter(),
		authMiddleware: authMiddleware,
		rateLimiter:    rateLimiter,
		logger:         logger,
	}

	// Setup routes
	srv.setupRoutes()

	// Create HTTP server with security middleware
	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%s", cfg.Port),
		Handler:           srv.securityHeadersMiddleware(srv.router),
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
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
			logger.Info("CloudForge API server starting with TLS", zap.String("port", cfg.Port))
			if err := httpServer.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil && err != http.ErrServerClosed {
				logger.Fatal("Server error", zap.Error(err))
			}
		} else {
			logger.Warn("CloudForge API server starting without TLS", zap.String("port", cfg.Port))
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Fatal("Server error", zap.Error(err))
			}
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Fatal("Server forced to shutdown", zap.Error(err))
	}

	logger.Info("Server stopped")
}

func (s *Server) setupRoutes() {
	// Health check (unauthenticated - skipped by middleware)
	s.router.HandleFunc("/health", s.healthCheck).Methods("GET")

	// API v1 routes with authentication and rate limiting middleware.
	// Auth runs first so that:
	//   1. Unauthenticated requests are rejected before consuming rate limit budget.
	//   2. Rate limits can be keyed on the verified identity (JWT subject) rather than IP.
	apiRouter := s.router.PathPrefix("/api/v1").Subrouter()

	// Apply authentication middleware first
	apiRouter.Use(s.authMiddleware.Middleware)

	// Apply rate limiting after auth (identity is now available in context)
	if s.rateLimiter != nil {
		apiRouter.Use(s.rateLimiter.Middleware(s.getTierFromRequest, s.getClientIDFromRequest))
	}

	// Exception management
	// Literal paths must be registered before parameterized paths in gorilla/mux
	// to prevent /{id} from shadowing /pending and /expiring.
	apiRouter.HandleFunc("/exceptions", s.createException).Methods("POST")
	apiRouter.HandleFunc("/exceptions/pending", s.getPendingApprovals).Methods("GET")
	apiRouter.HandleFunc("/exceptions/expiring", s.getExpiringExceptions).Methods("GET")
	apiRouter.HandleFunc("/exceptions/{id}", s.getException).Methods("GET")
	apiRouter.HandleFunc("/exceptions/{id}/approve", s.submitApproval).Methods("POST")
	apiRouter.HandleFunc("/applications/{appId}/exceptions", s.getExceptionsByApp).Methods("GET")

	// Policy validation (called by Terraform/provisioning)
	apiRouter.HandleFunc("/validate/exception", s.validateException).Methods("POST")
}

// getTierFromRequest extracts the API tier from the request.
// This can be based on API key lookup, JWT claims, or headers.
func (s *Server) getTierFromRequest(r *http.Request) string {
	// Check for tier in JWT claims (set by auth middleware)
	if claims, ok := api.GetClaimsFromContext(r.Context()); ok {
		// Look for tier in scope or custom claim
		if strings.Contains(claims.Scope, "enterprise") {
			return "enterprise"
		}
		if strings.Contains(claims.Scope, "professional") {
			return "professional"
		}
		if strings.Contains(claims.Scope, "basic") {
			return "basic"
		}
		if claims.Subject != "" {
			return "free" // Authenticated users get "free" tier minimum
		}
	}

	// Default to anonymous for unauthenticated requests
	return "anonymous"
}

// getClientIDFromRequest extracts the client identifier for rate limiting.
func (s *Server) getClientIDFromRequest(r *http.Request) string {
	// Prefer JWT subject (user ID)
	if claims, ok := api.GetClaimsFromContext(r.Context()); ok && claims.Subject != "" {
		return claims.Subject
	}

	// Fall back to API key if present
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		return apiKey
	}

	// Empty string will cause rate limiter to fall back to IP address
	return ""
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
	vars := mux.Vars(r)
	id := vars["id"]

	exc, err := s.grcProvider.GetException(r.Context(), id)
	if err != nil {
		s.logger.Error("get exception failed", zap.Error(err))
		writeErrorResponse(w, "exception not found", http.StatusNotFound)
		return
	}

	// Authorization: require admin scope or JWT subject matching the exception's app owner.
	claims, ok := api.GetClaimsFromContext(r.Context())
	if !ok {
		writeErrorResponse(w, "authentication required", http.StatusUnauthorized)
		return
	}
	if !strings.Contains(claims.Scope, "admin") && claims.Subject != exc.ApplicationID {
		writeErrorResponse(w, "forbidden: requires admin scope or matching application identity", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(exc)
}

func (s *Server) submitApproval(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

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

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "approval recorded"})
}

func (s *Server) getPendingApprovals(w http.ResponseWriter, r *http.Request) {
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

func (s *Server) getExpiringExceptions(w http.ResponseWriter, r *http.Request) {
	claims, ok := api.GetClaimsFromContext(r.Context())
	if !ok || !strings.Contains(claims.Scope, "compliance") {
		writeErrorResponse(w, "forbidden: requires compliance scope", http.StatusForbidden)
		return
	}

	expiring, err := s.grcProvider.GetExpiringExceptions(r.Context(), 30)
	if err != nil {
		s.writeInternalError(w, err, "get expiring exceptions")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(expiring)
}

func (s *Server) getExceptionsByApp(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	appID := vars["appId"]

	// Authorization: require admin scope or JWT subject matching appId
	claims, ok := api.GetClaimsFromContext(r.Context())
	if !ok {
		writeErrorResponse(w, "authentication required", http.StatusUnauthorized)
		return
	}
	if !strings.Contains(claims.Scope, "admin") && claims.Subject != appID {
		writeErrorResponse(w, "forbidden: requires admin scope or matching application identity", http.StatusForbidden)
		return
	}

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

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// securityHeadersMiddleware adds security headers.
// HSTS is only set on TLS connections or when the request was forwarded over HTTPS
// (X-Forwarded-Proto: https). Setting HSTS on plain HTTP causes browser lockout in dev.
func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isTLS := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
		if isTLS {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		next.ServeHTTP(w, r)
	})
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
