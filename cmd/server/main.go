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

	"cloudforge/internal/ai"
	"cloudforge/internal/api"
	"cloudforge/internal/api/gateway"
	"cloudforge/internal/grc"
	"cloudforge/internal/observability"

	"github.com/gorilla/mux"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
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
	AIEnabled        bool   // Enable Bedrock AI enrichment
	AIRegion         string // AWS region for Bedrock (default: us-east-1)
	AIModel          string // Bedrock model ID override
	CORSOrigins      string // Comma-separated allowed CORS origins
}

// Server holds the application state
type Server struct {
	config            Config
	grcProvider       grc.GRCProvider
	router            *mux.Router
	authMiddleware    *api.AuthMiddleware
	rateLimiter       *gateway.RateLimiter
	healthChecker     *observability.HealthChecker
	logger            *zap.Logger
	mockData          *MockData
	attackPaths       []AttackPath
	attackPathStats   *AttackPathStats
	aiProvider        ai.Provider // nil when AI is disabled (graceful degradation)
	findingEnrichment map[string]*FindingEnrichment
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
		AIEnabled:        getEnv("CLOUDFORGE_AI_ENABLED", "false") == "true",
		AIRegion:         getEnv("CLOUDFORGE_AI_REGION", "us-east-1"),
		AIModel:          getEnv("CLOUDFORGE_AI_MODEL", ""),
		CORSOrigins:      getEnv("CORS_ALLOWED_ORIGINS", ""),
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
		JWKSURLEnv:   "CLOUDFORGE_JWKS_URL",
		Issuer:       cfg.JWTIssuer,
		Audience:     cfg.JWTAudience,
		SkipPaths:    []string{"/health", "/healthz", "/ready"},
	}, logger)
	if err != nil {
		log.Fatalf("Failed to initialize auth middleware: %v", err)
	}

	// Initialize health checker
	healthChecker := observability.NewHealthChecker(logger, nil)

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
			_ = redisClient.Close()
			redisClient = nil
		} else {
			logger.Info("Redis connected for rate limiting",
				zap.String("redis_addr", cfg.RedisAddr),
			)
		}
		if redisClient != nil {
			healthChecker.RegisterRedisCheck("redis", redisClient)
		}
		cancel()

		rateLimiter = gateway.NewRateLimiter(redisClient, gateway.DefaultConfig(), logger)
		logger.Info("Rate limiter initialized")
	}

	// Initialize AI provider (optional — graceful degradation when unavailable)
	var aiProvider ai.Provider
	if cfg.AIEnabled {
		bp, err := ai.NewBedrockProvider(cfg.AIRegion, cfg.AIModel)
		if err != nil {
			logger.Warn("AI provider init failed, enrichment disabled", zap.Error(err))
		} else {
			// Validate credentials with a lightweight ping
			pingCtx, pingCancel := context.WithTimeout(context.Background(), 10*time.Second)
			if _, err := bp.Complete(pingCtx, "ping"); err != nil {
				logger.Warn("Bedrock credential validation failed, enrichment disabled",
					zap.Error(err),
					zap.String("region", cfg.AIRegion),
				)
			} else {
				aiProvider = bp
				logger.Info("AI provider initialized",
					zap.String("region", cfg.AIRegion),
					zap.String("model", bp.ModelID()),
				)
			}
			pingCancel()
		}
	}

	// Create server
	srv := &Server{
		config:            cfg,
		grcProvider:       grcProvider,
		router:            mux.NewRouter(),
		authMiddleware:    authMiddleware,
		rateLimiter:       rateLimiter,
		healthChecker:     healthChecker,
		logger:            logger,
		aiProvider:        aiProvider,
		findingEnrichment: make(map[string]*FindingEnrichment),
	}

	// Load mock data from frontend JSON files
	mockData, err := loadMockData(mockDataDir())
	if err != nil {
		log.Fatalf("Failed to load mock data: %v", err)
	}
	srv.mockData = mockData
	logger.Info("Mock data loaded",
		zap.Int("findings", len(mockData.Findings)),
		zap.Int("agents", len(mockData.Agents)),
		zap.Int("frameworks", len(mockData.Frameworks)),
		zap.Int("remediations", len(mockData.Remediations)),
		zap.Int("audit_events", len(mockData.AuditEvents)),
		zap.Int("users", len(mockData.Users)),
		zap.Int("policies", len(mockData.Policies)),
		zap.Int("catalog_modules", len(mockData.CatalogModules)),
	)

	// Compute attack paths from findings
	attackPaths, attackPathStats := computeAttackPaths(mockData.Findings)

	// Enrich attack paths with AI if provider is available
	if srv.aiProvider != nil {
		enrichCtx, enrichCancel := context.WithTimeout(context.Background(), 5*time.Minute)
		enrichAttackPaths(enrichCtx, srv.aiProvider, attackPaths, logger)
		enrichCancel()
	}

	srv.attackPaths = attackPaths
	srv.attackPathStats = attackPathStats
	logger.Info("Attack paths computed",
		zap.Int("paths", len(attackPaths)),
		zap.Int("findings_in_paths", attackPathStats.FindingsInPaths),
		zap.Int("isolated", attackPathStats.IsolatedFindings),
	)

	// Start periodic health checks
	healthCtx, healthCancel := context.WithCancel(context.Background())
	defer healthCancel()
	srv.healthChecker.StartPeriodicCheck(healthCtx, 30*time.Second)

	// Setup routes
	srv.setupRoutes()

	// Create HTTP server with security middleware
	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%s", cfg.Port),
		Handler:           srv.securityHeadersMiddleware(srv.router),
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      35 * time.Second, // must exceed AI enrichment's 30s context
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
	// CORS middleware — applied to all routes (including health for browser fetch).
	if s.config.CORSOrigins != "" {
		origins := strings.Split(s.config.CORSOrigins, ",")
		s.router.Use(api.CORSMiddleware(origins))
	}

	// Health check endpoints (unauthenticated - skipped by middleware)
	s.router.HandleFunc("/health", s.healthChecker.HealthHandler()).Methods("GET")
	s.router.HandleFunc("/healthz", s.healthChecker.LivenessHandler()).Methods("GET")
	s.router.HandleFunc("/ready", s.healthChecker.ReadinessHandler()).Methods("GET")

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

	// Exception read endpoints — require operator or admin
	// Literal paths registered before parameterized to prevent /{id} shadowing.
	apiRouter.Handle("/exceptions/pending", // operator, admin
		api.RequireRole(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.getPendingApprovals)),
	).Methods("GET")
	apiRouter.Handle("/exceptions/expiring", // operator, admin
		api.RequireRole(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.getExpiringExceptions)),
	).Methods("GET")
	apiRouter.Handle("/exceptions/{id}", // operator, admin
		api.RequireRole(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.getException)),
	).Methods("GET")
	apiRouter.Handle("/applications/{appId}/exceptions", // operator, admin
		api.RequireRole(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.getExceptionsByApp)),
	).Methods("GET")

	// Exception write endpoints — require admin
	apiRouter.Handle("/exceptions", // admin only
		api.RequireRole(api.RoleAdmin)(http.HandlerFunc(s.createException)),
	).Methods("POST")
	apiRouter.Handle("/exceptions/{id}/approve", // admin only
		api.RequireRole(api.RoleAdmin)(http.HandlerFunc(s.submitApproval)),
	).Methods("POST")

	// Policy validation — require operator or admin
	apiRouter.Handle("/validate/exception", // operator, admin
		api.RequireRole(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.validateException)),
	).Methods("POST")

	// Findings — read endpoints
	apiRouter.Handle("/findings",
		api.RequireRole(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.listFindings)),
	).Methods("GET")
	apiRouter.Handle("/findings/{id}/enrich",
		api.RequireRole(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.enrichFinding)),
	).Methods("POST")
	apiRouter.Handle("/findings/{id}",
		api.RequireRole(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.getFinding)),
	).Methods("GET")

	// Compliance
	apiRouter.Handle("/compliance/frameworks",
		api.RequireRole(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.listFrameworks)),
	).Methods("GET")

	// Agents
	apiRouter.Handle("/agents",
		api.RequireRole(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.listAgents)),
	).Methods("GET")
	apiRouter.Handle("/agents/{id}",
		api.RequireRole(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.getAgent)),
	).Methods("GET")

	// Costs
	apiRouter.Handle("/costs/summary",
		api.RequireRole(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.getCostSummary)),
	).Methods("GET")

	// Remediations
	apiRouter.Handle("/remediations",
		api.RequireRole(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.listRemediations)),
	).Methods("GET")
	apiRouter.Handle("/remediations/{id}/execute",
		api.RequireRole(api.RoleAdmin)(http.HandlerFunc(s.executeRemediation)),
	).Methods("POST")
	apiRouter.Handle("/remediations/{id}",
		api.RequireRole(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.getRemediation)),
	).Methods("GET")

	// Agent traces
	apiRouter.Handle("/agents/{id}/traces",
		api.RequireRole(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.listAgentTraces)),
	).Methods("GET")

	// Audit log — admin only
	apiRouter.Handle("/audit-log",
		api.RequireRole(api.RoleAdmin)(http.HandlerFunc(s.listAuditLog)),
	).Methods("GET")

	// Users — admin only
	apiRouter.Handle("/users",
		api.RequireRole(api.RoleAdmin)(http.HandlerFunc(s.listUsers)),
	).Methods("GET")

	// Catalog
	apiRouter.Handle("/catalog/modules",
		api.RequireRole(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.listCatalogModules)),
	).Methods("GET")

	// Policies
	apiRouter.Handle("/policies",
		api.RequireRole(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.listPolicies)),
	).Methods("GET")

	// Attack paths
	apiRouter.Handle("/attack-paths",
		api.RequireRole(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.listAttackPaths)),
	).Methods("GET")
	apiRouter.Handle("/attack-paths/stats",
		api.RequireRole(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.getAttackPathStats)),
	).Methods("GET")
	apiRouter.Handle("/attack-paths/{id}",
		api.RequireRole(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.getAttackPath)),
	).Methods("GET")
}

// getTierFromRequest extracts the API tier from the request.
// This can be based on API key lookup, JWT claims, or headers.
func (s *Server) getTierFromRequest(r *http.Request) string {
	// Check for tier in JWT claims (set by auth middleware)
	if claims, ok := api.GetClaimsFromContext(r.Context()); ok {
		// Look for tier in scope or custom claim
		scopes := make(map[string]bool)
		for _, s := range strings.Fields(claims.Scope) {
			scopes[s] = true
		}
		if scopes["enterprise"] {
			return "enterprise"
		}
		if scopes["professional"] {
			return "professional"
		}
		if scopes["basic"] {
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
		s.logger.Error("get exception failed", zap.Error(err))
		writeErrorResponse(w, "exception not found", http.StatusNotFound)
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
