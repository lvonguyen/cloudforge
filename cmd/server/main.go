package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"cloudforge/internal/ai"
	"cloudforge/internal/api"
	"cloudforge/internal/api/gateway"
	"cloudforge/internal/grc"
	"cloudforge/internal/identity"
	"cloudforge/internal/observability"

	"github.com/gorilla/mux"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
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
	findingsByID      map[string]*Finding
	agentsByID        map[string]*Agent
	tracesByAgentID   map[string][]AgentTrace
	remediationsByID  map[string]*RemediationRecord
	attackPaths       []AttackPath
	attackPathStats   *AttackPathStats
	attackPathMu      sync.RWMutex
	aiProvider        ai.Provider // nil when AI is disabled (graceful degradation)
	findingEnrichment map[string]*FindingEnrichment
	enrichMu          sync.Mutex
	roles             *api.RoleEnforcer
	finopsSvc         *finopsService
	identityProviders map[string]identity.Provider
}

func main() {
	// Initialize logger
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer func() { _ = logger.Sync() }()

	// Load configuration
	providerType, err := grc.ProviderFromString(getEnv("GRC_PROVIDER", "memory"))
	if err != nil {
		logger.Fatal("Invalid GRC provider", zap.Error(err))
	}

	cfg := Config{
		Port:             getEnv("PORT", "8080"),
		GRCProvider:      providerType,
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
		logger.Fatal("Failed to initialize GRC provider", zap.Error(err))
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
		logger.Fatal("Failed to initialize auth middleware", zap.Error(err))
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

		if redisClient != nil {
			defer func() {
				if err := redisClient.Close(); err != nil {
					logger.Warn("Failed to close Redis client", zap.Error(err))
				}
			}()
		}

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

	// Initialize identity providers — use real providers when env vars are set,
	// otherwise fall back to in-memory mocks for local development.
	idProviders := make(map[string]identity.Provider, 2)
	if oktaDomain := os.Getenv("OKTA_DOMAIN"); oktaDomain != "" {
		op, err := identity.NewOktaProvider(identity.OktaConfig{
			Domain:      oktaDomain,
			APITokenEnv: "OKTA_API_TOKEN",
		}, logger)
		if err != nil {
			logger.Warn("Okta provider init failed, falling back to mock", zap.Error(err))
			idProviders["okta"] = identity.NewMockOktaProvider()
		} else {
			idProviders["okta"] = op
			logger.Info("Okta identity provider initialized", zap.String("domain", oktaDomain))
		}
	} else {
		idProviders["okta"] = identity.NewMockOktaProvider()
		logger.Info("Using mock Okta identity provider (OKTA_DOMAIN not set)")
	}
	if entraTenantID := os.Getenv("ENTRA_TENANT_ID"); entraTenantID != "" {
		ep, err := identity.NewEntraIDProvider(identity.EntraIDConfig{
			TenantIDEnv:     "ENTRA_TENANT_ID",
			ClientIDEnv:     "ENTRA_CLIENT_ID",
			ClientSecretEnv: "ENTRA_CLIENT_SECRET",
		}, logger)
		if err != nil {
			logger.Warn("Entra ID provider init failed, falling back to mock", zap.Error(err))
			idProviders["entra_id"] = identity.NewMockEntraIDProvider()
		} else {
			idProviders["entra_id"] = ep
			logger.Info("Entra ID identity provider initialized", zap.String("tenant_id", entraTenantID))
		}
	} else {
		idProviders["entra_id"] = identity.NewMockEntraIDProvider()
		logger.Info("Using mock Entra ID identity provider (ENTRA_TENANT_ID not set)")
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
		roles:             &api.RoleEnforcer{DevMode: os.Getenv("APP_ENV") == "development"},
		finopsSvc:         newFinopsService(),
		identityProviders: idProviders,
	}

	// Load mock data from frontend JSON files
	mockData, err := loadMockData(mockDataDir())
	if err != nil {
		logger.Fatal("Failed to load mock data", zap.Error(err))
	}
	srv.mockData = mockData

	// Build O(1) lookup maps for hot-path single-item handlers
	srv.findingsByID = make(map[string]*Finding, len(mockData.Findings))
	for i := range mockData.Findings {
		srv.findingsByID[mockData.Findings[i].ID] = &mockData.Findings[i]
	}
	srv.agentsByID = make(map[string]*Agent, len(mockData.Agents))
	for i := range mockData.Agents {
		srv.agentsByID[mockData.Agents[i].ID] = &mockData.Agents[i]
	}
	srv.remediationsByID = make(map[string]*RemediationRecord, len(mockData.Remediations))
	for i := range mockData.Remediations {
		srv.remediationsByID[mockData.Remediations[i].ID] = &mockData.Remediations[i]
	}
	srv.tracesByAgentID = make(map[string][]AgentTrace, len(mockData.Agents))
	for _, tr := range mockData.Traces {
		srv.tracesByAgentID[tr.AgentID] = append(srv.tracesByAgentID[tr.AgentID], tr)
	}

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

	srv.attackPaths = attackPaths
	srv.attackPathStats = attackPathStats

	// Server-scoped context: cancelled on SIGINT/SIGTERM to stop background work.
	serverCtx, serverCancel := context.WithCancel(context.Background())
	defer serverCancel()

	// Enrich attack paths with AI in the background to avoid blocking startup.
	// Assign srv.attackPaths before spawning so HTTP handlers always see the slice.
	if srv.aiProvider != nil {
		go func() {
			enrichCtx, enrichCancel := context.WithTimeout(serverCtx, 5*time.Minute)
			defer enrichCancel()
			enrichAttackPaths(enrichCtx, srv.aiProvider, attackPaths, &srv.attackPathMu, logger)
		}()
	}
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
		Handler:           srv.gzipMiddleware(srv.securityHeadersMiddleware(srv.router)),
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

	// Cancel server-scoped context to stop background goroutines (enrichment, etc.)
	serverCancel()

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Fatal("Server forced to shutdown", zap.Error(err))
	}

	logger.Info("Server stopped")
}
