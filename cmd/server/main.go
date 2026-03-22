package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof" //nolint:gosec // G108: pprof is dev-only (APP_ENV==development, loopback:6060)
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"aegis/internal/ai"
	"aegis/internal/ai-governance/opa"
	"aegis/internal/api"
	"aegis/internal/api/gateway"
	"aegis/internal/asm"
	"aegis/internal/audit"
	"aegis/internal/compliance"
	"aegis/internal/container"
	"aegis/internal/cspm/threatintel"
	"aegis/internal/graph"
	"aegis/internal/grc"
	"aegis/internal/identity"
	"aegis/internal/ingestion"
	"aegis/internal/integrations"
	"aegis/internal/integrations/jira"
	"aegis/internal/observability"
	"aegis/internal/secrets"
	"aegis/internal/tenant"
	"aegis/internal/waf"
	"aegis/internal/webhooks"
	"aegis/internal/workflow"

	"github.com/gorilla/mux"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// Config holds application configuration
type Config struct {
	Port             string
	GRCProvider      grc.ProviderType
	JWTSecretEnv     string  // Environment variable name for JWT secret
	JWTIssuer        string  // Expected JWT issuer
	JWTAudience      string  // Expected JWT audience
	TLSCertFile      string  // Path to TLS certificate file
	TLSKeyFile       string  // Path to TLS key file
	RedisAddr        string  // Redis address for rate limiting
	RedisPasswordEnv string  // Environment variable name for Redis password
	RateLimitEnabled bool    // Enable rate limiting
	AIEnabled        bool    // Enable Bedrock AI enrichment
	AIRegion         string  // AWS region for Bedrock (default: us-east-1)
	AIModel          string  // Bedrock model ID override
	CORSOrigins      string  // Comma-separated allowed CORS origins
	WSServerURL      string  // URL of the ws-server for SSE event publishing
	WSPublishKey     string  // X-API-Key for ws-server /api/publish (WS_PUBLISH_KEY env var)
	TracingEnabled   bool    // Enable OpenTelemetry tracing
	OTLPEndpoint     string  // OTLP gRPC endpoint for trace export
	SamplingRate     float64 // Trace sampling rate (0.0 - 1.0)
}

// Server holds application state and wires domain services to HTTP routes.
// Domain logic lives in dedicated services; Server is the composition root.
type Server struct {
	config         Config
	grcHandler     *GRCHandler
	router         *mux.Router
	authMiddleware *api.AuthMiddleware
	rateLimiter    *gateway.RateLimiter
	healthChecker  *observability.HealthChecker
	logger         *zap.Logger
	roles          *api.RoleEnforcer
	auditLogger    audit.AuditLogger

	// Domain services (extracted from God Object)
	data          *DataStore         // findings, agents, traces, remediations, etc.
	attackPathSvc *AttackPathService // attack path queries + mutex
	enrichmentSvc *EnrichmentService // AI enrichment + cache
	opaEngine     *opa.Engine        // AI governance policy engine (nil = disabled)
	comments      *CommentsStore     // finding comments (in-memory)

	// Multi-tenancy (Phase 3)
	tenantStore tenant.Store

	// Observability
	telemetry *observability.Telemetry

	// Already-isolated services
	finopsSvc   *finopsService
	identitySvc *IdentityService
	dedupCache  *ingestion.DedupCache

	// Deploy preview (ws-server integration)
	wsServerURL   string
	wsPublishKey  string
	wsHTTPClient  *http.Client // Connection-pooled client for ws-server publish
	deployTracker *deployTracker

	// Singleton service instances (avoid per-request allocation)
	workflowEngine   workflow.Engine
	wafManager       waf.TemplateManager
	secretsProvider  *secrets.MemoryProvider
	secretsManager   *secrets.Manager
	containerScanner container.Scanner

	// Integration layer (Sprint: Integration Stubs)
	integrationHandler *IntegrationHandler
	webhookEngine      webhooks.Engine
	complianceMgr      *compliance.Manager
	asmSvc             *asmService
	orgScanner         secrets.OrgScanner

	// Graph query engine (PuppyGraph — feature-flagged via PUPPYGRAPH_URL)
	graphClient *graph.Client

	// Full-text search (BM25 + optional semantic/hybrid)
	searchSvc *SearchService
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
		JWTSecretEnv:     getEnv("JWT_SECRET_ENV", "AEGIS_JWT_SECRET"),
		JWTIssuer:        getEnv("JWT_ISSUER", ""),
		JWTAudience:      getEnv("JWT_AUDIENCE", ""),
		TLSCertFile:      getEnv("TLS_CERT_FILE", ""),
		TLSKeyFile:       getEnv("TLS_KEY_FILE", ""),
		RedisAddr:        getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPasswordEnv: getEnv("REDIS_PASSWORD_ENV", "AEGIS_REDIS_PASSWORD"),
		RateLimitEnabled: getEnv("RATE_LIMIT_ENABLED", "true") == "true",
		AIEnabled:        getEnv("AEGIS_AI_ENABLED", "false") == "true",
		AIRegion:         getEnv("AEGIS_AI_REGION", "us-east-1"),
		AIModel:          getEnv("AEGIS_AI_MODEL", ""),
		CORSOrigins:      getEnv("CORS_ALLOWED_ORIGINS", ""),
		WSServerURL:      getEnv("WS_SERVER_URL", ""),
		WSPublishKey:     getEnv("WS_PUBLISH_KEY", ""),
		TracingEnabled:   os.Getenv("AEGIS_TRACING_ENABLED") == "true",
		OTLPEndpoint:     getEnv("AEGIS_OTLP_ENDPOINT", "localhost:4317"),
		SamplingRate:     parseFloatOrDefault(os.Getenv("AEGIS_SAMPLING_RATE"), 1.0),
	}

	// Initialize GRC provider
	grcProvider, err := grc.NewProvider(grc.Config{
		Type: cfg.GRCProvider,
	})
	if err != nil {
		logger.Fatal("Failed to initialize GRC provider", zap.Error(err))
	}

	// Auto-derive JWKS URL from Okta domain when not explicitly set.
	// This removes the need to manually configure AEGIS_JWKS_URL alongside OKTA_DOMAIN.
	if domain := os.Getenv("OKTA_DOMAIN"); domain != "" && os.Getenv("AEGIS_JWKS_URL") == "" {
		jwksURL := "https://" + domain + "/oauth2/default/v1/keys"
		os.Setenv("AEGIS_JWKS_URL", jwksURL)
		logger.Info("Auto-derived JWKS URL from OKTA_DOMAIN", zap.String("jwks_url", jwksURL))
	}

	// Initialize authentication middleware
	authMiddleware, err := api.NewAuthMiddleware(api.AuthConfig{
		JWTSecretEnv: cfg.JWTSecretEnv,
		JWKSURLEnv:   "AEGIS_JWKS_URL",
		Issuer:       cfg.JWTIssuer,
		Audience:     cfg.JWTAudience,
		SkipPaths:    []string{"/health", "/healthz", "/ready", "/api/v1/config", "/config.json"},
	}, logger)
	if err != nil {
		logger.Fatal("Failed to initialize auth middleware", zap.Error(err))
	}

	// Initialize observability telemetry (Prometheus metrics + OTel tracing)
	telemetry, err := observability.New(observability.Config{
		ServiceName:    "aegis",
		ServiceVersion: "1.0.0",
		MetricsEnabled: true,
		TracingEnabled: cfg.TracingEnabled,
		OTLPEndpoint:   cfg.OTLPEndpoint,
		SamplingRate:   cfg.SamplingRate,
	})
	if err != nil {
		logger.Warn("Telemetry init failed, /metrics disabled", zap.Error(err))
	}

	// Initialize health checker
	healthChecker := observability.NewHealthChecker(logger, telemetry)

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

	// Initialize threat intel clients (nil-safe — skip if no API key)
	epssClient := threatintel.NewEPSSClient()
	kevCatalog := threatintel.NewKEVCatalog()
	var greynoiseClient *threatintel.GreyNoiseClient
	if key := os.Getenv("GREYNOISE_API_KEY"); key != "" {
		greynoiseClient = threatintel.NewGreyNoiseClient(key)
		logger.Info("GreyNoise threat intel client initialized")
	}
	var hibpClient *threatintel.HIBPClient
	if key := os.Getenv("HIBP_API_KEY"); key != "" {
		hibpClient = threatintel.NewHIBPClient(key)
		logger.Info("HIBP threat intel client initialized")
	}
	var otxClient *threatintel.OTXClient
	if key := os.Getenv("OTX_API_KEY"); key != "" {
		otxClient = threatintel.NewOTXClient(key)
		logger.Info("OTX threat intel client initialized")
	}
	tiEnricher := threatintel.NewEnricher(epssClient, kevCatalog, greynoiseClient, hibpClient, otxClient, logger.Named("threatintel"))

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

	// Initialize Jira ticket provider when credentials are available
	if jiraURL := os.Getenv("JIRA_URL"); jiraURL != "" {
		jiraCfg := jira.ConfigFromEnv()
		jiraClient, err := jira.NewClient(jiraCfg, logger.Named("jira"))
		if err != nil {
			logger.Warn("Jira client init failed, using mock ticket provider", zap.Error(err))
		} else {
			jiraAdapter := jira.NewAdapter(jiraClient, logger.Named("jira"))
			logger.Info("Jira ticket provider initialized", zap.String("url", jiraURL))
			// Will be wired to integrationHandler below
			_ = jiraAdapter // placeholder — wire when integrationHandler accepts provider injection
		}
	}

	// Initialize PuppyGraph client (feature-flagged — nil when PUPPYGRAPH_URL is empty)
	var graphClient *graph.Client
	if puppyURL := os.Getenv("PUPPYGRAPH_URL"); puppyURL != "" {
		graphClient = graph.NewClient(puppyURL, logger.Named("graph"))
		pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := graphClient.Ping(pingCtx); err != nil {
			logger.Warn("PuppyGraph not reachable, graph queries will fail at runtime", zap.Error(err))
		} else {
			logger.Info("PuppyGraph connected", zap.String("url", puppyURL))
		}
		pingCancel()
	}

	// Load mock data and build O(1) lookup maps via DataStore
	mockData, err := loadMockData(mockDataDir())
	if err != nil {
		logger.Fatal("Failed to load mock data", zap.Error(err))
	}
	dataStore := NewDataStore(mockData)

	// Initialize singleton service instances (created once, shared across requests)
	workflowEngine, err := workflow.NewEngine("memory")
	if err != nil {
		logger.Fatal("Failed to create workflow engine", zap.Error(err))
	}
	wafMgr, err := waf.NewTemplateManager("memory")
	if err != nil {
		logger.Fatal("Failed to create WAF template manager", zap.Error(err))
	}
	containerScnr, err := container.NewScanner(containerScannerProvider())
	if err != nil {
		logger.Fatal("Failed to create container scanner", zap.Error(err))
	}

	// Initialize OPA engine for AI governance (graceful degradation if no policies)
	var opaEngine *opa.Engine
	if engine, err := opa.NewEngine(); err != nil {
		logger.Warn("OPA engine init failed, AI governance disabled", zap.Error(err))
	} else {
		// Attempt to load AI governance policies from policies/ai/
		aiPolicyGlob, _ := filepath.Glob("policies/ai/*.rego")
		if len(aiPolicyGlob) > 0 {
			if err := engine.LoadPolicies(context.Background(), aiPolicyGlob); err != nil {
				logger.Warn("OPA AI policy load failed, governance disabled", zap.Error(err))
			} else {
				opaEngine = engine
				logger.Info("OPA AI governance engine loaded", zap.Int("policies", len(aiPolicyGlob)))
			}
		} else {
			logger.Info("No AI governance policies found in policies/ai/, OPA gate disabled")
		}
	}

	// Initialize tenant store with seed data
	tenantStore := seedTenants(logger)

	// Create server
	srv := &Server{
		config: cfg,
		grcHandler: &GRCHandler{
			provider:    grcProvider,
			logger:      logger.Named("grc"),
			auditLogger: audit.NewZapAuditLogger(logger.Named("audit.grc"), audit.NewMemoryAuditLogger()),
		},
		router:         mux.NewRouter(),
		authMiddleware: authMiddleware,
		rateLimiter:    rateLimiter,
		healthChecker:  healthChecker,
		logger:         logger,
		roles:          &api.RoleEnforcer{DevMode: os.Getenv("APP_ENV") == "development"},
		auditLogger:    audit.NewZapAuditLogger(logger.Named("audit"), audit.NewMemoryAuditLogger()),
		data:           dataStore,
		enrichmentSvc: &EnrichmentService{
			AI:          aiProvider,
			ThreatIntel: tiEnricher,
			Cache:       make(map[string]*FindingEnrichment),
			Logger:      logger.Named("enrichment"),
		},
		opaEngine:        opaEngine,
		telemetry:        telemetry,
		comments:         NewCommentsStore(),
		finopsSvc:        newFinopsService(logger),
		identitySvc:      NewIdentityService(idProviders),
		dedupCache:       ingestion.NewDedupCache(24 * time.Hour),
		workflowEngine:   workflowEngine,
		wafManager:       wafMgr,
		secretsProvider:  secrets.NewMemoryProvider("demo"),
		secretsManager:   secrets.NewManager(logger),
		containerScanner: containerScnr,
		tenantStore:      tenantStore,
		wsServerURL:      cfg.WSServerURL,
		wsPublishKey:     cfg.WSPublishKey,
		wsHTTPClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        20,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		deployTracker: newDeployTracker(),

		// Integration layer
		integrationHandler: &IntegrationHandler{
			provider: integrations.NewMockProvider(logger.Named("integrations.mock")),
			router:   integrations.NewRoutingEngine(integrations.DefaultRules()),
			workflow: workflowEngine,
			auditLogger: audit.NewZapAuditLogger(
				logger.Named("audit.integrations"),
				audit.NewMemoryAuditLogger(),
			),
			logger:            logger.Named("integrations"),
			asanaWebhookToken: os.Getenv("ASANA_WEBHOOK_TOKEN"),
		},
		webhookEngine: webhooks.NewMemoryEngine(logger.Named("webhooks")),
		complianceMgr: compliance.NewManager(logger.Named("compliance")),
		asmSvc:        &asmService{scanner: asm.NewMockScanner()},
		orgScanner:    secrets.NewMockOrgScanner(),
		graphClient:   graphClient,
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

	// Initialize full-text search index (BM25 + TF-IDF embeddings)
	searchSvc, err := NewSearchService(mockData.Findings)
	if err != nil {
		logger.Fatal("Failed to initialize search service", zap.Error(err))
	}
	embedSvc := NewEmbeddingService(mockData.Findings)
	searchSvc.embedSvc = embedSvc
	srv.searchSvc = searchSvc
	logger.Info("Search service initialized",
		zap.Int("indexed_findings", len(mockData.Findings)),
		zap.Int("vocab_size", embedSvc.vocabSize),
	)

	// Compute attack paths from findings
	attackPaths, attackPathStats := computeAttackPaths(mockData.Findings)

	srv.attackPathSvc = &AttackPathService{
		Paths: attackPaths,
		Stats: attackPathStats,
	}
	srv.attackPathSvc.buildPathIndex()

	// Server-scoped context: cancelled on SIGINT/SIGTERM to stop background work.
	serverCtx, serverCancel := context.WithCancel(context.Background())
	defer serverCancel()

	// Start Prometheus system metrics collector (goroutine count, memory usage)
	if telemetry != nil {
		telemetry.StartSystemMetricsCollector(serverCtx)
	}

	// Start background eviction of expired dedup cache entries.
	srv.dedupCache.StartEviction(serverCtx, 5*time.Minute)

	// Start background eviction of stale enrichment cache entries.
	srv.enrichmentSvc.StartEviction(serverCtx, 5*time.Minute)

	// Load KEV catalog asynchronously (non-blocking — first enrich call triggers RefreshIfStale)
	go func() {
		if err := kevCatalog.LoadCatalog(); err != nil {
			logger.Warn("KEV catalog initial load failed (will retry on next enrich)", zap.Error(err))
		} else {
			logger.Info("KEV catalog loaded", zap.Int("entries", kevCatalog.Count()))
		}
	}()

	// Enrich attack paths with AI in the background to avoid blocking startup.
	// Assign attackPathSvc before spawning so HTTP handlers always see the slice.
	// Guard on AI specifically (attack path enrichment requires an LLM, not just threat intel).
	if srv.enrichmentSvc.AI != nil {
		go func() {
			enrichCtx, enrichCancel := context.WithTimeout(serverCtx, 5*time.Minute)
			defer enrichCancel()
			enrichAttackPaths(enrichCtx, srv.enrichmentSvc.AI, srv.attackPathSvc.Paths, &srv.attackPathSvc.Mu, logger)
		}()
	}
	logger.Info("Attack paths computed",
		zap.Int("paths", len(attackPaths)),
		zap.Int("findings_in_paths", attackPathStats.FindingsInPaths),
		zap.Int("isolated", attackPathStats.IsolatedFindings),
	)

	// Register domain health checks so the /health endpoint reports real status
	healthChecker.RegisterCheck(observability.HealthCheck{
		Name:     "workflow",
		Critical: false,
		Timeout:  2 * time.Second,
		Check: func(ctx context.Context) error {
			_, err := srv.workflowEngine.ListWorkflows(ctx)
			return err
		},
	})
	healthChecker.RegisterCheck(observability.HealthCheck{
		Name:     "finops",
		Critical: false,
		Timeout:  2 * time.Second,
		Check: func(ctx context.Context) error {
			_, err := srv.finopsSvc.aggregator.FetchCosts(ctx, time.Now().Add(-time.Minute), time.Now())
			return err
		},
	})

	// Register ws-server health check (non-critical — deploy previews degrade gracefully)
	if cfg.WSServerURL != "" {
		healthChecker.RegisterHTTPCheck("ws-server", cfg.WSServerURL+"/health", false)
	}

	// Start periodic health checks
	healthCtx, healthCancel := context.WithCancel(context.Background())
	defer healthCancel()
	srv.healthChecker.StartPeriodicCheck(healthCtx, 30*time.Second)

	// Setup routes
	srv.setupRoutes()

	// Build middleware chain: gzip -> tracing -> security headers -> router
	var handler http.Handler = srv.router
	handler = srv.securityHeadersMiddleware(handler)
	if telemetry != nil {
		handler = telemetry.HTTPMiddleware()(handler)
	}
	handler = srv.gzipMiddleware(handler)

	// Create HTTP server with middleware chain
	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%s", cfg.Port),
		Handler:           handler,
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

	// Start pprof server in dev mode (loopback only, separate port, default mux)
	if os.Getenv("APP_ENV") == "development" {
		go func() {
			logger.Info("pprof server starting", zap.String("addr", "127.0.0.1:6060"))
			if err := http.ListenAndServe("127.0.0.1:6060", nil); err != nil { //nolint:gosec // G114: dev-only pprof on loopback
				logger.Warn("pprof server error", zap.Error(err))
			}
		}()
	}

	// Start server in goroutine
	go func() {
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			logger.Info("Cloud Aegis API server starting with TLS", zap.String("port", cfg.Port))
			if err := httpServer.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil && err != http.ErrServerClosed {
				logger.Fatal("Server error", zap.Error(err))
			}
		} else {
			logger.Warn("Cloud Aegis API server starting without TLS", zap.String("port", cfg.Port))
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

	// Close search index to release Bleve resources.
	if srv.searchSvc != nil {
		if err := srv.searchSvc.Close(); err != nil {
			logger.Warn("Search service close error", zap.Error(err))
		}
	}

	// Flush remaining trace spans to the collector
	if telemetry != nil {
		if err := telemetry.Shutdown(ctx); err != nil {
			logger.Warn("Telemetry shutdown error", zap.Error(err))
		}
	}

	logger.Info("Server stopped")
}

// seedTenants creates a MemoryStore with default tenants for local dev.
func seedTenants(logger *zap.Logger) tenant.Store {
	store := tenant.NewMemoryStore()

	ctx := context.Background()

	_ = store.Upsert(ctx, &tenant.Config{
		ID:   "contoso",
		Name: "Contoso Inc.",
		Branding: tenant.Branding{
			CompanyName:  "Contoso Inc.",
			ProductName:  "Cloud Aegis",
			LogoPath:     "/logo.svg",
			EmailDomain:  "contoso.com",
			PrimaryColor: "#f59e0b",
			AccentColor:  "#f97316",
		},
		EnabledModules: []string{"cspm", "grc", "finops", "identity", "attack-paths"},
	})

	_ = store.Upsert(ctx, &tenant.Config{
		ID:   "haea",
		Name: "HAEA Security",
		Branding: tenant.Branding{
			CompanyName:  "HAEA Security",
			ProductName:  "SecureCloud",
			LogoPath:     "/haea-logo.svg",
			EmailDomain:  "haea.io",
			PrimaryColor: "#22c55e",
			AccentColor:  "#16a34a",
		},
		EnabledModules: []string{"cspm", "grc", "identity"},
	})

	logger.Info("Tenant store seeded", zap.Int("tenants", 2))
	return store
}
