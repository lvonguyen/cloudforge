// Command server is the Cloud Aegis API server — the primary HTTP entry point
// that registers all route handlers, middleware, and background workers.
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
	"strings"
	"syscall"
	"time"

	"aegis/internal/ai-governance/opa"
	"aegis/internal/api"
	"aegis/internal/api/gateway"
	"aegis/internal/asm"
	"aegis/internal/audit"
	"aegis/internal/compliance"
	"aegis/internal/container"
	"aegis/internal/graph"
	"aegis/internal/grc"
	"aegis/internal/ingestion"
	"aegis/internal/integrations"
	"aegis/internal/observability"
	"aegis/internal/secgraph"
	"aegis/internal/secrets"
	"aegis/internal/tenant"
	"aegis/internal/terminal"
	"aegis/internal/waf"
	"aegis/internal/webhooks"
	"aegis/internal/workflow"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq" // PostgreSQL driver registration
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
	DatabaseURL      string  // PostgreSQL connection string (optional — memory-only if unset)
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
	secretsProvider  secrets.Provider
	secretsManager   *secrets.Manager
	containerScanner container.Scanner

	// Integration layer (Sprint: Integration Stubs)
	integrationHandler *IntegrationHandler
	webhookEngine      webhooks.Engine
	complianceMgr      *compliance.Manager
	secgraphSync       func(context.Context, Finding) error
	asmSvc             *asmService
	orgScanner         secrets.OrgScanner

	// Graph query engine (PuppyGraph — feature-flagged via PUPPYGRAPH_URL)
	graphClient    *graph.Client
	graphQuerier   secgraph.Querier     // structured graph queries (Postgres fallback)
	secgraphIssues secgraph.IssueReader // issue list/detail (Postgres store)

	// Full-text search (BM25 + optional semantic/hybrid)
	searchSvc *SearchService

	// Integrated terminal (WebSocket — operator+ only)
	terminalHandler *terminal.Handler
}

func main() {
	// Initialize logger
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer func() { _ = logger.Sync() }()

	// Load configuration
	cfg, err := loadConfig()
	if err != nil {
		logger.Fatal("Invalid GRC provider", zap.Error(err))
	}

	// Initialize database connection for postgres GRC provider
	grcProvider, grcDB, err := initGRCProvider(cfg, logger)
	if err != nil {
		logger.Fatal("Failed to initialize GRC provider", zap.Error(err))
	}
	if grcDB != nil {
		defer func() {
			if err := grcDB.Close(); err != nil {
				logger.Warn("Failed to close GRC provider database connection", zap.Error(err))
			}
		}()
	}

	// Auto-derive JWKS URL from Okta domain when not explicitly set.
	// This removes the need to manually configure AEGIS_JWKS_URL alongside OKTA_DOMAIN.
	autoDeriveJWKSURL(logger)

	// Initialize authentication middleware
	authMiddleware, err := api.NewAuthMiddleware(api.AuthConfig{
		JWTSecretEnv: cfg.JWTSecretEnv,
		JWKSURLEnv:   "AEGIS_JWKS_URL",
		Issuer:       cfg.JWTIssuer,
		Audience:     cfg.JWTAudience,
		SkipPaths:    []string{"/health", "/healthz", "/ready", "/api/v1/config", "/config.json", "/api/v1/providers"},
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

	aiProvider := initAIProvider(cfg, logger)
	tiEnricher, kevCatalog := initThreatIntelEnricher(logger)

	idProviders, err := initIdentityProviders(logger)
	if err != nil {
		logger.Fatal("Failed to initialize identity providers", zap.Error(err))
	}

	ticketProviders, defaultTicketProvider := buildTicketProviders(logger)
	routingEngine := integrations.NewRoutingEngine(integrations.DefaultRules())

	// Initialize PuppyGraph client (feature-flagged — nil when PUPPYGRAPH_URL is empty)
	graphClient := initGraphClient(logger)

	findingsSource, err := findingsSourceFromEnv()
	if err != nil {
		logger.Fatal("Invalid findings source", zap.Error(err))
	}

	// Initialize singleton service instances (created once, shared across requests)
	workflowEngine, err := initWorkflowEngine()
	if err != nil {
		logger.Fatal("Failed to create workflow engine", zap.Error(err))
	}
	wafMgr, err := initWAFManager()
	if err != nil {
		logger.Fatal("Failed to create WAF template manager", zap.Error(err))
	}
	containerScnr, err := initContainerScanner()
	if err != nil {
		logger.Fatal("Failed to create container scanner", zap.Error(err))
	}

	opaEngine := initOPAEngine(logger)

	finopsAgg, err := initFinopsAggregator(logger)
	if err != nil {
		logger.Fatal("Failed to initialize FinOps aggregator", zap.Error(err))
	}

	secretsProv, err := initSecretsProvider(logger)
	if err != nil {
		logger.Fatal("Failed to initialize secrets provider", zap.Error(err))
	}

	// Initialize tenant store with seed data
	tenantStore := seedTenants(logger)

	auditDB := initAuditDB(cfg, healthChecker, logger)
	if auditDB != nil {
		defer func() {
			if err := auditDB.Close(); err != nil {
				logger.Warn("Failed to close PostgreSQL connection", zap.Error(err))
			}
		}()
	}

	mockData, err := loadRuntimeData(findingsSource, auditDB, logger)
	if err != nil {
		logger.Fatal("Failed to load mock data", zap.Error(err))
	}

	complianceMgr := compliance.NewManager(logger.Named("compliance"))
	secgraphStore := secgraph.NewStore(auditDB)
	secgraphDispatcher := &secgraphTicketDispatcher{
		provider:     defaultTicketProvider,
		router:       routingEngine,
		loader:       sqlSecgraphIssueTicketLoader{db: auditDB},
		autoDispatch: secgraphAutoTicketsEnabled(),
		logger:       logger.Named("secgraph.tickets"),
	}

	// Backfill security graph edges when postgres is available.
	// Populates graph_edges (affects, belongs_to, maps_to, same_region)
	// used by PuppyGraph and future graph-native attack paths (ADR-020).
	if auditDB != nil {
		edgeCtx, edgeCancel := context.WithTimeout(context.Background(), 60*time.Second)
		if bfErr := secgraph.RunEdgeBackfill(edgeCtx, auditDB, logger); bfErr != nil {
			logger.Warn("Edge backfill failed (non-fatal, graph queries may be incomplete)",
				zap.Error(bfErr),
			)
		}
		edgeCancel()
	}

	// Seed controls and materialize issues/evaluations from loaded findings when
	// Postgres is available. This keeps the security graph tables warm for graph
	// queries while the full graph-native pipeline is being phased in.
	if auditDB != nil {
		secgraphCtx, secgraphCancel := context.WithTimeout(context.Background(), 60*time.Second)
		if sgErr := syncSecurityGraph(secgraphCtx, auditDB, complianceMgr, mockData.Findings, defaultTicketProvider, routingEngine, logger.Named("secgraph")); sgErr != nil {
			logger.Warn("Security graph sync failed (non-fatal, issue graph may be incomplete)",
				zap.Error(sgErr),
			)
		}
		secgraphCancel()
	}

	// Build O(1) lookup maps after the final findings source is selected.
	dataStore := NewDataStore(mockData)

	// Build audit logger — composite (postgres primary + memory secondary) when DB is
	// available, memory-only otherwise. Postgres primary ensures List() reads durable,
	// tenant-scoped data; memory secondary provides fast in-process reads for SSE.
	newAuditLogger := func(name string) audit.AuditLogger {
		mem := audit.NewMemoryAuditLogger()
		if auditDB != nil {
			return audit.NewZapAuditLogger(
				logger.Named("audit."+name),
				audit.NewCompositeAuditLogger(audit.NewPostgresAuditLogger(auditDB), mem),
			)
		}
		return audit.NewZapAuditLogger(logger.Named("audit."+name), mem)
	}

	// Create server
	srv := &Server{
		config: cfg,
		grcHandler: &GRCHandler{
			provider:    grcProvider,
			logger:      logger.Named("grc"),
			auditLogger: newAuditLogger("grc"),
		},
		router:         mux.NewRouter(),
		authMiddleware: authMiddleware,
		rateLimiter:    rateLimiter,
		healthChecker:  healthChecker,
		logger:         logger,
		roles:          &api.RoleEnforcer{DevMode: os.Getenv("APP_ENV") == "development"},
		auditLogger:    newAuditLogger("server"),
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
		finopsSvc:        newFinopsServiceFromAggregator(finopsAgg, defaultBudgetRules()),
		identitySvc:      NewIdentityService(idProviders),
		dedupCache:       ingestion.NewDedupCache(24 * time.Hour),
		workflowEngine:   workflowEngine,
		wafManager:       wafMgr,
		secretsProvider:  secretsProv,
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

		// Integration layer — real providers when env vars are set, mock fallback
		integrationHandler: &IntegrationHandler{
			provider:          defaultTicketProvider,
			providers:         ticketProviders,
			router:            routingEngine,
			workflow:          workflowEngine,
			auditLogger:       newAuditLogger("integrations"),
			logger:            logger.Named("integrations"),
			ticketStore:       make(map[string]*integrations.Ticket),
			asanaWebhookToken: os.Getenv("ASANA_WEBHOOK_TOKEN"),
		},
		webhookEngine: webhooks.NewMemoryEngine(logger.Named("webhooks")),
		complianceMgr: complianceMgr,
		secgraphSync: func(ctx context.Context, finding Finding) error {
			if auditDB == nil {
				return nil
			}
			adjacency, _ := loadSecgraphAdjacency(ctx, auditDB, logger.Named("secgraph.incremental"))
			return syncSecurityGraphWithStoreAndDispatcherMode(
				ctx,
				secgraphStore,
				complianceMgr,
				[]Finding{finding},
				defaultSecgraphTenantID,
				time.Now().UTC(),
				secgraphDispatcher,
				logger.Named("secgraph.incremental"),
				false,
				adjacency,
			)
		},
		asmSvc:         &asmService{scanner: asm.NewMockScanner()},
		orgScanner:     secrets.NewMockOrgScanner(),
		graphClient:    graphClient,
		graphQuerier:   initGraphQuerier(auditDB),
		secgraphIssues: secgraphStore,
	}

	logger.Info("Server data loaded",
		zap.String("findings_source", findingsSource),
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

	// Integrated terminal (WebSocket — operator+ only)
	var termOrigins []string
	if cfg.CORSOrigins != "" {
		termOrigins = strings.Split(cfg.CORSOrigins, ",")
	}
	srv.terminalHandler = terminal.NewHandler(authMiddleware, newAuditLogger("terminal"), logger.Named("terminal"), srv.roles.DevMode, termOrigins...)

	// Load adjacency set from graph_edges for evidence-based attack paths (ADR-020 Phase 2).
	// Returns nil when no DB is available — computeAttackPaths falls back to heuristic.
	var attackAdj *secgraph.AdjacencySet
	if auditDB != nil {
		adjCtx, adjCancel := context.WithTimeout(context.Background(), 15*time.Second)
		if loaded, adjErr := secgraph.LoadAdjacencyFromDB(adjCtx, auditDB); adjErr != nil {
			logger.Warn("Failed to load graph adjacency (using heuristic fallback)", zap.Error(adjErr))
		} else if loaded != nil {
			attackAdj = loaded
			logger.Info("Graph adjacency loaded for attack paths", zap.Int("edges", loaded.Size()))
		}
		adjCancel()
	}

	// Compute attack paths from findings
	attackPaths, attackPathStats := computeAttackPaths(mockData.Findings, attackAdj)

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

	// Build middleware chain: gzip -> tracing -> security headers -> CORS -> router
	//
	// CORS wraps the router directly so that OPTIONS preflight requests are
	// handled before gorilla/mux route matching (mux middleware only runs for
	// matched routes, so preflight to a GET-only route would 405).
	var handler http.Handler = srv.router
	if cfg.CORSOrigins != "" {
		origins := strings.Split(cfg.CORSOrigins, ",")
		handler = api.CORSMiddleware(origins, srv.roles.DevMode)(handler)
	}
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
