package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aegis/internal/ai"
	"aegis/internal/ai-governance/opa"
	"aegis/internal/container"
	"aegis/internal/cspm/threatintel"
	"aegis/internal/finops"
	"aegis/internal/finops/aggregator"
	"aegis/internal/finops/alerting"
	"aegis/internal/graph"
	"aegis/internal/grc"
	"aegis/internal/identity"
	"aegis/internal/integrations"
	"aegis/internal/integrations/ado"
	"aegis/internal/integrations/asana"
	"aegis/internal/integrations/jira"
	"aegis/internal/observability"
	"aegis/internal/secgraph"
	"aegis/internal/secrets"
	"aegis/internal/tenant"
	"aegis/internal/waf"
	"aegis/internal/workflow"

	"go.uber.org/zap"
)

func loadConfig() (Config, error) {
	providerType, err := grc.ProviderFromString(getEnv("GRC_PROVIDER", "memory"))
	if err != nil {
		return Config{}, err
	}

	return Config{
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
		DatabaseURL:      os.Getenv("AEGIS_DATABASE_URL"),
	}, nil
}

func initGRCProvider(cfg Config, logger *zap.Logger) (grc.GRCProvider, *sql.DB, error) {
	var grcDB *sql.DB
	if cfg.GRCProvider == grc.ProviderTypePostgres {
		if cfg.DatabaseURL == "" {
			return nil, nil, fmt.Errorf("AEGIS_DATABASE_URL required when GRC_PROVIDER=postgres")
		}

		var err error
		grcDB, err = sql.Open("postgres", cfg.DatabaseURL)
		if err != nil {
			return nil, nil, fmt.Errorf("opening database connection: %w", err)
		}
		if pingErr := grcDB.Ping(); pingErr != nil {
			_ = grcDB.Close()
			return nil, nil, fmt.Errorf("database ping failed: %w", pingErr)
		}

		if dbURL, parseErr := url.Parse(cfg.DatabaseURL); parseErr == nil {
			logger.Info("Database connection established for GRC provider",
				zap.String("host", dbURL.Hostname()+":"+dbURL.Port()))
		} else {
			logger.Info("Database connection established for GRC provider",
				zap.String("host", "<unparseable>"))
		}
	}

	grcProvider, err := grc.NewProvider(grc.Config{
		Type:     cfg.GRCProvider,
		Postgres: grcDB,
	})
	if err != nil {
		if grcDB != nil {
			_ = grcDB.Close()
		}
		return nil, nil, err
	}

	return grcProvider, grcDB, nil
}

func autoDeriveJWKSURL(logger *zap.Logger) {
	if domain := os.Getenv("OKTA_DOMAIN"); domain != "" && os.Getenv("AEGIS_JWKS_URL") == "" {
		jwksURL := "https://" + domain + "/oauth2/default/v1/keys"
		os.Setenv("AEGIS_JWKS_URL", jwksURL)
		logger.Info("Auto-derived JWKS URL from OKTA_DOMAIN", zap.String("jwks_url", jwksURL))
	}
}

func initAIProvider(cfg Config, logger *zap.Logger) ai.Provider {
	if !cfg.AIEnabled {
		return nil
	}

	bp, err := ai.NewBedrockProvider(cfg.AIRegion, cfg.AIModel)
	if err != nil {
		logger.Warn("AI provider init failed, enrichment disabled", zap.Error(err))
		return nil
	}

	pingCtx, pingCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer pingCancel()

	if _, err := bp.Complete(pingCtx, "ping"); err != nil {
		logger.Warn("Bedrock credential validation failed, enrichment disabled",
			zap.Error(err),
			zap.String("region", cfg.AIRegion),
		)
		return nil
	}

	logger.Info("AI provider initialized",
		zap.String("region", cfg.AIRegion),
		zap.String("model", bp.ModelID()),
	)
	return bp
}

func initThreatIntelEnricher(logger *zap.Logger) (*threatintel.Enricher, *threatintel.KEVCatalog) {
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

	return threatintel.NewEnricher(epssClient, kevCatalog, greynoiseClient, hibpClient, otxClient, logger.Named("threatintel")), kevCatalog
}

func initIdentityProviders(logger *zap.Logger) (map[string]identity.Provider, error) {
	idProviders, err := identity.NewProviders(buildIdentityConfigs(logger))
	if err != nil {
		return nil, err
	}

	for name := range idProviders {
		logger.Info("Identity provider initialized", zap.String("provider", name))
	}

	return idProviders, nil
}

func buildTicketProviders(logger *zap.Logger) (map[string]integrations.TicketProvider, integrations.TicketProvider) {
	ticketProviders := make(map[string]integrations.TicketProvider)
	var defaultTicketProvider integrations.TicketProvider

	if pat := os.Getenv("ASANA_PAT"); pat != "" {
		asanaCfg := asana.ConfigFromEnv()
		asanaClient, err := asana.NewClient(asanaCfg, logger.Named("asana"))
		if err != nil {
			logger.Warn("Asana client init failed", zap.Error(err))
		} else {
			asanaAdapter := asana.NewAdapter(asanaClient, logger.Named("asana"))
			ticketProviders["asana"] = asanaAdapter
			defaultTicketProvider = asanaAdapter
			logger.Info("Asana ticket provider initialized",
				zap.String("workspace", asanaCfg.WorkspaceGID),
				zap.String("project", asanaCfg.DefaultProjectID),
			)
		}
	}

	if jiraURL := os.Getenv("JIRA_URL"); jiraURL != "" {
		jiraCfg := jira.ConfigFromEnv()
		jiraClient, err := jira.NewClient(jiraCfg, logger.Named("jira"))
		if err != nil {
			logger.Warn("Jira client init failed", zap.Error(err))
		} else {
			jiraAdapter := jira.NewAdapter(jiraClient, logger.Named("jira"))
			ticketProviders["jira"] = jiraAdapter
			if defaultTicketProvider == nil {
				defaultTicketProvider = jiraAdapter
			}
			logger.Info("Jira ticket provider initialized", zap.String("url", jiraURL))
		}
	}

	if adoURL := os.Getenv("ADO_ORG_URL"); adoURL != "" {
		adoCfg := ado.ConfigFromEnv()
		adoClient, err := ado.NewClient(adoCfg, logger.Named("ado"))
		if err != nil {
			logger.Warn("ADO client init failed", zap.Error(err))
		} else {
			adoAdapter := ado.NewAdapter(adoClient, logger.Named("ado"))
			ticketProviders["ado"] = adoAdapter
			if defaultTicketProvider == nil {
				defaultTicketProvider = adoAdapter
			}
			logger.Info("ADO ticket provider initialized", zap.String("url", adoURL), zap.String("project", adoCfg.Project))
		}
	}

	mockProvider := integrations.NewMockProvider(logger.Named("integrations.mock"))
	ticketProviders["mock"] = mockProvider
	if defaultTicketProvider == nil {
		defaultTicketProvider = mockProvider
	}

	logger.Info("Ticket providers initialized",
		zap.Int("count", len(ticketProviders)),
		zap.String("default", defaultTicketProvider.Name()),
	)

	return ticketProviders, defaultTicketProvider
}

func initGraphClient(logger *zap.Logger) *graph.Client {
	puppyURL := os.Getenv("PUPPYGRAPH_URL")
	if puppyURL == "" {
		return nil
	}

	graphClient := graph.NewClient(puppyURL, logger.Named("graph"))
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer pingCancel()

	if err := graphClient.Ping(pingCtx); err != nil {
		logger.Warn("PuppyGraph not reachable, graph queries will fail at runtime", zap.Error(err))
	} else {
		logger.Info("PuppyGraph connected", zap.String("url", puppyURL))
	}

	return graphClient
}

func findingsSourceFromEnv() (string, error) {
	findingsSource := strings.ToLower(getEnv("FINDINGS_SOURCE", "mock"))
	switch findingsSource {
	case "mock", "postgres":
		return findingsSource, nil
	default:
		return "", fmt.Errorf("invalid findings source: %s", findingsSource)
	}
}

func initWorkflowEngine() (workflow.Engine, error) {
	workflowProvider, err := workflow.ProviderFromString(getEnv("WORKFLOW_ENGINE", "memory"))
	if err != nil {
		return nil, fmt.Errorf("invalid workflow engine provider: %w", err)
	}
	return workflow.NewEngine(workflowProvider)
}

func initWAFManager() (waf.TemplateManager, error) {
	wafProvider, err := waf.ProviderFromString(getEnv("WAF_PROVIDER", "memory"))
	if err != nil {
		return nil, fmt.Errorf("invalid WAF provider: %w", err)
	}
	return waf.NewTemplateManager(wafProvider)
}

func initContainerScanner() (container.Scanner, error) {
	containerType, err := container.ProviderFromString(getEnv("CONTAINER_SCANNER", "memory"))
	if err != nil {
		return nil, fmt.Errorf("invalid container scanner provider: %w", err)
	}
	return container.NewScannerFromConfig(container.ScannerConfig{Type: containerType})
}

func initOPAEngine(logger *zap.Logger) *opa.Engine {
	engine, err := opa.NewEngine()
	if err != nil {
		logger.Warn("OPA engine init failed, AI governance disabled", zap.Error(err))
		return nil
	}

	aiPolicyGlob, _ := filepath.Glob("policies/ai/*.rego")
	if len(aiPolicyGlob) == 0 {
		logger.Info("No AI governance policies found in policies/ai/, OPA gate disabled")
		return nil
	}

	if err := engine.LoadPolicies(context.Background(), aiPolicyGlob); err != nil {
		logger.Warn("OPA AI policy load failed, governance disabled", zap.Error(err))
		return nil
	}

	logger.Info("OPA AI governance engine loaded", zap.Int("policies", len(aiPolicyGlob)))
	return engine
}

func initFinopsAggregator(logger *zap.Logger) (finops.Aggregator, error) {
	finopsType, err := finops.ProviderFromString(getEnv("FINOPS_PROVIDER", "memory"))
	if err != nil {
		return nil, fmt.Errorf("invalid FinOps provider: %w", err)
	}

	if finopsType == finops.ProviderTypeMulti {
		providers := map[string]finops.Aggregator{
			"azure": finops.NewMemoryAggregator(),
			"gcp":   finops.NewMemoryAggregator(),
		}

		awsRegion := getEnv("FINOPS_AWS_REGION", "us-east-1")
		if awsAgg, awsErr := finops.NewAWSAggregator(awsRegion, logger.Named("finops.aws")); awsErr == nil {
			providers["aws"] = awsAgg
		} else {
			logger.Warn("AWS aggregator unavailable, using memory", zap.Error(awsErr))
			providers["aws"] = finops.NewMemoryAggregator()
		}
		return aggregator.NewMultiCloudAggregator(providers), nil
	}

	return finops.NewAggregator(finops.AggregatorConfig{
		Type:      finopsType,
		AWSRegion: getEnv("FINOPS_AWS_REGION", "us-east-1"),
		Logger:    logger.Named("finops"),
	})
}

func initSecretsProvider(logger *zap.Logger) (secrets.Provider, error) {
	secretsType, err := secrets.ProviderFromString(getEnv("SECRETS_PROVIDER", "memory"))
	if err != nil {
		return nil, fmt.Errorf("invalid secrets provider: %w", err)
	}

	return secrets.NewProviderFromConfig(secrets.ProviderConfig{
		Type:     secretsType,
		Region:   getEnv("SECRETS_AWS_REGION", getEnv("AWS_REGION", "")),
		VaultURL: getEnv("SECRETS_AZURE_KEY_VAULT_URL", ""),
		Project:  getEnv("SECRETS_GCP_PROJECT_ID", ""),
		Logger:   logger.Named("secrets"),
	})
}

func initAuditDB(cfg Config, healthChecker *observability.HealthChecker, logger *zap.Logger) *sql.DB {
	if cfg.DatabaseURL == "" {
		logger.Info("AEGIS_DATABASE_URL not set, audit will use memory-only")
		return nil
	}

	auditDB, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		logger.Warn("PostgreSQL connection failed, audit will use memory-only",
			zap.Error(err),
		)
		return nil
	}

	auditDB.SetMaxOpenConns(10)
	auditDB.SetMaxIdleConns(5)
	auditDB.SetConnMaxLifetime(5 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := auditDB.PingContext(ctx); err != nil {
		logger.Warn("PostgreSQL ping failed, audit will use memory-only",
			zap.Error(err),
		)
		_ = auditDB.Close()
		return nil
	}

	healthChecker.RegisterDatabaseCheck("postgres", auditDB)
	logger.Info("PostgreSQL connected for durable audit logging")
	return auditDB
}

func loadRuntimeData(findingsSource string, auditDB *sql.DB, logger *zap.Logger) (*MockData, error) {
	mockData, err := loadMockData(mockDataDir())
	if err != nil {
		return nil, err
	}

	if findingsSource != "postgres" {
		logger.Info("Findings loaded from mock JSON", zap.Int("findings", len(mockData.Findings)))
		return mockData, nil
	}

	if auditDB == nil {
		return nil, fmt.Errorf("FINDINGS_SOURCE=postgres requires AEGIS_DATABASE_URL and a reachable PostgreSQL instance")
	}

	findingsCtx, findingsCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer findingsCancel()

	findings, err := loadFindingsFromPostgres(findingsCtx, auditDB)
	if err != nil {
		return nil, err
	}

	mockData.Findings = findings
	logger.Info("Findings loaded from PostgreSQL", zap.Int("findings", len(findings)))
	return mockData, nil
}

func defaultBudgetRules() []alerting.BudgetRule {
	return []alerting.BudgetRule{
		{Name: "AWS Monthly", Provider: "aws", MonthlyUSD: 5000, Thresholds: []float64{80, 100, 120}},
		{Name: "Azure Monthly", Provider: "azure", MonthlyUSD: 3000, Thresholds: []float64{80, 100, 120}},
		{Name: "GCP Monthly", Provider: "gcp", MonthlyUSD: 2000, Thresholds: []float64{80, 100, 120}},
	}
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

// buildIdentityConfigs determines which identity providers to create based on
// available environment variables. Real providers are used when credentials are
// present; mock providers are used otherwise (graceful degradation).
func buildIdentityConfigs(logger *zap.Logger) []identity.Config {
	var cfgs []identity.Config

	if domain := os.Getenv("OKTA_DOMAIN"); domain != "" {
		cfgs = append(cfgs, identity.Config{
			Type:   identity.ProviderTypeOkta,
			Okta:   &identity.OktaConfig{Domain: domain, APITokenEnv: "OKTA_API_TOKEN"},
			Logger: logger,
		})
	} else {
		cfgs = append(cfgs, identity.Config{Type: identity.ProviderTypeMockOkta, Logger: logger})
	}

	if os.Getenv("ENTRA_TENANT_ID") != "" {
		cfgs = append(cfgs, identity.Config{
			Type: identity.ProviderTypeEntraID,
			EntraID: &identity.EntraIDConfig{
				TenantIDEnv:     "ENTRA_TENANT_ID",
				ClientIDEnv:     "ENTRA_CLIENT_ID",
				ClientSecretEnv: "ENTRA_CLIENT_SECRET",
			},
			Logger: logger,
		})
	} else {
		cfgs = append(cfgs, identity.Config{Type: identity.ProviderTypeMockEntra, Logger: logger})
	}

	return cfgs
}

// initGraphQuerier creates a structured graph querier. When postgres is
// available the querier runs CTEs over graph_edges; otherwise returns nil
// and the handlers return 501.
func initGraphQuerier(db *sql.DB) secgraph.Querier {
	if db == nil {
		return nil
	}
	return secgraph.NewPostgresQuerier(db)
}
