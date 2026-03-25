package main

import (
	"net/http"
	"strings"

	"aegis/internal/api"
	"aegis/internal/tenant"
)

// scopeGuarded wraps a handler with ScopeGuard middleware, blocking scoped
// users from endpoints that lack per-resource scope filtering. Apply to all
// data-returning endpoints that serve account/tenant-scoped resources.
// Exempt: endpoints with inline EnforceScope, global reference data, admin-only.
func scopeGuarded(h http.Handler) http.Handler {
	return api.ScopeGuard()(h)
}

func (s *Server) setupRoutes() {
	// NOTE: CORS middleware is applied in the outer handler chain (main.go)
	// rather than via s.router.Use(), because gorilla/mux middleware only
	// runs for matched routes — OPTIONS preflight requests would 405 before
	// the middleware fires.

	// Health check endpoints (unauthenticated - skipped by middleware)
	s.router.HandleFunc("/health", s.healthChecker.HealthHandler()).Methods("GET")
	s.router.HandleFunc("/healthz", s.healthChecker.LivenessHandler()).Methods("GET")
	s.router.HandleFunc("/ready", s.healthChecker.ReadinessHandler()).Methods("GET")

	// Prometheus metrics endpoint (unauthenticated — for scraper access)
	if s.telemetry != nil {
		s.router.Handle("/metrics", s.telemetry.MetricsHandler()).Methods("GET")
	}

	// Provider status endpoint (unauthenticated — operators need to verify deployment config)
	s.router.HandleFunc("/api/v1/providers", s.handleProviderStatus).Methods("GET")

	// Tenant config endpoint (unauthenticated — must load before auth)
	s.router.HandleFunc("/api/v1/config", s.handleConfig).Methods("GET")
	s.router.HandleFunc("/config.json", s.handleConfig).Methods("GET")

	// API v1 routes with authentication and rate limiting middleware.
	// Auth runs first so that:
	//   1. Unauthenticated requests are rejected before consuming rate limit budget.
	//   2. Rate limits can be keyed on the verified identity (JWT subject) rather than IP.
	apiRouter := s.router.PathPrefix("/api/v1").Subrouter()

	// Apply authentication middleware first
	apiRouter.Use(s.authMiddleware.Middleware)

	// Tenant resolution AFTER auth — JWT claims must be in context before
	// middleware can extract tenant_id from the token.
	if s.tenantStore != nil {
		apiRouter.Use(tenant.Middleware(s.tenantStore, s.logger))
	}

	// Apply rate limiting after auth (identity is now available in context)
	if s.rateLimiter != nil {
		apiRouter.Use(s.rateLimiter.Middleware(s.getTierFromRequest, s.getClientIDFromRequest))
	}

	// Exception read endpoints — require operator or admin
	// Literal paths registered before parameterized to prevent /{id} shadowing.
	apiRouter.Handle("/exceptions/pending", // operator, admin
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.grcHandler.GetPendingApprovals)),
	).Methods("GET")
	apiRouter.Handle("/exceptions/expiring", // operator, admin
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.grcHandler.GetExpiringExceptions)),
	).Methods("GET")
	apiRouter.Handle("/exceptions/mine", // requester, operator, admin
		s.roles.Require(api.RoleViewer, api.RoleRequester, api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.grcHandler.GetMyExceptions)),
	).Methods("GET")
	apiRouter.Handle("/exceptions/{id}/withdraw", // requester, operator, admin
		s.roles.Require(api.RoleRequester, api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.grcHandler.WithdrawException)),
	).Methods("POST")
	apiRouter.Handle("/exceptions/{id}", // operator, admin
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.grcHandler.GetException)),
	).Methods("GET")
	apiRouter.Handle("/applications/{appId}/exceptions", // operator, admin
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.grcHandler.GetExceptionsByApp)),
	).Methods("GET")

	// Exception write endpoints — require admin
	apiRouter.Handle("/exceptions", // operator, admin
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.grcHandler.CreateException)),
	).Methods("POST")
	apiRouter.Handle("/exceptions/{id}/approve", // admin only
		s.roles.Require(api.RoleAdmin)(http.HandlerFunc(s.grcHandler.SubmitApproval)),
	).Methods("POST")

	// Policy validation — require operator or admin
	apiRouter.Handle("/validate/exception", // operator, admin
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.grcHandler.ValidateException)),
	).Methods("POST")

	// Findings — static routes before parameterized {id} to avoid gorilla/mux shadowing
	apiRouter.Handle("/findings",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.listFindings)),
	).Methods("GET")
	apiRouter.Handle("/findings/stats",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.findingsStats)),
	).Methods("GET")
	apiRouter.Handle("/findings/query",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.queryFindings)),
	).Methods("GET")
	apiRouter.Handle("/findings/search", // operator, admin — BM25 + hybrid search
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.searchFindings)),
	).Methods("POST")
	apiRouter.Handle("/findings/ingest", // admin only
		s.roles.Require(api.RoleAdmin)(http.HandlerFunc(s.ingestFinding)),
	).Methods("POST")
	apiRouter.Handle("/findings/{id}/enrich", // operator, admin
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.enrichFinding)),
	).Methods("POST")
	apiRouter.Handle("/findings/{id}",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.getFinding)),
	).Methods("GET")

	// Finding comments — scope-guarded (comments inherit finding scope)
	apiRouter.Handle("/findings/{id}/comments",
		s.roles.Require(api.RoleViewer, api.RoleRequester, api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.listComments))),
	).Methods("GET")
	apiRouter.Handle("/findings/{id}/comments", // operator, admin — scope-guarded
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.addComment))),
	).Methods("POST")
	apiRouter.Handle("/findings/{id}/comments/{commentId}", // admin only — scope-guarded
		s.roles.Require(api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.deleteComment))),
	).Methods("DELETE")

	// Compliance (viewer can see frameworks read-only)
	apiRouter.Handle("/compliance/frameworks",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.listFrameworks)),
	).Methods("GET")

	// Agents — scope-guarded (agents may be account-scoped)
	apiRouter.Handle("/agents",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.listAgents))),
	).Methods("GET")
	apiRouter.Handle("/agents/{id}",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.getAgent))),
	).Methods("GET")

	// Costs — scope-guarded (aggregates cross-account cost data)
	apiRouter.Handle("/costs/summary",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.getCostSummaryComputed))),
	).Methods("GET")

	// Remediations — scope-guarded (tied to account-scoped findings)
	apiRouter.Handle("/remediations",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.listRemediations))),
	).Methods("GET")
	apiRouter.Handle("/remediations/{id}/execute", // operator, admin
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.executeRemediation))),
	).Methods("POST")
	apiRouter.Handle("/remediations/{id}",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.getRemediation))),
	).Methods("GET")
	apiRouter.Handle("/remediations/{id}", // operator, admin
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.patchRemediation))),
	).Methods("PATCH")

	// Agent traces — scope-guarded
	apiRouter.Handle("/agents/{id}/traces",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.listAgentTraces))),
	).Methods("GET")

	// Audit log — admin only
	apiRouter.Handle("/audit-log",
		s.roles.Require(api.RoleAdmin)(http.HandlerFunc(s.listAuditLog)),
	).Methods("GET")

	// Users — admin only
	apiRouter.Handle("/users",
		s.roles.Require(api.RoleAdmin)(http.HandlerFunc(s.listUsers)),
	).Methods("GET")

	// Catalog
	apiRouter.Handle("/catalog/modules",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.listCatalogModules)),
	).Methods("GET")

	// Policies
	apiRouter.Handle("/policies",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.listPolicies)),
	).Methods("GET")
	apiRouter.Handle("/policies/{id}",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.getPolicy)),
	).Methods("GET")

	// Attack paths (delegated to AttackPathService)
	apiRouter.Handle("/attack-paths",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.attackPathSvc.listAttackPaths)),
	).Methods("GET")
	apiRouter.Handle("/attack-paths/stats",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.attackPathSvc.getAttackPathStats)),
	).Methods("GET")
	apiRouter.Handle("/attack-paths/{id}/analysis",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.getAttackPathAnalysis)),
	).Methods("GET")
	apiRouter.Handle("/attack-paths/{id}",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.attackPathSvc.getAttackPath)),
	).Methods("GET")

	// Graph query proxy (PuppyGraph — feature-flagged via PUPPYGRAPH_URL)
	// Scope-guarded: graph traversals can reach cross-account data.
	apiRouter.Handle("/graph/query", // operator, admin
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.handleGraphQuery))),
	).Methods("POST")

	// Data classification (DSPM) — scope-guarded (account-scoped assets)
	apiRouter.Handle("/data-classification/assets",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.listDataClassificationAssets))),
	).Methods("GET")

	// Container security — scope-guarded (account/cluster-scoped)
	apiRouter.Handle("/containers",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.listContainers))),
	).Methods("GET")
	apiRouter.Handle("/containers/{id}",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.getContainer))),
	).Methods("GET")
	apiRouter.Handle("/container/scan", // operator, admin
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.scanContainer))),
	).Methods("GET")
	apiRouter.Handle("/container/admission", // operator, admin
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.checkAdmission))),
	).Methods("GET")

	// Secrets management — scope-guarded (account-scoped secrets)
	apiRouter.Handle("/secrets",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.listSecrets))),
	).Methods("GET")
	apiRouter.Handle("/secrets/scan", // operator, admin
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.scanSecrets))),
	).Methods("POST")
	apiRouter.Handle("/secrets/{path:.*}",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.getSecret))),
	).Methods("GET")

	// WAF templates
	apiRouter.Handle("/waf/templates",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.listWAFTemplates)),
	).Methods("GET")
	apiRouter.Handle("/waf/compliance/{templateId}",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.validateWAFCompliance)),
	).Methods("GET")

	// Identity & Zero Trust — scope-guarded (identity data is tenant-scoped)
	apiRouter.Handle("/identity/users",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.listIdentityUsers))),
	).Methods("GET")
	apiRouter.Handle("/identity/users/{id}/risk",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.getIdentityUserRisk))),
	).Methods("GET")

	// NLQ (natural language query) — operator, admin; scope-guarded (queries data across accounts)
	apiRouter.Handle("/ai/nlq",
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.queryNLQ))),
	).Methods("POST")

	// AI usage/budget status — admin only
	apiRouter.Handle("/ai/usage",
		s.roles.Require(api.RoleAdmin)(http.HandlerFunc(s.getAIUsage)),
	).Methods("GET")

	// Deploy preview (operator + admin)
	apiRouter.Handle("/deploy/preview",
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.startDeployPreview)),
	).Methods("POST")
	apiRouter.Handle("/deploy/preview/{id}/abort",
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.abortDeployPreview)),
	).Methods("POST")

	// Workflow orchestration — scope-guarded (workflows tied to account resources)
	apiRouter.Handle("/workflows",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.listWorkflows))),
	).Methods("GET")
	apiRouter.Handle("/workflows/{id}",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.getWorkflow))),
	).Methods("GET")
	apiRouter.Handle("/workflows/{id}/approve", // admin only — scope-guarded
		s.roles.Require(api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.approveWorkflow))),
	).Methods("POST")

	// --- Integration layer routes ---

	// Remediation ticket routing (IntegrationHandler)
	apiRouter.Handle("/findings/{id}/remediate", // operator, admin — scope-guarded
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.integrationHandler.RemediateFinding))),
	).Methods("POST")
	apiRouter.Handle("/findings/{id}/ticket/comments",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.integrationHandler.GetTicketComments))),
	).Methods("GET")
	apiRouter.Handle("/findings/{id}/ticket/comments", // operator, admin
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.integrationHandler.AddTicketComment))),
	).Methods("POST")
	apiRouter.Handle("/findings/{id}/ticket/sync", // operator, admin — force-refresh status
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.integrationHandler.SyncTicketStatus))),
	).Methods("POST")
	apiRouter.Handle("/findings/{id}/ticket",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.integrationHandler.GetFindingTicket))),
	).Methods("GET")

	// Webhook management
	apiRouter.Handle("/webhooks", // admin only
		s.roles.Require(api.RoleAdmin)(http.HandlerFunc(s.registerWebhook)),
	).Methods("POST")
	apiRouter.Handle("/webhooks", // operator, admin
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.listWebhooks)),
	).Methods("GET")
	apiRouter.Handle("/webhooks/{id}", // admin only
		s.roles.Require(api.RoleAdmin)(http.HandlerFunc(s.deleteWebhook)),
	).Methods("DELETE")
	apiRouter.Handle("/webhooks/{id}/deliveries",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.listWebhookDeliveries))),
	).Methods("GET")

	// Compliance posture — scope-guarded (aggregates account-level compliance)
	apiRouter.Handle("/compliance/posture",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.getCompliancePosture))),
	).Methods("GET")
	apiRouter.Handle("/compliance/controls/{fw}",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.getComplianceControls))),
	).Methods("GET")

	// ASM scanning — scope-guarded (account-scoped external assets)
	apiRouter.Handle("/asm/scan", // operator, admin
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.handleASMScan))),
	).Methods("POST")
	apiRouter.Handle("/asm/assets",
		s.roles.Require(api.RoleViewer, api.RoleOperator, api.RoleAdmin)(scopeGuarded(http.HandlerFunc(s.handleASMAssets))),
	).Methods("GET")

	// Secrets org-wide scanning
	apiRouter.Handle("/secrets/org-scan", // admin only
		s.roles.Require(api.RoleAdmin)(http.HandlerFunc(s.handleOrgScan)),
	).Methods("POST")

	// Asana webhook (unauthenticated handshake, HMAC-verified events)
	s.router.HandleFunc("/api/v1/webhooks/asana", s.integrationHandler.AsanaWebhook).Methods("POST")
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
