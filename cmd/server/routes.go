package main

import (
	"net/http"
	"strings"

	"cloudforge/internal/api"
	"cloudforge/internal/tenant"
)

func (s *Server) setupRoutes() {
	// CORS middleware — applied to all routes (including health for browser fetch).
	if s.config.CORSOrigins != "" {
		origins := strings.Split(s.config.CORSOrigins, ",")
		s.router.Use(api.CORSMiddleware(origins, s.roles.DevMode))
	}

	// Tenant resolution middleware — resolves tenant from JWT, header, or subdomain.
	if s.tenantStore != nil {
		s.router.Use(tenant.Middleware(s.tenantStore, s.logger))
	}

	// Health check endpoints (unauthenticated - skipped by middleware)
	s.router.HandleFunc("/health", s.healthChecker.HealthHandler()).Methods("GET")
	s.router.HandleFunc("/healthz", s.healthChecker.LivenessHandler()).Methods("GET")
	s.router.HandleFunc("/ready", s.healthChecker.ReadinessHandler()).Methods("GET")

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

	// Apply rate limiting after auth (identity is now available in context)
	if s.rateLimiter != nil {
		apiRouter.Use(s.rateLimiter.Middleware(s.getTierFromRequest, s.getClientIDFromRequest))
	}

	// Exception read endpoints — require operator or admin
	// Literal paths registered before parameterized to prevent /{id} shadowing.
	apiRouter.Handle("/exceptions/pending", // operator, admin
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.getPendingApprovals)),
	).Methods("GET")
	apiRouter.Handle("/exceptions/expiring", // operator, admin
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.getExpiringExceptions)),
	).Methods("GET")
	apiRouter.Handle("/exceptions/mine", // requester, operator, admin
		s.roles.Require(api.RoleRequester, api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.getMyExceptions)),
	).Methods("GET")
	apiRouter.Handle("/exceptions/{id}", // operator, admin
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.getException)),
	).Methods("GET")
	apiRouter.Handle("/applications/{appId}/exceptions", // operator, admin
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.getExceptionsByApp)),
	).Methods("GET")

	// Exception write endpoints — require admin
	apiRouter.Handle("/exceptions", // admin only
		s.roles.Require(api.RoleAdmin)(http.HandlerFunc(s.createException)),
	).Methods("POST")
	apiRouter.Handle("/exceptions/{id}/approve", // admin only
		s.roles.Require(api.RoleAdmin)(http.HandlerFunc(s.submitApproval)),
	).Methods("POST")

	// Policy validation — require operator or admin
	apiRouter.Handle("/validate/exception", // operator, admin
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.validateException)),
	).Methods("POST")

	// Findings — read endpoints
	apiRouter.Handle("/findings",
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.listFindings)),
	).Methods("GET")
	apiRouter.Handle("/findings/{id}/enrich",
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.enrichFinding)),
	).Methods("POST")
	apiRouter.Handle("/findings/{id}",
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.getFinding)),
	).Methods("GET")

	// Compliance
	apiRouter.Handle("/compliance/frameworks",
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.listFrameworks)),
	).Methods("GET")

	// Agents
	apiRouter.Handle("/agents",
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.listAgents)),
	).Methods("GET")
	apiRouter.Handle("/agents/{id}",
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.getAgent)),
	).Methods("GET")

	// Costs
	apiRouter.Handle("/costs/summary",
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.getCostSummaryComputed)),
	).Methods("GET")

	// Remediations
	apiRouter.Handle("/remediations",
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.listRemediations)),
	).Methods("GET")
	apiRouter.Handle("/remediations/{id}/execute",
		s.roles.Require(api.RoleAdmin)(http.HandlerFunc(s.executeRemediation)),
	).Methods("POST")
	apiRouter.Handle("/remediations/{id}",
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.getRemediation)),
	).Methods("GET")

	// Agent traces
	apiRouter.Handle("/agents/{id}/traces",
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.listAgentTraces)),
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
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.listCatalogModules)),
	).Methods("GET")

	// Policies
	apiRouter.Handle("/policies",
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.listPolicies)),
	).Methods("GET")

	// Attack paths (delegated to AttackPathService)
	apiRouter.Handle("/attack-paths",
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.attackPathSvc.listAttackPaths)),
	).Methods("GET")
	apiRouter.Handle("/attack-paths/stats",
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.attackPathSvc.getAttackPathStats)),
	).Methods("GET")
	apiRouter.Handle("/attack-paths/{id}",
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.attackPathSvc.getAttackPath)),
	).Methods("GET")

	// Container security
	apiRouter.Handle("/container/scan",
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.scanContainer)),
	).Methods("GET")
	apiRouter.Handle("/container/admission",
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.checkAdmission)),
	).Methods("GET")

	// Secrets management
	apiRouter.Handle("/secrets",
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.listSecrets)),
	).Methods("GET")
	apiRouter.Handle("/secrets/scan",
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.scanSecrets)),
	).Methods("POST")
	apiRouter.Handle("/secrets/{path:.*}",
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.getSecret)),
	).Methods("GET")

	// WAF templates
	apiRouter.Handle("/waf/templates",
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.listWAFTemplates)),
	).Methods("GET")
	apiRouter.Handle("/waf/compliance/{templateId}",
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.validateWAFCompliance)),
	).Methods("GET")

	// Identity & Zero Trust
	apiRouter.Handle("/identity/users",
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.listIdentityUsers)),
	).Methods("GET")
	apiRouter.Handle("/identity/users/{id}/risk",
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.getIdentityUserRisk)),
	).Methods("GET")

	// Finding ingestion (admin-only write endpoint with deduplication)
	apiRouter.Handle("/findings/ingest",
		s.roles.Require(api.RoleAdmin)(http.HandlerFunc(s.ingestFinding)),
	).Methods("POST")

	// Workflow orchestration
	apiRouter.Handle("/workflows",
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.listWorkflows)),
	).Methods("GET")
	apiRouter.Handle("/workflows/{id}",
		s.roles.Require(api.RoleOperator, api.RoleAdmin)(http.HandlerFunc(s.getWorkflow)),
	).Methods("GET")
	apiRouter.Handle("/workflows/{id}/approve",
		s.roles.Require(api.RoleAdmin)(http.HandlerFunc(s.approveWorkflow)),
	).Methods("POST")
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
