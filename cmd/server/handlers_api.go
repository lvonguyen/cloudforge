package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"cloudforge/internal/ai-governance/opa"
	"cloudforge/internal/api"
	"cloudforge/internal/audit"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"
)

func (s *Server) listFindings(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.listFindings")
	defer span.End()
	r = r.WithContext(ctx)

	severity := strings.ToUpper(r.URL.Query().Get("severity"))
	provider := strings.ToLower(r.URL.Query().Get("provider"))
	status := strings.ToLower(r.URL.Query().Get("status"))

	claims, _ := api.GetClaimsFromContext(r.Context())
	scope := api.ScopeFromContext(claims)

	results := make([]Finding, 0, len(s.data.Findings))
	for i := range s.data.Findings {
		f := &s.data.Findings[i]
		if severity != "" && !strings.EqualFold(f.Severity, severity) {
			continue
		}
		if provider != "" && !strings.EqualFold(f.CloudProvider, provider) {
			continue
		}
		if status != "" && !strings.EqualFold(f.Status, status) {
			continue
		}
		if err := api.EnforceScope(scope, f); err != nil {
			continue // silently skip out-of-scope findings in list
		}
		results = append(results, *f)
	}

	page, perPage := parsePagination(r, 50, 200)
	resp := paginateResult(results, page, perPage)

	span.SetAttributes(attribute.Int("findings.total", resp.Total))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) getFinding(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.getFinding")
	defer span.End()
	r = r.WithContext(ctx)

	id := mux.Vars(r)["id"]
	span.SetAttributes(attribute.String("finding.id", id))

	f, ok := s.data.FindingsByID[id]
	if !ok {
		writeErrorResponse(w, "finding not found", http.StatusNotFound)
		return
	}

	claims, _ := api.GetClaimsFromContext(r.Context())
	scope := api.ScopeFromContext(claims)
	if err := api.EnforceScope(scope, f); err != nil {
		api.LogScopeDenial(s.logger, claims.Subject, f.ID, f.AccountID, f.Region, err.Error())
		writeErrorResponse(w, "forbidden: resource outside authorized scope", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(f)
}

func (s *Server) listFrameworks(w http.ResponseWriter, r *http.Request) {
	_, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.listFrameworks")
	defer span.End()

	page, perPage := parsePagination(r, 50, 200)
	resp := paginateResult(s.data.Frameworks, page, perPage)

	span.SetAttributes(attribute.Int("frameworks.total", resp.Total))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) listAgents(w http.ResponseWriter, r *http.Request) {
	_, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.listAgents")
	defer span.End()

	span.SetAttributes(attribute.Int("agents.count", len(s.data.Agents)))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.data.Agents)
}

func (s *Server) getAgent(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.getAgent")
	defer span.End()
	r = r.WithContext(ctx)

	id := mux.Vars(r)["id"]
	span.SetAttributes(attribute.String("agent.id", id))

	if a, ok := s.data.AgentsByID[id]; ok {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(a)
		return
	}

	writeErrorResponse(w, "agent not found", http.StatusNotFound)
}

func (s *Server) getRemediation(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.getRemediation")
	defer span.End()
	r = r.WithContext(ctx)

	id := mux.Vars(r)["id"]
	span.SetAttributes(attribute.String("remediation.id", id))

	if rem, ok := s.data.RemediationsByID[id]; ok {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rem)
		return
	}

	writeErrorResponse(w, "remediation not found", http.StatusNotFound)
}

func (s *Server) listRemediations(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.listRemediations")
	defer span.End()
	r = r.WithContext(ctx)

	statusFilter := strings.ToLower(r.URL.Query().Get("status"))
	tierFilter := r.URL.Query().Get("tier")
	var tierVal int
	var hasTier bool
	if tierFilter != "" {
		var err error
		tierVal, err = strconv.Atoi(tierFilter)
		if err != nil {
			// Inverted check fixed: a non-empty but non-numeric tier parameter must
			// be rejected. Previously err == nil was used, which silently swallowed
			// parse failures and returned all records as if no filter was applied.
			writeErrorResponse(w, "invalid tier: must be a positive integer", http.StatusBadRequest)
			return
		}
		hasTier = true
	}

	results := make([]RemediationRecord, 0, len(s.data.Remediations))
	for _, rem := range s.data.Remediations {
		if statusFilter != "" && !strings.EqualFold(rem.Status, statusFilter) {
			continue
		}
		if hasTier && rem.Tier != tierVal {
			continue
		}
		results = append(results, rem)
	}

	page, perPage := parsePagination(r, 50, 200)
	resp := paginateResult(results, page, perPage)

	span.SetAttributes(attribute.Int("remediations.total", resp.Total))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) executeRemediation(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.executeRemediation")
	defer span.End()
	r = r.WithContext(ctx)

	id := mux.Vars(r)["id"]
	span.SetAttributes(attribute.String("remediation.id", id))

	if _, ok := s.data.RemediationsByID[id]; ok {
		s.logAuditEvent(r, "remediation.execute", "remediation", id, "success")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":         "executing",
			"remediation_id": id,
		})
		return
	}

	writeErrorResponse(w, "remediation not found", http.StatusNotFound)
}

func (s *Server) listAgentTraces(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.listAgentTraces")
	defer span.End()
	r = r.WithContext(ctx)

	agentID := mux.Vars(r)["id"]
	span.SetAttributes(attribute.String("agent.id", agentID))

	results := s.data.TracesByAgentID[agentID]
	if results == nil {
		results = []AgentTrace{}
	}

	span.SetAttributes(attribute.Int("traces.count", len(results)))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(results)
}

func (s *Server) listAuditLog(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.listAuditLog")
	defer span.End()
	r = r.WithContext(ctx)

	resultFilter := strings.ToLower(r.URL.Query().Get("result"))
	if resultFilter != "" {
		validResults := map[string]bool{"success": true, "failure": true, "blocked": true}
		if !validResults[resultFilter] {
			writeErrorResponse(w, "invalid result filter: must be success, failure, or blocked", http.StatusBadRequest)
			return
		}
	}
	actorFilter := r.URL.Query().Get("actor")
	if len(actorFilter) > 255 {
		http.Error(w, `{"error":"actor filter too long (max 255)"}`, http.StatusBadRequest)
		return
	}
	page, perPage := parsePagination(r, 50, 200)

	// Start with mock data (historical events loaded from JSON)
	results := make([]AuditEvent, 0, len(s.data.AuditEvents))
	for _, evt := range s.data.AuditEvents {
		if resultFilter != "" && !strings.EqualFold(evt.Result, resultFilter) {
			continue
		}
		if actorFilter != "" && !strings.EqualFold(evt.Actor, actorFilter) {
			continue
		}
		results = append(results, evt)
	}

	// Merge real audit events from the audit logger (newest first)
	if s.auditLogger != nil {
		realEvents, err := s.auditLogger.List(r.Context(), audit.ListOpts{
			Actor: actorFilter,
			Limit: perPage,
		})
		if err == nil {
			for _, re := range realEvents {
				if resultFilter != "" && !strings.EqualFold(re.Result, resultFilter) {
					continue
				}
				results = append(results, AuditEvent{
					ID:        re.ID,
					Timestamp: re.Timestamp,
					Actor:     re.Actor,
					ActorRole: re.ActorRole,
					Action:    re.Action,
					Resource:  re.Resource,
					Result:    re.Result,
					IP:        re.IP,
				})
			}
		}
	}

	resp := paginateResult(results, page, perPage)

	span.SetAttributes(attribute.Int("audit.total", resp.Total))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.listUsers")
	defer span.End()
	r = r.WithContext(ctx)

	roleFilter := strings.ToLower(r.URL.Query().Get("role"))

	results := make([]UserRow, 0, len(s.data.Users))
	for _, u := range s.data.Users {
		if roleFilter != "" && !strings.EqualFold(u.Role, roleFilter) {
			continue
		}
		results = append(results, u)
	}

	page, perPage := parsePagination(r, 50, 200)
	resp := paginateResult(results, page, perPage)

	span.SetAttributes(attribute.Int("users.total", resp.Total))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) listCatalogModules(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.listCatalogModules")
	defer span.End()
	r = r.WithContext(ctx)

	providerFilter := strings.ToLower(r.URL.Query().Get("provider"))
	categoryFilter := strings.ToLower(r.URL.Query().Get("category"))
	searchFilter := strings.ToLower(r.URL.Query().Get("search"))
	if len(searchFilter) > 200 {
		http.Error(w, `{"error":"search filter too long (max 200)"}`, http.StatusBadRequest)
		return
	}

	results := make([]CatalogModule, 0, len(s.data.CatalogModules))
	for _, m := range s.data.CatalogModules {
		if providerFilter != "" && !strings.EqualFold(m.Provider, providerFilter) {
			continue
		}
		if categoryFilter != "" && !strings.EqualFold(m.Category, categoryFilter) {
			continue
		}
		if searchFilter != "" {
			matched := strings.Contains(strings.ToLower(m.Name), searchFilter) ||
				strings.Contains(strings.ToLower(m.Description), searchFilter)
			if !matched {
				for _, tag := range m.Tags {
					if strings.Contains(strings.ToLower(tag), searchFilter) {
						matched = true
						break
					}
				}
			}
			if !matched {
				continue
			}
		}
		results = append(results, m)
	}

	page, perPage := parsePagination(r, 50, 200)
	resp := paginateResult(results, page, perPage)

	span.SetAttributes(attribute.Int("catalog.total", resp.Total))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) listPolicies(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.listPolicies")
	defer span.End()
	r = r.WithContext(ctx)

	statusFilter := strings.ToLower(r.URL.Query().Get("status"))
	categoryFilter := strings.ToLower(r.URL.Query().Get("category"))

	results := make([]Policy, 0, len(s.data.Policies))
	for _, p := range s.data.Policies {
		if statusFilter != "" && !strings.EqualFold(p.Status, statusFilter) {
			continue
		}
		if categoryFilter != "" && !strings.EqualFold(p.Category, categoryFilter) {
			continue
		}
		results = append(results, p)
	}

	page, perPage := parsePagination(r, 50, 200)
	resp := paginateResult(results, page, perPage)

	span.SetAttributes(attribute.Int("policies.total", resp.Total))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// FindingEnrichment holds cached AI analysis for a single finding.
type FindingEnrichment struct {
	FindingID       string    `json:"finding_id"`
	RootCause       string    `json:"root_cause"`
	Impact          string    `json:"impact"`
	Remediation     string    `json:"remediation"`
	RelatedControls []string  `json:"related_controls"`
	EnrichedAt      string    `json:"enriched_at"`
	CreatedAt       time.Time `json:"-"` // cache eviction timestamp
}

const findingEnrichSystemPrompt = `You are a cloud security analyst. Given a security finding, provide:
1. Root cause analysis
2. Business impact assessment
3. Step-by-step remediation
4. Related CIS/NIST controls

Respond ONLY with valid JSON matching this schema:
{"root_cause":"...","impact":"...","remediation":"...","related_controls":["CIS x.y","NIST SC-z"]}`

func (s *Server) enrichFinding(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.enrichFinding")
	defer span.End()
	r = r.WithContext(ctx)

	id := mux.Vars(r)["id"]
	span.SetAttributes(attribute.String("finding.id", id))

	if !s.enrichmentSvc.Enabled() {
		writeErrorResponse(w, "AI enrichment is not enabled", http.StatusServiceUnavailable)
		return
	}

	// OPA policy gate: evaluate AI tool access if engine is configured.
	// Nil engine = no policies loaded = allow (graceful degradation).
	if s.opaEngine != nil {
		opaInput := &opa.EvaluationInput{
			Agent: opa.AgentContext{
				ID:          "cloudforge-api",
				Name:        "enrichment",
				Environment: getEnv("APP_ENV", "production"),
			},
			Tool: &opa.ToolContext{
				Name:     "ai_enrich",
				Category: "analysis",
			},
		}
		decision, err := s.opaEngine.EvaluateToolAccess(ctx, &opaInput.Agent, opaInput.Tool)
		if err != nil {
			s.logger.Warn("OPA evaluation failed, allowing request", zap.Error(err))
		} else if !decision.Allow {
			s.logger.Warn("OPA denied enrichment",
				zap.String("finding_id", id),
				zap.Strings("reasons", decision.Reasons),
			)
			writeErrorResponse(w, "policy denied: AI enrichment not permitted", http.StatusForbidden)
			return
		}
	}

	// Find the finding in the DataStore
	finding, ok := s.data.FindingsByID[id]
	if !ok {
		writeErrorResponse(w, "finding not found", http.StatusNotFound)
		return
	}

	// Delegate to EnrichmentService (handles cache + AI call)
	enrichment, err := s.enrichmentSvc.Enrich(ctx, finding)
	if err != nil {
		s.logger.Error("AI enrichment failed", zap.String("finding_id", id), zap.Error(err))
		writeErrorResponse(w, "AI enrichment failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(enrichment)
}

func parseFindingEnrichment(findingID, response string) (*FindingEnrichment, error) {
	type aiResponse struct {
		RootCause       string   `json:"root_cause"`
		Impact          string   `json:"impact"`
		Remediation     string   `json:"remediation"`
		RelatedControls []string `json:"related_controls"`
	}

	var parsed aiResponse

	// Try direct parse
	if err := json.Unmarshal([]byte(response), &parsed); err != nil {
		// Extract JSON from surrounding text
		start := strings.Index(response, "{")
		end := strings.LastIndex(response, "}")
		if start == -1 || end == -1 || end <= start {
			return nil, fmt.Errorf("no JSON in response")
		}
		if err := json.Unmarshal([]byte(response[start:end+1]), &parsed); err != nil {
			return nil, fmt.Errorf("parsing extracted JSON: %w", err)
		}
	}

	if parsed.RootCause == "" {
		return nil, fmt.Errorf("missing root_cause in response")
	}

	now := time.Now().UTC()
	return &FindingEnrichment{
		FindingID:       findingID,
		RootCause:       parsed.RootCause,
		Impact:          parsed.Impact,
		Remediation:     parsed.Remediation,
		RelatedControls: parsed.RelatedControls,
		EnrichedAt:      now.Format(time.RFC3339),
		CreatedAt:       now,
	}, nil
}
