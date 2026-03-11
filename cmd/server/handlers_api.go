package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

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

	results := make([]Finding, 0, len(s.mockData.Findings))
	for _, f := range s.mockData.Findings {
		if severity != "" && !strings.EqualFold(f.Severity, severity) {
			continue
		}
		if provider != "" && !strings.EqualFold(f.CloudProvider, provider) {
			continue
		}
		if status != "" && !strings.EqualFold(f.Status, status) {
			continue
		}
		results = append(results, f)
	}

	span.SetAttributes(attribute.Int("findings.count", len(results)))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(results)
}

func (s *Server) getFinding(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.getFinding")
	defer span.End()
	r = r.WithContext(ctx)

	id := mux.Vars(r)["id"]
	span.SetAttributes(attribute.String("finding.id", id))

	for _, f := range s.mockData.Findings {
		if f.ID == id {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(f)
			return
		}
	}

	writeErrorResponse(w, "finding not found", http.StatusNotFound)
}

func (s *Server) listFrameworks(w http.ResponseWriter, r *http.Request) {
	_, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.listFrameworks")
	defer span.End()

	span.SetAttributes(attribute.Int("frameworks.count", len(s.mockData.Frameworks)))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.mockData.Frameworks)
}

func (s *Server) listAgents(w http.ResponseWriter, r *http.Request) {
	_, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.listAgents")
	defer span.End()

	span.SetAttributes(attribute.Int("agents.count", len(s.mockData.Agents)))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.mockData.Agents)
}

func (s *Server) getAgent(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.getAgent")
	defer span.End()
	r = r.WithContext(ctx)

	id := mux.Vars(r)["id"]
	span.SetAttributes(attribute.String("agent.id", id))

	for _, a := range s.mockData.Agents {
		if a.ID == id {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(a)
			return
		}
	}

	writeErrorResponse(w, "agent not found", http.StatusNotFound)
}

func (s *Server) getCostSummary(w http.ResponseWriter, r *http.Request) {
	_, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.getCostSummary")
	defer span.End()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.mockData.Costs)
}

func (s *Server) getRemediation(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.getRemediation")
	defer span.End()
	r = r.WithContext(ctx)

	id := mux.Vars(r)["id"]
	span.SetAttributes(attribute.String("remediation.id", id))

	for _, rem := range s.mockData.Remediations {
		if rem.ID == id {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(rem)
			return
		}
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

	results := make([]RemediationRecord, 0, len(s.mockData.Remediations))
	for _, rem := range s.mockData.Remediations {
		if statusFilter != "" && !strings.EqualFold(rem.Status, statusFilter) {
			continue
		}
		if hasTier && rem.Tier != tierVal {
			continue
		}
		results = append(results, rem)
	}

	span.SetAttributes(attribute.Int("remediations.count", len(results)))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(results)
}

func (s *Server) executeRemediation(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.executeRemediation")
	defer span.End()
	r = r.WithContext(ctx)

	id := mux.Vars(r)["id"]
	span.SetAttributes(attribute.String("remediation.id", id))

	for _, rem := range s.mockData.Remediations {
		if rem.ID == id {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status":         "executing",
				"remediation_id": id,
			})
			return
		}
	}

	writeErrorResponse(w, "remediation not found", http.StatusNotFound)
}

func (s *Server) listAgentTraces(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.listAgentTraces")
	defer span.End()
	r = r.WithContext(ctx)

	agentID := mux.Vars(r)["id"]
	span.SetAttributes(attribute.String("agent.id", agentID))

	results := make([]AgentTrace, 0)
	for _, tr := range s.mockData.Traces {
		if tr.AgentID == agentID {
			results = append(results, tr)
		}
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
	actorFilter := r.URL.Query().Get("actor")

	results := make([]AuditEvent, 0, len(s.mockData.AuditEvents))
	for _, evt := range s.mockData.AuditEvents {
		if resultFilter != "" && !strings.EqualFold(evt.Result, resultFilter) {
			continue
		}
		if actorFilter != "" && !strings.EqualFold(evt.Actor, actorFilter) {
			continue
		}
		results = append(results, evt)
	}

	span.SetAttributes(attribute.Int("audit.count", len(results)))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(results)
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.listUsers")
	defer span.End()
	r = r.WithContext(ctx)

	roleFilter := strings.ToLower(r.URL.Query().Get("role"))

	results := make([]UserRow, 0, len(s.mockData.Users))
	for _, u := range s.mockData.Users {
		if roleFilter != "" && !strings.EqualFold(u.Role, roleFilter) {
			continue
		}
		results = append(results, u)
	}

	span.SetAttributes(attribute.Int("users.count", len(results)))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(results)
}

func (s *Server) listCatalogModules(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.listCatalogModules")
	defer span.End()
	r = r.WithContext(ctx)

	providerFilter := strings.ToLower(r.URL.Query().Get("provider"))
	categoryFilter := strings.ToLower(r.URL.Query().Get("category"))
	searchFilter := strings.ToLower(r.URL.Query().Get("search"))

	results := make([]CatalogModule, 0, len(s.mockData.CatalogModules))
	for _, m := range s.mockData.CatalogModules {
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

	span.SetAttributes(attribute.Int("catalog.count", len(results)))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(results)
}

func (s *Server) listPolicies(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.listPolicies")
	defer span.End()
	r = r.WithContext(ctx)

	statusFilter := strings.ToLower(r.URL.Query().Get("status"))
	categoryFilter := strings.ToLower(r.URL.Query().Get("category"))

	results := make([]Policy, 0, len(s.mockData.Policies))
	for _, p := range s.mockData.Policies {
		if statusFilter != "" && !strings.EqualFold(p.Status, statusFilter) {
			continue
		}
		if categoryFilter != "" && !strings.EqualFold(p.Category, categoryFilter) {
			continue
		}
		results = append(results, p)
	}

	span.SetAttributes(attribute.Int("policies.count", len(results)))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(results)
}

// FindingEnrichment holds cached AI analysis for a single finding.
type FindingEnrichment struct {
	FindingID       string   `json:"finding_id"`
	RootCause       string   `json:"root_cause"`
	Impact          string   `json:"impact"`
	Remediation     string   `json:"remediation"`
	RelatedControls []string `json:"related_controls"`
	EnrichedAt      string   `json:"enriched_at"`
}

var enrichMu sync.Mutex

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

	if s.aiProvider == nil {
		writeErrorResponse(w, "AI enrichment is not enabled", http.StatusServiceUnavailable)
		return
	}

	// Check cache first
	enrichMu.Lock()
	if cached, ok := s.findingEnrichment[id]; ok {
		enrichMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cached)
		return
	}
	enrichMu.Unlock()

	// Find the finding
	var finding *Finding
	for i := range s.mockData.Findings {
		if s.mockData.Findings[i].ID == id {
			finding = &s.mockData.Findings[i]
			break
		}
	}
	if finding == nil {
		writeErrorResponse(w, "finding not found", http.StatusNotFound)
		return
	}

	// Call AI provider
	callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	prompt := fmt.Sprintf(`Finding: %s
Severity: %s | Category: %s | Provider: %s
Resource: %s (%s) in %s
Status: %s
Description: %s`,
		finding.Title,
		finding.Severity, finding.Category, finding.CloudProvider,
		finding.ResourceName, finding.ResourceType, finding.Region,
		finding.Status,
		finding.Remediation,
	)

	response, err := s.aiProvider.CompleteWithSystem(callCtx, findingEnrichSystemPrompt, prompt)
	if err != nil {
		s.logger.Error("AI enrichment failed", zap.String("finding_id", id), zap.Error(err))
		writeErrorResponse(w, "AI enrichment failed", http.StatusInternalServerError)
		return
	}

	enrichment, err := parseFindingEnrichment(id, response)
	if err != nil {
		s.logger.Error("Failed to parse enrichment response", zap.String("finding_id", id), zap.Error(err))
		writeErrorResponse(w, "failed to parse AI response", http.StatusInternalServerError)
		return
	}

	// Cache the result
	enrichMu.Lock()
	s.findingEnrichment[id] = enrichment
	enrichMu.Unlock()

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

	return &FindingEnrichment{
		FindingID:       findingID,
		RootCause:       parsed.RootCause,
		Impact:          parsed.Impact,
		Remediation:     parsed.Remediation,
		RelatedControls: parsed.RelatedControls,
		EnrichedAt:      time.Now().UTC().Format(time.RFC3339),
	}, nil
}
