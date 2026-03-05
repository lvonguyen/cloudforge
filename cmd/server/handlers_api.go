package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
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
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.listFrameworks")
	defer span.End()
	r = r.WithContext(ctx)

	span.SetAttributes(attribute.Int("frameworks.count", len(s.mockData.Frameworks)))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.mockData.Frameworks)
}

func (s *Server) listAgents(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.listAgents")
	defer span.End()
	r = r.WithContext(ctx)

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
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.getCostSummary")
	defer span.End()
	r = r.WithContext(ctx)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.mockData.Costs)
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
		if err == nil {
			hasTier = true
		}
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
