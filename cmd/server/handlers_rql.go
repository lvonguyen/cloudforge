package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"cloudforge/internal/api"
	"cloudforge/internal/rql"

	"go.opentelemetry.io/otel"
)

// queryFindings evaluates an RQL query against all findings.
func (s *Server) queryFindings(w http.ResponseWriter, r *http.Request) {
	_, span := otel.Tracer("cloudforge").Start(r.Context(), "queryFindings")
	defer span.End()

	q := r.URL.Query().Get("q")
	if q == "" {
		writeErrorResponse(w, "missing required query parameter: q", http.StatusBadRequest)
		return
	}

	if len(q) > 1024 {
		writeErrorResponse(w, "query too long (max 1024 characters)", http.StatusBadRequest)
		return
	}

	parsed, err := rql.Parse(q)
	if err != nil {
		writeErrorResponse(w, fmt.Sprintf("invalid RQL query: %v", err), http.StatusBadRequest)
		return
	}

	page, perPage := parsePagination(r, 50, 200)
	claims, _ := api.GetClaimsFromContext(r.Context())
	scope := api.ScopeFromContext(claims)

	severityOrder := func(v string) (int, bool) {
		m := map[string]int{"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}
		p, ok := m[strings.ToUpper(v)]
		return p, ok
	}

	var results []Finding
	for i := range s.data.Findings {
		f := &s.data.Findings[i]
		if err := api.EnforceScope(scope, f); err != nil {
			continue
		}

		accessor := findingAccessor(f)
		ordered := map[string]rql.OrderedField{"severity": severityOrder}
		ev := rql.NewEvaluator(accessor, ordered)

		if ev.Match(parsed) {
			results = append(results, *f)
		}
	}

	resp := paginateResult(results, page, perPage)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// findingAccessor maps RQL field names to Finding struct values.
func findingAccessor(f *Finding) rql.FieldAccessor {
	return func(field string) (string, bool) {
		switch field {
		case "resource.type", "resource_type":
			return f.ResourceType, true
		case "resource.id", "resource_id":
			return f.ResourceID, true
		case "resource.arn", "resource_arn":
			return f.ResourceARN, f.ResourceARN != ""
		case "resource.name", "resource_name":
			return f.ResourceName, true
		case "severity":
			return f.Severity, true
		case "static_severity":
			return f.StaticSeverity, true
		case "status":
			return f.Status, true
		case "workflow_status":
			return f.WorkflowStatus, true
		case "cloud_provider", "provider":
			return f.CloudProvider, true
		case "platform":
			return f.Platform, true
		case "region":
			return f.Region, true
		case "account_id":
			return f.AccountID, true
		case "account_name":
			return f.AccountName, true
		case "environment", "environment_type":
			return f.EnvironmentType, true
		case "category":
			return f.Category, true
		case "type":
			return f.Type, true
		case "source":
			return f.Source, true
		case "service", "service_name":
			return f.ServiceName, true
		case "line_of_business", "lob":
			return f.LineOfBusiness, true
		case "ai_risk_score":
			return fmt.Sprintf("%g", f.AIRiskScore), true
		case "ai_risk_level":
			return f.AIRiskLevel, true
		case "exploit_available":
			if f.ExploitAvailable {
				return "true", true
			}
			return "false", true
		case "auto_remediatable":
			if f.AutoRemediatable {
				return "true", true
			}
			return "false", true
		case "suppressed":
			if f.Suppressed {
				return "true", true
			}
			return "false", true
		case "canonical_rule_id":
			return f.CanonicalRuleID, true
		default:
			return "", false
		}
	}
}
