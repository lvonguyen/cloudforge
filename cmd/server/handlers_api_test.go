package main

import (
	"net/http"
	"testing"
)

func TestListFindings(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/findings", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var results []Finding
	assertJSON(t, rr, &results)

	if len(results) != 80 {
		t.Errorf("findings count = %d, want 80", len(results))
	}
}

func TestListFindings_FilterBySeverity(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/findings?severity=CRITICAL", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var results []Finding
	assertJSON(t, rr, &results)

	if len(results) != 8 {
		t.Errorf("critical findings = %d, want 8", len(results))
	}
	for _, f := range results {
		if f.Severity != "CRITICAL" {
			t.Errorf("finding %s severity = %q, want CRITICAL", f.ID, f.Severity)
		}
	}
}

func TestListFindings_FilterByProvider(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/findings?provider=aws", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var results []Finding
	assertJSON(t, rr, &results)

	if len(results) != 52 {
		t.Errorf("aws findings = %d, want 52", len(results))
	}
}

func TestGetFinding(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/findings/f-001", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var result Finding
	assertJSON(t, rr, &result)

	if result.ID != "f-001" {
		t.Errorf("finding id = %q, want f-001", result.ID)
	}
}

func TestGetFinding_NotFound(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/findings/f-999", "", jwt)
	assertStatus(t, rr, http.StatusNotFound)
}

func TestListFrameworks(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/compliance/frameworks", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var results []ComplianceFramework
	assertJSON(t, rr, &results)

	if len(results) != 6 {
		t.Errorf("frameworks count = %d, want 6", len(results))
	}
}

func TestListAgents(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/agents", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var results []Agent
	assertJSON(t, rr, &results)

	if len(results) != 12 {
		t.Errorf("agents count = %d, want 12", len(results))
	}
}

func TestGetAgent(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/agents/550e8400-e29b-41d4-a716-446655440001", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var result Agent
	assertJSON(t, rr, &result)

	if result.ID != "550e8400-e29b-41d4-a716-446655440001" {
		t.Errorf("agent id = %q, want 550e8400-e29b-41d4-a716-446655440001", result.ID)
	}
}

func TestGetAgent_NotFound(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/agents/nonexistent-agent", "", jwt)
	assertStatus(t, rr, http.StatusNotFound)
}

func TestGetCostSummary(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/costs/summary", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var result CostSummary
	assertJSON(t, rr, &result)

	if result.Total != 2800000 {
		t.Errorf("total cost = %f, want 2800000", result.Total)
	}
}

func TestListRemediations(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/remediations", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var results []RemediationRecord
	assertJSON(t, rr, &results)

	if len(results) != 50 {
		t.Errorf("remediations count = %d, want 50", len(results))
	}
}

func TestListRemediations_FilterByStatus(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/remediations?status=completed", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var results []RemediationRecord
	assertJSON(t, rr, &results)

	for _, rem := range results {
		if rem.Status != "completed" {
			t.Errorf("remediation %s status = %q, want completed", rem.ID, rem.Status)
		}
	}
}

func TestExecuteRemediation_AdminOnly(t *testing.T) {
	_, router := testServer(t)

	// Operator should be forbidden
	rr := doRequest(t, router, "POST", "/api/v1/remediations/rem-001/execute", "", operatorJWT(t))
	assertStatus(t, rr, http.StatusForbidden)

	// Admin should succeed
	rr = doRequest(t, router, "POST", "/api/v1/remediations/rem-001/execute", "", adminJWT(t))
	assertStatus(t, rr, http.StatusOK)

	var result map[string]string
	assertJSON(t, rr, &result)

	if result["status"] != "executing" {
		t.Errorf("status = %q, want executing", result["status"])
	}
	if result["remediation_id"] != "rem-001" {
		t.Errorf("remediation_id = %q, want rem-001", result["remediation_id"])
	}
}

func TestExecuteRemediation_NotFound(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "POST", "/api/v1/remediations/rem-999/execute", "", jwt)
	assertStatus(t, rr, http.StatusNotFound)
}

func TestListAgentTraces(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/agents/550e8400-e29b-41d4-a716-446655440002/traces", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var results []AgentTrace
	assertJSON(t, rr, &results)

	if len(results) != 1 {
		t.Errorf("traces count = %d, want 1", len(results))
	}
	if len(results) > 0 && results[0].AgentID != "550e8400-e29b-41d4-a716-446655440002" {
		t.Errorf("agent_id = %q, want 550e8400-e29b-41d4-a716-446655440002", results[0].AgentID)
	}
}

func TestListAgentTraces_NoMatch(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/agents/nonexistent-agent/traces", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var results []AgentTrace
	assertJSON(t, rr, &results)

	if len(results) != 0 {
		t.Errorf("traces count = %d, want 0", len(results))
	}
}

func TestListAgentTraces_OperatorAllowed(t *testing.T) {
	_, router := testServer(t)
	jwt := operatorJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/agents/550e8400-e29b-41d4-a716-446655440002/traces", "", jwt)
	assertStatus(t, rr, http.StatusOK)
}

func TestListAuditLog(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/audit-log", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var results []AuditEvent
	assertJSON(t, rr, &results)

	if len(results) != 60 {
		t.Errorf("audit events count = %d, want 60", len(results))
	}
}

func TestListAuditLog_FilterByResult(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/audit-log?result=denied", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var results []AuditEvent
	assertJSON(t, rr, &results)

	for _, evt := range results {
		if evt.Result != "denied" {
			t.Errorf("event %s result = %q, want denied", evt.ID, evt.Result)
		}
	}
	if len(results) == 0 {
		t.Error("expected at least one denied event")
	}
}

func TestListAuditLog_FilterByActor(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/audit-log?actor=admin1@contoso.dev", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var results []AuditEvent
	assertJSON(t, rr, &results)

	for _, evt := range results {
		if evt.Actor != "admin1@contoso.dev" {
			t.Errorf("event %s actor = %q, want admin1@contoso.dev", evt.ID, evt.Actor)
		}
	}
	if len(results) == 0 {
		t.Error("expected at least one event for admin1@contoso.dev")
	}
}

func TestListAuditLog_OperatorForbidden(t *testing.T) {
	_, router := testServer(t)
	jwt := operatorJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/audit-log", "", jwt)
	assertStatus(t, rr, http.StatusForbidden)
}

func TestListUsers(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/users", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var results []UserRow
	assertJSON(t, rr, &results)

	if len(results) != 18 {
		t.Errorf("users count = %d, want 18", len(results))
	}
}

func TestListUsers_FilterByRole(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/users?role=admin", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var results []UserRow
	assertJSON(t, rr, &results)

	if len(results) != 6 {
		t.Errorf("admin users count = %d, want 6", len(results))
	}
	for _, u := range results {
		if u.Role != "admin" {
			t.Errorf("user %s role = %q, want admin", u.ID, u.Role)
		}
	}
}

func TestListUsers_OperatorForbidden(t *testing.T) {
	_, router := testServer(t)
	jwt := operatorJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/users", "", jwt)
	assertStatus(t, rr, http.StatusForbidden)
}

func TestListPolicies(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/policies", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var results []Policy
	assertJSON(t, rr, &results)

	if len(results) != 30 {
		t.Errorf("policies count = %d, want 30", len(results))
	}
}

func TestListPolicies_FilterByStatus(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/policies?status=draft", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var results []Policy
	assertJSON(t, rr, &results)

	for _, p := range results {
		if p.Status != "draft" {
			t.Errorf("policy %s status = %q, want draft", p.ID, p.Status)
		}
	}
	if len(results) == 0 {
		t.Error("expected at least one draft policy")
	}
}

func TestListPolicies_FilterByCategory(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/policies?category=security", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var results []Policy
	assertJSON(t, rr, &results)

	for _, p := range results {
		if p.Category != "security" {
			t.Errorf("policy %s category = %q, want security", p.ID, p.Category)
		}
	}
	if len(results) == 0 {
		t.Error("expected at least one security policy")
	}
}

func TestListPolicies_OperatorAllowed(t *testing.T) {
	_, router := testServer(t)
	jwt := operatorJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/policies", "", jwt)
	assertStatus(t, rr, http.StatusOK)
}

func TestAllEndpoints_RequireAuth(t *testing.T) {
	_, router := testServer(t)

	endpoints := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/findings"},
		{"GET", "/api/v1/findings/f-001"},
		{"GET", "/api/v1/compliance/frameworks"},
		{"GET", "/api/v1/agents"},
		{"GET", "/api/v1/agents/550e8400-e29b-41d4-a716-446655440001"},
		{"GET", "/api/v1/costs/summary"},
		{"GET", "/api/v1/remediations"},
		{"POST", "/api/v1/remediations/rem-001/execute"},
		{"GET", "/api/v1/agents/550e8400-e29b-41d4-a716-446655440002/traces"},
		{"GET", "/api/v1/audit-log"},
		{"GET", "/api/v1/users"},
		{"GET", "/api/v1/policies"},
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			rr := doRequest(t, router, ep.method, ep.path, "", "")
			assertStatus(t, rr, http.StatusUnauthorized)
		})
	}
}

func TestAllEndpoints_RequesterForbidden(t *testing.T) {
	_, router := testServer(t)
	jwt := requesterJWT(t)

	endpoints := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/findings"},
		{"GET", "/api/v1/compliance/frameworks"},
		{"GET", "/api/v1/agents"},
		{"GET", "/api/v1/costs/summary"},
		{"GET", "/api/v1/remediations"},
		{"GET", "/api/v1/agents/550e8400-e29b-41d4-a716-446655440002/traces"},
		{"GET", "/api/v1/audit-log"},
		{"GET", "/api/v1/users"},
		{"GET", "/api/v1/policies"},
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			rr := doRequest(t, router, ep.method, ep.path, "", jwt)
			assertStatus(t, rr, http.StatusForbidden)
		})
	}
}
