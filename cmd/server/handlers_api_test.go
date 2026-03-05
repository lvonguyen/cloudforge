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
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			rr := doRequest(t, router, ep.method, ep.path, "", jwt)
			assertStatus(t, rr, http.StatusForbidden)
		})
	}
}
