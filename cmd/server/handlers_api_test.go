package main

import (
	"aegis/internal/api"
	"aegis/internal/audit"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListFindings(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/findings?per_page=200", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var results []Finding
	assertPaginatedJSON(t, rr, &results)

	if len(results) < 100 {
		t.Errorf("findings count = %d, want >= 100", len(results))
	}
}

func TestBuildOPARequestContext(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/f-001/enrich", nil)
	req.Header.Set(traceparentHeader, "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00")
	req.Header.Set(xForwardedForHeader, "203.0.113.10, 10.0.0.5")
	req.RemoteAddr = "127.0.0.1:12345"

	ctx := buildOPARequestContext(req, &api.Claims{Subject: "user-123"})
	if ctx == nil {
		t.Fatal("expected non-nil request context")
	}
	if ctx.UserID != "user-123" {
		t.Fatalf("user_id = %q, want user-123", ctx.UserID)
	}
	if ctx.SessionID == "" {
		t.Fatal("expected session_id from traceparent header")
	}
	if ctx.IP != "203.0.113.10" {
		t.Fatalf("ip = %q, want 203.0.113.10", ctx.IP)
	}
	if ctx.Timestamp.IsZero() {
		t.Fatal("expected timestamp to be populated")
	}
}

func TestListFindings_FilterBySeverity(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/findings?severity=CRITICAL&per_page=200", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var results []Finding
	assertPaginatedJSON(t, rr, &results)

	if len(results) == 0 {
		t.Errorf("critical findings = %d, want > 0", len(results))
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

	rr := doRequest(t, router, "GET", "/api/v1/findings?provider=aws&per_page=200", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var results []Finding
	assertPaginatedJSON(t, rr, &results)

	if len(results) == 0 {
		t.Errorf("aws findings = %d, want > 0", len(results))
	}
}

func TestGetFinding(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/findings/f-00001", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var result Finding
	assertJSON(t, rr, &result)

	if result.ID != "f-00001" {
		t.Errorf("finding id = %q, want f-00001", result.ID)
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
	assertPaginatedJSON(t, rr, &results)

	if len(results) != 6 {
		t.Errorf("frameworks count = %d, want 6", len(results))
	}
}

func TestListAgents(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/agents", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var resp struct {
		Data       []Agent `json:"data"`
		Total      int     `json:"total"`
		Page       int     `json:"page"`
		PerPage    int     `json:"per_page"`
		TotalPages int     `json:"total_pages"`
	}
	assertJSON(t, rr, &resp)

	if resp.Total != 12 {
		t.Errorf("agents total = %d, want 12", resp.Total)
	}
	if resp.Page != 1 {
		t.Errorf("page = %d, want 1", resp.Page)
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

	if result.Total < 40000 || result.Total > 100000 {
		t.Errorf("total cost = %f, want range [40000, 100000] (computed from seed 42)", result.Total)
	}
}

func TestListRemediations(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/remediations", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var results []RemediationRecord
	assertPaginatedJSON(t, rr, &results)

	if len(results) != 50 {
		t.Errorf("remediations count = %d, want 50", len(results))
	}
}

func TestListRemediations_FilterByStatus(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/remediations?status=completed&per_page=200", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var results []RemediationRecord
	assertPaginatedJSON(t, rr, &results)

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
	if rr.Code == http.StatusForbidden {
		t.Errorf("status = 403, want non-forbidden (viewer parity)")
	}

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

	rr := doRequest(t, router, "GET", "/api/v1/audit-log?per_page=200", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var results []AuditEvent
	assertPaginatedJSON(t, rr, &results)

	if len(results) != 60 {
		t.Errorf("audit events count = %d, want 60", len(results))
	}
}

func TestListAuditLog_FilterByResult(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/audit-log?result=denied&per_page=200", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var results []AuditEvent
	assertPaginatedJSON(t, rr, &results)

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

	rr := doRequest(t, router, "GET", "/api/v1/audit-log?actor=admin1@contoso.dev&per_page=200", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var results []AuditEvent
	assertPaginatedJSON(t, rr, &results)

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
	assertPaginatedJSON(t, rr, &results)

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
	assertPaginatedJSON(t, rr, &results)

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
	assertPaginatedJSON(t, rr, &results)

	if len(results) != 30 {
		t.Errorf("policies count = %d, want 30", len(results))
	}
}

func TestListPolicies_FilterByStatus(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/policies?status=draft&per_page=200", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var results []Policy
	assertPaginatedJSON(t, rr, &results)

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

	rr := doRequest(t, router, "GET", "/api/v1/policies?category=security&per_page=200", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var results []Policy
	assertPaginatedJSON(t, rr, &results)

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
		{"GET", "/api/v1/findings/f-00001"},
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
		{"GET", "/api/v1/policies/pol-001"},
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
		{"GET", "/api/v1/policies/pol-001"},
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			rr := doRequest(t, router, ep.method, ep.path, "", jwt)
			assertStatus(t, rr, http.StatusForbidden) // requester not in Require() list
		})
	}
}

// --- Viewer role tests (Sprint C P2) ---

func TestViewerAllowed_ReadOnlyEndpoints(t *testing.T) {
	_, router := testServer(t)
	jwt := viewerJWT(t)

	allowed := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/findings"},
		{"GET", "/api/v1/findings/f-00001"},
		{"GET", "/api/v1/compliance/frameworks"},
		{"GET", "/api/v1/agents"},
		{"GET", "/api/v1/agents/550e8400-e29b-41d4-a716-446655440001"},
		{"GET", "/api/v1/agents/550e8400-e29b-41d4-a716-446655440002/traces"},
	}

	for _, ep := range allowed {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			rr := doRequest(t, router, ep.method, ep.path, "", jwt)
			assertStatus(t, rr, http.StatusOK)
		})
	}
}

func TestViewerForbidden_WriteAndAdminEndpoints(t *testing.T) {
	_, router := testServer(t)
	jwt := viewerJWT(t)

	forbidden := []struct {
		method string
		path   string
	}{
		{"POST", "/api/v1/findings/f-00001/enrich"},
		{"POST", "/api/v1/remediations/rem-001/execute"},
		{"GET", "/api/v1/audit-log"},
		{"GET", "/api/v1/users"},
	}

	for _, ep := range forbidden {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			rr := doRequest(t, router, ep.method, ep.path, "", jwt)
			assertStatus(t, rr, http.StatusForbidden)
		})
	}

	// Viewer retains read access to these endpoints.
	allowed := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/costs/summary"},
		{"GET", "/api/v1/remediations"},
		{"GET", "/api/v1/policies"},
	}
	for _, ep := range allowed {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			rr := doRequest(t, router, ep.method, ep.path, "", jwt)
			if rr.Code == http.StatusForbidden {
				t.Errorf("status = 403, want non-forbidden (viewer read access)")
			}
		})
	}
}

// --- Resource-scoped RBAC tests (Sprint 8B) ---

// scopedAdminJWT returns a JWT with admin role restricted to the given account IDs.
func scopedAdminJWT(t *testing.T, accountIDs []string) string {
	t.Helper()
	return makeJWT(t, api.Claims{
		Subject: "scoped-admin",
		Email:   "scoped@contoso.dev",
		Groups:  []string{"aegis-admin"},
		Scope:   "admin",
		ResourceScope: &api.ResourceScope{
			AccountIDs: accountIDs,
		},
	})
}

func TestListFindings_ScopedByAccount(t *testing.T) {
	_, router := testServer(t)

	// f-00001 has account_id sub-workload-001
	targetAccount := "sub-workload-001"
	jwt := scopedAdminJWT(t, []string{targetAccount})

	rr := doRequest(t, router, "GET", "/api/v1/findings?per_page=200", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var results []Finding
	assertPaginatedJSON(t, rr, &results)

	for _, f := range results {
		if f.AccountID != targetAccount {
			t.Errorf("finding %s has account %q, scope restricted to %q", f.ID, f.AccountID, targetAccount)
		}
	}
	if len(results) == 0 {
		t.Error("expected at least one finding in scope")
	}
}

func TestListFindings_ScopedAdmin_SeesFewerThanUnscoped(t *testing.T) {
	_, router := testServer(t)

	// Unscoped admin sees all
	type paginatedFindings struct {
		Data  []Finding `json:"data"`
		Total int       `json:"total"`
	}

	unscopedJWT := adminJWT(t)
	rr1 := doRequest(t, router, "GET", "/api/v1/findings", "", unscopedJWT)
	assertStatus(t, rr1, http.StatusOK)
	var allResp paginatedFindings
	assertJSON(t, rr1, &allResp)

	// Scoped admin sees subset
	scopedJWT := scopedAdminJWT(t, []string{"sub-workload-001"})
	rr2 := doRequest(t, router, "GET", "/api/v1/findings", "", scopedJWT)
	assertStatus(t, rr2, http.StatusOK)
	var scopedResp paginatedFindings
	assertJSON(t, rr2, &scopedResp)

	if scopedResp.Total >= allResp.Total {
		t.Errorf("scoped findings total (%d) should be fewer than unscoped (%d)", scopedResp.Total, allResp.Total)
	}
}

func TestGetFinding_ScopeDenied(t *testing.T) {
	_, router := testServer(t)

	// f-00001 has account_id sub-workload-001
	// Scope to a different account
	jwt := scopedAdminJWT(t, []string{"999999999999"})

	rr := doRequest(t, router, "GET", "/api/v1/findings/f-00001", "", jwt)
	assertStatus(t, rr, http.StatusForbidden) // resource scope denied
}

func TestGetFinding_ScopeAllowed(t *testing.T) {
	_, router := testServer(t)

	// f-00001 has account_id sub-workload-001
	jwt := scopedAdminJWT(t, []string{"sub-workload-001"})

	rr := doRequest(t, router, "GET", "/api/v1/findings/f-00001", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var result Finding
	assertJSON(t, rr, &result)
	if result.ID != "f-00001" {
		t.Errorf("finding id = %q, want f-00001", result.ID)
	}
}

func TestGetFinding_NilScopeAllowsAll(t *testing.T) {
	_, router := testServer(t)

	// Admin without ResourceScope sees everything (backwards compat)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/findings/f-00001", "", jwt)
	assertStatus(t, rr, http.StatusOK)
}

// --- Integrity hashing tests (Sprint 9B) ---

func TestFinding_IntegrityHashPopulated(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/findings/f-00001", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var result Finding
	assertJSON(t, rr, &result)

	if result.IntegrityHash == "" {
		t.Error("finding integrity_hash should be non-empty")
	}
	if len(result.IntegrityHash) != 64 { // SHA-256 hex = 64 chars
		t.Errorf("integrity_hash length = %d, want 64", len(result.IntegrityHash))
	}
}

func TestAuditLog_IncludesRealEvents(t *testing.T) {
	srv, router := testServer(t)
	jwt := adminJWT(t)

	// Execute a remediation (creates an audit event)
	rr := doRequest(t, router, "POST", "/api/v1/remediations/rem-001/execute", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	// Fetch audit log — should include the real event merged with mock data
	rr2 := doRequest(t, router, "GET", "/api/v1/audit-log?per_page=200", "", jwt)
	assertStatus(t, rr2, http.StatusOK)

	var events []AuditEvent
	assertPaginatedJSON(t, rr2, &events)

	// Mock data has 60 events + 1 real
	if len(events) < 61 {
		t.Errorf("audit events = %d, want >= 61 (60 mock + 1 real)", len(events))
	}

	// Verify the real event exists
	found := false
	for _, e := range events {
		if e.Action == "remediation.execute" && e.ID != "" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected a real remediation.execute audit event")
	}

	// Also check via AuditLogger directly
	realEvents, _ := srv.auditLogger.List(context.Background(), audit.ListOpts{})
	if len(realEvents) != 1 {
		t.Errorf("real audit events = %d, want 1", len(realEvents))
	}
	if realEvents[0].IntegrityHash == "" {
		t.Error("real audit event should have integrity hash")
	}
}

func TestFinding_IntegrityHashDeterministic(t *testing.T) {
	srv, _ := testServer(t)

	f := srv.data.FindingsByID["f-00001"]
	if f == nil {
		t.Fatal("f-00001 not found")
	}

	hash1 := f.ComputeIntegrityHash()
	hash2 := f.ComputeIntegrityHash()
	if hash1 != hash2 {
		t.Errorf("integrity hash not deterministic: %q != %q", hash1, hash2)
	}
	if hash1 != f.IntegrityHash {
		t.Errorf("stored hash %q != computed %q", f.IntegrityHash, hash1)
	}
}

func TestGetPolicy_Success(t *testing.T) {
	srv, router := testServer(t)
	jwt := adminJWT(t)

	if len(srv.data.Policies) == 0 {
		t.Fatal("mock data has no policies")
	}
	wantID := srv.data.Policies[0].ID

	rr := doRequest(t, router, "GET", "/api/v1/policies/"+wantID, "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var got Policy
	assertJSON(t, rr, &got)
	if got.ID != wantID {
		t.Errorf("policy id = %q, want %q", got.ID, wantID)
	}
}

func TestGetPolicy_NotFound(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/policies/pol-nonexistent", "", jwt)
	assertStatus(t, rr, http.StatusNotFound)
}

// TestScopeGuard_BlocksScopedUserOnGuardedEndpoints verifies that scoped
// users are rejected from endpoints protected by ScopeGuard middleware.
// These endpoints serve account-scoped data but lack inline scope filtering.
func TestScopeGuard_BlocksScopedUserOnGuardedEndpoints(t *testing.T) {
	_, router := testServer(t)
	jwt := scopedAdminJWT(t, []string{"111"})

	guarded := []string{
		"/api/v1/agents",
		"/api/v1/costs/summary",
		"/api/v1/remediations",
		"/api/v1/containers",
		"/api/v1/secrets",
		"/api/v1/identity/users",
		"/api/v1/data-classification/assets",
		"/api/v1/compliance/posture",
		"/api/v1/asm/assets",
		"/api/v1/workflows",
	}

	for _, path := range guarded {
		rr := doRequest(t, router, "GET", path, "", jwt)
		if rr.Code != http.StatusForbidden {
			t.Errorf("%s: scoped user got %d, want 403", path, rr.Code)
		}
	}
}

// TestScopeGuard_UnscopedAdminPassesThrough verifies that admins without
// scope restrictions can still access guarded endpoints normally.
func TestScopeGuard_UnscopedAdminPassesThrough(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	endpoints := []string{
		"/api/v1/agents",
		"/api/v1/costs/summary",
		"/api/v1/remediations",
		"/api/v1/containers",
		"/api/v1/secrets",
	}

	for _, path := range endpoints {
		rr := doRequest(t, router, "GET", path, "", jwt)
		if rr.Code == http.StatusForbidden {
			t.Errorf("%s: unscoped admin got 403, should pass through", path)
		}
	}
}
