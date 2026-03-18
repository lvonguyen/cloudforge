package main

import (
	"encoding/json"
	"net/http"
	"testing"
)

// ---------------------------------------------------------------------------
// Catalog
// ---------------------------------------------------------------------------

func TestHandlers_ListCatalogModules(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/catalog/modules", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var results []CatalogModule
	assertPaginatedJSON(t, rr, &results)

	if len(results) == 0 {
		t.Error("expected at least one catalog module")
	}
}

func TestHandlers_ListCatalogModules_OperatorAllowed(t *testing.T) {
	_, router := testServer(t)
	jwt := operatorJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/catalog/modules", "", jwt)
	assertStatus(t, rr, http.StatusOK)
}

// ---------------------------------------------------------------------------
// Remediations — single item
// ---------------------------------------------------------------------------

func TestHandlers_GetRemediation(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/remediations/rem-001", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var result RemediationRecord
	assertJSON(t, rr, &result)

	if result.ID != "rem-001" {
		t.Errorf("remediation id = %q, want rem-001", result.ID)
	}
}

func TestHandlers_GetRemediation_NotFound(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/remediations/nonexistent", "", jwt)
	assertStatus(t, rr, http.StatusNotFound)
}

// ---------------------------------------------------------------------------
// Identity — users and risk
// ---------------------------------------------------------------------------

func TestHandlers_ListIdentityUsers_Okta(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/identity/users?provider=okta", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var result map[string]interface{}
	assertJSON(t, rr, &result)

	if result["provider"] != "okta" {
		t.Errorf("provider = %v, want okta", result["provider"])
	}
	count, _ := result["count"].(float64)
	if count == 0 {
		t.Error("expected at least one identity user")
	}
}

func TestHandlers_ListIdentityUsers_EntraID(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/identity/users?provider=entra_id", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var result map[string]interface{}
	assertJSON(t, rr, &result)

	if result["provider"] != "entra_id" {
		t.Errorf("provider = %v, want entra_id", result["provider"])
	}
}

func TestHandlers_ListIdentityUsers_DefaultProvider(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/identity/users", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var result map[string]interface{}
	assertJSON(t, rr, &result)

	// Default should be okta
	if result["provider"] != "okta" {
		t.Errorf("default provider = %v, want okta", result["provider"])
	}
}

func TestHandlers_ListIdentityUsers_UnsupportedProvider(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/identity/users?provider=unknown", "", jwt)
	assertStatus(t, rr, http.StatusBadRequest)
}

func TestHandlers_GetIdentityUserRisk(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/identity/users/00u1a2b3c4d5e6f7g8h9/risk?provider=okta", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var result map[string]interface{}
	assertJSON(t, rr, &result)

	if result["user_id"] != "00u1a2b3c4d5e6f7g8h9" {
		t.Errorf("user_id = %v, want 00u1a2b3c4d5e6f7g8h9", result["user_id"])
	}
}

// ---------------------------------------------------------------------------
// Workflows
// ---------------------------------------------------------------------------

func TestHandlers_ListWorkflows(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/workflows", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var result map[string]interface{}
	assertJSON(t, rr, &result)

	count, _ := result["count"].(float64)
	if count == 0 {
		t.Error("expected at least one workflow")
	}
}

func TestHandlers_ListWorkflows_OperatorAllowed(t *testing.T) {
	_, router := testServer(t)
	jwt := operatorJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/workflows", "", jwt)
	assertStatus(t, rr, http.StatusOK)
}

func TestHandlers_GetWorkflow(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	// First, list workflows to get a valid ID
	listRR := doRequest(t, router, "GET", "/api/v1/workflows", "", jwt)
	assertStatus(t, listRR, http.StatusOK)

	var listResult struct {
		Workflows []struct {
			ID string `json:"id"`
		} `json:"workflows"`
	}
	assertJSON(t, listRR, &listResult)

	if len(listResult.Workflows) == 0 {
		t.Fatal("no workflows to test")
	}

	wfID := listResult.Workflows[0].ID
	rr := doRequest(t, router, "GET", "/api/v1/workflows/"+wfID, "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var result map[string]interface{}
	assertJSON(t, rr, &result)

	if result["id"] != wfID {
		t.Errorf("workflow id = %v, want %s", result["id"], wfID)
	}
}

func TestHandlers_GetWorkflow_NotFound(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/workflows/nonexistent-wf", "", jwt)
	assertStatus(t, rr, http.StatusNotFound)
}

func TestHandlers_ApproveWorkflow(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	// List workflows to find one with pending_approval status
	listRR := doRequest(t, router, "GET", "/api/v1/workflows", "", jwt)
	assertStatus(t, listRR, http.StatusOK)

	var listResult struct {
		Workflows []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"workflows"`
	}
	assertJSON(t, listRR, &listResult)

	var pendingID string
	for _, wf := range listResult.Workflows {
		if wf.Status == "pending_approval" {
			pendingID = wf.ID
			break
		}
	}

	if pendingID == "" {
		t.Skip("no pending_approval workflow found to test")
	}

	body := `{"approver":"admin@contoso.dev"}`
	rr := doRequest(t, router, "POST", "/api/v1/workflows/"+pendingID+"/approve", body, jwt)
	assertStatus(t, rr, http.StatusOK)

	var result map[string]interface{}
	assertJSON(t, rr, &result)
}

func TestHandlers_ApproveWorkflow_OperatorForbidden(t *testing.T) {
	_, router := testServer(t)
	jwt := operatorJWT(t)

	body := `{"approver":"operator@contoso.dev"}`
	rr := doRequest(t, router, "POST", "/api/v1/workflows/wf-001/approve", body, jwt)
	assertStatus(t, rr, http.StatusForbidden)
}

// ---------------------------------------------------------------------------
// Container security
// ---------------------------------------------------------------------------

func TestHandlers_ScanContainer(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/container/scan?image=nginx&tag=latest", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var result map[string]interface{}
	assertJSON(t, rr, &result)
}

func TestHandlers_ScanContainer_MissingImage(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/container/scan", "", jwt)
	assertStatus(t, rr, http.StatusBadRequest)
}

func TestHandlers_CheckAdmission(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/container/admission?image=nginx&tag=latest", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var result map[string]interface{}
	assertJSON(t, rr, &result)
}

func TestHandlers_CheckAdmission_MissingImage(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/container/admission", "", jwt)
	assertStatus(t, rr, http.StatusBadRequest)
}

// ---------------------------------------------------------------------------
// Secrets management
// ---------------------------------------------------------------------------

func TestHandlers_ListSecrets(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/secrets", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var result map[string]interface{}
	assertJSON(t, rr, &result)

	count, _ := result["count"].(float64)
	if count == 0 {
		t.Error("expected at least one secret path")
	}
}

func TestHandlers_ScanSecrets(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "POST", "/api/v1/secrets/scan", `{"content":"password123"}`, jwt)
	assertStatus(t, rr, http.StatusOK)

	var result map[string]interface{}
	assertJSON(t, rr, &result)
}

func TestHandlers_ScanSecrets_MissingContent(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "POST", "/api/v1/secrets/scan", `{"content":""}`, jwt)
	assertStatus(t, rr, http.StatusBadRequest)
}

// ---------------------------------------------------------------------------
// WAF templates
// ---------------------------------------------------------------------------

func TestHandlers_ListWAFTemplates(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/waf/templates", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var result map[string]interface{}
	assertJSON(t, rr, &result)

	count, _ := result["count"].(float64)
	if count == 0 {
		t.Error("expected at least one WAF template")
	}
}

func TestHandlers_ValidateWAFCompliance(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	// First, list templates to get a valid ID
	listRR := doRequest(t, router, "GET", "/api/v1/waf/templates", "", jwt)
	assertStatus(t, listRR, http.StatusOK)

	var listResult struct {
		Templates []struct {
			ID string `json:"id"`
		} `json:"templates"`
	}
	assertJSON(t, listRR, &listResult)

	if len(listResult.Templates) == 0 {
		t.Fatal("no WAF templates to test")
	}

	templateID := listResult.Templates[0].ID
	rr := doRequest(t, router, "GET", "/api/v1/waf/compliance/"+templateID, "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var result map[string]interface{}
	assertJSON(t, rr, &result)
}

func TestHandlers_ValidateWAFCompliance_NotFound(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/waf/compliance/nonexistent-template", "", jwt)
	assertStatus(t, rr, http.StatusNotFound)
}

// ---------------------------------------------------------------------------
// Additional RBAC coverage for new endpoints
// ---------------------------------------------------------------------------

func TestHandlers_NewEndpoints_RequireAuth(t *testing.T) {
	_, router := testServer(t)

	endpoints := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/catalog/modules"},
		{"GET", "/api/v1/identity/users"},
		{"GET", "/api/v1/identity/users/test-user/risk"},
		{"GET", "/api/v1/workflows"},
		{"GET", "/api/v1/workflows/wf-001"},
		{"POST", "/api/v1/workflows/wf-001/approve"},
		{"GET", "/api/v1/container/scan?image=nginx"},
		{"GET", "/api/v1/container/admission?image=nginx"},
		{"GET", "/api/v1/secrets"},
		{"GET", "/api/v1/secrets/scan?content=test"},
		{"GET", "/api/v1/waf/templates"},
		{"GET", "/api/v1/waf/compliance/tpl-001"},
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			rr := doRequest(t, router, ep.method, ep.path, "", "")
			assertStatus(t, rr, http.StatusUnauthorized)
		})
	}
}

func TestHandlers_NewEndpoints_RequesterForbidden(t *testing.T) {
	_, router := testServer(t)
	jwt := requesterJWT(t)

	endpoints := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/catalog/modules"},
		{"GET", "/api/v1/identity/users"},
		{"GET", "/api/v1/identity/users/test-user/risk"},
		{"GET", "/api/v1/workflows"},
		{"GET", "/api/v1/workflows/wf-001"},
		{"GET", "/api/v1/container/scan?image=nginx"},
		{"GET", "/api/v1/container/admission?image=nginx"},
		{"GET", "/api/v1/secrets"},
		{"GET", "/api/v1/secrets/scan?content=test"},
		{"GET", "/api/v1/waf/templates"},
		{"GET", "/api/v1/waf/compliance/tpl-001"},
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			rr := doRequest(t, router, ep.method, ep.path, "", jwt)
			assertStatus(t, rr, http.StatusForbidden)
		})
	}
}

// ---------------------------------------------------------------------------
// Verify mock identity providers are wired into the server
// ---------------------------------------------------------------------------

func TestHandlers_IdentityService_WiredCorrectly(t *testing.T) {
	srv, _ := testServer(t)

	if srv.identitySvc == nil {
		t.Fatal("identitySvc is nil")
	}

	if _, err := srv.identitySvc.GetProvider("okta"); err != nil {
		t.Error("okta provider not registered")
	}
	if _, err := srv.identitySvc.GetProvider("entra_id"); err != nil {
		t.Error("entra_id provider not registered")
	}
}

// ---------------------------------------------------------------------------
// JSON response validation helpers for additional endpoints
// ---------------------------------------------------------------------------

func TestHandlers_ListCatalogModules_FilterByProvider(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/catalog/modules?provider=aws", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var results []CatalogModule
	assertPaginatedJSON(t, rr, &results)

	for _, m := range results {
		if m.Provider != "aws" {
			t.Errorf("module %s provider = %q, want aws", m.ID, m.Provider)
		}
	}
}

func TestHandlers_ListCatalogModules_Search(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/catalog/modules?search=security", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var results []json.RawMessage
	assertPaginatedJSON(t, rr, &results)
	// Just verify it returns valid JSON, search may or may not match
}
