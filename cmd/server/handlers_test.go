package main

import (
	"encoding/json"
	"net/http"
	"testing"

	"cloudforge/internal/grc"
)

func TestHealthCheck(t *testing.T) {
	_, router := testServer(t)

	rr := doRequest(t, router, "GET", "/health", "", "")
	assertStatus(t, rr, http.StatusOK)

	var result map[string]string
	assertJSON(t, rr, &result)

	if result["status"] != "healthy" {
		t.Errorf("status = %q, want %q", result["status"], "healthy")
	}
	if result["version"] != "0.1.0" {
		t.Errorf("version = %q, want %q", result["version"], "0.1.0")
	}
}

func TestCreateException_Success(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	body := `{"application_id":"app-001","policy_violated":"REGION-001","business_case":"testing","requestor_email":"admin@contoso.dev"}`
	rr := doRequest(t, router, "POST", "/api/v1/exceptions", body, jwt)
	assertStatus(t, rr, http.StatusCreated)

	var result grc.ExceptionRequest
	assertJSON(t, rr, &result)

	if result.ID == "" {
		t.Error("expected non-empty id in response")
	}
}

func TestCreateException_Unauthorized(t *testing.T) {
	_, router := testServer(t)

	body := `{"application_id":"app-001","policy_violated":"REGION-001","requestor_email":"nobody@example.com"}`
	rr := doRequest(t, router, "POST", "/api/v1/exceptions", body, "")
	assertStatus(t, rr, http.StatusUnauthorized)
}

func TestCreateException_Forbidden(t *testing.T) {
	_, router := testServer(t)
	jwt := requesterJWT(t)

	body := `{"application_id":"app-001","policy_violated":"REGION-001","requestor_email":"user@contoso.dev"}`
	rr := doRequest(t, router, "POST", "/api/v1/exceptions", body, jwt)
	assertStatus(t, rr, http.StatusForbidden)
}

func TestCreateException_IdentitySpoof(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	body := `{"application_id":"app-001","policy_violated":"REGION-001","requestor_email":"someone-else@example.com"}`
	rr := doRequest(t, router, "POST", "/api/v1/exceptions", body, jwt)
	assertStatus(t, rr, http.StatusForbidden)
}

func TestGetException_Success(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	// Create an exception first.
	createBody := `{"application_id":"app-001","policy_violated":"REGION-001","business_case":"testing","requestor_email":"admin@contoso.dev"}`
	createRR := doRequest(t, router, "POST", "/api/v1/exceptions", createBody, jwt)
	assertStatus(t, createRR, http.StatusCreated)

	var created grc.ExceptionRequest
	assertJSON(t, createRR, &created)
	if created.ID == "" {
		t.Fatal("expected non-empty id from create response")
	}

	// Fetch it by ID.
	rr := doRequest(t, router, "GET", "/api/v1/exceptions/"+created.ID, "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var fetched grc.ExceptionRequest
	assertJSON(t, rr, &fetched)
	if fetched.ID != created.ID {
		t.Errorf("fetched id = %q, want %q", fetched.ID, created.ID)
	}
}

func TestGetException_NotFound(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/exceptions/nonexistent-id", "", jwt)
	assertStatus(t, rr, http.StatusNotFound)
}

func TestSubmitApproval_Success(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	// Create an exception with the admin in the approver chain.
	createBody := `{"application_id":"app-001","policy_violated":"REGION-001","business_case":"testing","requestor_email":"admin@contoso.dev","approver_chain":[{"email":"admin@contoso.dev","role":"SECURITY_LEAD","decision":"PENDING"}]}`
	createRR := doRequest(t, router, "POST", "/api/v1/exceptions", createBody, jwt)
	assertStatus(t, createRR, http.StatusCreated)

	var created grc.ExceptionRequest
	assertJSON(t, createRR, &created)

	// Submit approval.
	approvalBody := `{"email":"admin@contoso.dev","role":"SECURITY_LEAD","decision":"APPROVED","comments":"approved for testing"}`
	rr := doRequest(t, router, "POST", "/api/v1/exceptions/"+created.ID+"/approve", approvalBody, jwt)
	assertStatus(t, rr, http.StatusOK)
}

func TestGetPendingApprovals(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	// Create an exception so there is at least one pending item.
	createBody := `{"application_id":"app-001","policy_violated":"REGION-001","business_case":"testing","requestor_email":"admin@contoso.dev"}`
	createRR := doRequest(t, router, "POST", "/api/v1/exceptions", createBody, jwt)
	assertStatus(t, createRR, http.StatusCreated)

	rr := doRequest(t, router, "GET", "/api/v1/exceptions/pending?approver_email=admin@contoso.dev", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var result []json.RawMessage
	assertJSON(t, rr, &result)
}

func TestGetExpiringExceptions_RequiresComplianceScope(t *testing.T) {
	_, router := testServer(t)
	jwt := operatorJWT(t) // scope "operator" — no compliance

	rr := doRequest(t, router, "GET", "/api/v1/exceptions/expiring", "", jwt)
	assertStatus(t, rr, http.StatusForbidden)
}

func TestGetExpiringExceptions_Success(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t) // scope "admin compliance"

	rr := doRequest(t, router, "GET", "/api/v1/exceptions/expiring", "", jwt)
	assertStatus(t, rr, http.StatusOK)
}

func TestValidateException(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	body := `{"application_id":"app-nonexistent","policy_code":"POL-999"}`
	rr := doRequest(t, router, "POST", "/api/v1/validate/exception", body, jwt)
	assertStatus(t, rr, http.StatusOK)

	var result grc.ExceptionValidation
	assertJSON(t, rr, &result)

	if result.Valid {
		t.Error("expected valid=false for nonexistent application/policy")
	}
}
