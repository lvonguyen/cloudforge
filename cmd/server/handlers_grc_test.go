package main

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"aegis/internal/api"
	"aegis/internal/grc"
)

// --- GetExceptionsByApp ownership tests ---

func TestGetExceptionsByApp_AdminBypass(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t) // Subject: "test-admin", role: admin

	rr := doRequest(t, router, "GET", "/api/v1/applications/any-app/exceptions", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	// Memory provider returns null/[] for an app with no exceptions.
	// Verify the body is valid JSON (not an error object).
	var raw json.RawMessage
	if err := json.NewDecoder(rr.Body).Decode(&raw); err != nil {
		t.Fatalf("response body is not valid JSON: %v; body: %s", err, rr.Body.String())
	}
}

func TestGetExceptionsByApp_MatchingSubject(t *testing.T) {
	_, router := testServer(t)
	// Operator role with Subject matching the appId path param.
	jwt := makeJWT(t, api.Claims{
		Subject: "my-app",
		Email:   "my-app@contoso.dev",
		Groups:  []string{"aegis-operator"},
		Scope:   "operator",
	})

	rr := doRequest(t, router, "GET", "/api/v1/applications/my-app/exceptions", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var result []grc.ExceptionRequest
	assertJSON(t, rr, &result)
}

func TestGetExceptionsByApp_NonMatchingSubject(t *testing.T) {
	_, router := testServer(t)
	// Operator JWT whose Subject does not match the appId.
	jwt := makeJWT(t, api.Claims{
		Subject: "test-operator",
		Email:   "operator@contoso.dev",
		Groups:  []string{"aegis-operator"},
		Scope:   "operator",
	})

	rr := doRequest(t, router, "GET", "/api/v1/applications/other-app/exceptions", "", jwt)
	assertStatus(t, rr, http.StatusForbidden) // app-level ownership check — not route RBAC

	var errResp map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err == nil {
		msg := errResp["error"]
		if msg == "" {
			t.Error("expected non-empty error message in 403 body")
		}
	}
}

func TestGetExceptionsByApp_Unauthenticated(t *testing.T) {
	_, router := testServer(t)

	rr := doRequest(t, router, "GET", "/api/v1/applications/any-app/exceptions", "", "")
	assertStatus(t, rr, http.StatusUnauthorized)
}

// --- patchRemediation RBAC tests ---

// firstRemediationID returns the ID of the first remediation in the data store.
// It skips the test if no remediations are present.
func firstRemediationID(t *testing.T, srv *Server) string {
	t.Helper()
	for id := range srv.data.RemediationsByID {
		return id
	}
	t.Skip("no remediations in mock data")
	return ""
}

func TestPatchRemediation_Success(t *testing.T) {
	srv, router := testServer(t)
	jwt := operatorJWT(t)

	id := firstRemediationID(t, srv)

	rr := doRequest(t, router, "PATCH", "/api/v1/remediations/"+id, `{"status":"in_progress"}`, jwt)
	assertStatus(t, rr, http.StatusOK)

	var result RemediationRecord
	assertJSON(t, rr, &result)
	if result.Status != "in_progress" {
		t.Errorf("status = %q, want in_progress", result.Status)
	}
	if result.ID != id {
		t.Errorf("id = %q, want %q", result.ID, id)
	}
	if result.UpdatedAt == "" {
		t.Error("expected non-empty updated_at after patch")
	}
}

func TestPatchRemediation_InvalidStatus(t *testing.T) {
	srv, router := testServer(t)
	jwt := adminJWT(t)

	id := firstRemediationID(t, srv)

	rr := doRequest(t, router, "PATCH", "/api/v1/remediations/"+id, `{"status":"flying"}`, jwt)
	assertStatus(t, rr, http.StatusBadRequest)
}

func TestPatchRemediation_NotFound(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "PATCH", "/api/v1/remediations/rem-nonexistent", `{"status":"completed"}`, jwt)
	assertStatus(t, rr, http.StatusNotFound)
}

func TestPatchRemediation_ViewerForbidden(t *testing.T) {
	_, router := testServer(t)
	jwt := viewerJWT(t)

	rr := doRequest(t, router, "PATCH", "/api/v1/remediations/rem-001", `{"status":"in_progress"}`, jwt)
	if rr.Code == http.StatusForbidden {
		t.Errorf("status = 403, want non-forbidden (viewer parity)")
	}
}

func TestPatchRemediation_Unauthenticated(t *testing.T) {
	_, router := testServer(t)

	rr := doRequest(t, router, "PATCH", "/api/v1/remediations/rem-001", `{"status":"in_progress"}`, "")
	assertStatus(t, rr, http.StatusUnauthorized)
}

// --- WithdrawException tests ---

// seedPendingException creates a PENDING exception with the given requestor email
// and returns its ID. The provider is accessed via the server's grcHandler.
func seedPendingException(t *testing.T, srv *Server, requestorEmail string) string {
	t.Helper()
	ctx := context.Background()
	exc, err := srv.grcHandler.provider.CreateException(ctx, &grc.ExceptionRequest{
		ApplicationID:  "test-app",
		RequestorEmail: requestorEmail,
		PolicyViolated: "COST-001",
		BusinessCase:   "test withdrawal",
	})
	if err != nil {
		t.Fatalf("seed exception: %v", err)
	}
	return exc.ID
}

func TestWithdrawException_Success(t *testing.T) {
	srv, router := testServer(t)

	const requestor = "alice@test.com"
	excID := seedPendingException(t, srv, requestor)

	jwt := makeJWT(t, api.Claims{
		Subject: requestor,
		Email:   requestor,
		Scope:   "requester",
	})

	rr := doRequest(t, router, "POST", "/api/v1/exceptions/"+excID+"/withdraw", "{}", jwt)
	assertStatus(t, rr, http.StatusOK)

	var result grc.ExceptionRequest
	assertJSON(t, rr, &result)
	if result.Status != grc.StatusRevoked {
		t.Errorf("status = %q, want %q", result.Status, grc.StatusRevoked)
	}
}

func TestWithdrawException_AdminCanWithdraw(t *testing.T) {
	srv, router := testServer(t)

	excID := seedPendingException(t, srv, "alice@test.com")
	jwt := adminJWT(t) // admin, different subject

	rr := doRequest(t, router, "POST", "/api/v1/exceptions/"+excID+"/withdraw", "{}", jwt)
	assertStatus(t, rr, http.StatusOK)

	var result grc.ExceptionRequest
	assertJSON(t, rr, &result)
	if result.Status != grc.StatusRevoked {
		t.Errorf("status = %q, want %q", result.Status, grc.StatusRevoked)
	}
}

func TestWithdrawException_NotPending(t *testing.T) {
	srv, router := testServer(t)

	const requestor = "alice@test.com"
	excID := seedPendingException(t, srv, requestor)

	// Move to APPROVED so withdraw should fail with 409.
	ctx := context.Background()
	exc, _ := srv.grcHandler.provider.GetException(ctx, excID)
	exc.Status = grc.StatusApproved
	if err := srv.grcHandler.provider.UpdateException(ctx, exc); err != nil {
		t.Fatalf("update exception: %v", err)
	}

	jwt := makeJWT(t, api.Claims{
		Subject: requestor,
		Email:   requestor,
		Scope:   "requester",
	})

	rr := doRequest(t, router, "POST", "/api/v1/exceptions/"+excID+"/withdraw", "{}", jwt)
	assertStatus(t, rr, http.StatusConflict)

	var errResp map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err == nil {
		if errResp["error"] == "" {
			t.Error("expected non-empty error message in 409 body")
		}
	}
}

func TestWithdrawException_WrongUser(t *testing.T) {
	srv, router := testServer(t)

	excID := seedPendingException(t, srv, "alice@test.com")

	// bob is a requester, not the requestor and not admin.
	jwt := makeJWT(t, api.Claims{
		Subject: "bob@test.com",
		Email:   "bob@test.com",
		Scope:   "requester",
	})

	rr := doRequest(t, router, "POST", "/api/v1/exceptions/"+excID+"/withdraw", "{}", jwt)
	assertStatus(t, rr, http.StatusForbidden) // user-level ownership check
}

func TestWithdrawException_NotFound(t *testing.T) {
	_, router := testServer(t)

	jwt := adminJWT(t)
	rr := doRequest(t, router, "POST", "/api/v1/exceptions/nonexistent-id/withdraw", "{}", jwt)
	assertStatus(t, rr, http.StatusNotFound)
}

func TestWithdrawException_Unauthenticated(t *testing.T) {
	srv, router := testServer(t)
	excID := seedPendingException(t, srv, "alice@test.com")

	rr := doRequest(t, router, "POST", "/api/v1/exceptions/"+excID+"/withdraw", "{}", "")
	assertStatus(t, rr, http.StatusUnauthorized)
}
