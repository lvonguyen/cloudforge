package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestQueryNLQ_NoAIProvider(t *testing.T) {
	_, router := testServer(t)
	// testServer sets enrichmentSvc.AI = nil by default.
	jwt := adminJWT(t)

	rr := doRequest(t, router, "POST", "/api/v1/ai/nlq", `{"query":"critical AWS findings"}`, jwt)
	assertStatus(t, rr, http.StatusServiceUnavailable)
}

func TestQueryNLQ_EmptyQuery(t *testing.T) {
	srv, router := testServer(t)
	srv.enrichmentSvc.AI = stubAIProvider{} // handler checks AI != nil before validating query
	jwt := adminJWT(t)

	rr := doRequest(t, router, "POST", "/api/v1/ai/nlq", `{"query":""}`, jwt)
	assertStatus(t, rr, http.StatusBadRequest)
}

func TestQueryNLQ_TooLong(t *testing.T) {
	srv, router := testServer(t)
	srv.enrichmentSvc.AI = stubAIProvider{}
	// Use operatorJWT to avoid per-user rate limit collision with EmptyQuery test
	jwt := operatorJWT(t)

	long := strings.Repeat("x", 501)
	body, _ := json.Marshal(map[string]string{"query": long})
	rr := doRequest(t, router, "POST", "/api/v1/ai/nlq", string(body), jwt)
	assertStatus(t, rr, http.StatusBadRequest)
}

func TestQueryNLQ_Unauthenticated(t *testing.T) {
	_, router := testServer(t)

	rr := doRequest(t, router, "POST", "/api/v1/ai/nlq", `{"query":"critical findings"}`, "")
	assertStatus(t, rr, http.StatusUnauthorized)
}

func TestQueryNLQ_ViewerForbidden(t *testing.T) {
	_, router := testServer(t)
	jwt := viewerJWT(t)

	rr := doRequest(t, router, "POST", "/api/v1/ai/nlq", `{"query":"critical findings"}`, jwt)
	if rr.Code == http.StatusForbidden {
		t.Errorf("status = 403, want non-forbidden (viewer parity)")
	}
}

func TestGetAIUsage_NoProvider(t *testing.T) {
	_, router := testServer(t)
	// testServer sets enrichmentSvc.AI = nil — handler returns zero budget.
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/ai/usage", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var result map[string]interface{}
	assertJSON(t, rr, &result)

	if result["monthly_budget_cents"] == nil {
		t.Error("expected monthly_budget_cents in response")
	}
	if result["spent_cents"] == nil {
		t.Error("expected spent_cents in response")
	}
	if result["remaining_cents"] == nil {
		t.Error("expected remaining_cents in response")
	}
	if exhausted, ok := result["exhausted"].(bool); !ok || exhausted {
		t.Errorf("expected exhausted=false, got %v", result["exhausted"])
	}
}

func TestGetAIUsage_Unauthenticated(t *testing.T) {
	_, router := testServer(t)

	rr := doRequest(t, router, "GET", "/api/v1/ai/usage", "", "")
	assertStatus(t, rr, http.StatusUnauthorized)
}

func TestGetAIUsage_OperatorForbidden(t *testing.T) {
	_, router := testServer(t)
	jwt := operatorJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/ai/usage", "", jwt)
	if rr.Code == http.StatusForbidden {
		t.Errorf("status = 403, want non-forbidden (viewer parity)")
	}
}
