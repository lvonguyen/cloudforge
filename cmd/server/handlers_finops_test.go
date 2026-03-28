package main

import (
	"net/http"
	"strings"
	"testing"
)

func TestBudgetStatus_OperatorAllowed(t *testing.T) {
	_, router := testServer(t)
	jwt := operatorJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/costs/budgets", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var resp map[string]any
	assertJSON(t, rr, &resp)
	if _, ok := resp["alerts"]; !ok {
		t.Error("response missing 'alerts' field")
	}
	if _, ok := resp["checked_at"]; !ok {
		t.Error("response missing 'checked_at' field")
	}
}

func TestBudgetStatus_ViewerForbidden(t *testing.T) {
	_, router := testServer(t)
	jwt := viewerJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/costs/budgets", "", jwt)
	assertStatus(t, rr, http.StatusForbidden)
}

func TestBudgetStatus_AdminAllowed(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/costs/budgets", "", jwt)
	assertStatus(t, rr, http.StatusOK)
}

func TestCostEstimate_HappyPath(t *testing.T) {
	_, router := testServer(t)
	jwt := operatorJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/costs/estimate?resource_type=ec2&provider=aws&size=medium", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var resp map[string]any
	assertJSON(t, rr, &resp)
	if _, ok := resp["resource_type"]; !ok {
		t.Error("response missing 'resource_type' field")
	}
}

func TestCostEstimate_MissingParams(t *testing.T) {
	_, router := testServer(t)
	jwt := operatorJWT(t)

	tests := []struct {
		name string
		path string
	}{
		{"missing all", "/api/v1/costs/estimate"},
		{"missing provider", "/api/v1/costs/estimate?resource_type=ec2&size=medium"},
		{"missing size", "/api/v1/costs/estimate?resource_type=ec2&provider=aws"},
		{"missing resource_type", "/api/v1/costs/estimate?provider=aws&size=medium"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr := doRequest(t, router, "GET", tc.path, "", jwt)
			assertStatus(t, rr, http.StatusBadRequest)
		})
	}
}

func TestCostEstimate_UnknownResource(t *testing.T) {
	_, router := testServer(t)
	jwt := operatorJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/costs/estimate?resource_type=nonexistent&provider=aws&size=large", "", jwt)
	assertStatus(t, rr, http.StatusNotFound)
}

func TestCostEstimate_ViewerAllowed(t *testing.T) {
	_, router := testServer(t)
	jwt := viewerJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/costs/estimate?resource_type=ec2&provider=aws&size=small", "", jwt)
	assertStatus(t, rr, http.StatusOK)
}

func TestSupportedResources_HappyPath(t *testing.T) {
	_, router := testServer(t)
	jwt := viewerJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/costs/resources", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var resp map[string]any
	assertJSON(t, rr, &resp)
	resources, ok := resp["resources"]
	if !ok {
		t.Fatal("response missing 'resources' field")
	}
	arr, ok := resources.([]any)
	if !ok || len(arr) == 0 {
		t.Error("expected non-empty resources array")
	}
	if _, ok := resp["count"]; !ok {
		t.Error("response missing 'count' field")
	}
}

func TestCostEstimate_ErrorMessageDoesNotLeakInternal(t *testing.T) {
	_, router := testServer(t)
	jwt := operatorJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/costs/estimate?resource_type=nonexistent&provider=aws&size=xl", "", jwt)
	assertStatus(t, rr, http.StatusNotFound)

	body := rr.Body.String()
	// Verify the error message is generic, not the internal err.Error().
	if strings.Contains(body, "pricing") || strings.Contains(body, "pricingTable") {
		t.Errorf("error response leaks internal details: %s", body)
	}
}
