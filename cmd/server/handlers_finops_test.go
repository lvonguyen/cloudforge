package main

import (
	"net/http"
	"strings"
	"testing"

	"aegis/internal/finops"
	"aegis/internal/finops/alerting"
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

func TestBudgetStatus_ReturnsFiredAlerts(t *testing.T) {
	srv, router := testServer(t)
	srv.finopsSvc = newFinopsServiceFromAggregator(finops.NewMemoryAggregator(), []alerting.BudgetRule{
		{
			Name:       "AWS Test Budget",
			Provider:   "aws",
			MonthlyUSD: 1,
			Thresholds: []float64{80},
		},
	})
	jwt := operatorJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/costs/budgets", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var resp struct {
		Alerts []alerting.BudgetAlert `json:"alerts"`
	}
	assertJSON(t, rr, &resp)

	if len(resp.Alerts) != 1 {
		t.Fatalf("expected 1 fired alert, got %d", len(resp.Alerts))
	}
	if resp.Alerts[0].BudgetName != "AWS Test Budget" {
		t.Fatalf("expected alert for AWS Test Budget, got %q", resp.Alerts[0].BudgetName)
	}
	if resp.Alerts[0].Provider != "aws" {
		t.Fatalf("expected aws provider alert, got %q", resp.Alerts[0].Provider)
	}
	if resp.Alerts[0].ActualUSD <= 0 {
		t.Fatalf("expected positive spend in fired alert, got %f", resp.Alerts[0].ActualUSD)
	}
	if resp.Alerts[0].Severity != alerting.SeverityWarning {
		t.Fatalf("expected warning severity, got %q", resp.Alerts[0].Severity)
	}
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
