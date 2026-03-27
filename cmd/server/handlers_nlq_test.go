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
	assertStatus(t, rr, http.StatusForbidden)
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
	assertStatus(t, rr, http.StatusForbidden)
}

func TestSanitizeNLQQuery(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"normal query", "normal query"},
		{"<script>alert(1)</script>critical AWS", "alert(1)critical AWS"},
		{"hello\x00world", "helloworld"},
		{"  spaced  ", "spaced"},
		{"<img src=x onerror=alert(1)>", ""},
		{"severity > HIGH", "severity > HIGH"}, // bare > not stripped
	}
	for _, tt := range tests {
		got := sanitizeNLQQuery(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeNLQQuery(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestValidateNLQResponse(t *testing.T) {
	resp := &NLQResponse{
		Severity:    []string{"CRITICAL", "INVALID", "HIGH"},
		Provider:    []string{"aws", "evil"},
		Category:    []string{"NETWORK"},
		Status:      []string{"open", "<script>xss</script>"},
		Environment: []string{"production"},
		Text:        "<b>bold</b> text",
	}
	validateNLQResponse(resp)

	if len(resp.Severity) != 2 || resp.Severity[0] != "CRITICAL" || resp.Severity[1] != "HIGH" {
		t.Errorf("severity = %v, want [CRITICAL HIGH]", resp.Severity)
	}
	if len(resp.Provider) != 1 || resp.Provider[0] != "aws" {
		t.Errorf("provider = %v, want [aws]", resp.Provider)
	}
	if len(resp.Status) != 1 || resp.Status[0] != "open" {
		t.Errorf("status = %v, want [open]", resp.Status)
	}
	if resp.Text != "bold text" {
		t.Errorf("text = %q, want %q", resp.Text, "bold text")
	}
}

func TestValidateNLQResponse_AllInvalid(t *testing.T) {
	resp := &NLQResponse{
		Severity: []string{"SUPER_CRITICAL"},
		Provider: []string{"oracle"},
	}
	validateNLQResponse(resp)

	if resp.Severity != nil {
		t.Errorf("severity = %v, want nil", resp.Severity)
	}
	if resp.Provider != nil {
		t.Errorf("provider = %v, want nil", resp.Provider)
	}
}
