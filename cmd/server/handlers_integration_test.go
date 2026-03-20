package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"aegis/internal/integrations"
)

func TestRemediateFinding_Success(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	body := `{"severity":"CRITICAL","is_choke_point":true}`
	rr := doRequest(t, router, "POST", "/api/v1/findings/finding-001/remediate", body, jwt)
	assertStatus(t, rr, http.StatusCreated)

	var resp struct {
		Ticket  *integrations.Ticket          `json:"ticket"`
		Routing *integrations.RoutingDecision `json:"routing"`
	}
	assertJSON(t, rr, &resp)

	if resp.Ticket == nil {
		t.Fatal("expected ticket in response")
	}
	if resp.Ticket.Provider != "mock" {
		t.Errorf("expected provider mock, got %q", resp.Ticket.Provider)
	}
	if resp.Routing.Priority != integrations.PriorityUrgent {
		t.Errorf("expected urgent priority, got %q", resp.Routing.Priority)
	}
	if resp.Routing.SLAHours != 4 {
		t.Errorf("expected 4h SLA, got %d", resp.Routing.SLAHours)
	}
}

func TestRemediateFinding_Forbidden(t *testing.T) {
	_, router := testServer(t)
	jwt := operatorJWT(t)

	rr := doRequest(t, router, "POST", "/api/v1/findings/f-001/remediate", `{}`, jwt)
	if rr.Code == http.StatusForbidden {
		t.Errorf("status = 403, want non-forbidden (viewer parity)")
	}
}

func TestGetFindingTicket_NotFound(t *testing.T) {
	_, router := testServer(t)
	jwt := operatorJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/findings/nonexistent/ticket", "", jwt)
	assertStatus(t, rr, http.StatusNotFound)
}

func TestGetFindingTicket_AfterRemediate(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	doRequest(t, router, "POST", "/api/v1/findings/f-ticket-test/remediate", `{"severity":"HIGH"}`, jwt)

	rr := doRequest(t, router, "GET", "/api/v1/findings/f-ticket-test/ticket", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var ticket integrations.Ticket
	assertJSON(t, rr, &ticket)
	if ticket.FindingID != "f-ticket-test" {
		t.Errorf("expected finding_id f-ticket-test, got %q", ticket.FindingID)
	}
}

func TestAsanaWebhook_Handshake(t *testing.T) {
	_, router := testServer(t)

	req, _ := http.NewRequest("POST", "/api/v1/webhooks/asana", nil)
	req.Header.Set("X-Hook-Secret", "test-secret-123")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assertStatus(t, rr, http.StatusOK)

	if got := rr.Header().Get("X-Hook-Secret"); got != "test-secret-123" {
		t.Errorf("expected X-Hook-Secret echoed, got %q", got)
	}
}

func TestAsanaWebhook_EventDelivery(t *testing.T) {
	_, router := testServer(t)

	body := `{"events":[{"action":"changed"}]}`
	req, _ := http.NewRequest("POST", "/api/v1/webhooks/asana", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assertStatus(t, rr, http.StatusOK)
}
