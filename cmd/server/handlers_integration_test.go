package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"aegis/internal/integrations"
)

type stubFindingTicketStore struct {
	mu      sync.RWMutex
	tickets map[string]*integrations.Ticket
}

func (s *stubFindingTicketStore) GetTicket(_ context.Context, tenantID, findingID string) (*integrations.Ticket, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.tickets == nil {
		return nil, nil
	}
	ticket, ok := s.tickets[normalizeTicketTenantID(tenantID)+":"+findingID]
	if !ok {
		return nil, nil
	}
	copy := *ticket
	return &copy, nil
}

func (s *stubFindingTicketStore) PutTicket(_ context.Context, tenantID string, ticket *integrations.Ticket) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tickets == nil {
		s.tickets = make(map[string]*integrations.Ticket)
	}
	copy := *ticket
	s.tickets[normalizeTicketTenantID(tenantID)+":"+ticket.FindingID] = &copy
	return nil
}

func computeAsanaHMAC(secret, body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	return hex.EncodeToString(mac.Sum(nil))
}

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

func TestGetFindingTicket_FromDurableStore(t *testing.T) {
	srv, router := testServer(t)
	jwt := operatorJWT(t)
	repo := &stubFindingTicketStore{}
	srv.integrationHandler.ticketRepo = repo
	repo.tickets = map[string]*integrations.Ticket{
		"default:f-durable": {
			ID:         "ticket-1",
			ExternalID: "JIRA-42",
			Provider:   "jira",
			FindingID:  "f-durable",
			Title:      "Persisted remediation ticket",
			Status:     integrations.TicketStatusInProgress,
			Priority:   integrations.PriorityHigh,
			Assignee:   "alice",
			URL:        "https://jira.local/browse/JIRA-42",
		},
	}

	rr := doRequest(t, router, "GET", "/api/v1/findings/f-durable/ticket", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var ticket integrations.Ticket
	assertJSON(t, rr, &ticket)
	if ticket.ExternalID != "JIRA-42" {
		t.Fatalf("external_id = %q, want JIRA-42", ticket.ExternalID)
	}
	if ticket.Provider != "jira" {
		t.Fatalf("provider = %q, want jira", ticket.Provider)
	}
}

func TestSyncTicketStatus_PersistsDurableStore(t *testing.T) {
	srv, router := testServer(t)
	jwt := adminJWT(t)
	repo := &stubFindingTicketStore{}
	srv.integrationHandler.ticketRepo = repo

	doRequest(t, router, "POST", "/api/v1/findings/f-sync/remediate", `{"severity":"HIGH"}`, jwt)

	mockProvider, ok := srv.integrationHandler.provider.(*integrations.MockProvider)
	if !ok {
		t.Fatal("expected mock ticket provider")
	}
	ticket, found := mockProvider.GetTicketByFindingID("f-sync")
	if !found {
		t.Fatal("expected ticket in mock provider")
	}
	ticket.Status = integrations.TicketStatusInProgress

	srv.integrationHandler.ticketMu.Lock()
	srv.integrationHandler.ticketStore = make(map[string]*integrations.Ticket)
	srv.integrationHandler.ticketMu.Unlock()

	rr := doRequest(t, router, "POST", "/api/v1/findings/f-sync/ticket/sync", `{}`, jwt)
	assertStatus(t, rr, http.StatusOK)

	stored, err := repo.GetTicket(context.Background(), defaultSecgraphTenantID, "f-sync")
	if err != nil {
		t.Fatalf("repo.GetTicket: %v", err)
	}
	if stored == nil {
		t.Fatal("expected synced ticket in durable store")
	}
	if stored.Status != integrations.TicketStatusInProgress {
		t.Fatalf("status = %q, want %q", stored.Status, integrations.TicketStatusInProgress)
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

	// Perform handshake first so the secret is persisted
	hsReq, _ := http.NewRequest("POST", "/api/v1/webhooks/asana", nil)
	hsReq.Header.Set("X-Hook-Secret", "test-secret-123")
	hsRR := httptest.NewRecorder()
	router.ServeHTTP(hsRR, hsReq)
	assertStatus(t, hsRR, http.StatusOK)

	// Event delivery with valid HMAC signature
	body := `{"events":[{"action":"changed"}]}`
	sig := computeAsanaHMAC("test-secret-123", body)
	req, _ := http.NewRequest("POST", "/api/v1/webhooks/asana", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Hook-Signature", sig)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assertStatus(t, rr, http.StatusOK)
}

func TestAsanaWebhook_EventDelivery_NoSignature(t *testing.T) {
	_, router := testServer(t)

	// Handshake
	hsReq, _ := http.NewRequest("POST", "/api/v1/webhooks/asana", nil)
	hsReq.Header.Set("X-Hook-Secret", "test-secret-123")
	hsRR := httptest.NewRecorder()
	router.ServeHTTP(hsRR, hsReq)
	assertStatus(t, hsRR, http.StatusOK)

	// Event without signature -> 401
	body := `{"events":[{"action":"changed"}]}`
	req, _ := http.NewRequest("POST", "/api/v1/webhooks/asana", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assertStatus(t, rr, http.StatusUnauthorized)
}
