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
	"time"

	"aegis/internal/integrations"
)

type stubFindingTicketStore struct {
	mu      sync.RWMutex
	tickets map[string]*integrations.Ticket
}

type stubTicketProvider struct {
	name    string
	tickets map[string]*integrations.Ticket
}

func (p *stubTicketProvider) Name() string { return p.name }

func (p *stubTicketProvider) CreateTicket(_ context.Context, req integrations.CreateTicketRequest) (*integrations.Ticket, error) {
	now := time.Now().UTC()
	return &integrations.Ticket{
		ID:         req.FindingID,
		ExternalID: req.FindingID,
		Provider:   p.name,
		FindingID:  req.FindingID,
		Title:      req.Title,
		Status:     integrations.TicketStatusOpen,
		Priority:   req.Priority,
		Assignee:   req.Assignee,
		CreatedAt:  now,
		UpdatedAt:  now,
	}, nil
}

func (p *stubTicketProvider) GetTicket(_ context.Context, externalID string) (*integrations.Ticket, error) {
	ticket, ok := p.tickets[externalID]
	if !ok {
		return nil, http.ErrMissingFile
	}
	copy := *ticket
	return &copy, nil
}

func (p *stubTicketProvider) AddComment(_ context.Context, externalID, body string) (*integrations.CommentSync, error) {
	return &integrations.CommentSync{
		ID:         "comment-" + externalID,
		ExternalID: "comment-" + externalID,
		Body:       body,
		Author:     "stub",
		CreatedAt:  time.Now().UTC(),
	}, nil
}

func (p *stubTicketProvider) SyncStatus(_ context.Context, externalID string) (integrations.TicketStatus, error) {
	ticket, ok := p.tickets[externalID]
	if !ok {
		return "", http.ErrMissingFile
	}
	return ticket.Status, nil
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

func TestGetFindingTicket_RefreshesFromProviderAndDurableStore(t *testing.T) {
	srv, router := testServer(t)
	jwt := operatorJWT(t)
	repo := &stubFindingTicketStore{
		tickets: map[string]*integrations.Ticket{
			"default:f-refresh": {
				ID:         "JIRA-77",
				ExternalID: "JIRA-77",
				Provider:   "jira",
				FindingID:  "f-refresh",
				Title:      "Persisted remediation ticket",
				Status:     integrations.TicketStatusOpen,
				Priority:   integrations.PriorityHigh,
				Assignee:   "alice",
				URL:        "https://jira.local/browse/JIRA-77",
				CreatedAt:  time.Now().Add(-2 * time.Hour).UTC(),
				UpdatedAt:  time.Now().Add(-2 * time.Hour).UTC(),
			},
		},
	}
	jiraProvider := &stubTicketProvider{
		name: "jira",
		tickets: map[string]*integrations.Ticket{
			"JIRA-77": {
				ID:         "JIRA-77",
				ExternalID: "JIRA-77",
				Provider:   "jira",
				Title:      "Persisted remediation ticket",
				Status:     integrations.TicketStatusResolved,
				Priority:   integrations.PriorityHigh,
				Assignee:   "bob",
				URL:        "https://jira.local/browse/JIRA-77",
				CreatedAt:  time.Now().Add(-2 * time.Hour).UTC(),
				UpdatedAt:  time.Now().UTC(),
			},
		},
	}

	srv.integrationHandler.ticketRepo = repo
	srv.integrationHandler.provider = jiraProvider
	srv.integrationHandler.providers = map[string]integrations.TicketProvider{"jira": jiraProvider}

	rr := doRequest(t, router, "GET", "/api/v1/findings/f-refresh/ticket", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var ticket integrations.Ticket
	assertJSON(t, rr, &ticket)
	if ticket.Status != integrations.TicketStatusResolved {
		t.Fatalf("status = %q, want %q", ticket.Status, integrations.TicketStatusResolved)
	}
	if ticket.Assignee != "bob" {
		t.Fatalf("assignee = %q, want bob", ticket.Assignee)
	}

	stored, err := repo.GetTicket(context.Background(), defaultSecgraphTenantID, "f-refresh")
	if err != nil {
		t.Fatalf("repo.GetTicket: %v", err)
	}
	if stored == nil {
		t.Fatal("expected refreshed ticket in durable store")
	}
	if stored.Status != integrations.TicketStatusResolved {
		t.Fatalf("stored status = %q, want %q", stored.Status, integrations.TicketStatusResolved)
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

func TestAsanaWebhook_EventDelivery_RefreshesMatchingCachedTicket(t *testing.T) {
	srv, router := testServer(t)
	repo := &stubFindingTicketStore{}
	asanaProvider := &stubTicketProvider{
		name: "asana",
		tickets: map[string]*integrations.Ticket{
			"12001": {
				ID:         "12001",
				ExternalID: "12001",
				Provider:   "asana",
				Title:      "Cloud Aegis ticket",
				Status:     integrations.TicketStatusResolved,
				Priority:   integrations.PriorityHigh,
				Assignee:   "automation-bot",
				URL:        "https://app.asana.com/0/1/12001",
				CreatedAt:  time.Now().Add(-time.Hour).UTC(),
				UpdatedAt:  time.Now().UTC(),
			},
		},
	}
	srv.integrationHandler.provider = asanaProvider
	srv.integrationHandler.providers = map[string]integrations.TicketProvider{"asana": asanaProvider}
	srv.integrationHandler.ticketRepo = repo
	srv.integrationHandler.storeTicket(context.Background(), defaultSecgraphTenantID, "f-asana", &integrations.Ticket{
		ID:         "12001",
		ExternalID: "12001",
		Provider:   "asana",
		FindingID:  "f-asana",
		Title:      "Cloud Aegis ticket",
		Status:     integrations.TicketStatusOpen,
		Priority:   integrations.PriorityHigh,
		URL:        "https://app.asana.com/0/1/12001",
		CreatedAt:  time.Now().Add(-time.Hour).UTC(),
		UpdatedAt:  time.Now().Add(-time.Hour).UTC(),
	})

	hsReq, _ := http.NewRequest("POST", "/api/v1/webhooks/asana", nil)
	hsReq.Header.Set("X-Hook-Secret", "test-secret-123")
	hsRR := httptest.NewRecorder()
	router.ServeHTTP(hsRR, hsReq)
	assertStatus(t, hsRR, http.StatusOK)

	body := `{"events":[{"action":"changed","resource":{"gid":"story-1","resource_type":"story"},"parent":{"gid":"12001","resource_type":"task"}}]}`
	sig := computeAsanaHMAC("test-secret-123", body)
	req, _ := http.NewRequest("POST", "/api/v1/webhooks/asana", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Hook-Signature", sig)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assertStatus(t, rr, http.StatusOK)

	stored, err := repo.GetTicket(context.Background(), defaultSecgraphTenantID, "f-asana")
	if err != nil {
		t.Fatalf("repo.GetTicket: %v", err)
	}
	if stored == nil {
		t.Fatal("expected refreshed ticket in durable store")
	}
	if stored.Status != integrations.TicketStatusResolved {
		t.Fatalf("stored status = %q, want %q", stored.Status, integrations.TicketStatusResolved)
	}
	if stored.Assignee != "automation-bot" {
		t.Fatalf("stored assignee = %q, want automation-bot", stored.Assignee)
	}
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
