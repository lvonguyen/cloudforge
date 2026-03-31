package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"aegis/internal/integrations"
)

func TestHandleProviderStatus_IncludesIntegrationStatus(t *testing.T) {
	srv, _ := testServer(t)
	jiraProvider := &stubTicketProvider{name: "jira", tickets: map[string]*integrations.Ticket{}}
	asanaProvider := &stubTicketProvider{name: "asana", tickets: map[string]*integrations.Ticket{}}
	srv.integrationHandler.provider = jiraProvider
	srv.integrationHandler.providers = map[string]integrations.TicketProvider{
		"jira":  jiraProvider,
		"asana": asanaProvider,
	}
	srv.integrationHandler.asanaWebhookToken = "configured-token"
	srv.integrationHandler.ticketRepo = &stubFindingTicketStore{}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/providers", nil)
	rr := httptest.NewRecorder()

	srv.handleProviderStatus(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var resp struct {
		Integrations struct {
			Default      string   `json:"default"`
			Enabled      []string `json:"enabled"`
			TicketStore  string   `json:"ticket_store"`
			AsanaWebhook string   `json:"asana_webhook"`
		} `json:"integrations"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.Integrations.Default != "jira" {
		t.Fatalf("default = %q, want jira", resp.Integrations.Default)
	}
	if got, want := len(resp.Integrations.Enabled), 2; got != want {
		t.Fatalf("enabled count = %d, want %d", got, want)
	}
	if resp.Integrations.Enabled[0] != "asana" || resp.Integrations.Enabled[1] != "jira" {
		t.Fatalf("enabled = %#v, want [asana jira]", resp.Integrations.Enabled)
	}
	if resp.Integrations.TicketStore != "durable" {
		t.Fatalf("ticket_store = %q, want durable", resp.Integrations.TicketStore)
	}
	if resp.Integrations.AsanaWebhook != "configured" {
		t.Fatalf("asana_webhook = %q, want configured", resp.Integrations.AsanaWebhook)
	}
}
