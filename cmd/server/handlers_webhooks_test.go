package main

import (
	"encoding/json"
	"net/http"
	"testing"

	"aegis/internal/webhooks"
)

func TestRegisterWebhook_Success(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	body := `{"url":"https://example.com/hook","secret":"s3cr3t","events":["finding.created"]}`
	rr := doRequest(t, router, "POST", "/api/v1/webhooks", body, jwt)
	assertStatus(t, rr, http.StatusCreated)

	var ep webhooks.Endpoint
	assertJSON(t, rr, &ep)
	if ep.URL != "https://example.com/hook" {
		t.Errorf("expected URL, got %q", ep.URL)
	}
	if ep.ID == "" {
		t.Error("expected non-empty endpoint ID")
	}
}

func TestListWebhooks_Empty(t *testing.T) {
	_, router := testServer(t)
	jwt := operatorJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/webhooks", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var endpoints []webhooks.Endpoint
	assertJSON(t, rr, &endpoints)
	if len(endpoints) != 0 {
		t.Errorf("expected empty list, got %d", len(endpoints))
	}
}

func TestDeleteWebhook_NotFound(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "DELETE", "/api/v1/webhooks/nonexistent-id", "", jwt)
	assertStatus(t, rr, http.StatusNotFound)
}

func TestWebhookDeliveries_Empty(t *testing.T) {
	_, router := testServer(t)
	jwt := operatorJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/webhooks/some-id/deliveries", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var deliveries []json.RawMessage
	assertJSON(t, rr, &deliveries)
	if len(deliveries) != 0 {
		t.Errorf("expected empty deliveries, got %d", len(deliveries))
	}
}
