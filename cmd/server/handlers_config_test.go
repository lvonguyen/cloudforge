package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"aegis/internal/tenant"

	"go.uber.org/zap"
)

func newTestServerWithTenants(t *testing.T) (*Server, tenant.Store) {
	t.Helper()
	store := tenant.NewMemoryStore()
	_ = store.Upsert(context.Background(), &tenant.Config{
		ID:   "contoso",
		Name: "Contoso Inc.",
		Branding: tenant.Branding{
			CompanyName:  "Contoso Inc.",
			ProductName:  "Aegis",
			LogoPath:     "/logo.svg",
			PrimaryColor: "#f59e0b",
			AccentColor:  "#f97316",
		},
		EnabledModules: []string{"cspm", "grc"},
	})
	_ = store.Upsert(context.Background(), &tenant.Config{
		ID:   "acme",
		Name: "Acme Corp",
		Branding: tenant.Branding{
			CompanyName:  "Acme Corp",
			ProductName:  "SecureCloud",
			LogoPath:     "/acme-logo.svg",
			EmailDomain:  "acme.example.com",
			PrimaryColor: "#22c55e",
			AccentColor:  "#16a34a",
		},
		EnabledModules: []string{"cspm", "grc", "identity"},
	})

	srv := &Server{
		tenantStore: store,
		logger:      zap.NewNop(),
	}
	return srv, store
}

func TestHandleConfig_DefaultTenant(t *testing.T) {
	srv, _ := newTestServerWithTenants(t)

	req := httptest.NewRequest("GET", "/api/v1/config", nil)
	rr := httptest.NewRecorder()

	srv.handleConfig(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp configResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.CompanyName != "Contoso Inc." {
		t.Errorf("expected company name 'Contoso Inc.', got %q", resp.CompanyName)
	}
	if resp.ProductName != "Aegis" {
		t.Errorf("expected product name 'Aegis', got %q", resp.ProductName)
	}

	cacheControl := rr.Header().Get("Cache-Control")
	if cacheControl != "no-store" {
		t.Errorf("expected Cache-Control 'no-store', got %q", cacheControl)
	}
}

func TestHandleConfig_AcmeTenant(t *testing.T) {
	srv, store := newTestServerWithTenants(t)

	// Simulate tenant middleware having resolved Acme
	acmeCfg, _ := store.Get(context.Background(), "acme")

	req := httptest.NewRequest("GET", "/api/v1/config", nil)
	req = req.WithContext(tenant.WithContext(req.Context(), acmeCfg))
	rr := httptest.NewRecorder()

	srv.handleConfig(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp configResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.CompanyName != "Acme Corp" {
		t.Errorf("expected company name 'Acme Corp', got %q", resp.CompanyName)
	}
	if resp.ProductName != "SecureCloud" {
		t.Errorf("expected product name 'SecureCloud', got %q", resp.ProductName)
	}
	if resp.EmailDomain != "acme.example.com" {
		t.Errorf("expected email domain 'acme.example.com', got %q", resp.EmailDomain)
	}
	if resp.Theme["primaryColor"] != "#22c55e" {
		t.Errorf("expected primary color '#22c55e', got %q", resp.Theme["primaryColor"])
	}
	if resp.StoragePrefix != "acme" {
		t.Errorf("expected storage prefix 'acme', got %q", resp.StoragePrefix)
	}
}

func TestHandleConfig_Unauthenticated(t *testing.T) {
	srv, _ := newTestServerWithTenants(t)

	req := httptest.NewRequest("GET", "/config.json", nil)
	rr := httptest.NewRecorder()

	// No auth context, no tenant — should still return 200 with defaults
	srv.handleConfig(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for unauthenticated request, got %d", rr.Code)
	}

	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", contentType)
	}
}
