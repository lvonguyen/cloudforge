package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"cloudforge/internal/tenant"

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
			ProductName:  "CloudForge",
			LogoPath:     "/logo.svg",
			PrimaryColor: "#f59e0b",
			AccentColor:  "#f97316",
		},
		EnabledModules: []string{"cspm", "grc"},
	})
	_ = store.Upsert(context.Background(), &tenant.Config{
		ID:   "haea",
		Name: "HAEA Security",
		Branding: tenant.Branding{
			CompanyName:  "HAEA Security",
			ProductName:  "SecureCloud",
			LogoPath:     "/haea-logo.svg",
			EmailDomain:  "haea.io",
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
	if resp.ProductName != "CloudForge" {
		t.Errorf("expected product name 'CloudForge', got %q", resp.ProductName)
	}

	cacheControl := rr.Header().Get("Cache-Control")
	if cacheControl != "no-store" {
		t.Errorf("expected Cache-Control 'no-store', got %q", cacheControl)
	}
}

func TestHandleConfig_HAEATenant(t *testing.T) {
	srv, store := newTestServerWithTenants(t)

	// Simulate tenant middleware having resolved HAEA
	haeCfg, _ := store.Get(context.Background(), "haea")

	req := httptest.NewRequest("GET", "/api/v1/config", nil)
	req = req.WithContext(tenant.WithContext(req.Context(), haeCfg))
	rr := httptest.NewRecorder()

	srv.handleConfig(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp configResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.CompanyName != "HAEA Security" {
		t.Errorf("expected company name 'HAEA Security', got %q", resp.CompanyName)
	}
	if resp.ProductName != "SecureCloud" {
		t.Errorf("expected product name 'SecureCloud', got %q", resp.ProductName)
	}
	if resp.EmailDomain != "haea.io" {
		t.Errorf("expected email domain 'haea.io', got %q", resp.EmailDomain)
	}
	if resp.Theme["primaryColor"] != "#22c55e" {
		t.Errorf("expected primary color '#22c55e', got %q", resp.Theme["primaryColor"])
	}
	if resp.StoragePrefix != "haea" {
		t.Errorf("expected storage prefix 'haea', got %q", resp.StoragePrefix)
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
