package tenant

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"cloudforge/internal/api"

	"go.uber.org/zap"
)

func seedStore(t *testing.T) Store {
	t.Helper()
	store := NewMemoryStore()
	if err := store.Upsert(context.Background(), &Config{
		ID:   "contoso",
		Name: "Contoso Inc.",
		Branding: Branding{
			CompanyName:  "Contoso Inc.",
			ProductName:  "CloudForge",
			LogoPath:     "/logo.svg",
			PrimaryColor: "#f59e0b",
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Upsert(context.Background(), &Config{
		ID:   "haea",
		Name: "HAEA Security",
		Branding: Branding{
			CompanyName:  "HAEA Security",
			ProductName:  "SecureCloud",
			LogoPath:     "/haea-logo.svg",
			PrimaryColor: "#22c55e",
		},
	}); err != nil {
		t.Fatal(err)
	}
	return store
}

func TestMiddleware_NilStore(t *testing.T) {
	called := false
	handler := Middleware(nil, zap.NewNop())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		cfg := FromContext(r.Context())
		if cfg != nil {
			t.Error("expected nil tenant config with nil store")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("handler was not called")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestMiddleware_HeaderFallback(t *testing.T) {
	store := seedStore(t)

	handler := Middleware(store, zap.NewNop())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := FromContext(r.Context())
		if cfg == nil {
			t.Fatal("expected tenant config from X-Tenant-ID header")
		}
		if cfg.ID != "haea" {
			t.Errorf("expected tenant ID 'haea', got %q", cfg.ID)
		}
		if cfg.Branding.ProductName != "SecureCloud" {
			t.Errorf("expected product name 'SecureCloud', got %q", cfg.Branding.ProductName)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Tenant-ID", "haea")
	// Header fallback now requires JWT claims in context
	ctx := context.WithValue(req.Context(), api.ClaimsContextKey, &api.Claims{Subject: "test-user"})
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestMiddleware_Subdomain(t *testing.T) {
	store := seedStore(t)

	handler := Middleware(store, zap.NewNop())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := FromContext(r.Context())
		if cfg == nil {
			t.Fatal("expected tenant config from subdomain")
		}
		if cfg.ID != "contoso" {
			t.Errorf("expected tenant ID 'contoso', got %q", cfg.ID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Host = "contoso.cloudforge.io"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestMiddleware_JWTClaim(t *testing.T) {
	store := seedStore(t)

	handler := Middleware(store, zap.NewNop())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := FromContext(r.Context())
		if cfg == nil {
			t.Fatal("expected tenant config from JWT claim")
		}
		if cfg.ID != "haea" {
			t.Errorf("expected tenant ID 'haea', got %q", cfg.ID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	// Simulate JWT claims in context
	req := httptest.NewRequest("GET", "/test", nil)
	claims := &api.Claims{TenantID: "haea"}
	ctx := context.WithValue(req.Context(), api.ClaimsContextKey, claims)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestMiddleware_UnknownTenant(t *testing.T) {
	store := seedStore(t)

	handler := Middleware(store, zap.NewNop())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := FromContext(r.Context())
		if cfg != nil {
			t.Error("expected nil tenant config for unknown tenant")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Tenant-ID", "nonexistent")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestExtractSubdomain(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{"haea.cloudforge.io", "haea"},
		{"contoso.cloudforge.io:8080", "contoso"},
		{"cloudforge.io", ""},
		{"localhost:8080", ""},
		{"www.cloudforge.io", ""},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got := extractSubdomain(tt.host)
			if got != tt.want {
				t.Errorf("extractSubdomain(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}
