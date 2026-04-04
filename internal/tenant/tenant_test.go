package tenant

import (
	"context"
	"testing"
	"time"
)

func TestMemoryStore_Upsert_and_Get(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	cfg := &Config{
		ID:   "contoso",
		Name: "Contoso Inc.",
		Branding: Branding{
			CompanyName: "Contoso",
			ProductName: "CloudForge",
			EmailDomain: "contoso.dev",
		},
		EnabledModules: []string{"aegis", "cspm-aggregator"},
		RateLimits:     RateLimits{RequestsPerMinute: 100, BurstSize: 20},
	}

	// Upsert
	if err := store.Upsert(ctx, cfg); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// Get by ID
	got, err := store.Get(ctx, "contoso")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "Contoso Inc." {
		t.Errorf("Name = %q, want %q", got.Name, "Contoso Inc.")
	}
	if got.Branding.EmailDomain != "contoso.dev" {
		t.Errorf("EmailDomain = %q, want %q", got.Branding.EmailDomain, "contoso.dev")
	}
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
	if got.UpdatedAt.IsZero() {
		t.Error("UpdatedAt should be set")
	}
}

func TestMemoryStore_Get_NotFound(t *testing.T) {
	store := NewMemoryStore()
	_, err := store.Get(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent tenant")
	}
}

func TestMemoryStore_GetByDomain(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	cfg := &Config{
		ID:   "haea",
		Name: "HAEA Security",
		Branding: Branding{
			CompanyName: "HAEA",
			ProductName: "SecureCloud",
			EmailDomain: "haea.io",
		},
	}

	if err := store.Upsert(ctx, cfg); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// Get by domain (tenant ID = subdomain by default)
	got, err := store.GetByDomain(ctx, "haea")
	if err != nil {
		t.Fatalf("GetByDomain: %v", err)
	}
	if got.Name != "HAEA Security" {
		t.Errorf("Name = %q, want %q", got.Name, "HAEA Security")
	}
}

func TestMemoryStore_GetByDomain_NotFound(t *testing.T) {
	store := NewMemoryStore()
	_, err := store.GetByDomain(context.Background(), "unknown")
	if err == nil {
		t.Fatal("expected error for unknown subdomain")
	}
}

func TestMemoryStore_List(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	tenants := []Config{
		{ID: "contoso", Name: "Contoso"},
		{ID: "haea", Name: "HAEA"},
		{ID: "acme", Name: "Acme Corp"},
	}
	for i := range tenants {
		if err := store.Upsert(ctx, &tenants[i]); err != nil {
			t.Fatalf("Upsert %s: %v", tenants[i].ID, err)
		}
	}

	list, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 3 {
		t.Errorf("len = %d, want 3", len(list))
	}
}

func TestMemoryStore_Delete(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	cfg := &Config{ID: "temp", Name: "Temp Tenant"}
	if err := store.Upsert(ctx, cfg); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	if err := store.Delete(ctx, "temp"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err := store.Get(ctx, "temp")
	if err == nil {
		t.Fatal("expected error after delete")
	}
}

func TestMemoryStore_Delete_NotFound(t *testing.T) {
	store := NewMemoryStore()
	err := store.Delete(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent tenant")
	}
}

func TestMemoryStore_Upsert_EmptyID(t *testing.T) {
	store := NewMemoryStore()
	err := store.Upsert(context.Background(), &Config{})
	if err == nil {
		t.Fatal("expected error for empty tenant ID")
	}
}

func TestMemoryStore_Returns_Copy(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	cfg := &Config{ID: "test", Name: "Original"}
	if err := store.Upsert(ctx, cfg); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, _ := store.Get(ctx, "test")
	got.Name = "Mutated"

	got2, _ := store.Get(ctx, "test")
	if got2.Name != "Original" {
		t.Errorf("Store returned a reference instead of a copy; Name = %q, want %q", got2.Name, "Original")
	}
}

func TestMemoryStore_Upsert_PreservesCreatedAt(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	original := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := &Config{ID: "test", Name: "v1", CreatedAt: original}
	if err := store.Upsert(ctx, cfg); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, _ := store.Get(ctx, "test")
	if !got.CreatedAt.Equal(original) {
		t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, original)
	}
}

func TestContext_RoundTrip(t *testing.T) {
	cfg := &Config{ID: "ctx-test", Name: "Context Test"}
	ctx := WithContext(context.Background(), cfg)

	got := FromContext(ctx)
	if got == nil {
		t.Fatal("FromContext returned nil")
	}
	if got.ID != "ctx-test" {
		t.Errorf("ID = %q, want %q", got.ID, "ctx-test")
	}
}

func TestFromContext_NoTenant(t *testing.T) {
	got := FromContext(context.Background())
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}
