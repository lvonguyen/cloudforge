// Package tenant provides multi-tenant configuration and context management.
//
// Phase 3 prototype: in-memory store with a Postgres-ready interface.
// Tenant is resolved from subdomain or JWT tenant_id claim, injected
// into context by the tenant middleware, and consumed by downstream
// handlers for data scoping and branding.
package tenant

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// contextKey is an unexported type for context keys in this package.
type contextKey struct{}

// tenantCtxKey is the context key for the current tenant.
var tenantCtxKey = contextKey{}

// Config holds per-tenant configuration.
type Config struct {
	// ID is the unique tenant identifier (e.g., "contoso", "haea").
	ID string `json:"id"`

	// Name is the display name (e.g., "Contoso Inc.", "HAEA Security").
	Name string `json:"name"`

	// Branding holds UI customization values served via /config.json.
	Branding Branding `json:"branding"`

	// AuthProvider configures the OIDC provider for this tenant.
	AuthProvider AuthProviderConfig `json:"auth_provider"`

	// EnabledModules lists which application modules are active.
	EnabledModules []string `json:"enabled_modules"`

	// RateLimits overrides per-tenant rate limits (requests per minute).
	RateLimits RateLimits `json:"rate_limits"`

	// CreatedAt is when the tenant was onboarded.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when the tenant config was last modified.
	UpdatedAt time.Time `json:"updated_at"`
}

// Branding holds tenant-specific UI branding values.
type Branding struct {
	CompanyName  string `json:"company_name"`
	ProductName  string `json:"product_name"`
	LogoPath     string `json:"logo_path"`
	EmailDomain  string `json:"email_domain"`
	PrimaryColor string `json:"primary_color,omitempty"`
	AccentColor  string `json:"accent_color,omitempty"`
}

// AuthProviderConfig holds OIDC configuration for a tenant.
type AuthProviderConfig struct {
	// Type is the provider type: "okta", "entra_id", "auth0", "mock".
	Type string `json:"type"`

	// Issuer is the OIDC issuer URL.
	Issuer string `json:"issuer"`

	// ClientID is the OIDC client ID.
	ClientID string `json:"client_id"`

	// Audience is the expected JWT audience.
	Audience string `json:"audience,omitempty"`
}

// RateLimits defines per-tenant rate limiting thresholds.
type RateLimits struct {
	// RequestsPerMinute is the max requests per minute per user.
	RequestsPerMinute int `json:"requests_per_minute"`

	// BurstSize is the max burst size.
	BurstSize int `json:"burst_size"`
}

// Store defines the interface for tenant configuration persistence.
// The in-memory implementation is provided for Phase 3; a Postgres
// implementation can be swapped in for Phase 4.
type Store interface {
	// Get returns the tenant config by ID, or an error if not found.
	Get(ctx context.Context, id string) (*Config, error)

	// GetByDomain returns the tenant config for a given subdomain.
	GetByDomain(ctx context.Context, subdomain string) (*Config, error)

	// List returns all tenant configs.
	List(ctx context.Context) ([]*Config, error)

	// Upsert creates or updates a tenant config.
	Upsert(ctx context.Context, cfg *Config) error

	// Delete removes a tenant config.
	Delete(ctx context.Context, id string) error
}

// MemoryStore is an in-memory implementation of Store.
// Thread-safe via sync.RWMutex.
type MemoryStore struct {
	mu       sync.RWMutex
	tenants  map[string]*Config
	byDomain map[string]string // subdomain -> tenant ID
}

// NewMemoryStore creates a new in-memory tenant store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		tenants:  make(map[string]*Config),
		byDomain: make(map[string]string),
	}
}

// Get returns the tenant config by ID.
func (s *MemoryStore) Get(_ context.Context, id string) (*Config, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cfg, ok := s.tenants[id]
	if !ok {
		return nil, fmt.Errorf("tenant %q not found", id)
	}
	// Return a copy to prevent mutation
	c := *cfg
	return &c, nil
}

// GetByDomain returns the tenant config for a subdomain.
func (s *MemoryStore) GetByDomain(_ context.Context, subdomain string) (*Config, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, ok := s.byDomain[subdomain]
	if !ok {
		return nil, fmt.Errorf("no tenant for subdomain %q", subdomain)
	}
	cfg, ok := s.tenants[id]
	if !ok {
		return nil, fmt.Errorf("tenant %q not found (stale domain mapping)", id)
	}
	c := *cfg
	return &c, nil
}

// List returns all tenant configs.
func (s *MemoryStore) List(_ context.Context) ([]*Config, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Config, 0, len(s.tenants))
	for _, cfg := range s.tenants {
		c := *cfg
		result = append(result, &c)
	}
	return result, nil
}

// Upsert creates or updates a tenant config.
func (s *MemoryStore) Upsert(_ context.Context, cfg *Config) error {
	if cfg.ID == "" {
		return fmt.Errorf("tenant ID is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	if cfg.CreatedAt.IsZero() {
		cfg.CreatedAt = now
	}
	cfg.UpdatedAt = now

	c := *cfg
	s.tenants[cfg.ID] = &c

	// Update domain mapping (use tenant ID as subdomain by default)
	s.byDomain[cfg.ID] = cfg.ID

	return nil
}

// Delete removes a tenant config.
func (s *MemoryStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.tenants[id]; !ok {
		return fmt.Errorf("tenant %q not found", id)
	}

	delete(s.tenants, id)
	delete(s.byDomain, id)
	return nil
}

// FromContext extracts the tenant config from the request context.
// Returns nil if no tenant is set (single-tenant mode).
func FromContext(ctx context.Context) *Config {
	cfg, _ := ctx.Value(tenantCtxKey).(*Config)
	return cfg
}

// WithContext returns a new context with the tenant config set.
func WithContext(ctx context.Context, cfg *Config) context.Context {
	return context.WithValue(ctx, tenantCtxKey, cfg)
}
