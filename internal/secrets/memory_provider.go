package secrets

import (
	"context"
	"fmt"
	"crypto/rand"
	"sort"
	"strings"
	"sync"
	"time"
)

// MemoryProvider is an in-memory Provider implementation for testing and demos.
// NOT for production use — no persistence, no encryption at rest.
type MemoryProvider struct {
	mu      sync.RWMutex
	secrets map[string]*Secret
	name    string
}

// NewMemoryProvider creates a new MemoryProvider pre-seeded with demo secrets.
func NewMemoryProvider(name string) *MemoryProvider {
	p := &MemoryProvider{
		secrets: make(map[string]*Secret),
		name:    name,
	}
	p.seed()
	return p
}

func (p *MemoryProvider) seed() {
	now := time.Now()

	entries := []struct {
		path     string
		value    string
		metadata map[string]string
	}{
		{
			path:     "aws/prod/rds-master",
			value:    "a3f8c1d2-4e5b-6f7a-8b9c-0d1e2f3a4b5c",
			metadata: map[string]string{"provider": "aws", "env": "prod"},
		},
		{
			path:     "aws/staging/api-key",
			value:    "b4g9d2e3-5f6c-7a8b-9c0d-1e2f3a4b5c6d",
			metadata: map[string]string{"provider": "aws", "env": "staging"},
		},
		{
			path:     "azure/prod/storage-connection",
			value:    "c5h0e3f4-6a7d-8b9c-0d1e-2f3a4b5c6d7e",
			metadata: map[string]string{"provider": "azure", "env": "prod"},
		},
		{
			path:     "azure/prod/cosmos-key",
			value:    "d6i1f4a5-7b8e-9c0d-1e2f-3a4b5c6d7e8f",
			metadata: map[string]string{"provider": "azure", "env": "prod"},
		},
		{
			path:     "gcp/prod/service-account-key",
			value:    "e7j2a5b6-8c9f-0d1e-2f3a-4b5c6d7e8f9a",
			metadata: map[string]string{"provider": "gcp", "env": "prod"},
		},
		{
			path:     "gcp/staging/pubsub-token",
			value:    "f8k3b6c7-9d0a-1e2f-3a4b-5c6d7e8f9a0b",
			metadata: map[string]string{"provider": "gcp", "env": "staging"},
		},
		{
			path:     "shared/tls-cert-private-key",
			value:    "a9l4c7d8-0e1b-2f3a-4b5c-6d7e8f9a0b1c",
			metadata: map[string]string{"type": "certificate"},
		},
		{
			path:     "shared/jwt-signing-key",
			value:    "b0m5d8e9-1f2c-3a4b-5c6d-7e8f9a0b1c2d",
			metadata: map[string]string{"type": "jwt"},
		},
	}

	for _, e := range entries {
		s := &Secret{
			Path:      e.path,
			Value:     []byte(e.value),
			Version:   "1",
			CreatedAt: now.Add(-30 * 24 * time.Hour),
			UpdatedAt: now.Add(-30 * 24 * time.Hour),
			Metadata:  e.metadata,
		}
		p.secrets[e.path] = s
	}
}

// Name returns the provider name.
func (p *MemoryProvider) Name() string { return p.name }

// GetSecret returns a copy of the secret at path. Returns ErrNotFound if absent.
func (p *MemoryProvider) GetSecret(_ context.Context, path string) (*Secret, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	s, ok := p.secrets[path]
	if !ok {
		return nil, fmt.Errorf("getting secret %q: %w", path, ErrNotFound)
	}
	return copySecret(s), nil
}

// SetSecret creates or updates the secret at path, incrementing the version on update.
func (p *MemoryProvider) SetSecret(_ context.Context, path string, value []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	if existing, ok := p.secrets[path]; ok {
		existing.Value = append([]byte(nil), value...)
		existing.Version = incrementVersion(existing.Version)
		existing.UpdatedAt = now
		return nil
	}

	valCopy := append([]byte(nil), value...)
	p.secrets[path] = &Secret{
		Path:      path,
		Value:     valCopy,
		Version:   "1",
		CreatedAt: now,
		UpdatedAt: now,
		Metadata:  make(map[string]string),
	}
	return nil
}

// DeleteSecret removes the secret at path. Returns ErrNotFound if absent.
func (p *MemoryProvider) DeleteSecret(_ context.Context, path string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, ok := p.secrets[path]; !ok {
		return fmt.Errorf("deleting secret %q: %w", path, ErrNotFound)
	}
	delete(p.secrets, path)
	return nil
}

// ListSecrets returns sorted paths whose prefix matches prefix.
// An empty prefix returns all paths.
func (p *MemoryProvider) ListSecrets(_ context.Context, prefix string) ([]string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var paths []string
	for path := range p.secrets {
		if prefix == "" || strings.HasPrefix(path, prefix) {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)
	return paths, nil
}

// RotateSecret generates a new value for the secret at path, incrementing its version.
// Returns ErrNotFound if the path does not exist.
func (p *MemoryProvider) RotateSecret(_ context.Context, path string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	s, ok := p.secrets[path]
	if !ok {
		return fmt.Errorf("rotating secret %q: %w", path, ErrNotFound)
	}

	now := time.Now()
	s.Value = []byte(newUUID())
	s.Version = incrementVersion(s.Version)
	s.UpdatedAt = now
	return nil
}

// copySecret returns a deep copy of s to prevent callers from aliasing internal state.
func copySecret(s *Secret) *Secret {
	cp := *s
	cp.Value = append([]byte(nil), s.Value...)
	if s.Metadata != nil {
		cp.Metadata = make(map[string]string, len(s.Metadata))
		for k, v := range s.Metadata {
			cp.Metadata[k] = v
		}
	}
	if s.ExpiresAt != nil {
		t := *s.ExpiresAt
		cp.ExpiresAt = &t
	}
	return &cp
}

// incrementVersion parses the version string as an integer, increments it,
// and returns the string form. Defaults to "2" on parse failure.
func incrementVersion(v string) string {
	var n int
	_, _ = fmt.Sscanf(v, "%d", &n)
	return fmt.Sprintf("%d", n+1)
}

// newUUID generates a random UUID-like string for rotated secret values.
func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
