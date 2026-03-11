package secrets

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// memoryLifecycle is an in-memory Lifecycle implementation for testing and demos.
// NOT for production use — no persistence, no encryption at rest.
type memoryLifecycle struct {
	mu      sync.RWMutex
	secrets map[string]*SecretRecord
}

func newMemoryLifecycle() *memoryLifecycle {
	m := &memoryLifecycle{
		secrets: make(map[string]*SecretRecord),
	}
	m.seed()
	return m
}

// seed pre-populates the store with realistic mock secrets.
func (m *memoryLifecycle) seed() {
	now := time.Now()

	soon := now.Add(15 * 24 * time.Hour)  // expires in 15 days — should appear in CheckExpiry
	far := now.Add(180 * 24 * time.Hour)  // expires in 6 months
	past := now.Add(-10 * 24 * time.Hour) // already expired

	entries := []SecretRecord{
		{
			Key:       "db-password",
			Version:   3,
			CreatedAt: now.Add(-90 * 24 * time.Hour),
			ExpiresAt: &far,
			Metadata:  map[string]string{"owner": "platform-team", "env": "production"},
		},
		{
			Key:       "api-key",
			Version:   1,
			CreatedAt: now.Add(-30 * 24 * time.Hour),
			ExpiresAt: &soon, // expiring soon — surfaced by CheckExpiry
			Metadata:  map[string]string{"owner": "integrations-team", "env": "production"},
		},
		{
			Key:       "tls-cert",
			Version:   2,
			CreatedAt: now.Add(-60 * 24 * time.Hour),
			ExpiresAt: &far,
			Metadata:  map[string]string{"owner": "security-team", "env": "production", "type": "certificate"},
		},
		{
			Key:       "oauth-client-secret",
			Version:   1,
			CreatedAt: now.Add(-120 * 24 * time.Hour),
			ExpiresAt: &soon, // expiring soon — surfaced by CheckExpiry
			Metadata:  map[string]string{"owner": "identity-team", "env": "production"},
		},
		{
			Key:       "jwt-signing-key",
			Version:   4,
			CreatedAt: now.Add(-14 * 24 * time.Hour),
			ExpiresAt: nil, // no expiry
			Metadata:  map[string]string{"owner": "auth-team", "env": "production", "algorithm": "HS256"},
		},
		{
			Key:       "ssh-host-key",
			Version:   1,
			CreatedAt: now.Add(-365 * 24 * time.Hour),
			ExpiresAt: &past, // already expired — also surfaced by CheckExpiry (within window from past? no)
			Metadata:  map[string]string{"owner": "infrastructure-team", "env": "production"},
		},
	}

	for i := range entries {
		cp := entries[i]
		m.secrets[cp.Key] = &cp
	}
}

// GetSecret returns a copy of the secret record for the given key.
func (m *memoryLifecycle) GetSecret(_ context.Context, key string) (*SecretRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	s, ok := m.secrets[key]
	if !ok {
		return nil, fmt.Errorf("getting secret %q: %w", key, ErrNotFound)
	}
	cp := *s
	return &cp, nil
}

// RotateSecret increments the version and updates the timestamp for the given key.
func (m *memoryLifecycle) RotateSecret(_ context.Context, key string) (*RotationResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.secrets[key]
	if !ok {
		return nil, fmt.Errorf("rotating secret %q: %w", key, ErrNotFound)
	}

	oldVersion := s.Version
	s.Version++
	now := time.Now()
	s.CreatedAt = now

	return &RotationResult{
		Key:        key,
		OldVersion: oldVersion,
		NewVersion: s.Version,
		RotatedAt:  now,
	}, nil
}

// ListSecrets returns a snapshot of all secrets in the store.
func (m *memoryLifecycle) ListSecrets(_ context.Context) ([]SecretRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]SecretRecord, 0, len(m.secrets))
	for _, s := range m.secrets {
		out = append(out, *s)
	}
	return out, nil
}

// CheckExpiry returns secrets whose ExpiresAt falls within the next 30 days.
func (m *memoryLifecycle) CheckExpiry(_ context.Context) ([]SecretRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now()
	cutoff := now.Add(30 * 24 * time.Hour)

	var expiring []SecretRecord
	for _, s := range m.secrets {
		if s.ExpiresAt == nil {
			continue
		}
		// Include secrets that have already expired or expire within 30 days.
		if s.ExpiresAt.Before(cutoff) {
			cp := *s
			expiring = append(expiring, cp)
		}
	}
	return expiring, nil
}
