// Package secrets provides secrets management, scanning, and lifecycle capabilities.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrNotFound is returned when a requested secret key does not exist.
var ErrNotFound = errors.New("not found")

// SecretRecord is a lifecycle-oriented view of a secret (key/version/expiry).
// Distinct from the provider-level Secret to avoid coupling to the storage path model.
type SecretRecord struct {
	Key       string
	Version   int
	CreatedAt time.Time
	ExpiresAt *time.Time
	Metadata  map[string]string
}

// RotationResult describes the outcome of rotating a secret.
type RotationResult struct {
	Key        string
	OldVersion int
	NewVersion int
	RotatedAt  time.Time
}

// Lifecycle manages secrets at the key/version/expiry level.
// Implementations: MemoryLifecycle (mock), and future Vault/AWS SM backends.
type Lifecycle interface {
	GetSecret(ctx context.Context, key string) (*SecretRecord, error)
	RotateSecret(ctx context.Context, key string) (*RotationResult, error)
	ListSecrets(ctx context.Context) ([]SecretRecord, error)
	// CheckExpiry returns secrets expiring within 30 days or already expired.
	CheckExpiry(ctx context.Context) ([]SecretRecord, error)
}

// NewLifecycle returns a Lifecycle implementation for the given provider name.
// Supports "memory" (in-process mock). Extend the switch for real backends.
func NewLifecycle(provider string) Lifecycle {
	switch provider {
	case "memory", "":
		return newMemoryLifecycle()
	default:
		panic(fmt.Sprintf("unsupported secrets lifecycle provider: %q", provider))
	}
}
