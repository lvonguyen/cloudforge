package secrets

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestMemoryLifecycle_GetSecret_ReturnsExpectedSecret(t *testing.T) {
	lc, err := NewLifecycle("memory")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	s, err := lc.GetSecret(ctx, "db-password")
	if err != nil {
		t.Fatalf("GetSecret returned unexpected error: %v", err)
	}
	if s.Key != "db-password" {
		t.Errorf("expected Key=%q, got %q", "db-password", s.Key)
	}
	if s.Version < 1 {
		t.Errorf("expected Version >= 1, got %d", s.Version)
	}
	if s.CreatedAt.IsZero() {
		t.Error("expected non-zero CreatedAt")
	}
}

func TestMemoryLifecycle_GetSecret_NotFound(t *testing.T) {
	lc, err := NewLifecycle("memory")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	_, err = lc.GetSecret(ctx, "nonexistent-key")
	if err == nil {
		t.Fatal("expected error for missing key, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestMemoryLifecycle_RotateSecret_IncrementsVersion(t *testing.T) {
	lc, err := NewLifecycle("memory")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	before, err := lc.GetSecret(ctx, "jwt-signing-key")
	if err != nil {
		t.Fatalf("GetSecret before rotation failed: %v", err)
	}

	result, err := lc.RotateSecret(ctx, "jwt-signing-key")
	if err != nil {
		t.Fatalf("RotateSecret returned unexpected error: %v", err)
	}

	if result.OldVersion != before.Version {
		t.Errorf("expected OldVersion=%d, got %d", before.Version, result.OldVersion)
	}
	if result.NewVersion != before.Version+1 {
		t.Errorf("expected NewVersion=%d, got %d", before.Version+1, result.NewVersion)
	}
	if result.RotatedAt.IsZero() {
		t.Error("expected non-zero RotatedAt")
	}

	// Confirm the stored record reflects the new version.
	after, err := lc.GetSecret(ctx, "jwt-signing-key")
	if err != nil {
		t.Fatalf("GetSecret after rotation failed: %v", err)
	}
	if after.Version != result.NewVersion {
		t.Errorf("stored version not updated: expected %d, got %d", result.NewVersion, after.Version)
	}
}

func TestMemoryLifecycle_RotateSecret_NotFound(t *testing.T) {
	lc, err := NewLifecycle("memory")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	_, err = lc.RotateSecret(ctx, "nonexistent-key")
	if err == nil {
		t.Fatal("expected error rotating missing key, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestMemoryLifecycle_ListSecrets_ReturnsSeedData(t *testing.T) {
	lc, err := NewLifecycle("memory")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	secrets, err := lc.ListSecrets(ctx)
	if err != nil {
		t.Fatalf("ListSecrets returned unexpected error: %v", err)
	}
	if len(secrets) < 5 {
		t.Errorf("expected at least 5 seeded secrets, got %d", len(secrets))
	}
}

func TestMemoryLifecycle_CheckExpiry_FindsExpiringSoon(t *testing.T) {
	lc, err := NewLifecycle("memory")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	expiring, err := lc.CheckExpiry(ctx)
	if err != nil {
		t.Fatalf("CheckExpiry returned unexpected error: %v", err)
	}

	// Seed data has 3 secrets within the 30-day window:
	// api-key (15d), oauth-client-secret (15d), ssh-host-key (already expired).
	if len(expiring) < 2 {
		t.Errorf("expected at least 2 expiring secrets, got %d", len(expiring))
	}

	for _, s := range expiring {
		if s.ExpiresAt == nil {
			t.Errorf("CheckExpiry returned secret %q with nil ExpiresAt", s.Key)
		}
	}
}

func TestMemoryLifecycle_CheckExpiry_ExcludesNonExpiring(t *testing.T) {
	lc, err := NewLifecycle("memory")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	expiring, err := lc.CheckExpiry(ctx)
	if err != nil {
		t.Fatalf("CheckExpiry returned unexpected error: %v", err)
	}

	for _, s := range expiring {
		if s.Key == "db-password" || s.Key == "tls-cert" {
			t.Errorf("secret %q should not appear in expiry list (expires in 6 months)", s.Key)
		}
		if s.Key == "jwt-signing-key" {
			t.Errorf("secret %q should not appear in expiry list (no expiry set)", s.Key)
		}
	}
}

func TestNewLifecycle_InvalidProvider(t *testing.T) {
	_, err := NewLifecycle("invalid-provider")
	if err == nil {
		t.Fatal("expected error for invalid provider, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("expected error message to contain 'unsupported', got: %v", err)
	}
}
