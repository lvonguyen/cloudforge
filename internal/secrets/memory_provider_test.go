package secrets

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestMemoryProvider_Name(t *testing.T) {
	p := NewMemoryProvider("test-provider")
	if p.Name() != "test-provider" {
		t.Errorf("expected Name()=%q, got %q", "test-provider", p.Name())
	}
}

func TestMemoryProvider_GetSecret_HappyPath(t *testing.T) {
	p := NewMemoryProvider("memory")
	ctx := context.Background()

	s, err := p.GetSecret(ctx, "aws/prod/rds-master")
	if err != nil {
		t.Fatalf("GetSecret returned unexpected error: %v", err)
	}
	if s.Path != "aws/prod/rds-master" {
		t.Errorf("expected Path=%q, got %q", "aws/prod/rds-master", s.Path)
	}
	if len(s.Value) == 0 {
		t.Error("expected non-empty Value")
	}
	if s.Version == "" {
		t.Error("expected non-empty Version")
	}
	if s.CreatedAt.IsZero() {
		t.Error("expected non-zero CreatedAt")
	}
	if s.UpdatedAt.IsZero() {
		t.Error("expected non-zero UpdatedAt")
	}
	if s.Metadata["provider"] != "aws" {
		t.Errorf("expected metadata provider=aws, got %q", s.Metadata["provider"])
	}
	if s.Metadata["env"] != "prod" {
		t.Errorf("expected metadata env=prod, got %q", s.Metadata["env"])
	}
}

func TestMemoryProvider_GetSecret_NotFound(t *testing.T) {
	p := NewMemoryProvider("memory")
	ctx := context.Background()

	_, err := p.GetSecret(ctx, "nonexistent/path")
	if err == nil {
		t.Fatal("expected error for missing path, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestMemoryProvider_GetSecret_ReturnsCopy(t *testing.T) {
	p := NewMemoryProvider("memory")
	ctx := context.Background()

	s, err := p.GetSecret(ctx, "shared/jwt-signing-key")
	if err != nil {
		t.Fatalf("GetSecret returned unexpected error: %v", err)
	}

	// Mutate the returned value.
	originalValue := append([]byte(nil), s.Value...)
	s.Value[0] = 0xFF
	s.Metadata["type"] = "tampered"

	// Re-fetch and confirm internal state is unmodified.
	s2, err := p.GetSecret(ctx, "shared/jwt-signing-key")
	if err != nil {
		t.Fatalf("second GetSecret returned unexpected error: %v", err)
	}
	if !bytes.Equal(s2.Value, originalValue) {
		t.Error("modifying returned secret's Value affected the internal store (pointer aliasing)")
	}
	if s2.Metadata["type"] != "jwt" {
		t.Errorf("modifying returned secret's Metadata affected internal store: got %q", s2.Metadata["type"])
	}
}

func TestMemoryProvider_SetSecret_CreateNew(t *testing.T) {
	p := NewMemoryProvider("memory")
	ctx := context.Background()

	path := "shared/new-api-token"
	value := []byte("demo-token-abcdef1234567890")

	if err := p.SetSecret(ctx, path, value); err != nil {
		t.Fatalf("SetSecret returned unexpected error: %v", err)
	}

	s, err := p.GetSecret(ctx, path)
	if err != nil {
		t.Fatalf("GetSecret after SetSecret returned unexpected error: %v", err)
	}
	if !bytes.Equal(s.Value, value) {
		t.Errorf("expected Value=%q, got %q", value, s.Value)
	}
	if s.Version != "1" {
		t.Errorf("expected Version=%q for new secret, got %q", "1", s.Version)
	}
	if s.CreatedAt.IsZero() {
		t.Error("expected non-zero CreatedAt")
	}
}

func TestMemoryProvider_SetSecret_UpdateExisting(t *testing.T) {
	p := NewMemoryProvider("memory")
	ctx := context.Background()

	path := "aws/prod/rds-master"

	before, err := p.GetSecret(ctx, path)
	if err != nil {
		t.Fatalf("GetSecret before update returned unexpected error: %v", err)
	}

	newValue := []byte("updated-password-xyz9876")
	if err := p.SetSecret(ctx, path, newValue); err != nil {
		t.Fatalf("SetSecret update returned unexpected error: %v", err)
	}

	after, err := p.GetSecret(ctx, path)
	if err != nil {
		t.Fatalf("GetSecret after update returned unexpected error: %v", err)
	}
	if !bytes.Equal(after.Value, newValue) {
		t.Errorf("expected updated Value=%q, got %q", newValue, after.Value)
	}
	if after.Version == before.Version {
		t.Errorf("expected Version to increment from %q, but got same %q", before.Version, after.Version)
	}
}

func TestMemoryProvider_DeleteSecret_HappyPath(t *testing.T) {
	p := NewMemoryProvider("memory")
	ctx := context.Background()

	path := "gcp/staging/pubsub-token"

	if err := p.DeleteSecret(ctx, path); err != nil {
		t.Fatalf("DeleteSecret returned unexpected error: %v", err)
	}

	_, err := p.GetSecret(ctx, path)
	if err == nil {
		t.Fatal("expected error after deletion, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound after deletion, got %v", err)
	}
}

func TestMemoryProvider_DeleteSecret_NotFound(t *testing.T) {
	p := NewMemoryProvider("memory")
	ctx := context.Background()

	err := p.DeleteSecret(ctx, "does/not/exist")
	if err == nil {
		t.Fatal("expected error deleting missing path, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestMemoryProvider_ListSecrets_PrefixFilter(t *testing.T) {
	p := NewMemoryProvider("memory")
	ctx := context.Background()

	paths, err := p.ListSecrets(ctx, "aws/")
	if err != nil {
		t.Fatalf("ListSecrets returned unexpected error: %v", err)
	}
	if len(paths) != 2 {
		t.Errorf("expected 2 aws/ secrets, got %d: %v", len(paths), paths)
	}
	// Verify returned paths are sorted.
	if len(paths) == 2 && paths[0] > paths[1] {
		t.Errorf("expected sorted paths, got %v", paths)
	}
	for _, path := range paths {
		if len(path) < 4 || path[:4] != "aws/" {
			t.Errorf("ListSecrets returned non-aws path: %q", path)
		}
	}
}

func TestMemoryProvider_ListSecrets_EmptyPrefix(t *testing.T) {
	p := NewMemoryProvider("memory")
	ctx := context.Background()

	paths, err := p.ListSecrets(ctx, "")
	if err != nil {
		t.Fatalf("ListSecrets returned unexpected error: %v", err)
	}
	// Seed pre-populates 8 secrets.
	if len(paths) != 8 {
		t.Errorf("expected 8 seeded paths, got %d", len(paths))
	}
	// Confirm sorted.
	for i := 1; i < len(paths); i++ {
		if paths[i] < paths[i-1] {
			t.Errorf("paths not sorted at index %d: %v", i, paths)
			break
		}
	}
}

func TestMemoryProvider_RotateSecret(t *testing.T) {
	p := NewMemoryProvider("memory")
	ctx := context.Background()

	path := "azure/prod/cosmos-key"

	before, err := p.GetSecret(ctx, path)
	if err != nil {
		t.Fatalf("GetSecret before rotation returned unexpected error: %v", err)
	}

	if err := p.RotateSecret(ctx, path); err != nil {
		t.Fatalf("RotateSecret returned unexpected error: %v", err)
	}

	after, err := p.GetSecret(ctx, path)
	if err != nil {
		t.Fatalf("GetSecret after rotation returned unexpected error: %v", err)
	}
	if after.Version == before.Version {
		t.Errorf("expected Version to increment from %q, but got same %q", before.Version, after.Version)
	}
	if bytes.Equal(after.Value, before.Value) {
		t.Error("expected Value to change after rotation, but it remained the same")
	}
	if after.UpdatedAt.Before(before.UpdatedAt) || after.UpdatedAt.Equal(before.UpdatedAt) {
		t.Error("expected UpdatedAt to advance after rotation")
	}
}

func TestMemoryProvider_RotateSecret_NotFound(t *testing.T) {
	p := NewMemoryProvider("memory")
	ctx := context.Background()

	err := p.RotateSecret(ctx, "nonexistent/path")
	if err == nil {
		t.Fatal("expected error rotating missing path, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}
