package audit

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

func TestMemoryAuditLogger_Log(t *testing.T) {
	logger := NewMemoryAuditLogger()
	ctx := context.Background()

	err := logger.Log(ctx, AuditEntry{
		Actor:      "admin@contoso.dev",
		ActorRole:  "admin",
		Action:     "remediation.execute",
		Resource:   "finding",
		ResourceID: "f-aws-0001",
		Result:     "success",
		IP:         "10.0.0.1",
	})
	if err != nil {
		t.Fatalf("Log: %v", err)
	}

	entries, err := logger.List(ctx, ListOpts{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries count = %d, want 1", len(entries))
	}

	e := entries[0]
	if e.ID == "" {
		t.Error("expected auto-generated ID")
	}
	if e.Timestamp == "" {
		t.Error("expected auto-generated timestamp")
	}
	if e.IntegrityHash == "" {
		t.Error("expected integrity hash")
	}
	if len(e.IntegrityHash) != 64 {
		t.Errorf("integrity_hash length = %d, want 64", len(e.IntegrityHash))
	}
	if e.Actor != "admin@contoso.dev" {
		t.Errorf("actor = %q, want admin@contoso.dev", e.Actor)
	}
}

func TestMemoryAuditLogger_ListFilterByActor(t *testing.T) {
	logger := NewMemoryAuditLogger()
	ctx := context.Background()

	_ = logger.Log(ctx, AuditEntry{Actor: "admin@contoso.dev", Action: "create"})
	_ = logger.Log(ctx, AuditEntry{Actor: "operator@contoso.dev", Action: "read"})
	_ = logger.Log(ctx, AuditEntry{Actor: "admin@contoso.dev", Action: "delete"})

	results, _ := logger.List(ctx, ListOpts{Actor: "admin@contoso.dev"})
	if len(results) != 2 {
		t.Fatalf("filtered entries = %d, want 2", len(results))
	}
	for _, e := range results {
		if e.Actor != "admin@contoso.dev" {
			t.Errorf("actor = %q, want admin@contoso.dev", e.Actor)
		}
	}
}

func TestMemoryAuditLogger_ListFilterByAction(t *testing.T) {
	logger := NewMemoryAuditLogger()
	ctx := context.Background()

	_ = logger.Log(ctx, AuditEntry{Actor: "admin", Action: "remediation.execute"})
	_ = logger.Log(ctx, AuditEntry{Actor: "admin", Action: "exception.create"})
	_ = logger.Log(ctx, AuditEntry{Actor: "admin", Action: "remediation.execute"})

	results, _ := logger.List(ctx, ListOpts{Action: "remediation.execute"})
	if len(results) != 2 {
		t.Fatalf("filtered entries = %d, want 2", len(results))
	}
}

func TestMemoryAuditLogger_ListNewestFirst(t *testing.T) {
	logger := NewMemoryAuditLogger()
	ctx := context.Background()

	_ = logger.Log(ctx, AuditEntry{Actor: "first", Action: "a"})
	_ = logger.Log(ctx, AuditEntry{Actor: "second", Action: "b"})
	_ = logger.Log(ctx, AuditEntry{Actor: "third", Action: "c"})

	results, _ := logger.List(ctx, ListOpts{})
	if len(results) != 3 {
		t.Fatalf("entries = %d, want 3", len(results))
	}
	if results[0].Actor != "third" {
		t.Errorf("first result actor = %q, want third (newest)", results[0].Actor)
	}
}

func TestMemoryAuditLogger_ListLimit(t *testing.T) {
	logger := NewMemoryAuditLogger()
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		_ = logger.Log(ctx, AuditEntry{Actor: "admin", Action: "test"})
	}

	results, _ := logger.List(ctx, ListOpts{Limit: 3})
	if len(results) != 3 {
		t.Errorf("entries = %d, want 3", len(results))
	}
}

func TestMemoryAuditLogger_IntegrityHashDeterministic(t *testing.T) {
	entry := AuditEntry{
		Timestamp:  "2026-01-01T00:00:00Z",
		Actor:      "admin",
		ActorRole:  "admin",
		Action:     "test",
		Resource:   "finding",
		ResourceID: "f-001",
		Result:     "success",
		IP:         "10.0.0.1",
	}
	h1 := entry.computeHash()
	h2 := entry.computeHash()
	if h1 != h2 {
		t.Errorf("hash not deterministic: %q != %q", h1, h2)
	}
}

func TestZapAuditLogger_DelegatesToStore(t *testing.T) {
	store := NewMemoryAuditLogger()
	zapLogger := NewZapAuditLogger(zap.NewNop(), store)
	ctx := context.Background()

	err := zapLogger.Log(ctx, AuditEntry{
		Actor:  "admin",
		Action: "test",
	})
	if err != nil {
		t.Fatalf("Log: %v", err)
	}

	results, err := zapLogger.List(ctx, ListOpts{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("entries = %d, want 1", len(results))
	}
}
