package terminal

import (
	"testing"
	"time"

	"aegis/internal/api"

	"go.uber.org/zap"
)

func newTestStore() *TicketStore {
	ts := &TicketStore{
		tickets: make(map[string]*ticketEntry),
		logger:  zap.NewNop(),
		done:    make(chan struct{}),
	}
	return ts
}

func TestTicketStore_IssueAndConsume(t *testing.T) {
	ts := newTestStore()
	defer ts.Stop()

	ticket, err := ts.Issue("user@example.com", api.RoleOperator, []string{"aegis-operator"})
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}
	if ticket == "" {
		t.Fatal("expected non-empty ticket")
	}

	subject, role, groups, err := ts.Consume(ticket)
	if err != nil {
		t.Fatalf("Consume failed: %v", err)
	}
	if subject != "user@example.com" {
		t.Errorf("subject = %q, want %q", subject, "user@example.com")
	}
	if role != api.RoleOperator {
		t.Errorf("role = %q, want %q", role, api.RoleOperator)
	}
	if len(groups) != 1 || groups[0] != "aegis-operator" {
		t.Errorf("groups = %v, want [aegis-operator]", groups)
	}
}

func TestTicketStore_DoubleConsumeFails(t *testing.T) {
	ts := newTestStore()
	defer ts.Stop()

	ticket, err := ts.Issue("user@example.com", api.RoleAdmin, []string{"aegis-admin"})
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	// First consume succeeds.
	if _, _, _, err := ts.Consume(ticket); err != nil {
		t.Fatalf("first Consume failed: %v", err)
	}

	// Second consume must fail.
	if _, _, _, err := ts.Consume(ticket); err == nil {
		t.Fatal("expected error on double consume, got nil")
	}
}

func TestTicketStore_ExpiredTicketFails(t *testing.T) {
	ts := newTestStore()
	defer ts.Stop()

	// Manually insert an already-expired ticket.
	ts.mu.Lock()
	ts.tickets["expired-ticket"] = &ticketEntry{
		subject:   "user@example.com",
		role:      api.RoleOperator,
		groups:    []string{"aegis-operator"},
		expiresAt: time.Now().Add(-1 * time.Second),
	}
	ts.mu.Unlock()

	if _, _, _, err := ts.Consume("expired-ticket"); err == nil {
		t.Fatal("expected error for expired ticket, got nil")
	}
}

func TestTicketStore_UnknownTicketFails(t *testing.T) {
	ts := newTestStore()
	defer ts.Stop()

	if _, _, _, err := ts.Consume("nonexistent-ticket"); err == nil {
		t.Fatal("expected error for unknown ticket, got nil")
	}
}

func TestTicketStore_Reap(t *testing.T) {
	ts := newTestStore()
	defer ts.Stop()

	// Insert two tickets: one expired, one valid.
	ts.mu.Lock()
	ts.tickets["expired"] = &ticketEntry{
		subject:   "old",
		role:      api.RoleViewer,
		expiresAt: time.Now().Add(-10 * time.Second),
	}
	ts.tickets["valid"] = &ticketEntry{
		subject:   "new",
		role:      api.RoleAdmin,
		expiresAt: time.Now().Add(30 * time.Second),
	}
	ts.mu.Unlock()

	ts.reap()

	ts.mu.RLock()
	defer ts.mu.RUnlock()

	if _, ok := ts.tickets["expired"]; ok {
		t.Error("expired ticket should have been reaped")
	}
	if _, ok := ts.tickets["valid"]; !ok {
		t.Error("valid ticket should NOT have been reaped")
	}
}

func TestGenerateUUID_Format(t *testing.T) {
	id, err := generateUUID()
	if err != nil {
		t.Fatalf("generateUUID failed: %v", err)
	}
	// v4 UUID: 8-4-4-4-12 hex characters = 36 chars total.
	if len(id) != 36 {
		t.Errorf("UUID length = %d, want 36", len(id))
	}
	// Version nibble must be 4.
	if id[14] != '4' {
		t.Errorf("UUID version nibble = %c, want '4'", id[14])
	}
}

func TestGenerateUUID_Unique(t *testing.T) {
	seen := make(map[string]bool, 100)
	for i := 0; i < 100; i++ {
		id, err := generateUUID()
		if err != nil {
			t.Fatalf("generateUUID failed: %v", err)
		}
		if seen[id] {
			t.Fatalf("duplicate UUID: %s", id)
		}
		seen[id] = true
	}
}
