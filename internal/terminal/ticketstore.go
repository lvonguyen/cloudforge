package terminal

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"aegis/internal/api"

	"go.uber.org/zap"
)

const (
	ticketTTL      = 60 * time.Second
	ticketReapFreq = 30 * time.Second
)

// ticketEntry holds the user context for a one-time-use WebSocket ticket.
type ticketEntry struct {
	subject   string
	role      api.Role
	groups    []string
	expiresAt time.Time
	consumed  bool
}

// TicketStore manages short-lived, one-time-use nonces for WebSocket auth.
// Tickets replace JWT-in-URL to avoid token leakage in logs, browser history,
// and referrer headers (SA-002).
type TicketStore struct {
	mu      sync.RWMutex
	tickets map[string]*ticketEntry
	logger  *zap.Logger
	done    chan struct{}
}

// NewTicketStore creates a TicketStore and starts the background reaper.
func NewTicketStore(logger *zap.Logger) *TicketStore {
	ts := &TicketStore{
		tickets: make(map[string]*ticketEntry),
		logger:  logger,
		done:    make(chan struct{}),
	}
	go ts.reapLoop()
	return ts
}

// Issue generates a one-time-use ticket bound to the given user context.
// Returns the ticket UUID string.
func (ts *TicketStore) Issue(subject string, role api.Role, groups []string) (string, error) {
	id, err := generateUUID()
	if err != nil {
		return "", fmt.Errorf("generating ticket UUID: %w", err)
	}

	ts.mu.Lock()
	ts.tickets[id] = &ticketEntry{
		subject:   subject,
		role:      role,
		groups:    groups,
		expiresAt: time.Now().Add(ticketTTL),
	}
	ts.mu.Unlock()

	ts.logger.Debug("terminal: ticket issued",
		zap.String("ticket", id),
		zap.String("subject", subject),
	)
	return id, nil
}

// Consume validates and atomically consumes a ticket. Returns the stored user
// context on success. Fails if the ticket is unknown, expired, or already used.
func (ts *TicketStore) Consume(id string) (subject string, role api.Role, groups []string, err error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	entry, ok := ts.tickets[id]
	if !ok {
		return "", "", nil, fmt.Errorf("unknown ticket")
	}
	if entry.consumed {
		// Double-consume attempt — delete to prevent timing attacks.
		delete(ts.tickets, id)
		return "", "", nil, fmt.Errorf("ticket already consumed")
	}
	if time.Now().After(entry.expiresAt) {
		delete(ts.tickets, id)
		return "", "", nil, fmt.Errorf("ticket expired")
	}

	entry.consumed = true
	// Remove immediately after consumption — no reason to keep it.
	delete(ts.tickets, id)

	return entry.subject, entry.role, entry.groups, nil
}

// Stop halts the background reaper goroutine.
func (ts *TicketStore) Stop() {
	close(ts.done)
}

// reapLoop periodically removes expired tickets.
func (ts *TicketStore) reapLoop() {
	ticker := time.NewTicker(ticketReapFreq)
	defer ticker.Stop()

	for {
		select {
		case <-ts.done:
			return
		case <-ticker.C:
			ts.reap()
		}
	}
}

func (ts *TicketStore) reap() {
	now := time.Now()
	ts.mu.Lock()
	defer ts.mu.Unlock()

	reaped := 0
	for id, entry := range ts.tickets {
		if now.After(entry.expiresAt) {
			delete(ts.tickets, id)
			reaped++
		}
	}
	if reaped > 0 {
		ts.logger.Debug("terminal: reaped expired tickets", zap.Int("count", reaped))
	}
}

// generateUUID produces a v4 UUID using crypto/rand.
func generateUUID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("reading random bytes: %w", err)
	}
	// Set version (4) and variant (RFC 4122).
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16]), nil
}
