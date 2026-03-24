package audit

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
)

// CompositeAuditLogger writes to multiple AuditLogger backends.
// The primary store is used for List queries; all stores receive Log writes.
// Use this to maintain an in-memory store for fast reads/SSE while also
// persisting to PostgreSQL for durability.
type CompositeAuditLogger struct {
	primary AuditLogger   // used for List() queries
	stores  []AuditLogger // all stores receive Log() writes
	onError func(err error)
}

// NewCompositeAuditLogger creates a composite logger. The first store is the
// primary (used for reads). All stores receive writes.
func NewCompositeAuditLogger(primary AuditLogger, additional ...AuditLogger) *CompositeAuditLogger {
	stores := make([]AuditLogger, 0, 1+len(additional))
	stores = append(stores, primary)
	stores = append(stores, additional...)
	return &CompositeAuditLogger{
		primary: primary,
		stores:  stores,
		onError: func(err error) { log.Printf("[WARN] audit store error: %v", err) },
	}
}

// Log writes the entry to all backing stores. Auto-generates ID, timestamp,
// and integrity hash if not set. Returns the first error encountered.
func (c *CompositeAuditLogger) Log(ctx context.Context, entry AuditEntry) error {
	if entry.ID == "" {
		entry.ID = uuid.New().String()[:20]
	}
	if entry.Timestamp == "" {
		entry.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	entry.IntegrityHash = entry.computeHash()

	var firstErr error
	for i, s := range c.stores {
		if err := s.Log(ctx, entry); err != nil {
			wrapped := fmt.Errorf("composite audit log (store %d): %w", i, err)
			if firstErr == nil {
				firstErr = wrapped
			} else if c.onError != nil {
				c.onError(wrapped)
			}
		}
	}
	return firstErr
}

// List delegates to the primary store.
func (c *CompositeAuditLogger) List(ctx context.Context, opts ListOpts) ([]AuditEntry, error) {
	return c.primary.List(ctx, opts)
}
