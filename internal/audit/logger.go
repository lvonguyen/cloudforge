package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// AuditEntry represents a single auditable event with non-repudiation fields.
type AuditEntry struct {
	ID            string `json:"id"`
	Timestamp     string `json:"timestamp"`
	Actor         string `json:"actor"`
	ActorRole     string `json:"actor_role"`
	Action        string `json:"action"`
	Resource      string `json:"resource"`
	ResourceID    string `json:"resource_id"`
	Result        string `json:"result"`
	IP            string `json:"ip"`
	IntegrityHash string `json:"integrity_hash"`
}

// computeHash produces a tamper-evident SHA-256 hash of the entry's content fields.
func (e *AuditEntry) computeHash() string {
	h := sha256.New()
	for _, s := range []string{
		e.Timestamp, e.Actor, e.ActorRole, e.Action,
		e.Resource, e.ResourceID, e.Result, e.IP,
	} {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ListOpts controls filtering and pagination for audit log queries.
type ListOpts struct {
	Actor  string
	Action string
	Limit  int
}

// AuditLogger is the interface for audit event storage.
type AuditLogger interface {
	Log(ctx context.Context, entry AuditEntry) error
	List(ctx context.Context, opts ListOpts) ([]AuditEntry, error)
}

// maxAuditEntries caps the in-memory ring buffer to prevent OOM under sustained load.
const maxAuditEntries = 10000

// MemoryAuditLogger is a ring-buffer in-memory audit logger.
type MemoryAuditLogger struct {
	mu      sync.RWMutex
	entries []AuditEntry
	nextID  int
}

// NewMemoryAuditLogger creates an in-memory audit logger with a bounded ring buffer.
func NewMemoryAuditLogger() *MemoryAuditLogger {
	return &MemoryAuditLogger{
		entries: make([]AuditEntry, 0, 256),
	}
}

// Log appends an audit entry with auto-generated ID, timestamp, and integrity hash.
func (m *MemoryAuditLogger) Log(_ context.Context, entry AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.nextID++
	entry.ID = fmt.Sprintf("audit-%06d", m.nextID)
	if entry.Timestamp == "" {
		entry.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	entry.IntegrityHash = entry.computeHash()
	if len(m.entries) >= maxAuditEntries {
		m.entries = m.entries[1:]
	}
	m.entries = append(m.entries, entry)
	return nil
}

// List returns audit entries matching the filter criteria, newest first.
func (m *MemoryAuditLogger) List(_ context.Context, opts ListOpts) ([]AuditEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	limit := opts.Limit
	if limit <= 0 {
		limit = 100
	}

	results := make([]AuditEntry, 0, limit)
	// Iterate newest first
	for i := len(m.entries) - 1; i >= 0 && len(results) < limit; i-- {
		e := m.entries[i]
		if opts.Actor != "" && e.Actor != opts.Actor {
			continue
		}
		if opts.Action != "" && e.Action != opts.Action {
			continue
		}
		results = append(results, e)
	}
	return results, nil
}

// ZapAuditLogger writes audit entries as structured JSON to a dedicated zap logger.
// It also delegates to an underlying AuditLogger for queryable storage.
type ZapAuditLogger struct {
	logger *zap.Logger
	store  AuditLogger
}

// NewZapAuditLogger creates a logger that writes to both zap and a backing store.
func NewZapAuditLogger(logger *zap.Logger, store AuditLogger) *ZapAuditLogger {
	return &ZapAuditLogger{logger: logger, store: store}
}

// Log writes the entry to zap (for structured log shipping) and the backing store.
func (z *ZapAuditLogger) Log(ctx context.Context, entry AuditEntry) error {
	z.logger.Info("audit_event",
		zap.String("actor", entry.Actor),
		zap.String("actor_role", entry.ActorRole),
		zap.String("action", entry.Action),
		zap.String("resource", entry.Resource),
		zap.String("resource_id", entry.ResourceID),
		zap.String("result", entry.Result),
		zap.String("ip", entry.IP),
	)
	return z.store.Log(ctx, entry)
}

// List delegates to the backing store.
func (z *ZapAuditLogger) List(ctx context.Context, opts ListOpts) ([]AuditEntry, error) {
	return z.store.List(ctx, opts)
}
