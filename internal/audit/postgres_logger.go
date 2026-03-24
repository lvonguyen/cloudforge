package audit

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"aegis/internal/tenant"
)

// PostgresAuditLogger persists audit entries to the audit_log table.
// It implements AuditLogger for durable, queryable audit storage.
// The in-memory logger can be composed alongside this for fast reads/SSE.
type PostgresAuditLogger struct {
	db *sql.DB
}

// NewPostgresAuditLogger creates a PostgreSQL-backed audit logger.
func NewPostgresAuditLogger(db *sql.DB) *PostgresAuditLogger {
	return &PostgresAuditLogger{db: db}
}

// Log persists an audit entry to PostgreSQL with tenant isolation.
func (p *PostgresAuditLogger) Log(ctx context.Context, entry AuditEntry) error {
	if entry.Timestamp == "" {
		entry.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	entry.IntegrityHash = entry.computeHash()

	tenantID, tenantName := tenantFromCtx(ctx)

	query := `
		INSERT INTO audit_log (
			id, action, actor_email, actor_role, target_type,
			target_id, result, details, ip_address, timestamp,
			tenant_id, tenant_name
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	_, err := p.db.ExecContext(ctx, query,
		entry.ID,
		entry.Action,
		entry.Actor,
		entry.ActorRole,
		entry.Resource,
		entry.ResourceID,
		entry.Result,
		fmt.Sprintf(`{"integrity_hash":%q}`, entry.IntegrityHash),
		nilIfEmpty(entry.IP),
		entry.Timestamp,
		tenantID,
		tenantName,
	)
	if err != nil {
		return fmt.Errorf("persisting audit entry: %w", err)
	}
	return nil
}

// List queries audit entries from PostgreSQL, scoped to the current tenant.
func (p *PostgresAuditLogger) List(ctx context.Context, opts ListOpts) ([]AuditEntry, error) {
	tenantID, _ := tenantFromCtx(ctx)

	limit := opts.Limit
	if limit <= 0 {
		limit = 100
	}

	query := `
		SELECT id, action, actor_email, actor_role, target_type,
		       target_id, result, ip_address, timestamp
		FROM audit_log
		WHERE tenant_id = $1
	`
	args := []any{tenantID}
	argN := 2

	if opts.Actor != "" {
		query += fmt.Sprintf(" AND actor_email = $%d", argN)
		args = append(args, opts.Actor)
		argN++
	}
	if opts.Action != "" {
		query += fmt.Sprintf(" AND action = $%d", argN)
		args = append(args, opts.Action)
		argN++
	}

	query += fmt.Sprintf(" ORDER BY timestamp DESC LIMIT $%d", argN)
	args = append(args, limit)

	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying audit log: %w", err)
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ip sql.NullString
		if err := rows.Scan(
			&e.ID, &e.Action, &e.Actor, &e.ActorRole,
			&e.Resource, &e.ResourceID, &e.Result,
			&ip, &e.Timestamp,
		); err != nil {
			return nil, fmt.Errorf("scanning audit entry: %w", err)
		}
		if ip.Valid {
			e.IP = ip.String
		}
		e.IntegrityHash = e.computeHash()
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// tenantFromCtx extracts tenant ID and name from context.
func tenantFromCtx(ctx context.Context) (id, name string) {
	if cfg := tenant.FromContext(ctx); cfg != nil {
		return cfg.ID, cfg.Name
	}
	return "default", ""
}

// nilIfEmpty returns nil for empty strings (for nullable INET columns).
func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
