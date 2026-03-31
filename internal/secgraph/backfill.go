package secgraph

import (
	"context"
	"database/sql"
	"fmt"

	"go.uber.org/zap"
)

// RunEdgeBackfill populates graph_edges from existing relational data.
// Idempotent: uses ON CONFLICT DO NOTHING so repeated runs are safe.
// This is a startup-time operation, not a per-request path.
func RunEdgeBackfill(ctx context.Context, db *sql.DB, logger *zap.Logger) error {
	type op struct {
		name string
		fn   func(context.Context, *sql.DB) (int64, error)
	}

	ops := []op{
		{"affects", backfillAffects},
		{"belongs_to", backfillBelongsTo},
		{"maps_to", backfillMapsTo},
	}

	for _, o := range ops {
		n, err := o.fn(ctx, db)
		if err != nil {
			return fmt.Errorf("backfill %s: %w", o.name, err)
		}
		logger.Info("Edge backfill complete",
			zap.String("edge_type", o.name),
			zap.Int64("inserted", n),
		)
	}

	n, err := backfillCoLocation(ctx, db, 500)
	if err != nil {
		return fmt.Errorf("backfill same_region: %w", err)
	}
	logger.Info("Edge backfill complete",
		zap.String("edge_type", "same_region"),
		zap.Int64("inserted", n),
	)

	return nil
}

// backfillAffects creates finding→resource edges from the findings table.
func backfillAffects(ctx context.Context, db *sql.DB) (int64, error) {
	result, err := db.ExecContext(ctx, `
		INSERT INTO graph_edges (id, source_type, source_id, target_type, target_id, edge_type, tenant_id)
		SELECT gen_random_uuid(), 'finding', f.id, 'resource', f.resource_id, 'affects',
		       COALESCE(f.tenant_id, 'default')
		FROM findings f
		WHERE f.resource_id IS NOT NULL AND f.resource_id != ''
		ON CONFLICT (source_type, source_id, target_type, target_id, edge_type, tenant_id) DO NOTHING`)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// backfillBelongsTo creates resource→account edges from the resources table.
func backfillBelongsTo(ctx context.Context, db *sql.DB) (int64, error) {
	result, err := db.ExecContext(ctx, `
		INSERT INTO graph_edges (id, source_type, source_id, target_type, target_id, edge_type, tenant_id)
		SELECT gen_random_uuid(), 'resource', r.id, 'account', r.account_id, 'belongs_to',
		       COALESCE(r.tenant_id, 'default')
		FROM resources r
		WHERE r.account_id IS NOT NULL AND r.account_id != ''
		ON CONFLICT (source_type, source_id, target_type, target_id, edge_type, tenant_id) DO NOTHING`)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// backfillMapsTo creates finding→compliance_framework edges from compliance_mappings.
func backfillMapsTo(ctx context.Context, db *sql.DB) (int64, error) {
	result, err := db.ExecContext(ctx, `
		INSERT INTO graph_edges (id, source_type, source_id, target_type, target_id, edge_type, tenant_id)
		SELECT gen_random_uuid(), 'finding', cm.finding_id, 'compliance_framework', cm.framework_id,
		       'maps_to', 'default'
		FROM compliance_mappings cm
		ON CONFLICT (source_type, source_id, target_type, target_id, edge_type, tenant_id) DO NOTHING`)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// backfillCoLocation materializes same_region edges between resources sharing
// account_id AND region. Only processes groups with <= maxResources to prevent
// O(n^2) blowup in large accounts.
func backfillCoLocation(ctx context.Context, db *sql.DB, maxResources int) (int64, error) {
	if maxResources <= 0 {
		maxResources = 500
	}

	result, err := db.ExecContext(ctx, `
		WITH eligible_groups AS (
			SELECT account_id, region
			FROM resources
			WHERE account_id IS NOT NULL AND account_id != ''
			  AND region IS NOT NULL AND region != ''
			GROUP BY account_id, region
			HAVING COUNT(*) BETWEEN 2 AND $1
		)
		INSERT INTO graph_edges (id, source_type, source_id, target_type, target_id, edge_type, tenant_id)
		SELECT gen_random_uuid(), 'resource', r1.id, 'resource', r2.id, 'same_region',
		       COALESCE(r1.tenant_id, 'default')
		FROM eligible_groups eg
		JOIN resources r1 ON r1.account_id = eg.account_id AND r1.region = eg.region
		JOIN resources r2 ON r2.account_id = eg.account_id AND r2.region = eg.region AND r2.id > r1.id
		ON CONFLICT (source_type, source_id, target_type, target_id, edge_type, tenant_id) DO NOTHING`,
		maxResources)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
