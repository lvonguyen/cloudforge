package main

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type integrationRuntimeStateStore interface {
	GetValue(ctx context.Context, provider, key string) (string, error)
	PutValue(ctx context.Context, provider, key, value string) error
}

type sqlIntegrationRuntimeStateStore struct {
	db *sql.DB
}

func newIntegrationRuntimeStateStore(db *sql.DB) integrationRuntimeStateStore {
	if db == nil {
		return nil
	}
	return sqlIntegrationRuntimeStateStore{db: db}
}

func (s sqlIntegrationRuntimeStateStore) GetValue(ctx context.Context, provider, key string) (string, error) {
	if s.db == nil || provider == "" || key == "" {
		return "", nil
	}

	const query = `
		SELECT state_value
		FROM integration_runtime_state
		WHERE provider = $1
		  AND state_key = $2
	`

	var value string
	err := s.db.QueryRowContext(ctx, query, provider, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("load integration runtime state %s/%s: %w", provider, key, err)
	}

	return value, nil
}

func (s sqlIntegrationRuntimeStateStore) PutValue(ctx context.Context, provider, key, value string) error {
	if s.db == nil || provider == "" || key == "" || value == "" {
		return nil
	}

	const upsert = `
		INSERT INTO integration_runtime_state (
			provider, state_key, state_value, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5
		)
		ON CONFLICT (provider, state_key) DO UPDATE SET
			state_value = EXCLUDED.state_value,
			updated_at = EXCLUDED.updated_at
	`

	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx, upsert, provider, key, value, now, now); err != nil {
		return fmt.Errorf("upsert integration runtime state %s/%s: %w", provider, key, err)
	}

	return nil
}
