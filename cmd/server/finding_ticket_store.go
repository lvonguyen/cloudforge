package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"aegis/internal/integrations"
)

type findingTicketStore interface {
	GetTicket(ctx context.Context, tenantID, findingID string) (*integrations.Ticket, error)
	PutTicket(ctx context.Context, tenantID string, ticket *integrations.Ticket) error
}

type sqlFindingTicketStore struct {
	db *sql.DB
}

func newFindingTicketStore(db *sql.DB) findingTicketStore {
	if db == nil {
		return nil
	}
	return sqlFindingTicketStore{db: db}
}

func normalizeTicketTenantID(tenantID string) string {
	if tenantID == "" {
		return "default"
	}
	return tenantID
}

func (s sqlFindingTicketStore) GetTicket(ctx context.Context, tenantID, findingID string) (*integrations.Ticket, error) {
	if s.db == nil || findingID == "" {
		return nil, nil
	}
	tenantID = normalizeTicketTenantID(tenantID)

	const query = `
		SELECT provider, external_id, title, status, priority, assignee, url, metadata, created_at, updated_at
		FROM finding_tickets
		WHERE tenant_id = $1
		  AND finding_id = $2
	`

	var (
		ticket           integrations.Ticket
		assignee, url    sql.NullString
		metadata         []byte
		status, priority string
	)
	ticket.FindingID = findingID

	err := s.db.QueryRowContext(ctx, query, tenantID, findingID).Scan(
		&ticket.Provider,
		&ticket.ExternalID,
		&ticket.Title,
		&status,
		&priority,
		&assignee,
		&url,
		&metadata,
		&ticket.CreatedAt,
		&ticket.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load finding ticket %s/%s: %w", tenantID, findingID, err)
	}

	ticket.ID = ticket.ExternalID
	ticket.Status = integrations.TicketStatus(status)
	ticket.Priority = integrations.TicketPriority(priority)
	ticket.Assignee = assignee.String
	ticket.URL = url.String
	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &ticket.Metadata); err != nil {
			return nil, fmt.Errorf("decode finding ticket metadata %s: %w", findingID, err)
		}
	}
	return cloneTicket(ticket), nil
}

func (s sqlFindingTicketStore) PutTicket(ctx context.Context, tenantID string, ticket *integrations.Ticket) error {
	if s.db == nil || ticket == nil || ticket.FindingID == "" {
		return nil
	}
	tenantID = normalizeTicketTenantID(tenantID)
	findingID := ticket.FindingID

	metadata, err := json.Marshal(ticket.Metadata)
	if err != nil {
		return fmt.Errorf("encode finding ticket metadata %s/%s: %w", tenantID, findingID, err)
	}

	now := time.Now().UTC()
	createdAt := ticket.CreatedAt.UTC()
	if createdAt.IsZero() {
		createdAt = now
	}
	updatedAt := ticket.UpdatedAt.UTC()
	if updatedAt.IsZero() {
		updatedAt = now
	}

	const upsertTicket = `
		INSERT INTO finding_tickets (
			finding_id, tenant_id, provider, external_id, title, status,
			priority, assignee, url, metadata, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11, $12
		)
		ON CONFLICT (finding_id, tenant_id) DO UPDATE SET
			provider = EXCLUDED.provider,
			external_id = EXCLUDED.external_id,
			title = EXCLUDED.title,
			status = EXCLUDED.status,
			priority = EXCLUDED.priority,
			assignee = EXCLUDED.assignee,
			url = EXCLUDED.url,
			metadata = EXCLUDED.metadata,
			created_at = EXCLUDED.created_at,
			updated_at = EXCLUDED.updated_at
	`

	if _, err := s.db.ExecContext(ctx, upsertTicket,
		findingID,
		tenantID,
		ticket.Provider,
		ticket.ExternalID,
		ticket.Title,
		string(ticket.Status),
		string(ticket.Priority),
		nullableString(ticket.Assignee),
		nullableString(ticket.URL),
		metadata,
		createdAt,
		updatedAt,
	); err != nil {
		return fmt.Errorf("upsert finding ticket %s/%s: %w", tenantID, findingID, err)
	}

	// Mirror finding-level ticket linkage into related secgraph issues when those
	// issues do not already have their own distinct ticket. This keeps issue and
	// finding operator views aligned without clobbering separately dispatched
	// issue tickets.
	const mirrorIssueLinks = `
		UPDATE issues i
		SET ticket_id = CASE
				WHEN NULLIF(TRIM(COALESCE(i.ticket_id, '')), '') IS NULL OR i.ticket_id = $2 THEN $2
				ELSE i.ticket_id
			END,
			ticket_url = CASE
				WHEN NULLIF(TRIM(COALESCE(i.ticket_id, '')), '') IS NULL OR i.ticket_id = $2 THEN NULLIF($3, '')
				ELSE i.ticket_url
			END,
			assignee_id = CASE
				WHEN NULLIF(TRIM(COALESCE(i.ticket_id, '')), '') IS NULL OR i.ticket_id = $2 THEN COALESCE(NULLIF($4, ''), i.assignee_id)
				ELSE i.assignee_id
			END,
			updated_at = CASE
				WHEN NULLIF(TRIM(COALESCE(i.ticket_id, '')), '') IS NULL OR i.ticket_id = $2 THEN $5
				ELSE i.updated_at
			END
		FROM issue_findings ifl
		WHERE ifl.finding_id = $1
		  AND i.id = ifl.issue_id
	`
	if _, err := s.db.ExecContext(ctx, mirrorIssueLinks+`
		  AND i.tenant_id = $6
	`, findingID, ticket.ExternalID, ticket.URL, ticket.Assignee, now, tenantID); err != nil {
		return fmt.Errorf("mirror finding ticket into issues %s/%s: %w", tenantID, findingID, err)
	}

	return nil
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func cloneTicket(ticket integrations.Ticket) *integrations.Ticket {
	cloned := ticket
	if ticket.Metadata != nil {
		cloned.Metadata = make(map[string]string, len(ticket.Metadata))
		for key, value := range ticket.Metadata {
			cloned.Metadata[key] = value
		}
	}
	return &cloned
}
