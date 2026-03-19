package asana

import (
	"context"
	"fmt"
	"time"

	"aegis/internal/integrations"

	"go.uber.org/zap"
)

// Adapter implements integrations.TicketProvider backed by the Asana REST API.
type Adapter struct {
	client *Client
	logger *zap.Logger
}

// NewAdapter creates an Asana-backed TicketProvider.
func NewAdapter(client *Client, logger *zap.Logger) integrations.TicketProvider {
	return &Adapter{client: client, logger: logger}
}

func (a *Adapter) Name() string { return "asana" }

func (a *Adapter) CreateTicket(ctx context.Context, req integrations.CreateTicketRequest) (*integrations.Ticket, error) {
	notes := fmt.Sprintf("Cloud Aegis Finding: %s\n\n%s", req.FindingID, req.Description)
	resp, err := a.client.CreateTask(ctx, req.Title, notes, req.Assignee, req.DueDate)
	if err != nil {
		return nil, fmt.Errorf("creating asana task: %w", err)
	}

	createdAt, _ := time.Parse(time.RFC3339, resp.Data.CreatedAt)

	return &integrations.Ticket{
		ID:         resp.Data.GID,
		ExternalID: resp.Data.GID,
		Provider:   "asana",
		FindingID:  req.FindingID,
		Title:      resp.Data.Name,
		Status:     integrations.TicketStatusOpen,
		Priority:   req.Priority,
		Assignee:   req.Assignee,
		URL:        resp.Data.Permalink,
		CreatedAt:  createdAt,
		UpdatedAt:  createdAt,
		Metadata:   req.Metadata,
	}, nil
}

func (a *Adapter) GetTicket(ctx context.Context, externalID string) (*integrations.Ticket, error) {
	resp, err := a.client.GetTask(ctx, externalID)
	if err != nil {
		return nil, fmt.Errorf("getting asana task: %w", err)
	}

	status := integrations.TicketStatusOpen
	if resp.Data.Completed {
		status = integrations.TicketStatusResolved
	}

	createdAt, _ := time.Parse(time.RFC3339, resp.Data.CreatedAt)

	return &integrations.Ticket{
		ID:         resp.Data.GID,
		ExternalID: resp.Data.GID,
		Provider:   "asana",
		Title:      resp.Data.Name,
		Status:     status,
		URL:        resp.Data.Permalink,
		CreatedAt:  createdAt,
		UpdatedAt:  time.Now().UTC(),
	}, nil
}

func (a *Adapter) AddComment(ctx context.Context, externalID, body string) (*integrations.CommentSync, error) {
	resp, err := a.client.AddStory(ctx, externalID, body)
	if err != nil {
		return nil, fmt.Errorf("adding asana comment: %w", err)
	}

	createdAt, _ := time.Parse(time.RFC3339, resp.Data.CreatedAt)

	return &integrations.CommentSync{
		ID:         resp.Data.GID,
		ExternalID: resp.Data.GID,
		Body:       resp.Data.Text,
		Author:     resp.Data.CreatedBy.Name,
		CreatedAt:  createdAt,
	}, nil
}

func (a *Adapter) SyncStatus(ctx context.Context, externalID string) (integrations.TicketStatus, error) {
	resp, err := a.client.GetTask(ctx, externalID)
	if err != nil {
		return "", fmt.Errorf("syncing asana status: %w", err)
	}

	if resp.Data.Completed {
		return integrations.TicketStatusResolved, nil
	}
	return integrations.TicketStatusOpen, nil
}
