package ado

import (
	"context"
	"fmt"
	"strings"
	"time"

	"aegis/internal/integrations"

	"go.uber.org/zap"
)

// Adapter implements integrations.TicketProvider backed by the Azure DevOps REST API.
type Adapter struct {
	client *Client
	logger *zap.Logger
}

// NewAdapter creates an ADO-backed TicketProvider.
func NewAdapter(client *Client, logger *zap.Logger) integrations.TicketProvider {
	return &Adapter{client: client, logger: logger}
}

func (a *Adapter) Name() string { return "ado" }

func (a *Adapter) CreateTicket(ctx context.Context, req integrations.CreateTicketRequest) (*integrations.Ticket, error) {
	description := fmt.Sprintf("Cloud Aegis Finding: %s\n\n%s", req.FindingID, req.Description)
	priority := mapPriorityToADO(req.Priority)

	resp, err := a.client.CreateWorkItem(ctx, req.Title, description, priority, req.Assignee, req.Labels, req.DueDate)
	if err != nil {
		return nil, fmt.Errorf("creating ADO work item: %w", err)
	}

	return &integrations.Ticket{
		ID:         ExternalID(resp.ID),
		ExternalID: ExternalID(resp.ID),
		Provider:   "ado",
		FindingID:  req.FindingID,
		Title:      req.Title,
		Status:     integrations.TicketStatusOpen,
		Priority:   req.Priority,
		Assignee:   req.Assignee,
		URL:        resp.htmlURL(),
		CreatedAt:  resp.createdDate(),
		UpdatedAt:  resp.createdDate(),
		Metadata:   req.Metadata,
	}, nil
}

func (a *Adapter) GetTicket(ctx context.Context, externalID string) (*integrations.Ticket, error) {
	resp, err := a.client.GetWorkItem(ctx, externalID)
	if err != nil {
		return nil, fmt.Errorf("getting ADO work item: %w", err)
	}

	return &integrations.Ticket{
		ID:         ExternalID(resp.ID),
		ExternalID: ExternalID(resp.ID),
		Provider:   "ado",
		Title:      resp.title(),
		Status:     mapStatusFromADO(resp.state()),
		Priority:   mapPriorityFromADO(resp.priority()),
		Assignee:   resp.assignee(),
		URL:        resp.htmlURL(),
		CreatedAt:  resp.createdDate(),
		UpdatedAt:  resp.changedDate(),
	}, nil
}

func (a *Adapter) AddComment(ctx context.Context, externalID, body string) (*integrations.CommentSync, error) {
	resp, err := a.client.AddComment(ctx, externalID, body)
	if err != nil {
		return nil, fmt.Errorf("adding ADO comment: %w", err)
	}

	createdAt, err := time.Parse(time.RFC3339, resp.CreatedDate)
	if err != nil {
		a.logger.Warn("parsing ADO timestamp", zap.String("raw", resp.CreatedDate), zap.Error(err))
	}

	return &integrations.CommentSync{
		ID:         fmt.Sprintf("%d", resp.ID),
		ExternalID: fmt.Sprintf("%d", resp.ID),
		Body:       body,
		Author:     resp.CreatedBy.DisplayName,
		CreatedAt:  createdAt,
	}, nil
}

func (a *Adapter) SyncStatus(ctx context.Context, externalID string) (integrations.TicketStatus, error) {
	resp, err := a.client.GetWorkItem(ctx, externalID)
	if err != nil {
		return "", fmt.Errorf("syncing ADO status: %w", err)
	}
	return mapStatusFromADO(resp.state()), nil
}

// --- Mapping helpers ---

func mapStatusFromADO(state string) integrations.TicketStatus {
	switch strings.ToLower(state) {
	case "new", "to do":
		return integrations.TicketStatusOpen
	case "active", "doing", "in progress", "committed":
		return integrations.TicketStatusInProgress
	case "resolved":
		return integrations.TicketStatusResolved
	case "closed", "done":
		return integrations.TicketStatusClosed
	case "removed":
		return integrations.TicketStatusRejected
	default:
		return integrations.TicketStatusOpen
	}
}

func mapPriorityToADO(p integrations.TicketPriority) int {
	switch p {
	case integrations.PriorityUrgent:
		return 1
	case integrations.PriorityHigh:
		return 2
	case integrations.PriorityNormal:
		return 3
	case integrations.PriorityLow:
		return 4
	default:
		return 3
	}
}

func mapPriorityFromADO(p int) integrations.TicketPriority {
	switch p {
	case 1:
		return integrations.PriorityUrgent
	case 2:
		return integrations.PriorityHigh
	case 3:
		return integrations.PriorityNormal
	case 4:
		return integrations.PriorityLow
	default:
		return integrations.PriorityNormal
	}
}
