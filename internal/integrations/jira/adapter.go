package jira

import (
	"context"
	"fmt"
	"time"

	"aegis/internal/integrations"

	"go.uber.org/zap"
)

// Adapter implements integrations.TicketProvider backed by the Jira REST API.
type Adapter struct {
	client *Client
	logger *zap.Logger
}

// NewAdapter creates a Jira-backed TicketProvider.
func NewAdapter(client *Client, logger *zap.Logger) integrations.TicketProvider {
	return &Adapter{client: client, logger: logger}
}

func (a *Adapter) Name() string { return "jira" }

func (a *Adapter) CreateTicket(ctx context.Context, req integrations.CreateTicketRequest) (*integrations.Ticket, error) {
	description := fmt.Sprintf("Cloud Aegis Finding: %s\n\n%s", req.FindingID, req.Description)
	priority := mapPriorityToJira(req.Priority)

	resp, err := a.client.CreateIssue(ctx, req.Title, description, priority, req.Assignee, req.Labels, req.DueDate)
	if err != nil {
		return nil, fmt.Errorf("creating jira issue: %w", err)
	}

	createdAt, err := time.Parse("2006-01-02T15:04:05.000-0700", resp.Fields.Created)
	if err != nil {
		a.logger.Warn("parsing jira timestamp", zap.String("raw", resp.Fields.Created), zap.Error(err))
	}

	return &integrations.Ticket{
		ID:         resp.Key,
		ExternalID: resp.Key,
		Provider:   "jira",
		FindingID:  req.FindingID,
		Title:      req.Title,
		Status:     integrations.TicketStatusOpen,
		Priority:   req.Priority,
		Assignee:   req.Assignee,
		URL:        a.client.baseURL + "/browse/" + resp.Key,
		CreatedAt:  createdAt,
		UpdatedAt:  createdAt,
		Metadata:   req.Metadata,
	}, nil
}

func (a *Adapter) GetTicket(ctx context.Context, externalID string) (*integrations.Ticket, error) {
	resp, err := a.client.GetIssue(ctx, externalID)
	if err != nil {
		return nil, fmt.Errorf("getting jira issue: %w", err)
	}

	status := mapStatusFromJira(resp.Fields.Status.StatusCategory.Key)
	priority := mapPriorityFromJira(resp.Fields.Priority)

	createdAt, err := time.Parse("2006-01-02T15:04:05.000-0700", resp.Fields.Created)
	if err != nil {
		a.logger.Warn("parsing jira timestamp", zap.String("raw", resp.Fields.Created), zap.Error(err))
	}
	updatedAt, err := time.Parse("2006-01-02T15:04:05.000-0700", resp.Fields.Updated)
	if err != nil {
		a.logger.Warn("parsing jira timestamp", zap.String("raw", resp.Fields.Updated), zap.Error(err))
	}

	var assignee string
	if resp.Fields.Assignee != nil {
		assignee = resp.Fields.Assignee.DisplayName
	}

	return &integrations.Ticket{
		ID:         resp.Key,
		ExternalID: resp.Key,
		Provider:   "jira",
		Title:      resp.Fields.Summary,
		Status:     status,
		Priority:   priority,
		Assignee:   assignee,
		URL:        a.client.baseURL + "/browse/" + resp.Key,
		CreatedAt:  createdAt,
		UpdatedAt:  updatedAt,
	}, nil
}

func (a *Adapter) AddComment(ctx context.Context, externalID, body string) (*integrations.CommentSync, error) {
	resp, err := a.client.AddComment(ctx, externalID, body)
	if err != nil {
		return nil, fmt.Errorf("adding jira comment: %w", err)
	}

	createdAt, err := time.Parse("2006-01-02T15:04:05.000-0700", resp.Created)
	if err != nil {
		a.logger.Warn("parsing jira timestamp", zap.String("raw", resp.Created), zap.Error(err))
	}

	var author string
	if resp.Author != nil {
		author = resp.Author.DisplayName
	}

	return &integrations.CommentSync{
		ID:         resp.ID,
		ExternalID: resp.ID,
		Body:       body,
		Author:     author,
		CreatedAt:  createdAt,
	}, nil
}

func (a *Adapter) SyncStatus(ctx context.Context, externalID string) (integrations.TicketStatus, error) {
	resp, err := a.client.GetIssue(ctx, externalID)
	if err != nil {
		return "", fmt.Errorf("syncing jira status: %w", err)
	}

	return mapStatusFromJira(resp.Fields.Status.StatusCategory.Key), nil
}

// --- Mapping helpers ---

func mapStatusFromJira(categoryKey string) integrations.TicketStatus {
	switch categoryKey {
	case "new":
		return integrations.TicketStatusOpen
	case "indeterminate":
		return integrations.TicketStatusInProgress
	case "done":
		return integrations.TicketStatusResolved
	default:
		return integrations.TicketStatusOpen
	}
}

func mapPriorityToJira(p integrations.TicketPriority) string {
	switch p {
	case integrations.PriorityUrgent:
		return "Highest"
	case integrations.PriorityHigh:
		return "High"
	case integrations.PriorityNormal:
		return "Medium"
	case integrations.PriorityLow:
		return "Low"
	default:
		return "Medium"
	}
}

func mapPriorityFromJira(p *jiraPriority) integrations.TicketPriority {
	if p == nil {
		return integrations.PriorityNormal
	}
	switch p.Name {
	case "Highest":
		return integrations.PriorityUrgent
	case "High":
		return integrations.PriorityHigh
	case "Medium":
		return integrations.PriorityNormal
	case "Low", "Lowest":
		return integrations.PriorityLow
	default:
		return integrations.PriorityNormal
	}
}
