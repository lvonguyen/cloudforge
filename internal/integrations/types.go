// Package integrations provides ticket provider abstraction and risk-aware routing
// for remediation workflows across external systems (Asana, Jira, ServiceNow).
package integrations

import (
	"context"
	"time"
)

// TicketStatus represents the lifecycle state of an external ticket.
type TicketStatus string

const (
	TicketStatusOpen       TicketStatus = "open"
	TicketStatusInProgress TicketStatus = "in_progress"
	TicketStatusResolved   TicketStatus = "resolved"
	TicketStatusClosed     TicketStatus = "closed"
	TicketStatusRejected   TicketStatus = "rejected"
)

// TicketPriority represents the urgency of a remediation ticket.
type TicketPriority string

const (
	PriorityUrgent TicketPriority = "urgent"
	PriorityHigh   TicketPriority = "high"
	PriorityNormal TicketPriority = "normal"
	PriorityLow    TicketPriority = "low"
)

// TicketProvider abstracts external ticket/project management systems.
type TicketProvider interface {
	Name() string
	CreateTicket(ctx context.Context, req CreateTicketRequest) (*Ticket, error)
	GetTicket(ctx context.Context, externalID string) (*Ticket, error)
	AddComment(ctx context.Context, externalID, body string) (*CommentSync, error)
	SyncStatus(ctx context.Context, externalID string) (TicketStatus, error)
}

// CreateTicketRequest is the input for creating a ticket in an external system.
type CreateTicketRequest struct {
	FindingID   string            `json:"finding_id"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Priority    TicketPriority    `json:"priority"`
	Assignee    string            `json:"assignee,omitempty"`
	Labels      []string          `json:"labels,omitempty"`
	DueDate     *time.Time        `json:"due_date,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// Ticket represents a ticket in an external system.
type Ticket struct {
	ID         string            `json:"id"`          // Internal CF ticket ID
	ExternalID string            `json:"external_id"` // Provider-specific ID (e.g. Asana GID)
	Provider   string            `json:"provider"`    // "asana", "jira", "servicenow"
	FindingID  string            `json:"finding_id"`
	Title      string            `json:"title"`
	Status     TicketStatus      `json:"status"`
	Priority   TicketPriority    `json:"priority"`
	Assignee   string            `json:"assignee,omitempty"`
	URL        string            `json:"url,omitempty"` // Deep link to external ticket
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// CommentSync represents a comment synced to/from an external system.
type CommentSync struct {
	ID         string    `json:"id"`
	ExternalID string    `json:"external_id"`
	Body       string    `json:"body"`
	Author     string    `json:"author"`
	CreatedAt  time.Time `json:"created_at"`
}

// RoutingDecision is the output of the risk-aware routing engine.
type RoutingDecision struct {
	Priority TicketPriority `json:"priority"`
	Team     string         `json:"team"`
	SLAHours int            `json:"sla_hours"`
	Reason   string         `json:"reason"`
}
