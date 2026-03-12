package workflow

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var ErrNotFound = errors.New("not found")

// Status represents a workflow state.
type Status string

const (
	StatusPending   Status = "pending"
	StatusRunning   Status = "running"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
	StatusCancelled Status = "cancelled"
)

// WorkflowType categorizes workflows.
type WorkflowType string

const (
	TypeRemediation      WorkflowType = "remediation"
	TypeAccessReview     WorkflowType = "access_review"
	TypeComplianceScan   WorkflowType = "compliance_scan"
	TypeApproval         WorkflowType = "approval"
	TypeIncidentResponse WorkflowType = "incident_response"
)

// Workflow represents a workflow instance.
type Workflow struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Type        WorkflowType      `json:"type"`
	Status      Status            `json:"status"`
	Priority    int               `json:"priority"` // 1=critical, 2=high, 3=medium, 4=low
	Initiator   string            `json:"initiator"`
	Assignee    string            `json:"assignee,omitempty"`
	Description string            `json:"description"`
	Steps       []Step            `json:"steps"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	CompletedAt *time.Time        `json:"completed_at,omitempty"`
}

// Step represents a single step in a workflow.
type Step struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Status      Status     `json:"status"`
	Output      string     `json:"output,omitempty"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// Engine is the workflow orchestration interface.
type Engine interface {
	StartWorkflow(ctx context.Context, wf *Workflow) (*Workflow, error)
	GetWorkflow(ctx context.Context, id string) (*Workflow, error)
	ListWorkflows(ctx context.Context) ([]*Workflow, error)
	CancelWorkflow(ctx context.Context, id string) error
	ApproveWorkflow(ctx context.Context, id, approver string) (*Workflow, error)
}

// NewEngine creates a workflow engine for the given provider.
func NewEngine(provider string) (Engine, error) {
	switch provider {
	case "memory", "":
		return newMemoryEngine(), nil
	default:
		return nil, fmt.Errorf("unsupported workflow engine provider: %q", provider)
	}
}
