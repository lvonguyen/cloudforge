// Package remediation provides types and interfaces for cloud security remediation.
package remediation

import (
	"context"
	"time"

	"cloudforge/internal/findings"
)

// Remediator is the interface that all remediation handlers must implement.
type Remediator interface {
	// Remediate executes the remediation action for the given finding.
	Remediate(ctx context.Context, finding *findings.PrioritizedFinding) (*RemediationResult, error)

	// Validate verifies that the remediation was successful.
	Validate(ctx context.Context, finding *findings.PrioritizedFinding) (*ValidationResult, error)

	// Tier returns the complexity tier (1-3) for this remediation.
	// Tier 1: Auto-safe, no approval needed (DEV/STG)
	// Tier 2: Requires verification before PROD
	// Tier 3: Requires change window
	Tier() int

	// DryRun simulates the remediation without making changes.
	DryRun(ctx context.Context, finding *findings.PrioritizedFinding) (*DryRunResult, error)
}

// RemediationResult contains the outcome of a remediation action.
type RemediationResult struct {
	FindingID   string    `json:"finding_id"`
	Success     bool      `json:"success"`
	Message     string    `json:"message"`
	ResourceID  string    `json:"resource_id"`
	Actions     []string  `json:"actions"` // List of actions taken
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
	Duration    string    `json:"duration"`
	Error       string    `json:"error,omitempty"`
}

// ValidationResult contains the outcome of validating a remediation.
type ValidationResult struct {
	FindingID    string     `json:"finding_id"`
	IsCompliant  bool       `json:"is_compliant"`
	Message      string     `json:"message"`
	Evidence     []string   `json:"evidence"` // Evidence of compliance
	ValidatedAt  time.Time  `json:"validated_at"`
	RecheckAfter *time.Time `json:"recheck_after,omitempty"` // When to revalidate
}

// DryRunResult contains the outcome of a dry-run simulation.
type DryRunResult struct {
	FindingID        string   `json:"finding_id"`
	WouldSucceed     bool     `json:"would_succeed"`
	PlannedActions   []string `json:"planned_actions"`
	PrerequisitesMet bool     `json:"prerequisites_met"`
	Warnings         []string `json:"warnings,omitempty"`
	EstimatedImpact  string   `json:"estimated_impact"`
}

// RemediationStatus represents the state of a remediation operation.
type RemediationStatus string

const (
	StatusPending    RemediationStatus = "pending"
	StatusInProgress RemediationStatus = "in_progress"
	StatusCompleted  RemediationStatus = "completed"
	StatusFailed     RemediationStatus = "failed"
	StatusSkipped    RemediationStatus = "skipped"
)

// RollbackState captures pre-remediation state needed to reverse an action.
type RollbackState struct {
	FindingID  string                 `json:"finding_id"`
	ResourceID string                 `json:"resource_id"`
	Region     string                 `json:"region"`
	AccountID  string                 `json:"account_id"`
	PreState   map[string]interface{} `json:"pre_state"` // Handler-specific state (detector IDs, key IDs, etc.)
	CapturedAt time.Time              `json:"captured_at"`
}

// RollbackResult contains the outcome of a rollback operation.
type RollbackResult struct {
	FindingID    string    `json:"finding_id"`
	Success      bool      `json:"success"`
	Message      string    `json:"message"`
	Actions      []string  `json:"actions"`
	RolledBackAt time.Time `json:"rolled_back_at"`
	Error        string    `json:"error,omitempty"`
}

// RemediationRecord tracks a remediation operation for auditing.
type RemediationRecord struct {
	ID           string             `json:"id"`
	FindingID    string             `json:"finding_id"`
	Domain       string             `json:"domain"`  // compute, identity, network, etc.
	Handler      string             `json:"handler"` // Specific remediator name
	Tier         int                `json:"tier"`
	Status       RemediationStatus  `json:"status"`
	Result       *RemediationResult `json:"result,omitempty"`
	Validation   *ValidationResult  `json:"validation,omitempty"`
	AsanaTaskURL string             `json:"asana_task_url,omitempty"`
	CreatedAt    time.Time          `json:"created_at"`
	UpdatedAt    time.Time          `json:"updated_at"`
}
