// Package alerting provides budget monitoring and multi-channel alert delivery.
package alerting

import (
	"context"
	"time"
)

// Severity indicates how urgent a budget alert is.
type Severity string

const (
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// BudgetAlert represents a single budget threshold breach.
type BudgetAlert struct {
	ID           string    `json:"id"`
	BudgetName   string    `json:"budget_name"`
	Provider     string    `json:"provider,omitempty"` // empty = all providers
	CostCenter   string    `json:"cost_center,omitempty"`
	BudgetUSD    float64   `json:"budget_usd"`
	ActualUSD    float64   `json:"actual_usd"`
	ThresholdPct float64   `json:"threshold_pct"` // e.g. 80 means 80 %
	Severity     Severity  `json:"severity"`
	FiredAt      time.Time `json:"fired_at"`
	Message      string    `json:"message"`
}

// AlertChannel is the interface every notification backend must implement.
type AlertChannel interface {
	// Send delivers the alert. Implementations should respect ctx cancellation.
	Send(ctx context.Context, alert BudgetAlert) error
}
