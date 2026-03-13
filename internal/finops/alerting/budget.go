package alerting

import (
	"context"
	"fmt"
	"time"
)

// BudgetRule defines a budget and the thresholds that trigger alerts.
type BudgetRule struct {
	Name       string    // Human-readable budget name
	Provider   string    // Empty means all providers
	CostCenter string    // Empty means all cost centers
	MonthlyUSD float64   // Monthly budget in USD
	Thresholds []float64 // Percentage thresholds, e.g. [80, 100, 120]
}

// SpendProvider returns the current spend for a (provider, costCenter) pair.
type SpendProvider interface {
	CurrentSpend(ctx context.Context, provider, costCenter string) (float64, error)
}

// BudgetMonitor checks current spend against budget rules and fires alerts
// through all configured channels.
type BudgetMonitor struct {
	rules    []BudgetRule
	spend    SpendProvider
	channels []AlertChannel
}

// NewBudgetMonitor creates a BudgetMonitor.
func NewBudgetMonitor(rules []BudgetRule, spend SpendProvider, channels []AlertChannel) *BudgetMonitor {
	return &BudgetMonitor{
		rules:    rules,
		spend:    spend,
		channels: channels,
	}
}

// Check evaluates every rule against current spend and delivers alerts for
// any threshold breaches. Returns the list of alerts that were fired.
func (m *BudgetMonitor) Check(ctx context.Context) ([]BudgetAlert, error) {
	var fired []BudgetAlert

	for _, rule := range m.rules {
		actual, err := m.spend.CurrentSpend(ctx, rule.Provider, rule.CostCenter)
		if err != nil {
			return fired, fmt.Errorf("budget %q: fetch spend: %w", rule.Name, err)
		}

		pct := (actual / rule.MonthlyUSD) * 100

		for _, threshold := range rule.Thresholds {
			if pct < threshold {
				continue
			}

			severity := SeverityWarning
			if threshold >= 100 {
				severity = SeverityCritical
			}

			alert := BudgetAlert{
				ID:           fmt.Sprintf("budget-%s-%.0f", rule.Name, threshold),
				BudgetName:   rule.Name,
				Provider:     rule.Provider,
				CostCenter:   rule.CostCenter,
				BudgetUSD:    rule.MonthlyUSD,
				ActualUSD:    actual,
				ThresholdPct: pct,
				Severity:     severity,
				FiredAt:      time.Now(),
				Message:      fmt.Sprintf("Budget %q is at %.1f%% ($%.2f / $%.2f). Threshold %.0f%% breached.", rule.Name, pct, actual, rule.MonthlyUSD, threshold),
			}

			for _, ch := range m.channels {
				if sendErr := ch.Send(ctx, alert); sendErr != nil {
					return fired, fmt.Errorf("budget %q: send alert: %w", rule.Name, sendErr)
				}
			}

			fired = append(fired, alert)
		}
	}

	return fired, nil
}
