package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

const defaultEventsEndpoint = "https://events.pagerduty.com/v2/enqueue"

// PagerDutyChannel sends budget alerts via the PagerDuty Events API v2.
type PagerDutyChannel struct {
	RoutingKey     string
	EventsEndpoint string // Override for testing; defaults to PagerDuty production URL.
	Client         *http.Client
}

// NewPagerDutyChannel creates a PagerDutyChannel. If client is nil
// http.DefaultClient is used. eventsEndpoint can be empty to use the
// default PagerDuty endpoint.
func NewPagerDutyChannel(routingKey, eventsEndpoint string, client *http.Client) *PagerDutyChannel {
	if client == nil {
		client = http.DefaultClient
	}
	if eventsEndpoint == "" {
		eventsEndpoint = defaultEventsEndpoint
	}
	return &PagerDutyChannel{
		RoutingKey:     routingKey,
		EventsEndpoint: eventsEndpoint,
		Client:         client,
	}
}

// pdEvent is the Events API v2 request body.
type pdEvent struct {
	RoutingKey  string    `json:"routing_key"`
	EventAction string    `json:"event_action"`
	DedupKey    string    `json:"dedup_key"`
	Payload     pdPayload `json:"payload"`
}

type pdPayload struct {
	Summary       string            `json:"summary"`
	Source        string            `json:"source"`
	Severity      string            `json:"severity"` // critical, error, warning, info
	Component     string            `json:"component,omitempty"`
	CustomDetails map[string]string `json:"custom_details,omitempty"`
}

// Send posts an Events API v2 trigger event to PagerDuty.
func (p *PagerDutyChannel) Send(ctx context.Context, alert BudgetAlert) error {
	severity := "warning"
	if alert.Severity == SeverityCritical {
		severity = "critical"
	}

	event := pdEvent{
		RoutingKey:  p.RoutingKey,
		EventAction: "trigger",
		DedupKey:    alert.ID,
		Payload: pdPayload{
			Summary:   fmt.Sprintf("Budget Alert: %s — $%.2f / $%.2f (%.0f%%)", alert.BudgetName, alert.ActualUSD, alert.BudgetUSD, alert.ThresholdPct),
			Source:    "aegis-finops",
			Severity:  severity,
			Component: alert.Provider,
			CustomDetails: map[string]string{
				"budget_name": alert.BudgetName,
				"cost_center": alert.CostCenter,
				"budget_usd":  fmt.Sprintf("%.2f", alert.BudgetUSD),
				"actual_usd":  fmt.Sprintf("%.2f", alert.ActualUSD),
				"threshold":   fmt.Sprintf("%.0f%%", alert.ThresholdPct),
			},
		},
	}

	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("pagerduty: marshal event: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.EventsEndpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("pagerduty: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.Client.Do(req)
	if err != nil {
		return fmt.Errorf("pagerduty: send: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("pagerduty: unexpected status %d", resp.StatusCode)
	}
	return nil
}
