package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// SlackChannel sends budget alerts to a Slack incoming webhook using Block Kit.
type SlackChannel struct {
	WebhookURL string
	Client     *http.Client
}

// NewSlackChannel creates a SlackChannel. If client is nil http.DefaultClient is used.
func NewSlackChannel(webhookURL string, client *http.Client) *SlackChannel {
	if client == nil {
		client = http.DefaultClient
	}
	return &SlackChannel{WebhookURL: webhookURL, Client: client}
}

// slackPayload is the Block Kit message sent to the webhook.
type slackPayload struct {
	Blocks []slackBlock `json:"blocks"`
}

type slackBlock struct {
	Type   string      `json:"type"`
	Text   *slackText  `json:"text,omitempty"`
	Fields []slackText `json:"fields,omitempty"`
}

type slackText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Send posts a Block Kit formatted message to the Slack webhook URL.
func (s *SlackChannel) Send(ctx context.Context, alert BudgetAlert) error {
	emoji := ":warning:"
	if alert.Severity == SeverityCritical {
		emoji = ":rotating_light:"
	}

	payload := slackPayload{
		Blocks: []slackBlock{
			{
				Type: "header",
				Text: &slackText{Type: "plain_text", Text: fmt.Sprintf("%s Budget Alert: %s", emoji, alert.BudgetName)},
			},
			{
				Type: "section",
				Fields: []slackText{
					{Type: "mrkdwn", Text: fmt.Sprintf("*Severity:*\n%s", alert.Severity)},
					{Type: "mrkdwn", Text: fmt.Sprintf("*Provider:*\n%s", providerOrAll(alert.Provider))},
					{Type: "mrkdwn", Text: fmt.Sprintf("*Budget:*\n$%.2f", alert.BudgetUSD)},
					{Type: "mrkdwn", Text: fmt.Sprintf("*Actual:*\n$%.2f (%.0f%%)", alert.ActualUSD, alert.ThresholdPct)},
				},
			},
			{
				Type: "section",
				Text: &slackText{Type: "mrkdwn", Text: alert.Message},
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("slack: marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("slack: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.Client.Do(req)
	if err != nil {
		return fmt.Errorf("slack: send: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack: unexpected status %d", resp.StatusCode)
	}
	return nil
}

func providerOrAll(p string) string {
	if p == "" {
		return "all"
	}
	return p
}
