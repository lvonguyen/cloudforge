package alerting

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ---------------------------------------------------------------------------
// SlackChannel
// ---------------------------------------------------------------------------

func TestSlackChannelSend(t *testing.T) {
	var received slackPayload

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected application/json, got %s", ct)
		}

		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &received); err != nil {
			t.Fatalf("invalid json: %v", err)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ch := NewSlackChannel(server.URL, server.Client())

	alert := BudgetAlert{
		ID:           "test-1",
		BudgetName:   "Engineering Q1",
		Provider:     "aws",
		BudgetUSD:    10000,
		ActualUSD:    8500,
		ThresholdPct: 85,
		Severity:     SeverityWarning,
		Message:      "Budget at 85%",
	}

	if err := ch.Send(context.Background(), alert); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(received.Blocks) != 3 {
		t.Fatalf("expected 3 blocks, got %d", len(received.Blocks))
	}
	if received.Blocks[0].Type != "header" {
		t.Errorf("expected header block, got %s", received.Blocks[0].Type)
	}
}

func TestSlackChannelSendCritical(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if len(body) == 0 {
			t.Error("empty body")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ch := NewSlackChannel(server.URL, server.Client())
	alert := BudgetAlert{
		ID:       "test-2",
		Severity: SeverityCritical,
		Message:  "Over budget",
	}
	if err := ch.Send(context.Background(), alert); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSlackChannelSendHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	ch := NewSlackChannel(server.URL, server.Client())
	err := ch.Send(context.Background(), BudgetAlert{})
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

// ---------------------------------------------------------------------------
// PagerDutyChannel
// ---------------------------------------------------------------------------

func TestPagerDutyChannelSend(t *testing.T) {
	var received pdEvent

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &received); err != nil {
			t.Fatalf("invalid json: %v", err)
		}

		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	ch := NewPagerDutyChannel("test-routing-key", server.URL, server.Client())

	alert := BudgetAlert{
		ID:           "pd-test-1",
		BudgetName:   "Production Budget",
		Provider:     "gcp",
		CostCenter:   "platform",
		BudgetUSD:    20000,
		ActualUSD:    22000,
		ThresholdPct: 110,
		Severity:     SeverityCritical,
		Message:      "Over budget by 10%",
	}

	if err := ch.Send(context.Background(), alert); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if received.RoutingKey != "test-routing-key" {
		t.Errorf("expected routing key test-routing-key, got %s", received.RoutingKey)
	}
	if received.EventAction != "trigger" {
		t.Errorf("expected trigger action, got %s", received.EventAction)
	}
	if received.Payload.Severity != "critical" {
		t.Errorf("expected critical severity, got %s", received.Payload.Severity)
	}
	if received.DedupKey != "pd-test-1" {
		t.Errorf("expected dedup key pd-test-1, got %s", received.DedupKey)
	}
}

func TestPagerDutyChannelSendWarning(t *testing.T) {
	var received pdEvent

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &received)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	ch := NewPagerDutyChannel("key", server.URL, server.Client())
	alert := BudgetAlert{ID: "pd-warn", Severity: SeverityWarning}
	if err := ch.Send(context.Background(), alert); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if received.Payload.Severity != "warning" {
		t.Errorf("expected warning severity, got %s", received.Payload.Severity)
	}
}

func TestPagerDutyChannelSendHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	ch := NewPagerDutyChannel("key", server.URL, server.Client())
	err := ch.Send(context.Background(), BudgetAlert{})
	if err == nil {
		t.Fatal("expected error for 503 response")
	}
}

// ---------------------------------------------------------------------------
// BudgetMonitor
// ---------------------------------------------------------------------------

func TestBudgetMonitorCheck(t *testing.T) {
	var sentAlerts []BudgetAlert
	recorder := &alertRecorder{alerts: &sentAlerts}

	spend := &stubSpend{amount: 8500}
	rules := []BudgetRule{
		{
			Name:       "Engineering",
			MonthlyUSD: 10000,
			Thresholds: []float64{80, 100},
		},
	}

	monitor := NewBudgetMonitor(rules, spend, []AlertChannel{recorder})
	fired, err := monitor.Check(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 85% > 80 threshold, but < 100 threshold, so only one alert.
	if len(fired) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(fired))
	}
	if fired[0].Severity != SeverityWarning {
		t.Errorf("expected warning severity, got %s", fired[0].Severity)
	}
	if len(sentAlerts) != 1 {
		t.Errorf("expected 1 sent alert, got %d", len(sentAlerts))
	}
}

func TestBudgetMonitorCheckCritical(t *testing.T) {
	var sentAlerts []BudgetAlert
	recorder := &alertRecorder{alerts: &sentAlerts}

	spend := &stubSpend{amount: 12000}
	rules := []BudgetRule{
		{
			Name:       "Production",
			MonthlyUSD: 10000,
			Thresholds: []float64{80, 100, 120},
		},
	}

	monitor := NewBudgetMonitor(rules, spend, []AlertChannel{recorder})
	fired, err := monitor.Check(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 120% > all three thresholds.
	if len(fired) != 3 {
		t.Fatalf("expected 3 alerts, got %d", len(fired))
	}

	// First should be warning (80%), second and third critical (100%, 120%).
	if fired[0].Severity != SeverityWarning {
		t.Errorf("expected warning, got %s", fired[0].Severity)
	}
	if fired[1].Severity != SeverityCritical {
		t.Errorf("expected critical, got %s", fired[1].Severity)
	}
}

func TestBudgetMonitorCheckUnderBudget(t *testing.T) {
	var sentAlerts []BudgetAlert
	recorder := &alertRecorder{alerts: &sentAlerts}

	spend := &stubSpend{amount: 5000}
	rules := []BudgetRule{
		{
			Name:       "Under",
			MonthlyUSD: 10000,
			Thresholds: []float64{80, 100},
		},
	}

	monitor := NewBudgetMonitor(rules, spend, []AlertChannel{recorder})
	fired, err := monitor.Check(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fired) != 0 {
		t.Errorf("expected 0 alerts, got %d", len(fired))
	}
}

// --- test helpers --------------------------------------------------------

type alertRecorder struct {
	alerts *[]BudgetAlert
}

func (r *alertRecorder) Send(_ context.Context, alert BudgetAlert) error {
	*r.alerts = append(*r.alerts, alert)
	return nil
}

type stubSpend struct {
	amount float64
}

func (s *stubSpend) CurrentSpend(context.Context, string, string) (float64, error) {
	return s.amount, nil
}
