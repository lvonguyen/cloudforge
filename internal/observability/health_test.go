package observability

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestHealthCheckerReportsLatencyMilliseconds(t *testing.T) {
	t.Parallel()

	hc := NewHealthChecker(zap.NewNop(), nil)
	hc.RegisterCheck(HealthCheck{
		Name:     "slow-component",
		Critical: true,
		Timeout:  time.Second,
		Check: func(ctx context.Context) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(25 * time.Millisecond):
				return nil
			}
		},
	})

	status := hc.Check(context.Background())
	component, ok := status.Components["slow-component"]
	if !ok {
		t.Fatal("expected slow-component health entry")
	}
	if component.LatencyMS < 20 {
		t.Fatalf("latency_ms = %d, want >= 20", component.LatencyMS)
	}
	if component.LatencyMS > 500 {
		t.Fatalf("latency_ms = %d, want <= 500", component.LatencyMS)
	}
}
