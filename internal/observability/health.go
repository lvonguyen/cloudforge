// Package observability provides logging, metrics, and tracing capabilities
package observability

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// HealthChecker provides application health monitoring
type HealthChecker struct {
	checks     map[string]HealthCheck
	mu         sync.RWMutex
	logger     *zap.Logger
	lastStatus *HealthStatus
	telemetry  *Telemetry
	httpClient *http.Client // Dedicated client with timeout for HTTP checks
}

// HealthCheck defines a health check function
type HealthCheck struct {
	Name     string
	Check    func(ctx context.Context) error
	Timeout  time.Duration
	Critical bool // If true, failure makes the app unhealthy
}

// HealthStatus represents overall health status
type HealthStatus struct {
	Status     string                     `json:"status"` // healthy, degraded, unhealthy
	Timestamp  time.Time                  `json:"timestamp"`
	Version    string                     `json:"version"`
	Uptime     string                     `json:"uptime"`
	Components map[string]ComponentHealth `json:"components"`
}

// ComponentHealth represents health of a single component
type ComponentHealth struct {
	Status      string    `json:"status"` // healthy, unhealthy
	Message     string    `json:"message,omitempty"`
	LastChecked time.Time `json:"last_checked"`
	LatencyMS   int64     `json:"latency_ms"`
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(logger *zap.Logger, telemetry *Telemetry) *HealthChecker {
	return &HealthChecker{
		checks:    make(map[string]HealthCheck),
		logger:    logger,
		telemetry: telemetry,
		httpClient: &http.Client{
			Timeout: 10 * time.Second, // Prevent hanging on unresponsive endpoints
		},
	}
}

// RegisterCheck registers a health check
func (h *HealthChecker) RegisterCheck(check HealthCheck) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if check.Timeout == 0 {
		check.Timeout = 5 * time.Second
	}
	h.checks[check.Name] = check
}

// RegisterDatabaseCheck registers a database health check
func (h *HealthChecker) RegisterDatabaseCheck(name string, db *sql.DB) {
	h.RegisterCheck(HealthCheck{
		Name:     name,
		Critical: true,
		Timeout:  5 * time.Second,
		Check: func(ctx context.Context) error {
			return db.PingContext(ctx)
		},
	})
}

// RegisterRedisCheck registers a Redis health check
func (h *HealthChecker) RegisterRedisCheck(name string, client *redis.Client) {
	h.RegisterCheck(HealthCheck{
		Name:     name,
		Critical: true,
		Timeout:  3 * time.Second,
		Check: func(ctx context.Context) error {
			return client.Ping(ctx).Err()
		},
	})
}

// RegisterHTTPCheck registers an HTTP endpoint health check
func (h *HealthChecker) RegisterHTTPCheck(name, url string, critical bool) {
	h.RegisterCheck(HealthCheck{
		Name:     name,
		Critical: critical,
		Timeout:  10 * time.Second,
		Check: func(ctx context.Context) error {
			req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				return err
			}
			// Use dedicated HTTP client with timeout instead of DefaultClient
			resp, err := h.httpClient.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode >= 400 {
				return fmt.Errorf("HTTP %d", resp.StatusCode)
			}
			return nil
		},
	})
}

// Check performs all health checks
func (h *HealthChecker) Check(ctx context.Context) *HealthStatus {
	h.mu.RLock()
	checks := make(map[string]HealthCheck, len(h.checks))
	for k, v := range h.checks {
		checks[k] = v
	}
	h.mu.RUnlock()

	status := &HealthStatus{
		Status:     "healthy",
		Timestamp:  time.Now(),
		Components: make(map[string]ComponentHealth),
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, check := range checks {
		wg.Add(1)
		go func(c HealthCheck) {
			defer wg.Done()

			checkCtx, cancel := context.WithTimeout(ctx, c.Timeout)
			defer cancel()

			start := time.Now()
			err := c.Check(checkCtx)
			latency := time.Since(start)

			health := ComponentHealth{
				Status:      "healthy",
				LastChecked: time.Now(),
				LatencyMS:   latency.Milliseconds(),
			}

			if err != nil {
				health.Status = "unhealthy"
				health.Message = err.Error()

				h.logger.Warn("Health check failed",
					zap.String("component", c.Name),
					zap.Error(err),
					zap.Duration("latency", latency),
				)

				// Update metrics
				if h.telemetry != nil && h.telemetry.Metrics() != nil {
					h.telemetry.Metrics().HealthStatus.WithLabelValues(c.Name).Set(0)
				}
			} else {
				if h.telemetry != nil && h.telemetry.Metrics() != nil {
					h.telemetry.Metrics().HealthStatus.WithLabelValues(c.Name).Set(1)
				}
			}

			mu.Lock()
			status.Components[c.Name] = health

			// Update overall status
			if health.Status == "unhealthy" {
				if c.Critical {
					status.Status = "unhealthy"
				} else if status.Status == "healthy" {
					status.Status = "degraded"
				}
			}
			mu.Unlock()
		}(check)
	}

	wg.Wait()

	// Update metrics
	if h.telemetry != nil && h.telemetry.Metrics() != nil {
		h.telemetry.Metrics().LastHealthCheck.SetToCurrentTime()
	}

	h.mu.Lock()
	h.lastStatus = status
	h.mu.Unlock()

	return status
}

// GetLastStatus returns the last health status
func (h *HealthChecker) GetLastStatus() *HealthStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.lastStatus
}

// StartPeriodicCheck starts periodic health checking
func (h *HealthChecker) StartPeriodicCheck(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		// Initial check
		h.Check(ctx)

		for {
			select {
			case <-ctx.Done():
				ticker.Stop()
				return
			case <-ticker.C:
				h.Check(ctx)
			}
		}
	}()
}

// LivenessHandler returns an HTTP handler for liveness probes
func (h *HealthChecker) LivenessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "alive",
			"time":   time.Now().Format(time.RFC3339),
		})
	}
}

// ReadinessHandler returns an HTTP handler for readiness probes
func (h *HealthChecker) ReadinessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		status := h.Check(ctx)

		w.Header().Set("Content-Type", "application/json")

		if status.Status == "unhealthy" {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}

		_ = json.NewEncoder(w).Encode(status)
	}
}

// HealthHandler returns an HTTP handler for detailed health info
func (h *HealthChecker) HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		status := h.Check(ctx)

		w.Header().Set("Content-Type", "application/json")

		switch status.Status {
		case "healthy":
			w.WriteHeader(http.StatusOK)
		case "degraded":
			w.WriteHeader(http.StatusOK) // Still serving, but degraded
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		_ = json.NewEncoder(w).Encode(status)
	}
}
