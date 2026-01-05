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
	Status      string                   `json:"status"` // healthy, degraded, unhealthy
	Timestamp   time.Time                `json:"timestamp"`
	Version     string                   `json:"version"`
	Uptime      string                   `json:"uptime"`
	Components  map[string]ComponentHealth `json:"components"`
}

// ComponentHealth represents health of a single component
type ComponentHealth struct {
	Status      string        `json:"status"` // healthy, unhealthy
	Message     string        `json:"message,omitempty"`
	LastChecked time.Time     `json:"last_checked"`
	Latency     time.Duration `json:"latency_ms"`
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(logger *zap.Logger, telemetry *Telemetry) *HealthChecker {
	return &HealthChecker{
		checks:    make(map[string]HealthCheck),
		logger:    logger,
		telemetry: telemetry,
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
			resp, err := http.DefaultClient.Do(req)
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
				Latency:     latency,
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
		json.NewEncoder(w).Encode(map[string]string{
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

		json.NewEncoder(w).Encode(status)
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

		json.NewEncoder(w).Encode(status)
	}
}

// Troubleshooting provides common issue detection and remediation
type Troubleshooting struct {
	logger *zap.Logger
}

// CommonIssue represents a detected issue
type CommonIssue struct {
	Component   string   `json:"component"`
	Issue       string   `json:"issue"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Remediation []string `json:"remediation_steps"`
	KBArticle   string   `json:"kb_article,omitempty"`
}

// NewTroubleshooting creates a new troubleshooting helper
func NewTroubleshooting(logger *zap.Logger) *Troubleshooting {
	return &Troubleshooting{logger: logger}
}

// DiagnoseHealthStatus analyzes health status and provides remediation
func (t *Troubleshooting) DiagnoseHealthStatus(status *HealthStatus) []CommonIssue {
	var issues []CommonIssue

	for name, component := range status.Components {
		if component.Status != "healthy" {
			issue := t.diagnoseComponent(name, component)
			if issue != nil {
				issues = append(issues, *issue)
			}
		}
	}

	return issues
}

func (t *Troubleshooting) diagnoseComponent(name string, health ComponentHealth) *CommonIssue {
	switch name {
	case "database", "postgres", "postgresql":
		return t.diagnoseDatabaseIssue(health)
	case "redis", "cache":
		return t.diagnoseRedisIssue(health)
	case "ai_provider", "anthropic", "openai":
		return t.diagnoseAIProviderIssue(health)
	default:
		return &CommonIssue{
			Component:   name,
			Issue:       "Component unhealthy",
			Severity:    "high",
			Description: health.Message,
			Remediation: []string{
				"Check component logs for errors",
				"Verify network connectivity to the component",
				"Check component resource utilization (CPU, memory)",
				"Restart the component if other checks pass",
			},
		}
	}
}

func (t *Troubleshooting) diagnoseDatabaseIssue(health ComponentHealth) *CommonIssue {
	return &CommonIssue{
		Component:   "database",
		Issue:       "Database connection failure",
		Severity:    "critical",
		Description: health.Message,
		Remediation: []string{
			"1. Check database server is running: `systemctl status postgresql`",
			"2. Verify connection string in config: DATABASE_URL environment variable",
			"3. Check database connectivity: `pg_isready -h <host> -p <port>`",
			"4. Verify credentials: test with `psql -h <host> -U <user> -d <database>`",
			"5. Check max connections: `SELECT count(*) FROM pg_stat_activity;`",
			"6. If connections exhausted, increase `max_connections` or use connection pooling",
			"7. Check disk space: `df -h /var/lib/postgresql`",
			"8. Review PostgreSQL logs: `/var/log/postgresql/`",
		},
		KBArticle: "https://docs.cloudforge.io/troubleshooting/database",
	}
}

func (t *Troubleshooting) diagnoseRedisIssue(health ComponentHealth) *CommonIssue {
	return &CommonIssue{
		Component:   "redis",
		Issue:       "Redis connection failure",
		Severity:    "high",
		Description: health.Message,
		Remediation: []string{
			"1. Check Redis server is running: `systemctl status redis`",
			"2. Test connectivity: `redis-cli ping`",
			"3. Verify REDIS_URL environment variable",
			"4. Check Redis memory usage: `redis-cli INFO memory`",
			"5. If memory full, check eviction policy or increase maxmemory",
			"6. Review Redis logs: `/var/log/redis/`",
			"7. For ElastiCache: check security group allows inbound on port 6379",
			"8. Check network ACLs and route tables for VPC connectivity",
		},
		KBArticle: "https://docs.cloudforge.io/troubleshooting/redis",
	}
}

func (t *Troubleshooting) diagnoseAIProviderIssue(health ComponentHealth) *CommonIssue {
	return &CommonIssue{
		Component:   "ai_provider",
		Issue:       "AI provider connection failure",
		Severity:    "medium",
		Description: health.Message,
		Remediation: []string{
			"1. Verify API key is set: ANTHROPIC_API_KEY or OPENAI_API_KEY",
			"2. Check API key validity at provider dashboard",
			"3. Verify rate limits haven't been exceeded",
			"4. Check network allows outbound HTTPS to api.anthropic.com or api.openai.com",
			"5. Test connectivity: `curl -I https://api.anthropic.com`",
			"6. Check for provider status at status.anthropic.com or status.openai.com",
			"7. If rate limited, implement exponential backoff or upgrade plan",
			"8. Consider enabling fallback provider in config",
		},
		KBArticle: "https://docs.cloudforge.io/troubleshooting/ai-provider",
	}
}

// GetCommonRemediations returns common remediation patterns
func (t *Troubleshooting) GetCommonRemediations() map[string][]string {
	return map[string][]string{
		"connection_timeout": {
			"Increase connection timeout in config",
			"Check network latency between components",
			"Verify security groups allow traffic on required ports",
			"Check for packet loss: `ping -c 100 <host>`",
		},
		"out_of_memory": {
			"Increase container memory limits",
			"Check for memory leaks using pprof",
			"Reduce batch sizes for processing",
			"Enable memory-efficient streaming where possible",
		},
		"rate_limit_exceeded": {
			"Implement request queuing with backoff",
			"Cache frequently accessed data",
			"Upgrade API tier for higher limits",
			"Distribute requests across multiple API keys",
		},
		"certificate_error": {
			"Verify certificate hasn't expired: `openssl s_client -connect <host>:443`",
			"Check CA certificates are installed",
			"For internal CAs, add to trusted certificates",
			"Verify hostname matches certificate SAN",
		},
		"disk_full": {
			"Clear old log files: `find /var/log -mtime +30 -delete`",
			"Expand volume size",
			"Enable log rotation with size limits",
			"Move large files to object storage",
		},
	}
}
