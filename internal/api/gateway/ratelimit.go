// Package gateway provides API gateway functionality including rate limiting
package gateway

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// RateLimiter provides configurable rate limiting for API endpoints
type RateLimiter struct {
	redis       *redis.Client
	logger      *zap.Logger
	config      RateLimitConfig
	localLimits sync.Map // Fallback for Redis unavailability
}

// RateLimitConfig configures the rate limiter
type RateLimitConfig struct {
	// Global defaults
	DefaultRequestsPerSecond int           `yaml:"default_requests_per_second"`
	DefaultRequestsPerMinute int           `yaml:"default_requests_per_minute"`
	DefaultRequestsPerHour   int           `yaml:"default_requests_per_hour"`
	DefaultBurstSize         int           `yaml:"default_burst_size"`

	// Tier-based limits
	Tiers map[string]TierLimits `yaml:"tiers"`

	// Endpoint-specific limits
	Endpoints map[string]EndpointLimits `yaml:"endpoints"`

	// Circuit breaker
	CircuitBreaker CircuitBreakerConfig `yaml:"circuit_breaker"`

	// Response headers
	IncludeHeaders bool `yaml:"include_headers"`
}

// TierLimits defines rate limits per API tier/plan
type TierLimits struct {
	RequestsPerSecond int `yaml:"requests_per_second"`
	RequestsPerMinute int `yaml:"requests_per_minute"`
	RequestsPerHour   int `yaml:"requests_per_hour"`
	RequestsPerDay    int `yaml:"requests_per_day"`
	BurstSize         int `yaml:"burst_size"`
	ConcurrentLimit   int `yaml:"concurrent_limit"`
}

// EndpointLimits defines rate limits for specific endpoints
type EndpointLimits struct {
	Path              string `yaml:"path"`
	Method            string `yaml:"method"`
	RequestsPerSecond int    `yaml:"requests_per_second"`
	RequestsPerMinute int    `yaml:"requests_per_minute"`
	BurstSize         int    `yaml:"burst_size"`
	CostMultiplier    int    `yaml:"cost_multiplier"` // For expensive operations
}

// CircuitBreakerConfig configures circuit breaker behavior
type CircuitBreakerConfig struct {
	Enabled          bool          `yaml:"enabled"`
	FailureThreshold int           `yaml:"failure_threshold"`
	SuccessThreshold int           `yaml:"success_threshold"`
	Timeout          time.Duration `yaml:"timeout"`
	HalfOpenRequests int           `yaml:"half_open_requests"`
}

// RateLimitResult contains the result of a rate limit check
type RateLimitResult struct {
	Allowed       bool
	Remaining     int
	Limit         int
	ResetAt       time.Time
	RetryAfter    time.Duration
	Tier          string
	Reason        string
	RequestCost   int
	QuotaUsed     int
	QuotaLimit    int
}

// RateLimitKey identifies a rate limit bucket
type RateLimitKey struct {
	ClientID   string
	Tier       string
	Endpoint   string
	Method     string
	IPAddress  string
	APIKey     string
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(redisClient *redis.Client, cfg RateLimitConfig, logger *zap.Logger) *RateLimiter {
	// Set defaults if not configured
	if cfg.DefaultRequestsPerSecond == 0 {
		cfg.DefaultRequestsPerSecond = 10
	}
	if cfg.DefaultRequestsPerMinute == 0 {
		cfg.DefaultRequestsPerMinute = 100
	}
	if cfg.DefaultBurstSize == 0 {
		cfg.DefaultBurstSize = 20
	}

	// Initialize default tiers if not configured
	if cfg.Tiers == nil {
		cfg.Tiers = map[string]TierLimits{
			"free": {
				RequestsPerSecond: 5,
				RequestsPerMinute: 60,
				RequestsPerHour:   500,
				RequestsPerDay:    5000,
				BurstSize:         10,
				ConcurrentLimit:   5,
			},
			"basic": {
				RequestsPerSecond: 20,
				RequestsPerMinute: 200,
				RequestsPerHour:   2000,
				RequestsPerDay:    20000,
				BurstSize:         50,
				ConcurrentLimit:   20,
			},
			"professional": {
				RequestsPerSecond: 50,
				RequestsPerMinute: 500,
				RequestsPerHour:   5000,
				RequestsPerDay:    50000,
				BurstSize:         100,
				ConcurrentLimit:   50,
			},
			"enterprise": {
				RequestsPerSecond: 200,
				RequestsPerMinute: 2000,
				RequestsPerHour:   20000,
				RequestsPerDay:    200000,
				BurstSize:         500,
				ConcurrentLimit:   200,
			},
		}
	}

	return &RateLimiter{
		redis:  redisClient,
		logger: logger,
		config: cfg,
	}
}

// Check performs a rate limit check for a request
func (rl *RateLimiter) Check(ctx context.Context, key RateLimitKey) (*RateLimitResult, error) {
	// Get tier limits
	tierLimits := rl.getTierLimits(key.Tier)

	// Get endpoint-specific limits (override tier if more restrictive)
	endpointLimits := rl.getEndpointLimits(key.Endpoint, key.Method)

	// Calculate effective limits
	effectiveLimits := rl.calculateEffectiveLimits(tierLimits, endpointLimits)

	// Check all rate limit windows
	results := make([]*windowResult, 0, 4)

	// Per-second limit (sliding window)
	if effectiveLimits.RequestsPerSecond > 0 {
		result, err := rl.checkWindow(ctx, key, "second", time.Second, effectiveLimits.RequestsPerSecond)
		if err != nil {
			rl.logger.Warn("Rate limit check failed, allowing request", zap.Error(err))
		} else {
			results = append(results, result)
		}
	}

	// Per-minute limit (sliding window)
	if effectiveLimits.RequestsPerMinute > 0 {
		result, err := rl.checkWindow(ctx, key, "minute", time.Minute, effectiveLimits.RequestsPerMinute)
		if err != nil {
			rl.logger.Warn("Rate limit check failed, allowing request", zap.Error(err))
		} else {
			results = append(results, result)
		}
	}

	// Per-hour limit
	if effectiveLimits.RequestsPerHour > 0 {
		result, err := rl.checkWindow(ctx, key, "hour", time.Hour, effectiveLimits.RequestsPerHour)
		if err != nil {
			rl.logger.Warn("Rate limit check failed, allowing request", zap.Error(err))
		} else {
			results = append(results, result)
		}
	}

	// Per-day limit
	if effectiveLimits.RequestsPerDay > 0 {
		result, err := rl.checkWindow(ctx, key, "day", 24*time.Hour, effectiveLimits.RequestsPerDay)
		if err != nil {
			rl.logger.Warn("Rate limit check failed, allowing request", zap.Error(err))
		} else {
			results = append(results, result)
		}
	}

	// Find the most restrictive result
	return rl.combineResults(results, key.Tier, effectiveLimits), nil
}

type windowResult struct {
	window     string
	allowed    bool
	remaining  int
	limit      int
	resetAt    time.Time
	retryAfter time.Duration
}

// checkWindow checks a single rate limit window using Redis
func (rl *RateLimiter) checkWindow(ctx context.Context, key RateLimitKey, window string, duration time.Duration, limit int) (*windowResult, error) {
	redisKey := rl.buildRedisKey(key, window)
	now := time.Now()

	// Use sliding window counter algorithm
	// Script: INCR + EXPIRE atomically
	script := redis.NewScript(`
		local current = redis.call('INCR', KEYS[1])
		if current == 1 then
			redis.call('PEXPIRE', KEYS[1], ARGV[1])
		end
		return current
	`)

	result, err := script.Run(ctx, rl.redis, []string{redisKey}, duration.Milliseconds()).Int()
	if err != nil {
		return nil, fmt.Errorf("redis script failed: %w", err)
	}

	allowed := result <= limit
	remaining := limit - result
	if remaining < 0 {
		remaining = 0
	}

	// Calculate reset time
	ttl, _ := rl.redis.TTL(ctx, redisKey).Result()
	resetAt := now.Add(ttl)

	var retryAfter time.Duration
	if !allowed {
		retryAfter = ttl
	}

	return &windowResult{
		window:     window,
		allowed:    allowed,
		remaining:  remaining,
		limit:      limit,
		resetAt:    resetAt,
		retryAfter: retryAfter,
	}, nil
}

// buildRedisKey constructs the Redis key for rate limiting
func (rl *RateLimiter) buildRedisKey(key RateLimitKey, window string) string {
	identifier := key.ClientID
	if identifier == "" {
		identifier = key.APIKey
	}
	if identifier == "" {
		identifier = key.IPAddress
	}
	return fmt.Sprintf("ratelimit:%s:%s:%s:%s", key.Tier, identifier, key.Endpoint, window)
}

// getTierLimits returns limits for a tier
func (rl *RateLimiter) getTierLimits(tier string) TierLimits {
	if limits, ok := rl.config.Tiers[tier]; ok {
		return limits
	}
	// Return default tier
	if limits, ok := rl.config.Tiers["free"]; ok {
		return limits
	}
	return TierLimits{
		RequestsPerSecond: rl.config.DefaultRequestsPerSecond,
		RequestsPerMinute: rl.config.DefaultRequestsPerMinute,
		BurstSize:         rl.config.DefaultBurstSize,
	}
}

// getEndpointLimits returns limits for a specific endpoint
func (rl *RateLimiter) getEndpointLimits(endpoint, method string) *EndpointLimits {
	key := method + ":" + endpoint
	if limits, ok := rl.config.Endpoints[key]; ok {
		return &limits
	}
	return nil
}

// calculateEffectiveLimits combines tier and endpoint limits
func (rl *RateLimiter) calculateEffectiveLimits(tier TierLimits, endpoint *EndpointLimits) TierLimits {
	if endpoint == nil {
		return tier
	}

	// Use the more restrictive limit
	effective := tier
	if endpoint.RequestsPerSecond > 0 && endpoint.RequestsPerSecond < tier.RequestsPerSecond {
		effective.RequestsPerSecond = endpoint.RequestsPerSecond
	}
	if endpoint.RequestsPerMinute > 0 && endpoint.RequestsPerMinute < tier.RequestsPerMinute {
		effective.RequestsPerMinute = endpoint.RequestsPerMinute
	}

	// Apply cost multiplier for expensive operations
	if endpoint.CostMultiplier > 1 {
		effective.RequestsPerSecond /= endpoint.CostMultiplier
		effective.RequestsPerMinute /= endpoint.CostMultiplier
		effective.RequestsPerHour /= endpoint.CostMultiplier
		effective.RequestsPerDay /= endpoint.CostMultiplier
	}

	return effective
}

// combineResults finds the most restrictive result
func (rl *RateLimiter) combineResults(results []*windowResult, tier string, limits TierLimits) *RateLimitResult {
	if len(results) == 0 {
		return &RateLimitResult{
			Allowed: true,
			Tier:    tier,
		}
	}

	// Find the first denied or most restrictive allowed
	var mostRestrictive *windowResult
	for _, r := range results {
		if !r.allowed {
			return &RateLimitResult{
				Allowed:    false,
				Remaining:  r.remaining,
				Limit:      r.limit,
				ResetAt:    r.resetAt,
				RetryAfter: r.retryAfter,
				Tier:       tier,
				Reason:     fmt.Sprintf("Rate limit exceeded for %s window", r.window),
			}
		}
		if mostRestrictive == nil || r.remaining < mostRestrictive.remaining {
			mostRestrictive = r
		}
	}

	return &RateLimitResult{
		Allowed:   true,
		Remaining: mostRestrictive.remaining,
		Limit:     mostRestrictive.limit,
		ResetAt:   mostRestrictive.resetAt,
		Tier:      tier,
	}
}

// Middleware returns an HTTP middleware for rate limiting
func (rl *RateLimiter) Middleware(getTier func(r *http.Request) string, getClientID func(r *http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Build rate limit key
			key := RateLimitKey{
				ClientID:  getClientID(r),
				Tier:      getTier(r),
				Endpoint:  r.URL.Path,
				Method:    r.Method,
				IPAddress: getClientIP(r),
				APIKey:    r.Header.Get("X-API-Key"),
			}

			// Check rate limit
			result, err := rl.Check(ctx, key)
			if err != nil {
				rl.logger.Error("Rate limit check failed", zap.Error(err))
				// Allow request on error (fail open)
				next.ServeHTTP(w, r)
				return
			}

			// Set rate limit headers
			if rl.config.IncludeHeaders {
				w.Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
				w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
				w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(result.ResetAt.Unix(), 10))
				w.Header().Set("X-RateLimit-Tier", result.Tier)
			}

			if !result.Allowed {
				w.Header().Set("Retry-After", strconv.Itoa(int(result.RetryAfter.Seconds())))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				
				response := fmt.Sprintf(`{
					"error": "rate_limit_exceeded",
					"message": "%s",
					"retry_after_seconds": %d,
					"limit": %d,
					"tier": "%s"
				}`, result.Reason, int(result.RetryAfter.Seconds()), result.Limit, result.Tier)
				
				w.Write([]byte(response))
				
				rl.logger.Warn("Rate limit exceeded",
					zap.String("client_id", key.ClientID),
					zap.String("tier", key.Tier),
					zap.String("endpoint", key.Endpoint),
					zap.String("ip", key.IPAddress),
				)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxies/load balancers)
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// Take the first IP in the chain
		return xff
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}

// DefaultConfig returns a sensible default configuration
func DefaultConfig() RateLimitConfig {
	return RateLimitConfig{
		DefaultRequestsPerSecond: 10,
		DefaultRequestsPerMinute: 100,
		DefaultRequestsPerHour:   1000,
		DefaultBurstSize:         20,
		IncludeHeaders:           true,
		Tiers: map[string]TierLimits{
			"anonymous": {
				RequestsPerSecond: 2,
				RequestsPerMinute: 20,
				RequestsPerHour:   100,
				RequestsPerDay:    500,
				BurstSize:         5,
				ConcurrentLimit:   2,
			},
			"free": {
				RequestsPerSecond: 5,
				RequestsPerMinute: 60,
				RequestsPerHour:   500,
				RequestsPerDay:    5000,
				BurstSize:         10,
				ConcurrentLimit:   5,
			},
			"basic": {
				RequestsPerSecond: 20,
				RequestsPerMinute: 200,
				RequestsPerHour:   2000,
				RequestsPerDay:    20000,
				BurstSize:         50,
				ConcurrentLimit:   20,
			},
			"professional": {
				RequestsPerSecond: 50,
				RequestsPerMinute: 500,
				RequestsPerHour:   5000,
				RequestsPerDay:    50000,
				BurstSize:         100,
				ConcurrentLimit:   50,
			},
			"enterprise": {
				RequestsPerSecond: 200,
				RequestsPerMinute: 2000,
				RequestsPerHour:   20000,
				RequestsPerDay:    200000,
				BurstSize:         500,
				ConcurrentLimit:   200,
			},
		},
		Endpoints: map[string]EndpointLimits{
			// AI analysis is expensive
			"POST:/api/v1/findings/analyze": {
				Path:              "/api/v1/findings/analyze",
				Method:            "POST",
				RequestsPerSecond: 2,
				RequestsPerMinute: 30,
				CostMultiplier:    5,
			},
			// Bulk operations
			"POST:/api/v1/findings/bulk": {
				Path:              "/api/v1/findings/bulk",
				Method:            "POST",
				RequestsPerSecond: 1,
				RequestsPerMinute: 10,
				CostMultiplier:    10,
			},
			// Report generation
			"POST:/api/v1/reports/generate": {
				Path:              "/api/v1/reports/generate",
				Method:            "POST",
				RequestsPerSecond: 1,
				RequestsPerMinute: 5,
				CostMultiplier:    20,
			},
		},
		CircuitBreaker: CircuitBreakerConfig{
			Enabled:          true,
			FailureThreshold: 5,
			SuccessThreshold: 2,
			Timeout:          30 * time.Second,
			HalfOpenRequests: 3,
		},
	}
}

