// Package observability provides logging, metrics, and tracing capabilities
package observability

import (
	"context"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Telemetry provides unified observability
type Telemetry struct {
	logger       *zap.Logger
	tracer       trace.Tracer
	metrics      *Metrics
	config       Config
	shutdownOnce sync.Once
	shutdownFns  []func(context.Context) error
}

// Config configures telemetry
type Config struct {
	ServiceName    string `yaml:"service_name"`
	ServiceVersion string `yaml:"service_version"`
	Environment    string `yaml:"environment"`

	// Logging
	LogLevel  string `yaml:"log_level"`
	LogFormat string `yaml:"log_format"` // json, console

	// Tracing
	TracingEnabled bool   `yaml:"tracing_enabled"`
	OTLPEndpoint   string `yaml:"otlp_endpoint"`
	SamplingRate   float64 `yaml:"sampling_rate"`

	// Metrics
	MetricsEnabled bool `yaml:"metrics_enabled"`
	MetricsPort    int  `yaml:"metrics_port"`

	// Health
	HealthPort int `yaml:"health_port"`
}

// Metrics holds Prometheus metrics
type Metrics struct {
	// Request metrics
	RequestsTotal    *prometheus.CounterVec
	RequestDuration  *prometheus.HistogramVec
	RequestsInFlight prometheus.Gauge

	// Finding metrics
	FindingsProcessed *prometheus.CounterVec
	FindingsActive    *prometheus.GaugeVec
	AIAnalysisDuration *prometheus.HistogramVec

	// System metrics
	GoroutineCount prometheus.Gauge
	MemoryUsage    prometheus.Gauge
	
	// Health metrics
	HealthStatus *prometheus.GaugeVec
	LastHealthCheck prometheus.Gauge

	// Error metrics
	ErrorsTotal *prometheus.CounterVec

	// Rate limit metrics
	RateLimitHits *prometheus.CounterVec
}

// New creates a new Telemetry instance
func New(cfg Config) (*Telemetry, error) {
	t := &Telemetry{
		config: cfg,
	}

	// Initialize logger
	logger, err := t.initLogger()
	if err != nil {
		return nil, err
	}
	t.logger = logger

	// Initialize tracer
	if cfg.TracingEnabled {
		if err := t.initTracer(); err != nil {
			logger.Warn("Failed to initialize tracer", zap.Error(err))
		}
	}
	t.tracer = otel.Tracer(cfg.ServiceName)

	// Initialize metrics
	if cfg.MetricsEnabled {
		t.metrics = t.initMetrics()
	}

	return t, nil
}

// initLogger initializes structured logging
func (t *Telemetry) initLogger() (*zap.Logger, error) {
	var config zap.Config

	if t.config.LogFormat == "console" {
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	} else {
		config = zap.NewProductionConfig()
		config.EncoderConfig.TimeKey = "timestamp"
		config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	}

	// Set log level
	switch t.config.LogLevel {
	case "debug":
		config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	case "info":
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	case "warn":
		config.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
	case "error":
		config.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	default:
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}

	// Add standard fields
	config.InitialFields = map[string]interface{}{
		"service":     t.config.ServiceName,
		"version":     t.config.ServiceVersion,
		"environment": t.config.Environment,
	}

	return config.Build()
}

// initTracer initializes OpenTelemetry tracing
func (t *Telemetry) initTracer() error {
	ctx := context.Background()

	// Create OTLP exporter
	exporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(t.config.OTLPEndpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		return err
	}

	// Create resource
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(t.config.ServiceName),
			semconv.ServiceVersion(t.config.ServiceVersion),
			attribute.String("environment", t.config.Environment),
		),
	)
	if err != nil {
		return err
	}

	// Create trace provider
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(t.config.SamplingRate)),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	t.shutdownFns = append(t.shutdownFns, tp.Shutdown)

	return nil
}

// initMetrics initializes Prometheus metrics
func (t *Telemetry) initMetrics() *Metrics {
	namespace := "cloudforge"

	return &Metrics{
		RequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "http_requests_total",
				Help:      "Total HTTP requests",
			},
			[]string{"method", "path", "status"},
		),
		RequestDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "http_request_duration_seconds",
				Help:      "HTTP request duration",
				Buckets:   prometheus.ExponentialBuckets(0.001, 2, 15),
			},
			[]string{"method", "path"},
		),
		RequestsInFlight: promauto.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "http_requests_in_flight",
				Help:      "Current HTTP requests being processed",
			},
		),
		FindingsProcessed: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "findings_processed_total",
				Help:      "Total findings processed",
			},
			[]string{"source", "type", "severity"},
		),
		FindingsActive: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "findings_active",
				Help:      "Current active findings by status",
			},
			[]string{"status", "severity"},
		),
		AIAnalysisDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "ai_analysis_duration_seconds",
				Help:      "AI analysis duration",
				Buckets:   prometheus.ExponentialBuckets(0.1, 2, 10),
			},
			[]string{"provider", "type"},
		),
		GoroutineCount: promauto.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "goroutine_count",
				Help:      "Current goroutine count",
			},
		),
		MemoryUsage: promauto.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "memory_usage_bytes",
				Help:      "Current memory usage in bytes",
			},
		),
		HealthStatus: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "health_status",
				Help:      "Health status of components (1=healthy, 0=unhealthy)",
			},
			[]string{"component"},
		),
		LastHealthCheck: promauto.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "last_health_check_timestamp",
				Help:      "Timestamp of last health check",
			},
		),
		ErrorsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "errors_total",
				Help:      "Total errors by type",
			},
			[]string{"type", "component"},
		),
		RateLimitHits: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "rate_limit_hits_total",
				Help:      "Total rate limit hits",
			},
			[]string{"tier", "endpoint"},
		),
	}
}

// Logger returns the logger
func (t *Telemetry) Logger() *zap.Logger {
	return t.logger
}

// Tracer returns the tracer
func (t *Telemetry) Tracer() trace.Tracer {
	return t.tracer
}

// Metrics returns the metrics
func (t *Telemetry) Metrics() *Metrics {
	return t.metrics
}

// StartSpan starts a new trace span
func (t *Telemetry) StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return t.tracer.Start(ctx, name, opts...)
}

// RecordError records an error to the current span and logs it
func (t *Telemetry) RecordError(ctx context.Context, err error, fields ...zap.Field) {
	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		span.RecordError(err)
	}
	t.logger.Error(err.Error(), fields...)
}

// MetricsHandler returns the Prometheus metrics handler
func (t *Telemetry) MetricsHandler() http.Handler {
	return promhttp.Handler()
}

// StartSystemMetricsCollector starts collecting system metrics
func (t *Telemetry) StartSystemMetricsCollector(ctx context.Context) {
	if t.metrics == nil {
		return
	}

	ticker := time.NewTicker(15 * time.Second)
	go func() {
		for {
			select {
			case <-ctx.Done():
				ticker.Stop()
				return
			case <-ticker.C:
				// Goroutines
				t.metrics.GoroutineCount.Set(float64(runtime.NumGoroutine()))

				// Memory
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				t.metrics.MemoryUsage.Set(float64(m.Alloc))
			}
		}
	}()
}

// Shutdown gracefully shuts down telemetry
func (t *Telemetry) Shutdown(ctx context.Context) error {
	var err error
	t.shutdownOnce.Do(func() {
		for _, fn := range t.shutdownFns {
			if e := fn(ctx); e != nil {
				err = e
			}
		}
		t.logger.Sync()
	})
	return err
}

// HTTPMiddleware returns HTTP middleware for request tracing and metrics
func (t *Telemetry) HTTPMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Start span
			ctx, span := t.StartSpan(r.Context(), r.URL.Path,
				trace.WithAttributes(
					attribute.String("http.method", r.Method),
					attribute.String("http.url", r.URL.String()),
					attribute.String("http.user_agent", r.UserAgent()),
				),
			)
			defer span.End()

			// Track in-flight requests
			if t.metrics != nil {
				t.metrics.RequestsInFlight.Inc()
				defer t.metrics.RequestsInFlight.Dec()
			}

			// Wrap response writer to capture status
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			// Process request
			next.ServeHTTP(wrapped, r.WithContext(ctx))

			// Record metrics
			duration := time.Since(start)
			if t.metrics != nil {
				t.metrics.RequestsTotal.WithLabelValues(r.Method, r.URL.Path, http.StatusText(wrapped.statusCode)).Inc()
				t.metrics.RequestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(duration.Seconds())
			}

			// Add span attributes
			span.SetAttributes(
				attribute.Int("http.status_code", wrapped.statusCode),
				attribute.Float64("http.duration_ms", float64(duration.Milliseconds())),
			)

			// Log request
			t.logger.Info("HTTP request",
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.Int("status", wrapped.statusCode),
				zap.Duration("duration", duration),
				zap.String("remote_addr", r.RemoteAddr),
			)
		})
	}
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
