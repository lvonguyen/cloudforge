# ADR-001: Programming Language Selection

## Status

Accepted

## Date

2026-01-05

## Context

We need to select a primary programming language for CloudForge that supports:
- High-performance API services
- Concurrent processing of security findings
- Strong typing for complex compliance data structures
- Easy deployment and containerization
- Good ecosystem for cloud integrations

### Options Considered

1. **Go** - Compiled, statically typed, built-in concurrency
2. **Python** - Dynamic, extensive libraries, slower runtime
3. **Rust** - Memory-safe, high performance, steeper learning curve
4. **Java/Kotlin** - JVM ecosystem, mature libraries, higher memory overhead

## Decision

We will use **Go 1.22** as the primary language.

## Rationale

### Performance
- Compiled to native binary, no runtime overhead
- Goroutines provide efficient concurrency for processing thousands of findings
- Low memory footprint compared to JVM languages

### Developer Experience
- Simple syntax with fast learning curve
- Excellent tooling (go fmt, go vet, golangci-lint)
- Built-in testing framework
- Single binary deployment simplifies container images

### Ecosystem
- Strong support for cloud SDKs (AWS, Azure, GCP)
- Excellent HTTP/gRPC libraries
- Prometheus client for metrics
- OpenTelemetry support

### Operational
- Small container images (~10-20MB vs 200MB+ for JVM)
- Fast startup time (milliseconds vs seconds)
- Predictable memory usage

## Consequences

### Positive
- High performance for API and background processing
- Simple deployment and operations
- Good hire-ability for Go developers

### Negative
- Less flexibility than dynamic languages for quick prototyping
- Verbose error handling
- Smaller library ecosystem than Python/Node.js

### Mitigations
- Use code generation for repetitive patterns
- Create internal libraries for common patterns
- Consider Python for data science/ML components if needed

## Related Decisions

- ADR-002: API Framework Selection
- ADR-003: Database Selection

