# ADR-010: FinOps Multi-Cloud Cost Aggregation

## Status

Accepted

## Date

2026-01-15

## Context

Enterprise cloud environments span AWS, Azure, and GCP. Cost visibility is fragmented across three billing portals with different data models, granularity, and API patterns. CloudForge needs unified cost visibility to support:

1. Executive cost dashboards (multi-cloud summary)
2. Budget tracking with proactive alerting
3. Chargeback/showback reporting by business unit
4. Cost anomaly detection
5. Resource cost estimation for provisioning requests

### Requirements

- Normalize cost data across AWS Cost Explorer, Azure Cost Management, and GCP Billing
- Support tag-based cost allocation (team, project, environment)
- Alert on budget threshold breaches via Slack and PagerDuty
- Provide cost estimation for 21+ resource types before provisioning

## Decision

We will implement a **multi-cloud cost aggregation layer** with the following components:

### 1. Cloud Cost Clients

Each CSP has a dedicated client that implements a common interface:

```go
type CostClient interface {
    GetCosts(ctx context.Context, req CostRequest) (*CostResponse, error)
    GetBudgets(ctx context.Context) ([]Budget, error)
}
```

| Client | Package | API |
|--------|---------|-----|
| AWS | `internal/finops/aggregator/aws.go` | AWS Cost Explorer |
| Azure | `internal/finops/aggregator/azure.go` | Azure Cost Management |
| GCP | `internal/finops/aggregator/gcp.go` | GCP Cloud Billing |

### 2. MultiCloudAggregator

Orchestrates calls to all three clients and produces a unified cost view:

```go
type MultiCloudAggregator struct {
    clients map[string]CostClient
}
```

### 3. Budget Alerting

The `BudgetMonitor` in `internal/finops/alerting/` checks budget thresholds and dispatches alerts:

| Channel | Implementation | Format |
|---------|---------------|--------|
| Slack | `slack.go` | Block Kit messages |
| PagerDuty | `pagerduty.go` | Events API v2 |

### 4. Cost Estimation

A lookup table in `internal/finops/estimation.go` provides low/mid/high cost ranges for 21 resource types (EC2, RDS, S3, Lambda, etc.). Used during provisioning requests to show estimated monthly cost before approval.

### 5. Anomaly Detection

ML-based spend anomaly detection in `internal/finops/anomaly/` with configurable thresholds per account and service.

### 6. Chargeback

Tag-based cost allocation in `internal/finops/chargeback/` with:
- `GenerateReport()` for structured chargeback data
- CSV export for finance team consumption

## Consequences

### Positive

- **Unified view**: Single API for cost data across all three clouds
- **Proactive alerting**: Budget breaches detected before month-end
- **Self-service estimation**: Users see cost impact before requesting resources
- **Extensibility**: New CSP clients implement the same interface

### Negative

- **API rate limits**: Cost Explorer is rate-limited (5 TPS), requiring batching
- **Data freshness**: Cost data lags 8-24 hours depending on CSP
- **Interface-only status**: Cloud API clients are defined but not wired to production credentials

### Mitigations

- Cache cost data (1-hour TTL) to reduce API calls
- Display "last updated" timestamp on all cost views
- Use memory aggregator for development and demos

## Alternatives Considered

### 1. CloudHealth / Apptio

Commercial FinOps platforms with built-in multi-cloud support.

**Deferred because**: Adds significant license cost ($5K+/month) and external dependency. The interface-based approach allows swapping in a commercial tool later while demonstrating the architectural pattern.

### 2. AWS-Only Cost Reporting

Focus on AWS Cost Explorer only, defer Azure and GCP.

**Rejected because**: Most target customers are multi-cloud. Single-cloud cost visibility provides limited value for the platform's positioning.

## References

- `internal/finops/` — All FinOps packages
- `internal/finops/aggregator/` — Multi-cloud cost clients
- `internal/finops/alerting/` — Budget alerting (Slack, PagerDuty)
- `internal/finops/estimation.go` — 21-resource cost estimation table
