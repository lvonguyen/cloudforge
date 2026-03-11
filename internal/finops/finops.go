// Package finops provides cloud cost management capabilities
// including multi-cloud cost aggregation, anomaly detection,
// and chargeback reporting.
//
// This module was consolidated from:
// - finops-platform (cost aggregation, anomaly detection)
// - finops-aggregator (chargeback engine)
package finops

import (
	"context"
	"time"
)

// CostRecord represents a normalized cost entry across clouds
type CostRecord struct {
	ID          string            `json:"id"`
	Provider    string            `json:"provider"` // aws, azure, gcp
	AccountID   string            `json:"account_id"`
	ServiceName string            `json:"service_name"`
	ResourceID  string            `json:"resource_id"`
	Region      string            `json:"region"`
	Date        time.Time         `json:"date"`
	Cost        float64           `json:"cost"`
	Currency    string            `json:"currency"`
	Tags        map[string]string `json:"tags"`
	CostCenter  string            `json:"cost_center"`
	Team        string            `json:"team"`
	Environment string            `json:"environment"`
}

// AnomalyAlert represents a detected cost anomaly
type AnomalyAlert struct {
	ID           string    `json:"id"`
	Provider     string    `json:"provider"`
	AccountID    string    `json:"account_id"`
	ServiceName  string    `json:"service_name"`
	DetectedAt   time.Time `json:"detected_at"`
	ExpectedCost float64   `json:"expected_cost"`
	ActualCost   float64   `json:"actual_cost"`
	Deviation    float64   `json:"deviation_percent"`
	Severity     string    `json:"severity"` // low, medium, high, critical
}

// ChargebackReport represents allocated costs by cost center
type ChargebackReport struct {
	Period      string           `json:"period"`
	GeneratedAt time.Time        `json:"generated_at"`
	TotalCost   float64          `json:"total_cost"`
	Allocations []CostAllocation `json:"allocations"`
}

// CostAllocation represents cost allocated to a specific cost center
type CostAllocation struct {
	CostCenter string             `json:"cost_center"`
	Team       string             `json:"team"`
	TotalCost  float64            `json:"total_cost"`
	ByProvider map[string]float64 `json:"by_provider"`
	ByService  map[string]float64 `json:"by_service"`
	Percentage float64            `json:"percentage"`
}

// CostSummary is the computed response for /costs/summary.
type CostSummary struct {
	TotalCost   float64            `json:"total_cost"`
	ByProvider  map[string]float64 `json:"by_provider"`
	ByService   map[string]float64 `json:"by_service"`
	Anomalies   []AnomalyAlert     `json:"anomalies"`
	Allocations []CostAllocation   `json:"allocations"`
	Period      string             `json:"period"`
	RecordCount int                `json:"record_count"`
}

// Aggregator aggregates costs from multiple cloud providers
type Aggregator interface {
	// FetchCosts retrieves cost data from cloud provider for date range
	FetchCosts(ctx context.Context, startDate, endDate time.Time) ([]CostRecord, error)
	// NormalizeCosts converts provider-specific costs to unified schema
	NormalizeCosts(records []CostRecord) []CostRecord
}

// AnomalyDetector detects cost anomalies
type AnomalyDetector interface {
	// DetectAnomalies analyzes cost patterns and returns alerts
	DetectAnomalies(ctx context.Context, records []CostRecord) ([]AnomalyAlert, error)
	// UpdateBaseline updates the baseline for a service/account
	UpdateBaseline(ctx context.Context, accountID, service string, baseline float64) error
}

// ChargebackEngine allocates costs to cost centers
type ChargebackEngine interface {
	// GenerateReport creates a chargeback report for a period
	GenerateReport(ctx context.Context, period string) (*ChargebackReport, error)
	// AllocateCosts assigns costs to cost centers based on rules
	AllocateCosts(records []CostRecord) ([]CostAllocation, error)
}
