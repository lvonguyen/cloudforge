// Package aggregator provides multi-cloud cost aggregation clients.
package aggregator

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"aegis/internal/finops"
)

// AWSConfig holds configuration for the AWS Cost Explorer client.
type AWSConfig struct {
	Region  string
	RoleARN string
}

// CostExplorerAPI abstracts the AWS Cost Explorer GetCostAndUsage call
// so the client can be tested without a real SDK dependency.
type CostExplorerAPI interface {
	GetCostAndUsage(ctx context.Context, start, end time.Time, granularity string) ([]RawCostEntry, error)
}

// RawCostEntry mirrors a single row returned by the Cost Explorer API.
type RawCostEntry struct {
	TimePeriodStart string
	TimePeriodEnd   string
	ServiceName     string
	Amount          float64
	Currency        string
	AccountID       string
	Region          string
	Tags            map[string]string
}

// AWSCostExplorerClient implements finops.Aggregator for AWS.
type AWSCostExplorerClient struct {
	cfg AWSConfig
	api CostExplorerAPI
}

// NewAWSCostExplorerClient creates a client. If api is nil a demo stub is used.
func NewAWSCostExplorerClient(cfg AWSConfig, api CostExplorerAPI) *AWSCostExplorerClient {
	if api == nil {
		api = &demoCostExplorer{region: cfg.Region}
	}
	return &AWSCostExplorerClient{cfg: cfg, api: api}
}

// FetchCosts retrieves cost data from AWS Cost Explorer.
func (c *AWSCostExplorerClient) FetchCosts(ctx context.Context, start, end time.Time) ([]finops.CostRecord, error) {
	raw, err := c.api.GetCostAndUsage(ctx, start, end, "DAILY")
	if err != nil {
		return nil, fmt.Errorf("aws cost explorer: %w", err)
	}

	records := make([]finops.CostRecord, 0, len(raw))
	for i, e := range raw {
		t, _ := time.Parse("2006-01-02", e.TimePeriodStart)
		records = append(records, finops.CostRecord{
			ID:          fmt.Sprintf("aws-%d", i),
			Provider:    "aws",
			AccountID:   e.AccountID,
			ServiceName: e.ServiceName,
			Region:      e.Region,
			Date:        t,
			Cost:        e.Amount,
			Currency:    e.Currency,
			Tags:        e.Tags,
		})
	}
	return records, nil
}

// NormalizeCosts converts AWS-specific fields to the unified schema.
func (c *AWSCostExplorerClient) NormalizeCosts(records []finops.CostRecord) []finops.CostRecord {
	out := make([]finops.CostRecord, len(records))
	for i, r := range records {
		r.Provider = "aws"
		r.Currency = "USD"
		if cc, ok := r.Tags["cost_center"]; ok {
			r.CostCenter = cc
		}
		if team, ok := r.Tags["team"]; ok {
			r.Team = team
		}
		if env, ok := r.Tags["environment"]; ok {
			r.Environment = env
		}
		out[i] = r
	}
	return out
}

// --- demo stub ----------------------------------------------------------

type demoCostExplorer struct {
	region string
}

func (d *demoCostExplorer) GetCostAndUsage(_ context.Context, start, end time.Time, _ string) ([]RawCostEntry, error) {
	rng := rand.New(rand.NewSource(1)) //nolint:gosec

	services := []struct {
		name string
		base float64
	}{
		{"Amazon EC2", 480},
		{"Amazon S3", 125},
		{"Amazon RDS", 310},
		{"AWS Lambda", 55},
		{"Amazon EKS", 220},
	}

	var entries []RawCostEntry
	for d := start; d.Before(end); d = d.AddDate(0, 0, 1) {
		for _, svc := range services {
			entries = append(entries, RawCostEntry{
				TimePeriodStart: d.Format("2006-01-02"),
				TimePeriodEnd:   d.AddDate(0, 0, 1).Format("2006-01-02"),
				ServiceName:     svc.name,
				Amount:          svc.base * (0.85 + rng.Float64()*0.30),
				Currency:        "USD",
				AccountID:       "123456789012",
				Region:          "us-east-1",
				Tags: map[string]string{
					"cost_center": "engineering",
					"team":        "platform",
					"environment": "production",
				},
			})
		}
	}
	return entries, nil
}
