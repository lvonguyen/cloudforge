package aggregator

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"cloudforge/internal/finops"
)

// GCPConfig holds configuration for the GCP Cloud Billing client.
type GCPConfig struct {
	ProjectID      string
	BillingAccount string
}

// CloudBillingAPI abstracts the GCP Cloud Billing export query.
type CloudBillingAPI interface {
	QueryBillingExport(ctx context.Context, start, end time.Time) ([]GCPBillingRow, error)
}

// GCPBillingRow mirrors a single row from a BigQuery billing export table.
type GCPBillingRow struct {
	UsageStartTime string
	ServiceDesc    string
	SKUDesc        string
	Cost           float64
	Currency       string
	ProjectID      string
	Region         string
	Labels         map[string]string
}

// GCPBillingClient implements finops.Aggregator for GCP.
type GCPBillingClient struct {
	cfg GCPConfig
	api CloudBillingAPI
}

// NewGCPBillingClient creates a client. If api is nil a demo stub is used.
func NewGCPBillingClient(cfg GCPConfig, api CloudBillingAPI) *GCPBillingClient {
	if api == nil {
		api = &demoBilling{projectID: cfg.ProjectID}
	}
	return &GCPBillingClient{cfg: cfg, api: api}
}

// FetchCosts retrieves cost data from GCP Cloud Billing.
func (c *GCPBillingClient) FetchCosts(ctx context.Context, start, end time.Time) ([]finops.CostRecord, error) {
	rows, err := c.api.QueryBillingExport(ctx, start, end)
	if err != nil {
		return nil, fmt.Errorf("gcp cloud billing: %w", err)
	}

	records := make([]finops.CostRecord, 0, len(rows))
	for i, row := range rows {
		t, _ := time.Parse("2006-01-02", row.UsageStartTime)
		records = append(records, finops.CostRecord{
			ID:          fmt.Sprintf("gcp-%d", i),
			Provider:    "gcp",
			AccountID:   row.ProjectID,
			ServiceName: row.ServiceDesc,
			Region:      row.Region,
			Date:        t,
			Cost:        row.Cost,
			Currency:    row.Currency,
			Tags:        row.Labels,
		})
	}
	return records, nil
}

// NormalizeCosts converts GCP-specific fields to the unified schema.
func (c *GCPBillingClient) NormalizeCosts(records []finops.CostRecord) []finops.CostRecord {
	out := make([]finops.CostRecord, len(records))
	for i, r := range records {
		r.Provider = "gcp"
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

type demoBilling struct {
	projectID string
}

func (d *demoBilling) QueryBillingExport(_ context.Context, start, end time.Time) ([]GCPBillingRow, error) {
	rng := rand.New(rand.NewSource(3)) //nolint:gosec

	services := []struct {
		desc string
		sku  string
		base float64
	}{
		{"Compute Engine", "N2 Instance Core", 360},
		{"Cloud Storage", "Standard Storage", 90},
		{"BigQuery", "Analysis", 170},
		{"Cloud Run", "vCPU Allocation Time", 65},
		{"Google Kubernetes Engine", "Cluster Management Fee", 290},
	}

	var rows []GCPBillingRow
	for day := start; day.Before(end); day = day.AddDate(0, 0, 1) {
		for _, svc := range services {
			rows = append(rows, GCPBillingRow{
				UsageStartTime: day.Format("2006-01-02"),
				ServiceDesc:    svc.desc,
				SKUDesc:        svc.sku,
				Cost:           svc.base * (0.85 + rng.Float64()*0.30),
				Currency:       "USD",
				ProjectID:      d.projectID,
				Region:         "us-central1",
				Labels: map[string]string{
					"cost_center": "engineering",
					"team":        "platform",
					"environment": "production",
				},
			})
		}
	}
	return rows, nil
}
