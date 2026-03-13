package aggregator

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"cloudforge/internal/finops"
)

// AzureConfig holds configuration for the Azure Cost Management client.
type AzureConfig struct {
	SubscriptionID string
	TenantID       string
	ClientID       string
}

// CostManagementAPI abstracts the Azure Cost Management query call.
type CostManagementAPI interface {
	QueryCosts(ctx context.Context, start, end time.Time, granularity string) ([]AzureCostRow, error)
}

// AzureCostRow mirrors a single row from the Cost Management query response.
type AzureCostRow struct {
	Date        string
	ServiceName string
	Amount      float64
	Currency    string
	ResourceID  string
	Region      string
	Tags        map[string]string
}

// AzureCostManagementClient implements finops.Aggregator for Azure.
type AzureCostManagementClient struct {
	cfg AzureConfig
	api CostManagementAPI
}

// NewAzureCostManagementClient creates a client. If api is nil a demo stub is used.
func NewAzureCostManagementClient(cfg AzureConfig, api CostManagementAPI) *AzureCostManagementClient {
	if api == nil {
		api = &demoCostManagement{subscriptionID: cfg.SubscriptionID}
	}
	return &AzureCostManagementClient{cfg: cfg, api: api}
}

// FetchCosts retrieves cost data from Azure Cost Management.
func (c *AzureCostManagementClient) FetchCosts(ctx context.Context, start, end time.Time) ([]finops.CostRecord, error) {
	rows, err := c.api.QueryCosts(ctx, start, end, "Daily")
	if err != nil {
		return nil, fmt.Errorf("azure cost management: %w", err)
	}

	records := make([]finops.CostRecord, 0, len(rows))
	for i, row := range rows {
		t, _ := time.Parse("2006-01-02", row.Date)
		records = append(records, finops.CostRecord{
			ID:          fmt.Sprintf("azure-%d", i),
			Provider:    "azure",
			AccountID:   c.cfg.SubscriptionID,
			ServiceName: row.ServiceName,
			ResourceID:  row.ResourceID,
			Region:      row.Region,
			Date:        t,
			Cost:        row.Amount,
			Currency:    row.Currency,
			Tags:        row.Tags,
		})
	}
	return records, nil
}

// NormalizeCosts converts Azure-specific fields to the unified schema.
func (c *AzureCostManagementClient) NormalizeCosts(records []finops.CostRecord) []finops.CostRecord {
	out := make([]finops.CostRecord, len(records))
	for i, r := range records {
		r.Provider = "azure"
		// Azure sometimes reports in EUR for European subscriptions.
		if r.Currency == "EUR" {
			r.Cost *= 1.08
		}
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

type demoCostManagement struct {
	subscriptionID string
}

func (d *demoCostManagement) QueryCosts(_ context.Context, start, end time.Time, _ string) ([]AzureCostRow, error) {
	rng := rand.New(rand.NewSource(2)) //nolint:gosec

	services := []struct {
		name string
		base float64
	}{
		{"Virtual Machines", 420},
		{"Azure Storage", 100},
		{"Cosmos DB", 240},
		{"Azure Kubernetes Service", 330},
		{"Azure SQL Database", 180},
	}

	var rows []AzureCostRow
	for day := start; day.Before(end); day = day.AddDate(0, 0, 1) {
		for _, svc := range services {
			rows = append(rows, AzureCostRow{
				Date:        day.Format("2006-01-02"),
				ServiceName: svc.name,
				Amount:      svc.base * (0.85 + rng.Float64()*0.30),
				Currency:    "USD",
				ResourceID:  fmt.Sprintf("/subscriptions/%s/resourceGroups/prod/%s", d.subscriptionID, svc.name),
				Region:      "eastus",
				Tags: map[string]string{
					"cost_center": "engineering",
					"team":        "platform",
					"environment": "production",
				},
			})
		}
	}
	return rows, nil
}
