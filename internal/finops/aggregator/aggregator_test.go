package aggregator

import (
	"context"
	"errors"
	"testing"
	"time"

	"cloudforge/internal/finops"
)

var (
	testStart = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	testEnd   = time.Date(2026, 3, 8, 0, 0, 0, 0, time.UTC)
)

// ---------------------------------------------------------------------------
// AWS
// ---------------------------------------------------------------------------

func TestAWSFetchCosts(t *testing.T) {
	client := NewAWSCostExplorerClient(AWSConfig{Region: "us-east-1", RoleARN: "arn:aws:iam::role/test"}, nil)
	records, err := client.FetchCosts(context.Background(), testStart, testEnd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) == 0 {
		t.Fatal("expected records, got none")
	}
	for _, r := range records {
		if r.Provider != "aws" {
			t.Errorf("expected provider aws, got %s", r.Provider)
		}
		if r.Cost <= 0 {
			t.Errorf("expected positive cost, got %f", r.Cost)
		}
	}
}

func TestAWSNormalize(t *testing.T) {
	client := NewAWSCostExplorerClient(AWSConfig{Region: "us-east-1"}, nil)
	input := []finops.CostRecord{
		{Provider: "aws", Currency: "USD", Cost: 100, Tags: map[string]string{"cost_center": "eng", "team": "sre", "environment": "prod"}},
	}
	out := client.NormalizeCosts(input)
	if len(out) != 1 {
		t.Fatalf("expected 1 record, got %d", len(out))
	}
	if out[0].CostCenter != "eng" {
		t.Errorf("expected cost_center eng, got %s", out[0].CostCenter)
	}
	if out[0].Team != "sre" {
		t.Errorf("expected team sre, got %s", out[0].Team)
	}
}

func TestAWSFetchCostsError(t *testing.T) {
	stub := &failingCostExplorer{}
	client := NewAWSCostExplorerClient(AWSConfig{Region: "us-east-1"}, stub)
	_, err := client.FetchCosts(context.Background(), testStart, testEnd)
	if err == nil {
		t.Fatal("expected error from failing API")
	}
}

type failingCostExplorer struct{}

func (f *failingCostExplorer) GetCostAndUsage(context.Context, time.Time, time.Time, string) ([]RawCostEntry, error) {
	return nil, errors.New("aws api unavailable")
}

// ---------------------------------------------------------------------------
// Azure
// ---------------------------------------------------------------------------

func TestAzureFetchCosts(t *testing.T) {
	client := NewAzureCostManagementClient(AzureConfig{SubscriptionID: "sub-123"}, nil)
	records, err := client.FetchCosts(context.Background(), testStart, testEnd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) == 0 {
		t.Fatal("expected records, got none")
	}
	for _, r := range records {
		if r.Provider != "azure" {
			t.Errorf("expected provider azure, got %s", r.Provider)
		}
	}
}

func TestAzureNormalize(t *testing.T) {
	client := NewAzureCostManagementClient(AzureConfig{SubscriptionID: "sub-123"}, nil)
	input := []finops.CostRecord{
		{Provider: "azure", Currency: "EUR", Cost: 100, Tags: map[string]string{"cost_center": "sec", "team": "infra", "environment": "staging"}},
	}
	out := client.NormalizeCosts(input)
	if out[0].Cost != 108 {
		t.Errorf("expected EUR->USD conversion to 108, got %f", out[0].Cost)
	}
	if out[0].Currency != "USD" {
		t.Errorf("expected USD, got %s", out[0].Currency)
	}
}

func TestAzureFetchCostsError(t *testing.T) {
	stub := &failingCostManagement{}
	client := NewAzureCostManagementClient(AzureConfig{SubscriptionID: "sub-123"}, stub)
	_, err := client.FetchCosts(context.Background(), testStart, testEnd)
	if err == nil {
		t.Fatal("expected error from failing API")
	}
}

type failingCostManagement struct{}

func (f *failingCostManagement) QueryCosts(context.Context, time.Time, time.Time, string) ([]AzureCostRow, error) {
	return nil, errors.New("azure api unavailable")
}

// ---------------------------------------------------------------------------
// GCP
// ---------------------------------------------------------------------------

func TestGCPFetchCosts(t *testing.T) {
	client := NewGCPBillingClient(GCPConfig{ProjectID: "my-project", BillingAccount: "01ABCD-012345-ABCDEF"}, nil)
	records, err := client.FetchCosts(context.Background(), testStart, testEnd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) == 0 {
		t.Fatal("expected records, got none")
	}
	for _, r := range records {
		if r.Provider != "gcp" {
			t.Errorf("expected provider gcp, got %s", r.Provider)
		}
	}
}

func TestGCPNormalize(t *testing.T) {
	client := NewGCPBillingClient(GCPConfig{ProjectID: "my-project"}, nil)
	input := []finops.CostRecord{
		{Provider: "gcp", Currency: "USD", Cost: 200, Tags: map[string]string{"cost_center": "data", "team": "analytics", "environment": "production"}},
	}
	out := client.NormalizeCosts(input)
	if out[0].CostCenter != "data" {
		t.Errorf("expected cost_center data, got %s", out[0].CostCenter)
	}
}

func TestGCPFetchCostsError(t *testing.T) {
	stub := &failingBilling{}
	client := NewGCPBillingClient(GCPConfig{ProjectID: "my-project"}, stub)
	_, err := client.FetchCosts(context.Background(), testStart, testEnd)
	if err == nil {
		t.Fatal("expected error from failing API")
	}
}

type failingBilling struct{}

func (f *failingBilling) QueryBillingExport(context.Context, time.Time, time.Time) ([]GCPBillingRow, error) {
	return nil, errors.New("gcp api unavailable")
}

// ---------------------------------------------------------------------------
// MultiCloudAggregator
// ---------------------------------------------------------------------------

func TestMultiCloudAggregator(t *testing.T) {
	aws := NewAWSCostExplorerClient(AWSConfig{Region: "us-east-1"}, nil)
	azure := NewAzureCostManagementClient(AzureConfig{SubscriptionID: "sub-123"}, nil)
	gcp := NewGCPBillingClient(GCPConfig{ProjectID: "my-project"}, nil)

	multi := NewMultiCloudAggregator(map[string]finops.Aggregator{
		"aws":   aws,
		"azure": azure,
		"gcp":   gcp,
	})

	records, err := multi.FetchCosts(context.Background(), testStart, testEnd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	providers := make(map[string]int)
	for _, r := range records {
		providers[r.Provider]++
	}

	for _, p := range []string{"aws", "azure", "gcp"} {
		if providers[p] == 0 {
			t.Errorf("expected records from %s, got 0", p)
		}
	}
}

func TestMultiCloudAggregatorPartialFailure(t *testing.T) {
	aws := NewAWSCostExplorerClient(AWSConfig{Region: "us-east-1"}, &failingCostExplorer{})
	gcp := NewGCPBillingClient(GCPConfig{ProjectID: "my-project"}, nil)

	multi := NewMultiCloudAggregator(map[string]finops.Aggregator{
		"aws": aws,
		"gcp": gcp,
	})

	records, err := multi.FetchCosts(context.Background(), testStart, testEnd)
	if err == nil {
		t.Fatal("expected error for partial failure")
	}
	// Should still get GCP records despite AWS failure.
	if len(records) == 0 {
		t.Fatal("expected GCP records despite AWS failure")
	}
}

func TestMultiCloudNormalizeCostsPassthrough(t *testing.T) {
	multi := NewMultiCloudAggregator(nil)
	input := []finops.CostRecord{{ID: "test"}}
	out := multi.NormalizeCosts(input)
	if len(out) != 1 || out[0].ID != "test" {
		t.Fatal("NormalizeCosts should pass through records unchanged")
	}
}
