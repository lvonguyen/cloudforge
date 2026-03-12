package finops

import (
	"context"
	"testing"
	"time"
)

func TestCovMemoryAggregator_FetchCosts(t *testing.T) {
	a := NewMemoryAggregator()
	now := time.Now().UTC().Truncate(24 * time.Hour)
	start := now.AddDate(0, 0, -10)
	end := now

	records, err := a.FetchCosts(context.Background(), start, end)
	if err != nil {
		t.Fatalf("FetchCosts: %v", err)
	}
	if len(records) == 0 {
		t.Error("expected records in date range")
	}
	for _, r := range records {
		if r.Date.Before(start) || r.Date.After(end) {
			t.Errorf("record date %v outside range [%v, %v]", r.Date, start, end)
		}
	}
}

func TestCovMemoryAggregator_FetchCosts_EmptyRange(t *testing.T) {
	a := NewMemoryAggregator()
	future := time.Now().AddDate(1, 0, 0)
	records, err := a.FetchCosts(context.Background(), future, future.Add(time.Hour))
	if err != nil {
		t.Fatalf("FetchCosts: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("expected 0 records for future range, got %d", len(records))
	}
}

func TestCovMemoryAggregator_NormalizeCosts(t *testing.T) {
	a := NewMemoryAggregator()

	records := []CostRecord{
		{Cost: 100, Currency: "USD"},
		{Cost: 100, Currency: "EUR"},
		{Cost: 100, Currency: "GBP"},
		{Cost: 100, Currency: "JPY"},
	}

	normalized := a.NormalizeCosts(records)
	if len(normalized) != 4 {
		t.Fatal("expected 4 records")
	}

	if normalized[0].Cost != 100 || normalized[0].Currency != "USD" {
		t.Error("USD should be unchanged")
	}
	if normalized[1].Cost != 108 {
		t.Errorf("EUR cost = %f, want 108", normalized[1].Cost)
	}
	if normalized[2].Cost != 127 {
		t.Errorf("GBP cost = %f, want 127", normalized[2].Cost)
	}
	if normalized[3].Cost != 100 {
		t.Errorf("JPY cost = %f, want 100 (unchanged)", normalized[3].Cost)
	}
	for _, r := range normalized {
		if r.Currency != "USD" {
			t.Errorf("expected all currencies normalized to USD, got %s", r.Currency)
		}
	}
}

func TestCovCostEstimator_EstimateMonthlyCost(t *testing.T) {
	e := NewCostEstimator()

	tests := []struct {
		resource, provider, size string
		wantErr                  bool
	}{
		{"ec2", "aws", "small", false},
		{"ec2", "aws", "medium", false},
		{"ec2", "aws", "large", false},
		{"rds", "aws", "small", false},
		{"vm", "azure", "small", false},
		{"gce", "gcp", "small", false},
		{"unknown", "aws", "small", true},
		{"ec2", "unknown", "small", true},
	}

	for _, tt := range tests {
		t.Run(tt.provider+"/"+tt.resource+"/"+tt.size, func(t *testing.T) {
			est, err := e.EstimateMonthlyCost(tt.resource, tt.provider, tt.size)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if est.LowUSD >= est.MidUSD || est.MidUSD >= est.HighUSD {
					t.Errorf("expected low < mid < high, got %f < %f < %f", est.LowUSD, est.MidUSD, est.HighUSD)
				}
				if est.Unit != "monthly" {
					t.Errorf("unit = %q, want monthly", est.Unit)
				}
			}
		})
	}
}

func TestCovCostEstimator_SupportedResources(t *testing.T) {
	e := NewCostEstimator()
	resources := e.SupportedResources()
	if len(resources) == 0 {
		t.Error("expected supported resources")
	}
	if len(resources) < 20 {
		t.Errorf("expected at least 20 resources, got %d", len(resources))
	}
}

func TestCovRegionFor(t *testing.T) {
	tests := []struct {
		provider, want string
	}{
		{"aws", "us-east-1"},
		{"azure", "eastus"},
		{"gcp", "us-central1"},
		{"other", "us-east-1"},
	}
	for _, tt := range tests {
		if got := regionFor(tt.provider); got != tt.want {
			t.Errorf("regionFor(%q) = %q, want %q", tt.provider, got, tt.want)
		}
	}
}

func TestCovPricingKey(t *testing.T) {
	key := pricingKey("AWS", "EC2", "Small")
	if key != "aws:ec2:small" {
		t.Errorf("pricingKey = %q, want aws:ec2:small", key)
	}
}
