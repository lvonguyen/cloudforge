package finops

import (
	"strings"
	"testing"
)

func TestEstimateMonthlyCostAllEntries(t *testing.T) {
	est := NewCostEstimator()

	// Every entry in the pricing table should be estimable.
	for key, entry := range pricingTable {
		parts := strings.SplitN(key, ":", 3)
		provider, resource, size := parts[0], parts[1], parts[2]

		result, err := est.EstimateMonthlyCost(resource, provider, size)
		if err != nil {
			t.Errorf("(%s, %s, %s): unexpected error: %v", provider, resource, size, err)
			continue
		}
		if result.LowUSD != entry.low || result.MidUSD != entry.mid || result.HighUSD != entry.high {
			t.Errorf("(%s, %s, %s): pricing mismatch", provider, resource, size)
		}
		if result.Unit != "monthly" {
			t.Errorf("expected unit monthly, got %s", result.Unit)
		}
	}
}

func TestEstimateMonthlyCostRangeOrdering(t *testing.T) {
	est := NewCostEstimator()

	for key := range pricingTable {
		parts := strings.SplitN(key, ":", 3)
		result, err := est.EstimateMonthlyCost(parts[1], parts[0], parts[2])
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.LowUSD > result.MidUSD || result.MidUSD > result.HighUSD {
			t.Errorf("(%s): low=%f mid=%f high=%f — not in ascending order", key, result.LowUSD, result.MidUSD, result.HighUSD)
		}
	}
}

func TestEstimateMonthlyCostUnknownResource(t *testing.T) {
	est := NewCostEstimator()
	_, err := est.EstimateMonthlyCost("nonexistent", "aws", "large")
	if err == nil {
		t.Fatal("expected error for unknown resource type")
	}
}

func TestEstimateMonthlyCostCaseInsensitive(t *testing.T) {
	est := NewCostEstimator()
	r1, err := est.EstimateMonthlyCost("EC2", "AWS", "Small")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r2, err := est.EstimateMonthlyCost("ec2", "aws", "small")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r1.MidUSD != r2.MidUSD {
		t.Errorf("case-insensitive mismatch: %f != %f", r1.MidUSD, r2.MidUSD)
	}
}

func TestEstimateSpecificResources(t *testing.T) {
	est := NewCostEstimator()

	cases := []struct {
		provider string
		resource string
		size     string
		wantMid  float64
	}{
		{"aws", "ec2", "large", 280},
		{"aws", "lambda", "standard", 30},
		{"azure", "aks", "standard", 145},
		{"azure", "cosmos-db", "standard", 100},
		{"gcp", "cloud-run", "standard", 25},
		{"gcp", "bigquery", "standard", 60},
	}

	for _, tc := range cases {
		t.Run(tc.provider+"/"+tc.resource+"/"+tc.size, func(t *testing.T) {
			result, err := est.EstimateMonthlyCost(tc.resource, tc.provider, tc.size)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.MidUSD != tc.wantMid {
				t.Errorf("expected mid %f, got %f", tc.wantMid, result.MidUSD)
			}
		})
	}
}

func TestSupportedResources(t *testing.T) {
	est := NewCostEstimator()
	resources := est.SupportedResources()
	if len(resources) != len(pricingTable) {
		t.Errorf("expected %d supported resources, got %d", len(pricingTable), len(resources))
	}
}
