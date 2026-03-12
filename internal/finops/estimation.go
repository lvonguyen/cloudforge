package finops

import (
	"fmt"
	"strings"
)

// CostEstimate represents a monthly cost estimate with confidence range.
type CostEstimate struct {
	Provider     string  `json:"provider"`
	ResourceType string  `json:"resource_type"`
	Size         string  `json:"size"`
	LowUSD      float64 `json:"low_usd"`
	MidUSD      float64 `json:"mid_usd"`
	HighUSD     float64 `json:"high_usd"`
	Unit         string  `json:"unit"` // e.g. "monthly", "per-hour"
}

// pricingEntry stores the lookup-table row for a (provider, resourceType, size) triple.
type pricingEntry struct {
	low  float64
	mid  float64
	high float64
}

// pricingKey normalizes lookup keys.
func pricingKey(provider, resourceType, size string) string {
	return strings.ToLower(provider) + ":" + strings.ToLower(resourceType) + ":" + strings.ToLower(size)
}

// pricingTable holds ~20 common resource types with realistic monthly USD ranges.
var pricingTable = map[string]pricingEntry{
	// AWS
	pricingKey("aws", "ec2", "small"):      {low: 15, mid: 30, high: 45},
	pricingKey("aws", "ec2", "medium"):     {low: 60, mid: 120, high: 180},
	pricingKey("aws", "ec2", "large"):      {low: 140, mid: 280, high: 420},
	pricingKey("aws", "rds", "small"):      {low: 25, mid: 50, high: 80},
	pricingKey("aws", "rds", "medium"):     {low: 100, mid: 200, high: 320},
	pricingKey("aws", "rds", "large"):      {low: 350, mid: 700, high: 1100},
	pricingKey("aws", "s3", "standard"):    {low: 20, mid: 50, high: 120},
	pricingKey("aws", "lambda", "standard"): {low: 5, mid: 30, high: 150},
	pricingKey("aws", "eks", "standard"):   {low: 73, mid: 150, high: 350},
	// Azure
	pricingKey("azure", "vm", "small"):          {low: 14, mid: 28, high: 42},
	pricingKey("azure", "vm", "medium"):         {low: 55, mid: 110, high: 170},
	pricingKey("azure", "vm", "large"):          {low: 130, mid: 260, high: 400},
	pricingKey("azure", "aks", "standard"):      {low: 70, mid: 145, high: 340},
	pricingKey("azure", "cosmos-db", "standard"): {low: 25, mid: 100, high: 400},
	pricingKey("azure", "sql-db", "standard"):   {low: 50, mid: 150, high: 450},
	// GCP
	pricingKey("gcp", "gce", "small"):          {low: 12, mid: 25, high: 40},
	pricingKey("gcp", "gce", "medium"):         {low: 50, mid: 100, high: 155},
	pricingKey("gcp", "gce", "large"):          {low: 120, mid: 240, high: 370},
	pricingKey("gcp", "cloud-run", "standard"): {low: 5, mid: 25, high: 120},
	pricingKey("gcp", "bigquery", "standard"):  {low: 10, mid: 60, high: 300},
	pricingKey("gcp", "gke", "standard"):       {low: 73, mid: 150, high: 360},
}

// CostEstimator provides monthly cost estimates for common cloud resources.
type CostEstimator struct{}

// NewCostEstimator creates a CostEstimator.
func NewCostEstimator() *CostEstimator {
	return &CostEstimator{}
}

// EstimateMonthlyCost returns a low/mid/high cost range for the given
// resource. Returns an error if the (provider, resourceType, size) triple
// is not in the pricing table.
func (e *CostEstimator) EstimateMonthlyCost(resourceType, provider, size string) (*CostEstimate, error) {
	key := pricingKey(provider, resourceType, size)
	entry, ok := pricingTable[key]
	if !ok {
		return nil, fmt.Errorf("no pricing data for provider=%q resource=%q size=%q", provider, resourceType, size)
	}
	return &CostEstimate{
		Provider:     strings.ToLower(provider),
		ResourceType: strings.ToLower(resourceType),
		Size:         strings.ToLower(size),
		LowUSD:      entry.low,
		MidUSD:      entry.mid,
		HighUSD:     entry.high,
		Unit:         "monthly",
	}, nil
}

// SupportedResources returns all (provider, resourceType, size) triples
// available in the pricing table.
func (e *CostEstimator) SupportedResources() []CostEstimate {
	var out []CostEstimate
	for key, entry := range pricingTable {
		parts := strings.SplitN(key, ":", 3)
		out = append(out, CostEstimate{
			Provider:     parts[0],
			ResourceType: parts[1],
			Size:         parts[2],
			LowUSD:      entry.low,
			MidUSD:      entry.mid,
			HighUSD:     entry.high,
			Unit:         "monthly",
		})
	}
	return out
}
