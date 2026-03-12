package finops

import (
	"context"
	"fmt"
	"math/rand"
	"time"
)

// MemoryAggregator is an in-memory implementation of the Aggregator interface.
type MemoryAggregator struct {
	records []CostRecord
}

// NewMemoryAggregator creates an aggregator pre-seeded with 30 days of synthetic data.
func NewMemoryAggregator() *MemoryAggregator {
	a := &MemoryAggregator{}
	a.seed()
	return a
}

// FetchCosts returns records whose Date falls within [start, end].
func (a *MemoryAggregator) FetchCosts(_ context.Context, start, end time.Time) ([]CostRecord, error) {
	var out []CostRecord
	for _, r := range a.records {
		if !r.Date.Before(start) && !r.Date.After(end) {
			cp := r
			if cp.Tags != nil {
				tags := make(map[string]string, len(r.Tags))
				for k, v := range r.Tags {
					tags[k] = v
				}
				cp.Tags = tags
			}
			out = append(out, cp)
		}
	}
	return out, nil
}

// NormalizeCosts converts all records to USD in-place (returns new slice).
// EUR * 1.08, GBP * 1.27, others unchanged. Currency set to "USD".
func (a *MemoryAggregator) NormalizeCosts(records []CostRecord) []CostRecord {
	out := make([]CostRecord, len(records))
	for i, r := range records {
		switch r.Currency {
		case "EUR":
			r.Cost = r.Cost * 1.08
		case "GBP":
			r.Cost = r.Cost * 1.27
		}
		r.Currency = "USD"
		out[i] = r
	}
	return out
}

// seed generates 30 days of synthetic cost data ending today.
func (a *MemoryAggregator) seed() {
	// Fixed source for reproducibility.
	rng := rand.New(rand.NewSource(42)) //nolint:gosec

	type serviceSpec struct {
		provider string
		name     string
		base     float64
	}

	services := []serviceSpec{
		{"aws", "ec2", 450},
		{"aws", "s3", 120},
		{"aws", "rds", 280},
		{"aws", "lambda", 45},
		{"azure", "compute", 380},
		{"azure", "storage", 95},
		{"azure", "cosmos-db", 220},
		{"gcp", "gke", 340},
		{"gcp", "cloud-storage", 80},
		{"gcp", "bigquery", 150},
	}

	accounts := map[string]string{
		"aws":   "acct-aws-prod-001",
		"azure": "acct-azure-prod-003",
		"gcp":   "acct-gcp-prod-004",
	}

	costCenters := []string{"engineering", "security", "data"}
	departments := []string{"platform", "security", "analytics"}
	environments := []string{"production", "staging"}

	today := time.Now().UTC().Truncate(24 * time.Hour)
	start := today.AddDate(0, 0, -30)

	var records []CostRecord
	id := 0

	for day := 0; day < 30; day++ {
		date := start.AddDate(0, 0, day)

		for _, svc := range services {
			cost := svc.base * (1 + (rng.Float64()*0.30 - 0.15))

			// Inject anomalies on specific days.
			if day == 7 && svc.name == "ec2" {
				cost = 1200
			}
			if day == 15 && svc.name == "cosmos-db" {
				cost = 660
			}

			ccIdx := rng.Intn(len(costCenters))
			id++
			r := CostRecord{
				ID:          fmt.Sprintf("rec-%04d", id),
				Provider:    svc.provider,
				AccountID:   accounts[svc.provider],
				ServiceName: svc.name,
				ResourceID:  fmt.Sprintf("%s-%s-resource", svc.provider, svc.name),
				Region:      regionFor(svc.provider),
				Date:        date,
				Cost:        cost,
				Currency:    "USD",
				Tags: map[string]string{
					"cost_center": costCenters[ccIdx],
					"department":  departments[ccIdx],
					"environment": environments[rng.Intn(len(environments))],
				},
				CostCenter:  costCenters[ccIdx],
				Environment: environments[rng.Intn(len(environments))],
			}
			records = append(records, r)
		}
	}

	a.records = records
}

func regionFor(provider string) string {
	switch provider {
	case "aws":
		return "us-east-1"
	case "azure":
		return "eastus"
	case "gcp":
		return "us-central1"
	default:
		return "us-east-1"
	}
}
