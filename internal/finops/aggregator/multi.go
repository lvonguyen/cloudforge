package aggregator

import (
	"context"
	"fmt"
	"sync"
	"time"

	"cloudforge/internal/finops"
)

// MultiCloudAggregator fans out to multiple provider clients and merges the
// results into a single unified cost stream.
type MultiCloudAggregator struct {
	providers map[string]finops.Aggregator
}

// NewMultiCloudAggregator creates an aggregator that queries all supplied
// providers in parallel. The map key is an arbitrary label (e.g. "aws").
func NewMultiCloudAggregator(providers map[string]finops.Aggregator) *MultiCloudAggregator {
	return &MultiCloudAggregator{providers: providers}
}

// providerResult holds the outcome of a single provider fetch.
type providerResult struct {
	label   string
	records []finops.CostRecord
	err     error
}

// FetchCosts queries all providers concurrently and returns the merged,
// normalized results. If any provider fails, the error includes the provider
// label but other providers' records are still returned.
func (m *MultiCloudAggregator) FetchCosts(ctx context.Context, start, end time.Time) ([]finops.CostRecord, error) {
	ch := make(chan providerResult, len(m.providers))
	var wg sync.WaitGroup

	for label, agg := range m.providers {
		wg.Add(1)
		go func(label string, agg finops.Aggregator) {
			defer wg.Done()
			records, err := agg.FetchCosts(ctx, start, end)
			ch <- providerResult{label: label, records: records, err: err}
		}(label, agg)
	}

	// Close channel once all goroutines complete.
	go func() {
		wg.Wait()
		close(ch)
	}()

	var (
		merged []finops.CostRecord
		errs   []error
	)

	for res := range ch {
		if res.err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", res.label, res.err))
			continue
		}
		// Normalize through the same provider that fetched them.
		agg := m.providers[res.label]
		normalized := agg.NormalizeCosts(res.records)
		merged = append(merged, normalized...)
	}

	if len(errs) > 0 {
		return merged, fmt.Errorf("partial fetch errors: %v", errs)
	}
	return merged, nil
}

// NormalizeCosts is a no-op because records are already normalized during
// FetchCosts. Implementing it satisfies the Aggregator interface so
// MultiCloudAggregator can be composed with other aggregators.
func (m *MultiCloudAggregator) NormalizeCosts(records []finops.CostRecord) []finops.CostRecord {
	return records
}
