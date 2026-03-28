package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"aegis/internal/finops"
	"aegis/internal/finops/alerting"
	"aegis/internal/finops/anomaly"
	"aegis/internal/finops/chargeback"

	"go.opentelemetry.io/otel"
)

// finopsService wraps the FinOps subsystems for HTTP handler access.
// Aggregator is factory-created (see internal/finops/factory.go);
// detector and allocator are provider-agnostic composites.
type finopsService struct {
	aggregator    finops.Aggregator
	detector      *anomaly.Detector
	allocator     *chargeback.Allocator
	estimator     *finops.CostEstimator
	budgetMonitor *alerting.BudgetMonitor
}

// newFinopsServiceFromAggregator composes a finopsService from a factory-created
// aggregator and caller-supplied budget rules.
func newFinopsServiceFromAggregator(agg finops.Aggregator, budgetRules []alerting.BudgetRule) *finopsService {
	return &finopsService{
		aggregator: agg,
		detector: anomaly.NewDetector(anomaly.DetectorConfig{
			Sensitivity:  anomaly.SensitivityMedium,
			BaselineDays: 14,
			MinSpend:     10,
		}),
		allocator: chargeback.NewAllocator(chargeback.AllocatorConfig{
			PrimaryTag:   "cost_center",
			FallbackTag:  "department",
			UntaggedPool: "unallocated",
		}),
		estimator: finops.NewCostEstimator(),
		budgetMonitor: alerting.NewBudgetMonitor(budgetRules, &aggregatorSpendAdapter{
			agg:   agg,
			cache: make(map[string]spendCacheEntry),
			ttl:   5 * time.Minute,
		}, nil),
	}
}

// aggregatorSpendAdapter adapts a finops.Aggregator to the alerting.SpendProvider
// interface by summing current-month costs for the given provider.
// Results are cached per-provider with a configurable TTL to avoid redundant
// FetchCosts calls when BudgetMonitor.Check evaluates multiple rules.
type aggregatorSpendAdapter struct {
	agg   finops.Aggregator
	mu    sync.Mutex
	cache map[string]spendCacheEntry
	ttl   time.Duration
}

type spendCacheEntry struct {
	spend     float64
	fetchedAt time.Time
}

func (a *aggregatorSpendAdapter) CurrentSpend(ctx context.Context, provider, _ string) (float64, error) {
	a.mu.Lock()
	if entry, ok := a.cache[provider]; ok && time.Since(entry.fetchedAt) < a.ttl {
		a.mu.Unlock()
		return entry.spend, nil
	}
	a.mu.Unlock()

	now := time.Now().UTC()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	records, err := a.agg.FetchCosts(ctx, start, now)
	if err != nil {
		return 0, err
	}
	var total float64
	for _, r := range records {
		if provider != "" && r.Provider != provider {
			continue
		}
		total += r.Cost
	}

	a.mu.Lock()
	a.cache[provider] = spendCacheEntry{spend: total, fetchedAt: time.Now()}
	a.mu.Unlock()

	return total, nil
}

// ComputeSummary fetches costs for the given period and returns a fully-assembled CostSummary.
func (svc *finopsService) ComputeSummary(ctx context.Context, start, end time.Time) (*CostSummary, error) {
	records, err := svc.aggregator.FetchCosts(ctx, start, end)
	if err != nil {
		return nil, fmt.Errorf("fetching costs: %w", err)
	}

	records = svc.aggregator.NormalizeCosts(records)
	alerts := svc.detector.Detect(records)
	allocMap := svc.allocator.Allocate(records)

	summary := CostSummary{
		Period:     fmt.Sprintf("%s / %s", start.Format("2006-01-02"), end.Format("2006-01-02")),
		ByProvider: make(map[string]float64),
		ByService:  make(map[string]float64),
	}

	dailyMap := make(map[string]*CostDaily)
	for _, rec := range records {
		summary.Total += rec.Cost
		summary.ByProvider[rec.Provider] += rec.Cost
		summary.ByService[rec.ServiceName] += rec.Cost

		day := rec.Date.Format("2006-01-02")
		d, ok := dailyMap[day]
		if !ok {
			d = &CostDaily{Date: day}
			dailyMap[day] = d
		}
		d.Total += rec.Cost
		switch rec.Provider {
		case "aws":
			d.AWS += rec.Cost
		case "azure":
			d.Azure += rec.Cost
		case "gcp":
			d.GCP += rec.Cost
		}
	}

	summary.Daily = make([]CostDaily, 0, len(dailyMap))
	for _, d := range dailyMap {
		summary.Daily = append(summary.Daily, *d)
	}
	sort.Slice(summary.Daily, func(i, j int) bool {
		return summary.Daily[i].Date < summary.Daily[j].Date
	})

	summary.Anomalies = make([]CostAnomaly, len(alerts))
	for i, a := range alerts {
		summary.Anomalies[i] = CostAnomaly{
			ID:               a.ID,
			Provider:         a.Provider,
			AccountID:        a.AccountID,
			ServiceName:      a.ServiceName,
			DetectedAt:       a.DetectedAt.Format(time.RFC3339),
			ExpectedCost:     a.ExpectedCost,
			ActualCost:       a.ActualCost,
			DeviationPercent: a.Deviation,
			Severity:         a.Severity,
		}
	}

	allocs := make([]ChargebackAllocation, 0, len(allocMap))
	var chargeTotal float64
	for _, a := range allocMap {
		allocs = append(allocs, ChargebackAllocation{
			CostCenter: a.CostCenter,
			Team:       a.Team,
			TotalCost:  a.TotalCost,
			ByProvider: a.ByProvider,
			ByService:  a.ByService,
			Percentage: a.Percentage,
		})
		chargeTotal += a.TotalCost
	}
	summary.Chargeback = &Chargeback{
		Period:      summary.Period,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		TotalCost:   chargeTotal,
		Allocations: allocs,
	}

	return &summary, nil
}

// getCostSummaryComputed delegates to finopsService.ComputeSummary.
func (s *Server) getCostSummaryComputed(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.getCostSummaryComputed")
	defer span.End()
	r = r.WithContext(ctx)

	end := time.Now().UTC()
	start := end.AddDate(0, 0, -30)

	summary, err := s.finopsSvc.ComputeSummary(r.Context(), start, end)
	if err != nil {
		s.writeInternalError(w, err, "cost summary")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(summary)
}

// getBudgetStatus runs the budget monitor check and returns current budget status.
func (s *Server) getBudgetStatus(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.getBudgetStatus")
	defer span.End()
	r = r.WithContext(ctx)

	if s.finopsSvc.budgetMonitor == nil {
		writeErrorResponse(w, "budget monitor not configured", http.StatusNotImplemented)
		return
	}

	alerts, err := s.finopsSvc.budgetMonitor.Check(r.Context())
	if err != nil {
		s.writeInternalError(w, err, "budget check")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"alerts":     alerts,
		"checked_at": time.Now().UTC().Format(time.RFC3339),
	})
}

// getCostEstimate returns a cost estimate for a specific resource type.
func (s *Server) getCostEstimate(w http.ResponseWriter, r *http.Request) {
	_, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.getCostEstimate")
	defer span.End()

	resourceType := r.URL.Query().Get("resource_type")
	provider := r.URL.Query().Get("provider")
	size := r.URL.Query().Get("size")

	if resourceType == "" || provider == "" || size == "" {
		writeErrorResponse(w, "resource_type, provider, and size query parameters are required", http.StatusBadRequest)
		return
	}

	estimate, err := s.finopsSvc.estimator.EstimateMonthlyCost(resourceType, provider, size)
	if err != nil {
		writeErrorResponse(w, "unknown resource type or size", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(estimate)
}

// listSupportedResources returns all available resource types in the pricing table.
func (s *Server) listSupportedResources(w http.ResponseWriter, r *http.Request) {
	_, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.listSupportedResources")
	defer span.End()

	resources := s.finopsSvc.estimator.SupportedResources()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"resources": resources,
		"count":     len(resources),
	})
}
