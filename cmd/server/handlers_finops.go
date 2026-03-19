package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"time"

	"aegis/internal/finops"
	"aegis/internal/finops/anomaly"
	"aegis/internal/finops/chargeback"

	"go.uber.org/zap"
)

// finopsService wires the concrete FinOps implementations together.
// Lives in cmd/server to avoid import cycles (finops → anomaly → finops).
type finopsService struct {
	aggregator finops.Aggregator
	detector   *anomaly.Detector
	allocator  *chargeback.Allocator
}

// newFinopsService creates the FinOps service with provider selection via FINOPS_PROVIDER env var.
// "aws" → real AWS Cost Explorer data, "memory" (default) → synthetic 30-day seed.
func newFinopsService(logger *zap.Logger) *finopsService {
	var agg finops.Aggregator
	switch os.Getenv("FINOPS_PROVIDER") {
	case "aws":
		region := os.Getenv("FINOPS_AWS_REGION")
		if region == "" {
			region = "us-east-1"
		}
		a, err := finops.NewAWSAggregator(region, logger)
		if err != nil {
			logger.Warn("AWS FinOps aggregator init failed, falling back to memory", zap.Error(err))
			agg = finops.NewMemoryAggregator()
		} else {
			agg = a
			logger.Info("FinOps using AWS Cost Explorer", zap.String("region", region))
		}
	default:
		agg = finops.NewMemoryAggregator()
	}

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
	}
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
