package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"cloudforge/internal/finops"
	"cloudforge/internal/finops/anomaly"
	"cloudforge/internal/finops/chargeback"
)

// finopsService wires the concrete FinOps implementations together.
// Lives in cmd/server to avoid import cycles (finops → anomaly → finops).
type finopsService struct {
	aggregator *finops.MemoryAggregator
	detector   *anomaly.Detector
	allocator  *chargeback.Allocator
}

func newFinopsService() *finopsService {
	return &finopsService{
		aggregator: finops.NewMemoryAggregator(),
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

// getCostSummaryComputed replaces the old static JSON handler with computed data.
// It returns the types.go CostSummary shape to maintain API compatibility.
func (s *Server) getCostSummaryComputed(w http.ResponseWriter, r *http.Request) {
	svc := s.finopsSvc

	end := time.Now().UTC()
	start := end.AddDate(0, 0, -30)

	records, err := svc.aggregator.FetchCosts(r.Context(), start, end)
	if err != nil {
		s.writeInternalError(w, err, "cost summary")
		return
	}

	records = svc.aggregator.NormalizeCosts(records)
	alerts := svc.detector.Detect(records)
	allocMap := svc.allocator.Allocate(records)

	// Build API-compatible CostSummary (types.go shape).
	summary := CostSummary{
		Period:     fmt.Sprintf("%s / %s", start.Format("2006-01-02"), end.Format("2006-01-02")),
		ByProvider: make(map[string]float64),
		ByService:  make(map[string]float64),
	}

	// Aggregate totals and daily breakdown.
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

	// Sort daily entries by date.
	summary.Daily = make([]CostDaily, 0, len(dailyMap))
	for _, d := range dailyMap {
		summary.Daily = append(summary.Daily, *d)
	}
	sort.Slice(summary.Daily, func(i, j int) bool {
		return summary.Daily[i].Date < summary.Daily[j].Date
	})

	// Map anomaly alerts to API type.
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

	// Map allocations to chargeback.
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

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(summary)
}
