// Package anomaly provides cost anomaly detection.
// Consolidated from finops-platform/internal/anomaly
package anomaly

import (
	"math"
	"sort"
	"time"

	"aegis/internal/finops"
)

// Sensitivity levels for anomaly detection
type Sensitivity string

const (
	SensitivityLow    Sensitivity = "low"
	SensitivityMedium Sensitivity = "medium"
	SensitivityHigh   Sensitivity = "high"
)

// DetectorConfig holds configuration for anomaly detection
type DetectorConfig struct {
	Sensitivity  Sensitivity
	BaselineDays int     // Days for baseline calculation
	MinSpend     float64 // Minimum spend to consider
}

// Baseline holds statistical baseline for a service
type Baseline struct {
	Mean   float64
	StdDev float64
	Min    float64
	Max    float64
	Count  int
}

// Detector performs anomaly detection on cost data
type Detector struct {
	config     DetectorConfig
	thresholds map[Sensitivity]float64 // Z-score thresholds
}

// NewDetector creates a new anomaly detector
func NewDetector(cfg DetectorConfig) *Detector {
	return &Detector{
		config: cfg,
		thresholds: map[Sensitivity]float64{
			SensitivityLow:    3.0, // 3 standard deviations
			SensitivityMedium: 2.0, // 2 standard deviations
			SensitivityHigh:   1.5, // 1.5 standard deviations
		},
	}
}

// Detect analyzes cost records for anomalies
func (d *Detector) Detect(records []finops.CostRecord) []finops.AnomalyAlert {
	if len(records) == 0 {
		return nil
	}

	// Group by service
	byService := make(map[string][]finops.CostRecord)
	for _, r := range records {
		key := r.Provider + ":" + r.ServiceName
		byService[key] = append(byService[key], r)
	}

	var anomalies []finops.AnomalyAlert

	for serviceKey, serviceRecords := range byService {
		// Sort by date
		sort.Slice(serviceRecords, func(i, j int) bool {
			return serviceRecords[i].Date.Before(serviceRecords[j].Date)
		})

		// Calculate baseline from historical data
		baseline := d.calculateBaseline(serviceRecords)
		if baseline.Mean < d.config.MinSpend {
			continue // Skip low-spend services
		}

		// Check recent records for anomalies
		recentRecords := d.getRecentRecords(serviceRecords, 7)
		for _, r := range recentRecords {
			if anomaly := d.checkAnomaly(r, baseline, serviceKey); anomaly != nil {
				anomalies = append(anomalies, *anomaly)
			}
		}
	}

	// Sort by severity
	sort.Slice(anomalies, func(i, j int) bool {
		return severityRank(anomalies[i].Severity) > severityRank(anomalies[j].Severity)
	})

	return anomalies
}

// calculateBaseline computes statistical baseline from historical data
func (d *Detector) calculateBaseline(records []finops.CostRecord) Baseline {
	// Get baseline window
	cutoff := time.Now().AddDate(0, 0, -d.config.BaselineDays)
	var values []float64

	for _, r := range records {
		if r.Date.After(cutoff) {
			values = append(values, r.Cost)
		}
	}

	if len(values) == 0 {
		return Baseline{}
	}

	// Calculate statistics
	var sum float64
	min := values[0]
	max := values[0]

	for _, v := range values {
		sum += v
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}

	mean := sum / float64(len(values))

	// Calculate standard deviation
	var sumSqDiff float64
	for _, v := range values {
		sumSqDiff += (v - mean) * (v - mean)
	}
	stdDev := math.Sqrt(sumSqDiff / float64(len(values)))

	return Baseline{
		Mean:   mean,
		StdDev: stdDev,
		Min:    min,
		Max:    max,
		Count:  len(values),
	}
}

// getRecentRecords returns records from the last N days
func (d *Detector) getRecentRecords(records []finops.CostRecord, days int) []finops.CostRecord {
	cutoff := time.Now().AddDate(0, 0, -days)
	var recent []finops.CostRecord

	for _, r := range records {
		if r.Date.After(cutoff) {
			recent = append(recent, r)
		}
	}

	return recent
}

// checkAnomaly checks if a record is anomalous
func (d *Detector) checkAnomaly(r finops.CostRecord, baseline Baseline, serviceKey string) *finops.AnomalyAlert {
	if baseline.StdDev == 0 {
		return nil // Can't detect anomaly without variance
	}

	// Calculate Z-score
	zScore := (r.Cost - baseline.Mean) / baseline.StdDev
	threshold := d.thresholds[d.config.Sensitivity]

	if math.Abs(zScore) < threshold {
		return nil // Not anomalous
	}

	// Calculate percent change
	percentChange := ((r.Cost - baseline.Mean) / baseline.Mean) * 100

	// Determine severity
	severity := "low"
	if math.Abs(zScore) >= 4.0 {
		severity = "critical"
	} else if math.Abs(zScore) >= 3.0 {
		severity = "high"
	} else if math.Abs(zScore) >= 2.0 {
		severity = "medium"
	}

	return &finops.AnomalyAlert{
		ID:           r.ID + "-anomaly",
		Provider:     r.Provider,
		AccountID:    r.AccountID,
		ServiceName:  r.ServiceName,
		DetectedAt:   time.Now(),
		ExpectedCost: baseline.Mean,
		ActualCost:   r.Cost,
		Deviation:    percentChange,
		Severity:     severity,
	}
}

// severityRank returns numeric rank for sorting
func severityRank(severity string) int {
	switch severity {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
