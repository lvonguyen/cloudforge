package anomaly

import (
	"testing"
	"time"

	"aegis/internal/finops"
)

func uniformRecords(service, provider string, count int, costPerDay float64) []finops.CostRecord {
	records := make([]finops.CostRecord, count)
	for i := 0; i < count; i++ {
		records[i] = finops.CostRecord{
			ID:          "r-" + service + "-" + time.Now().Format("20060102") + "-" + string(rune('0'+i)),
			Provider:    provider,
			AccountID:   "acct-001",
			ServiceName: service,
			Date:        time.Now().AddDate(0, 0, -(count - 1 - i)),
			Cost:        costPerDay,
			Currency:    "USD",
		}
	}
	return records
}

func TestDetector_Detect_NoAnomalies(t *testing.T) {
	d := NewDetector(DetectorConfig{
		Sensitivity:  SensitivityMedium,
		BaselineDays: 30,
		MinSpend:     1,
	})

	// 20 days of perfectly uniform cost — std dev is 0, no anomaly possible.
	records := uniformRecords("ec2", "aws", 20, 100.0)
	alerts := d.Detect(records)

	if len(alerts) != 0 {
		t.Errorf("expected 0 anomalies for uniform data, got %d", len(alerts))
	}
}

func TestDetector_Detect_SpikeDetected(t *testing.T) {
	d := NewDetector(DetectorConfig{
		Sensitivity:  SensitivityMedium,
		BaselineDays: 30,
		MinSpend:     1,
	})

	// 25 days of normal cost, then a 3x spike on today.
	records := uniformRecords("ec2", "aws", 25, 100.0)
	// Add slight variation so std dev > 0.
	for i := range records {
		records[i].Cost = 100.0 + float64(i)*0.5
	}
	// Inject spike record on today (within last 7 days).
	records = append(records, finops.CostRecord{
		ID:          "spike-record",
		Provider:    "aws",
		AccountID:   "acct-001",
		ServiceName: "ec2",
		Date:        time.Now(),
		Cost:        3000.0,
		Currency:    "USD",
	})

	alerts := d.Detect(records)

	if len(alerts) == 0 {
		t.Error("expected at least one anomaly for 3x cost spike, got none")
	}

	found := false
	for _, a := range alerts {
		if a.ServiceName == "ec2" && a.ActualCost == 3000.0 {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected anomaly for ec2 spike record not found in alerts")
	}
}

func TestDetector_Detect_EmptyRecords(t *testing.T) {
	d := NewDetector(DetectorConfig{
		Sensitivity:  SensitivityMedium,
		BaselineDays: 30,
		MinSpend:     1,
	})

	alerts := d.Detect(nil)
	if alerts != nil {
		t.Errorf("expected nil result for empty input, got %v", alerts)
	}

	alerts = d.Detect([]finops.CostRecord{})
	if len(alerts) != 0 {
		t.Errorf("expected empty result for empty slice input, got %d", len(alerts))
	}
}

func TestDetector_Detect_SingleRecord(t *testing.T) {
	d := NewDetector(DetectorConfig{
		Sensitivity:  SensitivityMedium,
		BaselineDays: 30,
		MinSpend:     1,
	})

	// Single record has std dev = 0, checkAnomaly returns nil immediately.
	records := []finops.CostRecord{
		{
			ID:          "single-001",
			Provider:    "aws",
			AccountID:   "acct-001",
			ServiceName: "s3",
			Date:        time.Now(),
			Cost:        500.0,
			Currency:    "USD",
		},
	}

	alerts := d.Detect(records)
	if len(alerts) != 0 {
		t.Errorf("expected 0 anomalies for single record (no variance), got %d", len(alerts))
	}
}

func TestDetector_Detect_SeverityLevels(t *testing.T) {
	d := NewDetector(DetectorConfig{
		Sensitivity:  SensitivityLow,
		BaselineDays: 30,
		MinSpend:     1,
	})

	// Build baseline with measurable std dev.
	records := make([]finops.CostRecord, 20)
	for i := 0; i < 20; i++ {
		records[i] = finops.CostRecord{
			ID:          "base-" + string(rune('a'+i)),
			Provider:    "gcp",
			AccountID:   "acct-gcp",
			ServiceName: "bigquery",
			// All within baseline window, all but last outside recent window.
			Date:     time.Now().AddDate(0, 0, -(20 - i)),
			Cost:     200.0 + float64(i)*2,
			Currency: "USD",
		}
	}
	// Extreme spike: should yield high/critical severity.
	records = append(records, finops.CostRecord{
		ID:          "extreme-spike",
		Provider:    "gcp",
		AccountID:   "acct-gcp",
		ServiceName: "bigquery",
		Date:        time.Now(),
		Cost:        5000.0,
		Currency:    "USD",
	})

	alerts := d.Detect(records)
	for _, a := range alerts {
		if a.ServiceName == "bigquery" && a.ActualCost == 5000.0 {
			if a.Severity != "high" && a.Severity != "critical" {
				t.Errorf("expected high or critical severity for extreme spike, got %s", a.Severity)
			}
			return
		}
	}
}
