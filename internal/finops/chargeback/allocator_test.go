package chargeback

import (
	"testing"
	"time"

	"aegis/internal/finops"
)

func TestAllocator_Allocate_TaggedRecords(t *testing.T) {
	a := NewAllocator(AllocatorConfig{
		PrimaryTag:  "cost_center",
		FallbackTag: "department",
	})

	records := []finops.CostRecord{
		{ID: "r1", Provider: "aws", ServiceName: "ec2", Cost: 100.0, Date: time.Now(), Tags: map[string]string{"cost_center": "engineering"}},
		{ID: "r2", Provider: "aws", ServiceName: "s3", Cost: 50.0, Date: time.Now(), Tags: map[string]string{"cost_center": "engineering"}},
		{ID: "r3", Provider: "azure", ServiceName: "compute", Cost: 200.0, Date: time.Now(), Tags: map[string]string{"cost_center": "security"}},
	}

	result := a.Allocate(records)

	eng, ok := result["engineering"]
	if !ok {
		t.Fatal("expected engineering allocation")
	}
	if eng.TotalCost != 150.0 {
		t.Errorf("expected engineering total=150.0, got %.2f", eng.TotalCost)
	}

	sec, ok := result["security"]
	if !ok {
		t.Fatal("expected security allocation")
	}
	if sec.TotalCost != 200.0 {
		t.Errorf("expected security total=200.0, got %.2f", sec.TotalCost)
	}
}

func TestAllocator_Allocate_UntaggedGoesToDefault(t *testing.T) {
	a := NewAllocator(AllocatorConfig{
		PrimaryTag:   "cost_center",
		UntaggedPool: "unallocated",
	})

	records := []finops.CostRecord{
		{ID: "r1", Provider: "aws", ServiceName: "ec2", Cost: 100.0, Date: time.Now(), Tags: map[string]string{"cost_center": "engineering"}},
		{ID: "r2", Provider: "aws", ServiceName: "s3", Cost: 75.0, Date: time.Now(), Tags: map[string]string{}},
	}

	result := a.Allocate(records)

	untagged, ok := result["unallocated"]
	if !ok {
		t.Fatal("expected unallocated pool")
	}
	if untagged.TotalCost != 75.0 {
		t.Errorf("expected unallocated total=75.0, got %.2f", untagged.TotalCost)
	}
}

func TestAllocator_Allocate_EmptyRecords(t *testing.T) {
	a := NewAllocator(AllocatorConfig{
		PrimaryTag:   "cost_center",
		UntaggedPool: "unallocated",
	})

	result := a.Allocate(nil)
	if len(result) != 0 {
		t.Errorf("expected empty map for nil input, got %d entries", len(result))
	}

	result = a.Allocate([]finops.CostRecord{})
	if len(result) != 0 {
		t.Errorf("expected empty map for empty slice, got %d entries", len(result))
	}
}

func TestGenerateReport_HasCorrectPeriod(t *testing.T) {
	allocations := map[string]*finops.CostAllocation{
		"engineering": {CostCenter: "engineering", TotalCost: 500.0, ByProvider: map[string]float64{"aws": 500.0}, ByService: map[string]float64{"ec2": 500.0}},
		"security":    {CostCenter: "security", TotalCost: 300.0, ByProvider: map[string]float64{"azure": 300.0}, ByService: map[string]float64{"compute": 300.0}},
	}

	report := GenerateReport(allocations, "2026-02")

	if report.Period != "2026-02" {
		t.Errorf("expected period=2026-02, got %q", report.Period)
	}
	if report.TotalCost != 800.0 {
		t.Errorf("expected total=800.0, got %.2f", report.TotalCost)
	}
	if len(report.Allocations) != 2 {
		t.Errorf("expected 2 allocations, got %d", len(report.Allocations))
	}
	// First allocation should be highest cost (sorted descending)
	if report.Allocations[0].TotalCost < report.Allocations[1].TotalCost {
		t.Error("expected allocations sorted by cost descending")
	}
}

func TestAllocator_Allocate_FallbackTag(t *testing.T) {
	a := NewAllocator(AllocatorConfig{
		PrimaryTag:  "cost_center",
		FallbackTag: "department",
	})

	records := []finops.CostRecord{
		{ID: "r1", Cost: 100.0, Date: time.Now(), Tags: map[string]string{"department": "analytics"}},
	}

	result := a.Allocate(records)

	if _, ok := result["analytics"]; !ok {
		t.Error("expected fallback tag 'department' to be used when primary tag missing")
	}
}
