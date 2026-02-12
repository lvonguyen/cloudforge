// Package chargeback provides cost allocation and showback functionality.
// Consolidated from finops-platform/internal/chargeback
package chargeback

import (
	"encoding/csv"
	"fmt"
	"os"
	"sort"
	"time"

	"cloudforge/internal/finops"
)

// AllocatorConfig holds configuration for cost allocation
type AllocatorConfig struct {
	PrimaryTag      string           // Primary tag for allocation (e.g., cost_center)
	FallbackTag     string           // Fallback tag if primary missing
	UntaggedPool    string           // Where to allocate untagged costs
	SharedCostSplit []SharedCostRule // Rules for splitting shared costs
}

// SharedCostRule defines how to split shared costs
type SharedCostRule struct {
	CostCenter string
	Percentage float64
}

// Allocator performs tag-based cost allocation
type Allocator struct {
	config AllocatorConfig
}

// NewAllocator creates a new cost allocator
func NewAllocator(cfg AllocatorConfig) *Allocator {
	return &Allocator{config: cfg}
}

// Allocate distributes costs to cost centers based on tags
func (a *Allocator) Allocate(records []finops.CostRecord) map[string]*finops.CostAllocation {
	allocations := make(map[string]*finops.CostAllocation)
	var untaggedCosts []finops.CostRecord

	for _, r := range records {
		costCenter := a.getCostCenter(r)

		if costCenter == "" {
			untaggedCosts = append(untaggedCosts, r)
			continue
		}

		if _, exists := allocations[costCenter]; !exists {
			allocations[costCenter] = &finops.CostAllocation{
				CostCenter: costCenter,
				ByProvider: make(map[string]float64),
				ByService:  make(map[string]float64),
			}
		}

		alloc := allocations[costCenter]
		alloc.TotalCost += r.Cost
		alloc.ByProvider[r.Provider] += r.Cost
		alloc.ByService[r.ServiceName] += r.Cost
	}

	// Handle untagged costs
	a.allocateUntagged(allocations, untaggedCosts)

	return allocations
}

// getCostCenter extracts the cost center from a record's tags
func (a *Allocator) getCostCenter(r finops.CostRecord) string {
	// Try primary tag
	if cc, ok := r.Tags[a.config.PrimaryTag]; ok && cc != "" {
		return cc
	}

	// Try fallback tag
	if cc, ok := r.Tags[a.config.FallbackTag]; ok && cc != "" {
		return cc
	}

	return ""
}

// allocateUntagged distributes untagged costs
func (a *Allocator) allocateUntagged(allocations map[string]*finops.CostAllocation, untagged []finops.CostRecord) {
	if len(untagged) == 0 {
		return
	}

	// Calculate total untagged cost
	var totalUntagged float64
	for _, r := range untagged {
		totalUntagged += r.Cost
	}

	// If we have shared cost rules, use them
	if len(a.config.SharedCostSplit) > 0 {
		remainingPct := 100.0

		for _, rule := range a.config.SharedCostSplit {
			if _, exists := allocations[rule.CostCenter]; !exists {
				allocations[rule.CostCenter] = &finops.CostAllocation{
					CostCenter: rule.CostCenter,
					ByProvider: make(map[string]float64),
					ByService:  make(map[string]float64),
				}
			}

			allocated := totalUntagged * (rule.Percentage / 100)
			allocations[rule.CostCenter].TotalCost += allocated
			remainingPct -= rule.Percentage
		}

		// Distribute remaining proportionally
		if remainingPct > 0 {
			a.distributeProportionally(allocations, totalUntagged*(remainingPct/100))
		}
	} else if a.config.UntaggedPool != "" {
		// Allocate all to untagged pool
		if _, exists := allocations[a.config.UntaggedPool]; !exists {
			allocations[a.config.UntaggedPool] = &finops.CostAllocation{
				CostCenter: a.config.UntaggedPool,
				ByProvider: make(map[string]float64),
				ByService:  make(map[string]float64),
			}
		}
		allocations[a.config.UntaggedPool].TotalCost += totalUntagged

		for _, r := range untagged {
			allocations[a.config.UntaggedPool].ByProvider[r.Provider] += r.Cost
			allocations[a.config.UntaggedPool].ByService[r.ServiceName] += r.Cost
		}
	} else {
		// Distribute proportionally to existing cost centers
		a.distributeProportionally(allocations, totalUntagged)
	}
}

// distributeProportionally allocates costs based on existing spend
func (a *Allocator) distributeProportionally(allocations map[string]*finops.CostAllocation, amount float64) {
	var totalDirect float64
	for _, alloc := range allocations {
		totalDirect += alloc.TotalCost
	}

	if totalDirect == 0 {
		return
	}

	for _, alloc := range allocations {
		proportion := alloc.TotalCost / totalDirect
		alloc.TotalCost += amount * proportion
	}
}

// GenerateReport creates a chargeback report from allocations
func GenerateReport(allocations map[string]*finops.CostAllocation, period string) *finops.ChargebackReport {
	report := &finops.ChargebackReport{
		Period:      period,
		GeneratedAt: time.Now(),
		Allocations: make([]finops.CostAllocation, 0),
	}

	for _, alloc := range allocations {
		report.Allocations = append(report.Allocations, *alloc)
		report.TotalCost += alloc.TotalCost
	}

	// Calculate percentages
	for i := range report.Allocations {
		if report.TotalCost > 0 {
			report.Allocations[i].Percentage = (report.Allocations[i].TotalCost / report.TotalCost) * 100
		}
	}

	// Sort by cost descending
	sort.Slice(report.Allocations, func(i, j int) bool {
		return report.Allocations[i].TotalCost > report.Allocations[j].TotalCost
	})

	return report
}

// SaveCSV saves the report as a CSV file
func SaveCSV(report *finops.ChargebackReport, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Header
	header := []string{"Cost Center", "Team", "Total Cost", "AWS", "Azure", "GCP", "% of Total"}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Data rows
	for _, alloc := range report.Allocations {
		row := []string{
			alloc.CostCenter,
			alloc.Team,
			fmt.Sprintf("%.2f", alloc.TotalCost),
			fmt.Sprintf("%.2f", alloc.ByProvider["aws"]),
			fmt.Sprintf("%.2f", alloc.ByProvider["azure"]),
			fmt.Sprintf("%.2f", alloc.ByProvider["gcp"]),
			fmt.Sprintf("%.1f%%", alloc.Percentage),
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	// Total row
	totalRow := []string{
		"TOTAL",
		"",
		fmt.Sprintf("%.2f", report.TotalCost),
		"", "", "",
		"100.0%",
	}
	return writer.Write(totalRow)
}
