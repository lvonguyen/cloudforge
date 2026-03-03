// Package remediation provides the execution engine for cloud security remediations.
package remediation

import (
	"context"
	"fmt"
	"strings"

	cspmscoring "cloudforge/internal/cspm/scoring"
)

// Executor dispatches findings to appropriate remediation handlers.
type Executor struct {
	handlers map[string]Remediator
	dryRun   bool
}

// NewExecutor creates a new remediation executor.
func NewExecutor(dryRun bool) *Executor {
	return &Executor{
		handlers: make(map[string]Remediator),
		dryRun:   dryRun,
	}
}

// Register adds a remediation handler for a specific finding type.
func (e *Executor) Register(findingType string, handler Remediator) {
	e.handlers[findingType] = handler
}

// Execute processes a finding and routes it to the appropriate handler.
func (e *Executor) Execute(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*RemediationResult, error) {
	// Validate finding to prevent nil pointer panics [SEC-001]
	if finding == nil || finding.Finding == nil {
		return nil, fmt.Errorf("finding or finding.Finding is nil")
	}
	if finding.Finding.ID == "" || finding.Finding.FindingType == "" {
		return nil, fmt.Errorf("finding missing required fields: ID=%q, FindingType=%q",
			finding.Finding.ID, finding.Finding.FindingType)
	}

	// Find handler for this finding type
	handler, ok := e.handlers[finding.Finding.FindingType]
	if !ok {
		return nil, fmt.Errorf("no handler registered for finding type: %s", finding.Finding.FindingType)
	}

	// Tier 1 = auto-safe (always runs). Tier 2+ require AutoRemediationReady [SEC-006]
	if !finding.AutoRemediationReady && handler.Tier() > 1 {
		return &RemediationResult{
			FindingID: finding.Finding.ID,
			Success:   false,
			Message:   fmt.Sprintf("Auto-remediation not approved for tier %d finding", handler.Tier()),
		}, nil
	}

	// Dry-run mode
	if e.dryRun {
		dryRunResult, err := handler.DryRun(ctx, finding)
		if err != nil {
			return nil, fmt.Errorf("dry-run failed: %w", err)
		}
		return &RemediationResult{
			FindingID: finding.Finding.ID,
			Success:   dryRunResult.WouldSucceed,
			Message:   fmt.Sprintf("DRY-RUN: %s", strings.Join(dryRunResult.PlannedActions, ", ")),
			Actions:   dryRunResult.PlannedActions,
		}, nil
	}

	// Execute remediation
	result, err := handler.Remediate(ctx, finding)
	if err != nil {
		return nil, fmt.Errorf("remediation failed: %w", err)
	}

	// Validate remediation
	validation, err := handler.Validate(ctx, finding)
	if err != nil {
		result.Error = fmt.Sprintf("Validation failed: %v", err)
		result.Success = false
		return result, nil
	}

	if !validation.IsCompliant {
		result.Success = false
		result.Message = fmt.Sprintf("Remediation applied but validation failed: %s", validation.Message)
		return result, nil
	}

	result.Success = true
	result.Message = fmt.Sprintf("Remediation successful and validated: %s", validation.Message)
	return result, nil
}

// ExecuteBatch processes multiple findings concurrently (up to maxConcurrency).
// Results are returned in the same order as the input batch [SEC-002].
func (e *Executor) ExecuteBatch(ctx context.Context, batch []*cspmscoring.PrioritizedFinding, maxConcurrency int) ([]*RemediationResult, error) {
	if maxConcurrency <= 0 {
		maxConcurrency = 5
	}

	// Pre-allocate results at fixed indices to guarantee ordering [SEC-002]
	results := make([]*RemediationResult, len(batch))
	sem := make(chan struct{}, maxConcurrency)

	type resultPair struct {
		result *RemediationResult
		err    error
		index  int
	}

	resultChan := make(chan resultPair, len(batch))

	// Launch goroutines with context-aware semaphore [SEC-005]
	launched := 0
	cancelled := false
	for i := range batch {
		if cancelled {
			results[i] = &RemediationResult{
				FindingID: safeFindingID(batch[i]),
				Success:   false,
				Error:     fmt.Sprintf("cancelled: %v", ctx.Err()),
			}
			continue
		}

		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			cancelled = true
			results[i] = &RemediationResult{
				FindingID: safeFindingID(batch[i]),
				Success:   false,
				Error:     fmt.Sprintf("cancelled: %v", ctx.Err()),
			}
			continue
		}

		launched++
		go func(idx int, f *cspmscoring.PrioritizedFinding) {
			defer func() { <-sem }()
			result, err := e.Execute(ctx, f)
			resultChan <- resultPair{result: result, err: err, index: idx}
		}(i, batch[i])
	}

	// Collect results from launched goroutines at their correct indices
	for i := 0; i < launched; i++ {
		pair := <-resultChan
		if pair.err != nil {
			results[pair.index] = &RemediationResult{
				FindingID: safeFindingID(batch[pair.index]),
				Success:   false,
				Error:     pair.err.Error(),
			}
		} else {
			results[pair.index] = pair.result
		}
	}

	return results, nil
}

// safeFindingID extracts the finding ID safely, returning empty string for nil findings.
func safeFindingID(f *cspmscoring.PrioritizedFinding) string {
	if f != nil && f.Finding != nil {
		return f.Finding.ID
	}
	return ""
}

// ListHandlers returns all registered finding types.
func (e *Executor) ListHandlers() []string {
	types := make([]string, 0, len(e.handlers))
	for findingType := range e.handlers {
		types = append(types, findingType)
	}
	return types
}
