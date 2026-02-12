// Package remediation provides the execution engine for cloud security remediations.
package remediation

import (
	"context"
	"fmt"
	"strings"

	"cloudforge/internal/findings"
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
func (e *Executor) Execute(ctx context.Context, finding *findings.PrioritizedFinding) (*RemediationResult, error) {
	// Find handler for this finding type
	handler, ok := e.handlers[finding.Finding.FindingType]
	if !ok {
		return nil, fmt.Errorf("no handler registered for finding type: %s", finding.Finding.FindingType)
	}

	// Check tier compatibility with auto-remediation setting
	if !finding.AutoRemediationReady && handler.Tier() == 1 {
		return &RemediationResult{
			FindingID: finding.Finding.ID,
			Success:   false,
			Message:   "Auto-remediation not enabled for this finding",
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
func (e *Executor) ExecuteBatch(ctx context.Context, batch []*findings.PrioritizedFinding, maxConcurrency int) ([]*RemediationResult, error) {
	if maxConcurrency <= 0 {
		maxConcurrency = 5 // Default: 5 concurrent remediations
	}

	results := make([]*RemediationResult, 0, len(batch))
	sem := make(chan struct{}, maxConcurrency)

	type resultPair struct {
		result *RemediationResult
		err    error
		index  int
	}

	resultChan := make(chan resultPair, len(batch))

	// Launch goroutines
	for i, finding := range batch {
		sem <- struct{}{} // Acquire semaphore
		go func(idx int, f *findings.PrioritizedFinding) {
			defer func() { <-sem }() // Release semaphore

			result, err := e.Execute(ctx, f)
			resultChan <- resultPair{result: result, err: err, index: idx}
		}(i, finding)
	}

	// Collect results
	for i := 0; i < len(batch); i++ {
		pair := <-resultChan
		if pair.err != nil {
			// Log error but continue processing others
			results = append(results, &RemediationResult{
				FindingID: batch[pair.index].Finding.ID,
				Success:   false,
				Error:     pair.err.Error(),
			})
		} else {
			results = append(results, pair.result)
		}
	}

	return results, nil
}

// ListHandlers returns all registered finding types.
func (e *Executor) ListHandlers() []string {
	types := make([]string, 0, len(e.handlers))
	for findingType := range e.handlers {
		types = append(types, findingType)
	}
	return types
}
