package remediation

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"

	cspmscoring "cloudforge/internal/cspm/scoring"
)

// mockRemediator implements the Remediator interface for testing.
type mockRemediator struct {
	tier           int
	remediateFunc  func(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*RemediationResult, error)
	validateFunc   func(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*ValidationResult, error)
	dryRunFunc     func(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*DryRunResult, error)
	remediateCalls int
	validateCalls  int
	dryRunCalls    int
	mu             sync.Mutex
}

func (m *mockRemediator) Tier() int { return m.tier }

func (m *mockRemediator) Remediate(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*RemediationResult, error) {
	m.mu.Lock()
	m.remediateCalls++
	m.mu.Unlock()
	if m.remediateFunc != nil {
		return m.remediateFunc(ctx, finding)
	}
	return &RemediationResult{
		FindingID: finding.Finding.ID,
		Success:   true,
		Message:   "remediated",
	}, nil
}

func (m *mockRemediator) Validate(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*ValidationResult, error) {
	m.mu.Lock()
	m.validateCalls++
	m.mu.Unlock()
	if m.validateFunc != nil {
		return m.validateFunc(ctx, finding)
	}
	return &ValidationResult{
		FindingID:   finding.Finding.ID,
		IsCompliant: true,
		Message:     "compliant",
	}, nil
}

func (m *mockRemediator) DryRun(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*DryRunResult, error) {
	m.mu.Lock()
	m.dryRunCalls++
	m.mu.Unlock()
	if m.dryRunFunc != nil {
		return m.dryRunFunc(ctx, finding)
	}
	return &DryRunResult{
		FindingID:      finding.Finding.ID,
		WouldSucceed:   true,
		PlannedActions: []string{"action-1", "action-2"},
	}, nil
}

func makeFinding(id, findingType string) *cspmscoring.PrioritizedFinding {
	return &cspmscoring.PrioritizedFinding{
		Finding: &cspmscoring.Finding{
			ID:          id,
			FindingType: findingType,
			Source:      "test-source",
			Severity:    "HIGH",
			ResourceID:  "arn:aws:s3:::test-bucket",
		},
		AutoRemediationReady: true,
	}
}

func TestExecutor_RegisterAndExecute(t *testing.T) {
	tests := []struct {
		name        string
		findingType string
		registerAs  string
		wantSuccess bool
		wantErr     bool
		wantErrMsg  string
	}{
		{
			name:        "routes to correct handler",
			findingType: "S3_PUBLIC_ACCESS",
			registerAs:  "S3_PUBLIC_ACCESS",
			wantSuccess: true,
		},
		{
			name:        "unknown finding type returns error",
			findingType: "UNKNOWN_TYPE",
			registerAs:  "S3_PUBLIC_ACCESS",
			wantErr:     true,
			wantErrMsg:  "no handler registered for finding type: UNKNOWN_TYPE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executor := NewExecutor(false)
			mock := &mockRemediator{tier: 1}
			executor.Register(tt.registerAs, mock)

			finding := makeFinding("f-1", tt.findingType)
			result, err := executor.Execute(context.Background(), finding)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErrMsg) {
					t.Fatalf("expected error containing %q, got %q", tt.wantErrMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Success != tt.wantSuccess {
				t.Fatalf("expected success=%v, got %v", tt.wantSuccess, result.Success)
			}
		})
	}
}

func TestExecutor_ExecuteDryRun(t *testing.T) {
	tests := []struct {
		name          string
		dryRunResult  *DryRunResult
		dryRunErr     error
		wantSuccess   bool
		wantErr       bool
		wantMsgPrefix string
	}{
		{
			name: "successful dry-run",
			dryRunResult: &DryRunResult{
				WouldSucceed:   true,
				PlannedActions: []string{"disable public access"},
			},
			wantSuccess:   true,
			wantMsgPrefix: "DRY-RUN:",
		},
		{
			name: "dry-run would not succeed",
			dryRunResult: &DryRunResult{
				WouldSucceed:   false,
				PlannedActions: []string{"check permissions"},
			},
			wantSuccess:   false,
			wantMsgPrefix: "DRY-RUN:",
		},
		{
			name:      "dry-run returns error",
			dryRunErr: fmt.Errorf("permission denied"),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executor := NewExecutor(true) // dry-run mode
			mock := &mockRemediator{
				tier: 1,
				dryRunFunc: func(_ context.Context, _ *cspmscoring.PrioritizedFinding) (*DryRunResult, error) {
					return tt.dryRunResult, tt.dryRunErr
				},
			}
			executor.Register("S3_PUBLIC_ACCESS", mock)

			finding := makeFinding("f-dry", "S3_PUBLIC_ACCESS")
			result, err := executor.Execute(context.Background(), finding)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Success != tt.wantSuccess {
				t.Fatalf("expected success=%v, got %v", tt.wantSuccess, result.Success)
			}
			if !strings.HasPrefix(result.Message, tt.wantMsgPrefix) {
				t.Fatalf("expected message prefix %q, got %q", tt.wantMsgPrefix, result.Message)
			}
			if mock.remediateCalls != 0 {
				t.Fatalf("Remediate should not be called in dry-run, got %d calls", mock.remediateCalls)
			}
			if mock.validateCalls != 0 {
				t.Fatalf("Validate should not be called in dry-run, got %d calls", mock.validateCalls)
			}
		})
	}
}

func TestExecutor_AutoRemediationNotReady_Tier1_Allowed(t *testing.T) {
	// Tier 1 = auto-safe, should ALWAYS run regardless of AutoRemediationReady [SEC-006]
	executor := NewExecutor(false)
	mock := &mockRemediator{tier: 1}
	executor.Register("OPEN_SSH_PORT", mock)

	finding := makeFinding("f-noauto", "OPEN_SSH_PORT")
	finding.AutoRemediationReady = false

	result, err := executor.Execute(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatal("expected Success=true for Tier 1 (auto-safe) even with AutoRemediationReady=false")
	}
	if mock.remediateCalls != 1 {
		t.Fatalf("expected 1 Remediate call for Tier 1, got %d", mock.remediateCalls)
	}
}

func TestExecutor_AutoRemediationNotReady_Tier2_Blocked(t *testing.T) {
	// Tier 2+ require AutoRemediationReady=true [SEC-006]
	executor := NewExecutor(false)
	mock := &mockRemediator{tier: 2}
	executor.Register("OPEN_SSH_PORT", mock)

	finding := makeFinding("f-tier2", "OPEN_SSH_PORT")
	finding.AutoRemediationReady = false

	result, err := executor.Execute(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Fatal("expected Success=false for Tier 2 when AutoRemediationReady=false")
	}
	if mock.remediateCalls != 0 {
		t.Fatal("Remediate should not be called for unapproved Tier 2")
	}
}

func TestExecutor_ValidationFailure(t *testing.T) {
	tests := []struct {
		name          string
		validateRes   *ValidationResult
		validateErr   error
		wantSuccess   bool
		wantMsgPart   string
		wantErrorPart string
	}{
		{
			name: "validation returns not compliant",
			validateRes: &ValidationResult{
				IsCompliant: false,
				Message:     "resource still public",
			},
			wantSuccess: false,
			wantMsgPart: "validation failed",
		},
		{
			name:          "validation returns error",
			validateErr:   fmt.Errorf("timeout checking compliance"),
			wantSuccess:   false,
			wantErrorPart: "Validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executor := NewExecutor(false)
			mock := &mockRemediator{
				tier: 1,
				validateFunc: func(_ context.Context, _ *cspmscoring.PrioritizedFinding) (*ValidationResult, error) {
					return tt.validateRes, tt.validateErr
				},
			}
			executor.Register("S3_PUBLIC_ACCESS", mock)

			finding := makeFinding("f-valfail", "S3_PUBLIC_ACCESS")
			result, err := executor.Execute(context.Background(), finding)

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Success != tt.wantSuccess {
				t.Fatalf("expected success=%v, got %v", tt.wantSuccess, result.Success)
			}
			if tt.wantMsgPart != "" && !strings.Contains(strings.ToLower(result.Message), tt.wantMsgPart) {
				t.Fatalf("expected message containing %q, got %q", tt.wantMsgPart, result.Message)
			}
			if tt.wantErrorPart != "" && !strings.Contains(result.Error, tt.wantErrorPart) {
				t.Fatalf("expected error field containing %q, got %q", tt.wantErrorPart, result.Error)
			}
		})
	}
}

func TestExecutor_ExecuteBatch(t *testing.T) {
	tests := []struct {
		name           string
		numFindings    int
		maxConcurrency int
		wantResults    int
	}{
		{
			name:           "batch of 3 with concurrency 2",
			numFindings:    3,
			maxConcurrency: 2,
			wantResults:    3,
		},
		{
			name:           "batch of 5 with default concurrency",
			numFindings:    5,
			maxConcurrency: 0,
			wantResults:    5,
		},
		{
			name:           "single finding",
			numFindings:    1,
			maxConcurrency: 1,
			wantResults:    1,
		},
		{
			name:           "empty batch",
			numFindings:    0,
			maxConcurrency: 3,
			wantResults:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executor := NewExecutor(false)
			mock := &mockRemediator{tier: 1}
			executor.Register("S3_PUBLIC_ACCESS", mock)

			var batch []*cspmscoring.PrioritizedFinding
			for i := 0; i < tt.numFindings; i++ {
				batch = append(batch, makeFinding(fmt.Sprintf("f-%d", i), "S3_PUBLIC_ACCESS"))
			}

			results, err := executor.ExecuteBatch(context.Background(), batch, tt.maxConcurrency)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(results) != tt.wantResults {
				t.Fatalf("expected %d results, got %d", tt.wantResults, len(results))
			}
		})
	}
}

func TestExecutor_ExecuteBatch_MixedResults(t *testing.T) {
	executor := NewExecutor(false)

	goodHandler := &mockRemediator{tier: 1}
	executor.Register("GOOD_TYPE", goodHandler)

	batch := []*cspmscoring.PrioritizedFinding{
		makeFinding("f-good-1", "GOOD_TYPE"),
		makeFinding("f-bad-1", "BAD_TYPE"),
		makeFinding("f-good-2", "GOOD_TYPE"),
	}

	results, err := executor.ExecuteBatch(context.Background(), batch, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	var successes, failures int
	for _, r := range results {
		if r.Success {
			successes++
		} else {
			failures++
		}
	}
	if successes != 2 {
		t.Fatalf("expected 2 successes, got %d", successes)
	}
	if failures != 1 {
		t.Fatalf("expected 1 failure, got %d", failures)
	}
}

func TestExecutor_ListHandlers(t *testing.T) {
	tests := []struct {
		name      string
		register  []string
		wantTypes []string
	}{
		{
			name:      "no handlers",
			register:  nil,
			wantTypes: nil,
		},
		{
			name:      "single handler",
			register:  []string{"S3_PUBLIC_ACCESS"},
			wantTypes: []string{"S3_PUBLIC_ACCESS"},
		},
		{
			name:      "multiple handlers",
			register:  []string{"S3_PUBLIC_ACCESS", "OPEN_SSH_PORT", "IAM_ROOT_KEY"},
			wantTypes: []string{"IAM_ROOT_KEY", "OPEN_SSH_PORT", "S3_PUBLIC_ACCESS"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executor := NewExecutor(false)
			for _, ft := range tt.register {
				executor.Register(ft, &mockRemediator{tier: 1})
			}

			got := executor.ListHandlers()
			sort.Strings(got)
			sort.Strings(tt.wantTypes)

			if len(got) != len(tt.wantTypes) {
				t.Fatalf("expected %d handlers, got %d", len(tt.wantTypes), len(got))
			}
			for i := range got {
				if got[i] != tt.wantTypes[i] {
					t.Fatalf("handler[%d]: expected %q, got %q", i, tt.wantTypes[i], got[i])
				}
			}
		})
	}
}
