package workflow

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
)

// ─── Full lifecycle: pending → running → completed ─────────────────────────

func TestLifecycle_PendingToCompleted(t *testing.T) {
	e := newMemoryEngine()
	ctx := context.Background()

	wf := &Workflow{
		ID:        "lc-001",
		Name:      "Lifecycle Test",
		Type:      TypeRemediation,
		Priority:  2,
		Initiator: "test-runner",
		Steps: []Step{
			{ID: "s1", Name: "Scan", Status: StatusPending},
			{ID: "s2", Name: "Remediate", Status: StatusPending},
			{ID: "s3", Name: "Verify", Status: StatusPending},
		},
	}

	// Phase 1: Start — workflow should begin as pending.
	created, err := e.StartWorkflow(ctx, wf)
	if err != nil {
		t.Fatalf("StartWorkflow: %v", err)
	}
	if created.Status != StatusPending {
		t.Fatalf("after start: expected pending, got %q", created.Status)
	}
	if created.CreatedAt.IsZero() {
		t.Error("CreatedAt must be set after start")
	}
	if created.UpdatedAt.IsZero() {
		t.Error("UpdatedAt must be set after start")
	}
	if created.CompletedAt != nil {
		t.Error("CompletedAt must be nil after start")
	}

	// Phase 2: Approve — transitions through running to completed.
	approved, err := e.ApproveWorkflow(ctx, "lc-001", "manager@example.com")
	if err != nil {
		t.Fatalf("ApproveWorkflow: %v", err)
	}
	if approved.Status != StatusCompleted {
		t.Fatalf("after approval: expected completed, got %q", approved.Status)
	}
	if approved.Assignee != "manager@example.com" {
		t.Errorf("expected assignee manager@example.com, got %q", approved.Assignee)
	}
	if approved.CompletedAt == nil {
		t.Error("CompletedAt must be set after completion")
	}
	if approved.UpdatedAt.Before(created.UpdatedAt) {
		t.Error("UpdatedAt should not go backwards after completion")
	}

	// Phase 3: Verify the stored state matches.
	fetched, err := e.GetWorkflow(ctx, "lc-001")
	if err != nil {
		t.Fatalf("GetWorkflow after completion: %v", err)
	}
	if fetched.Status != StatusCompleted {
		t.Errorf("stored status: expected completed, got %q", fetched.Status)
	}
}

// ─── Cancellation: pending → cancelled ─────────────────────────────────────

func TestCancellation_PendingToCancelled(t *testing.T) {
	e := newMemoryEngine()
	ctx := context.Background()

	wf := &Workflow{
		ID:        "cancel-001",
		Name:      "Cancellation Test",
		Type:      TypeAccessReview,
		Priority:  3,
		Initiator: "test-runner",
		Steps: []Step{
			{ID: "s1", Name: "Collect", Status: StatusPending},
			{ID: "s2", Name: "Review", Status: StatusPending},
		},
	}

	_, err := e.StartWorkflow(ctx, wf)
	if err != nil {
		t.Fatalf("StartWorkflow: %v", err)
	}

	if err := e.CancelWorkflow(ctx, "cancel-001"); err != nil {
		t.Fatalf("CancelWorkflow: %v", err)
	}

	fetched, err := e.GetWorkflow(ctx, "cancel-001")
	if err != nil {
		t.Fatalf("GetWorkflow after cancel: %v", err)
	}
	if fetched.Status != StatusCancelled {
		t.Errorf("expected cancelled, got %q", fetched.Status)
	}
}

func TestCancellation_RunningWorkflow(t *testing.T) {
	e := newMemoryEngine()
	ctx := context.Background()

	// wf-002 is seeded as running — cancellation should succeed.
	if err := e.CancelWorkflow(ctx, "wf-002"); err != nil {
		t.Fatalf("CancelWorkflow on running wf: %v", err)
	}
	wf, err := e.GetWorkflow(ctx, "wf-002")
	if err != nil {
		t.Fatalf("GetWorkflow: %v", err)
	}
	if wf.Status != StatusCancelled {
		t.Errorf("expected cancelled, got %q", wf.Status)
	}
}

// ─── Approval flow: pending → running (with approver recorded) ─────────────

func TestApprovalFlow_ApproverRecorded(t *testing.T) {
	e := newMemoryEngine()
	ctx := context.Background()

	wf := &Workflow{
		ID:        "approve-001",
		Name:      "Approval Flow Test",
		Type:      TypeApproval,
		Priority:  1,
		Initiator: "requester@example.com",
		Steps: []Step{
			{ID: "s1", Name: "Security Review", Status: StatusPending},
			{ID: "s2", Name: "Deploy", Status: StatusPending},
		},
	}

	_, err := e.StartWorkflow(ctx, wf)
	if err != nil {
		t.Fatalf("StartWorkflow: %v", err)
	}

	approver := "ciso@example.com"
	approved, err := e.ApproveWorkflow(ctx, "approve-001", approver)
	if err != nil {
		t.Fatalf("ApproveWorkflow: %v", err)
	}

	if approved.Assignee != approver {
		t.Errorf("approver: expected %q, got %q", approver, approved.Assignee)
	}
	if approved.Status != StatusCompleted {
		t.Errorf("expected completed, got %q", approved.Status)
	}

	// All steps should be completed with output.
	for i, step := range approved.Steps {
		if step.Status != StatusCompleted {
			t.Errorf("step[%d] %q: expected completed, got %q", i, step.Name, step.Status)
		}
		if step.Output == "" {
			t.Errorf("step[%d] %q: output should not be empty", i, step.Name)
		}
		if step.StartedAt == nil {
			t.Errorf("step[%d] %q: StartedAt must be set", i, step.Name)
		}
		if step.CompletedAt == nil {
			t.Errorf("step[%d] %q: CompletedAt must be set", i, step.Name)
		}
	}
}

func TestApprovalFlow_PreservesExistingOutput(t *testing.T) {
	e := newMemoryEngine()
	ctx := context.Background()

	wf := &Workflow{
		ID:        "approve-output",
		Name:      "Output Preservation Test",
		Type:      TypeRemediation,
		Priority:  2,
		Initiator: "scanner",
		Steps: []Step{
			{ID: "s1", Name: "Scan", Status: StatusPending, Output: "custom output from scan"},
			{ID: "s2", Name: "Patch", Status: StatusPending},
		},
	}

	_, err := e.StartWorkflow(ctx, wf)
	if err != nil {
		t.Fatalf("StartWorkflow: %v", err)
	}

	approved, err := e.ApproveWorkflow(ctx, "approve-output", "admin")
	if err != nil {
		t.Fatalf("ApproveWorkflow: %v", err)
	}

	// Step with pre-existing output should keep it.
	if approved.Steps[0].Output != "custom output from scan" {
		t.Errorf("step 0 output changed: got %q", approved.Steps[0].Output)
	}
	// Step without output gets auto-generated message.
	if approved.Steps[1].Output == "" {
		t.Error("step 1 should have auto-generated output")
	}
}

// ─── Concurrent workflow creation ──────────────────────────────────────────

func TestConcurrent_WorkflowCreation(t *testing.T) {
	e := newMemoryEngine()
	ctx := context.Background()

	const numGoroutines = 50
	var wg sync.WaitGroup
	errs := make(chan error, numGoroutines)

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			wf := &Workflow{
				ID:        fmt.Sprintf("concurrent-%03d", idx),
				Name:      fmt.Sprintf("Concurrent Workflow %d", idx),
				Type:      TypeComplianceScan,
				Priority:  3,
				Initiator: "load-test",
			}
			_, err := e.StartWorkflow(ctx, wf)
			if err != nil {
				errs <- fmt.Errorf("goroutine %d: %w", idx, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	// All workflows plus the 5 seed workflows should be present.
	wfs, err := e.ListWorkflows(ctx)
	if err != nil {
		t.Fatalf("ListWorkflows: %v", err)
	}
	expectedCount := numGoroutines + 5
	if len(wfs) != expectedCount {
		t.Errorf("expected %d workflows, got %d", expectedCount, len(wfs))
	}
}

func TestConcurrent_MixedOperations(t *testing.T) {
	e := newMemoryEngine()
	ctx := context.Background()

	// Create workflows for concurrent operations.
	for i := 0; i < 10; i++ {
		wf := &Workflow{
			ID:        fmt.Sprintf("mixed-%03d", i),
			Name:      fmt.Sprintf("Mixed Op %d", i),
			Type:      TypeIncidentResponse,
			Priority:  2,
			Initiator: "test",
		}
		if _, err := e.StartWorkflow(ctx, wf); err != nil {
			t.Fatalf("setup: %v", err)
		}
	}

	var wg sync.WaitGroup
	// Concurrently: cancel some, approve others, list, get.
	wg.Add(4)

	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			_ = e.CancelWorkflow(ctx, fmt.Sprintf("mixed-%03d", i))
		}
	}()

	go func() {
		defer wg.Done()
		for i := 5; i < 10; i++ {
			_, _ = e.ApproveWorkflow(ctx, fmt.Sprintf("mixed-%03d", i), "approver")
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			_, _ = e.ListWorkflows(ctx)
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			_, _ = e.GetWorkflow(ctx, fmt.Sprintf("mixed-%03d", i))
		}
	}()

	wg.Wait()
	// If no race detector panic, the test passes.
}

// ─── Step progression within a workflow ────────────────────────────────────

func TestStepProgression_AllStepsCompleted(t *testing.T) {
	e := newMemoryEngine()
	ctx := context.Background()

	wf := &Workflow{
		ID:        "steps-001",
		Name:      "Step Progression Test",
		Type:      TypeComplianceScan,
		Priority:  2,
		Initiator: "compliance-engine",
		Steps: []Step{
			{ID: "s1", Name: "Scan Infrastructure", Status: StatusPending},
			{ID: "s2", Name: "Evaluate Controls", Status: StatusPending},
			{ID: "s3", Name: "Generate Evidence", Status: StatusPending},
			{ID: "s4", Name: "Create Report", Status: StatusPending},
		},
	}

	_, err := e.StartWorkflow(ctx, wf)
	if err != nil {
		t.Fatalf("StartWorkflow: %v", err)
	}

	approved, err := e.ApproveWorkflow(ctx, "steps-001", "auditor@example.com")
	if err != nil {
		t.Fatalf("ApproveWorkflow: %v", err)
	}

	if len(approved.Steps) != 4 {
		t.Fatalf("expected 4 steps, got %d", len(approved.Steps))
	}

	for i, step := range approved.Steps {
		if step.Status != StatusCompleted {
			t.Errorf("step[%d] %q: expected completed, got %q", i, step.Name, step.Status)
		}
		if step.StartedAt == nil {
			t.Errorf("step[%d] %q: StartedAt should be set", i, step.Name)
		}
		if step.CompletedAt == nil {
			t.Errorf("step[%d] %q: CompletedAt should be set", i, step.Name)
		}
		if step.Output == "" {
			t.Errorf("step[%d] %q: Output should not be empty", i, step.Name)
		}
	}
}

func TestStepProgression_ZeroSteps(t *testing.T) {
	e := newMemoryEngine()
	ctx := context.Background()

	wf := &Workflow{
		ID:        "steps-zero",
		Name:      "No Steps Workflow",
		Type:      TypeApproval,
		Priority:  4,
		Initiator: "test",
	}

	_, err := e.StartWorkflow(ctx, wf)
	if err != nil {
		t.Fatalf("StartWorkflow: %v", err)
	}

	approved, err := e.ApproveWorkflow(ctx, "steps-zero", "admin")
	if err != nil {
		t.Fatalf("ApproveWorkflow: %v", err)
	}
	if approved.Status != StatusCompleted {
		t.Errorf("expected completed, got %q", approved.Status)
	}
	if len(approved.Steps) != 0 {
		t.Errorf("expected 0 steps, got %d", len(approved.Steps))
	}
}

// ─── Error cases ───────────────────────────────────────────────────────────

func TestError_CancelAlreadyCompleted(t *testing.T) {
	e := newMemoryEngine()
	ctx := context.Background()

	wf := &Workflow{
		ID:        "err-cancel-completed",
		Name:      "Already Completed",
		Type:      TypeRemediation,
		Priority:  3,
		Initiator: "test",
		Steps:     []Step{{ID: "s1", Name: "Do", Status: StatusPending}},
	}

	if _, err := e.StartWorkflow(ctx, wf); err != nil {
		t.Fatalf("StartWorkflow: %v", err)
	}
	if _, err := e.ApproveWorkflow(ctx, "err-cancel-completed", "admin"); err != nil {
		t.Fatalf("ApproveWorkflow: %v", err)
	}

	err := e.CancelWorkflow(ctx, "err-cancel-completed")
	if err == nil {
		t.Fatal("expected error cancelling completed workflow, got nil")
	}
}

func TestError_CancelAlreadyCancelled(t *testing.T) {
	e := newMemoryEngine()
	ctx := context.Background()

	wf := &Workflow{
		ID:        "err-cancel-twice",
		Name:      "Double Cancel",
		Type:      TypeAccessReview,
		Priority:  3,
		Initiator: "test",
	}

	if _, err := e.StartWorkflow(ctx, wf); err != nil {
		t.Fatalf("StartWorkflow: %v", err)
	}
	if err := e.CancelWorkflow(ctx, "err-cancel-twice"); err != nil {
		t.Fatalf("first cancel: %v", err)
	}

	err := e.CancelWorkflow(ctx, "err-cancel-twice")
	if err == nil {
		t.Fatal("expected error cancelling already-cancelled workflow, got nil")
	}
}

func TestError_ApproveAlreadyRunning(t *testing.T) {
	e := newMemoryEngine()
	ctx := context.Background()

	// wf-002 is seeded as running.
	_, err := e.ApproveWorkflow(ctx, "wf-002", "approver@example.com")
	if err == nil {
		t.Fatal("expected error approving running workflow, got nil")
	}
}

func TestError_ApproveAlreadyCompleted(t *testing.T) {
	e := newMemoryEngine()
	ctx := context.Background()

	// wf-003 is seeded as completed.
	_, err := e.ApproveWorkflow(ctx, "wf-003", "approver@example.com")
	if err == nil {
		t.Fatal("expected error approving completed workflow, got nil")
	}
}

func TestError_ApproveAlreadyFailed(t *testing.T) {
	e := newMemoryEngine()
	ctx := context.Background()

	// wf-004 is seeded as failed.
	_, err := e.ApproveWorkflow(ctx, "wf-004", "approver@example.com")
	if err == nil {
		t.Fatal("expected error approving failed workflow, got nil")
	}
}

func TestError_GetNonexistent(t *testing.T) {
	e := newMemoryEngine()
	ctx := context.Background()

	_, err := e.GetWorkflow(ctx, "nonexistent-workflow-id")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestError_CancelNonexistent(t *testing.T) {
	e := newMemoryEngine()
	ctx := context.Background()

	err := e.CancelWorkflow(ctx, "nonexistent-workflow-id")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestError_ApproveNonexistent(t *testing.T) {
	e := newMemoryEngine()
	ctx := context.Background()

	_, err := e.ApproveWorkflow(ctx, "nonexistent-workflow-id", "admin")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

// ─── ListWorkflows count validation ────────────────────────────────────────

func TestListWorkflows_CountAfterMultipleOperations(t *testing.T) {
	e := newMemoryEngine()
	ctx := context.Background()

	// Baseline: 5 seed workflows.
	initial, err := e.ListWorkflows(ctx)
	if err != nil {
		t.Fatalf("initial ListWorkflows: %v", err)
	}
	if len(initial) != 5 {
		t.Fatalf("expected 5 seed workflows, got %d", len(initial))
	}

	// Add 3 new workflows.
	for i := 0; i < 3; i++ {
		wf := &Workflow{
			ID:        fmt.Sprintf("count-%03d", i),
			Name:      fmt.Sprintf("Count Test %d", i),
			Type:      TypeApproval,
			Priority:  3,
			Initiator: "test",
		}
		if _, err := e.StartWorkflow(ctx, wf); err != nil {
			t.Fatalf("StartWorkflow %d: %v", i, err)
		}
	}

	afterAdd, err := e.ListWorkflows(ctx)
	if err != nil {
		t.Fatalf("ListWorkflows after add: %v", err)
	}
	if len(afterAdd) != 8 {
		t.Errorf("expected 8 workflows after adding 3, got %d", len(afterAdd))
	}

	// Cancel one of the new workflows — it remains in the list (state changed, not removed).
	if err := e.CancelWorkflow(ctx, "count-000"); err != nil {
		t.Fatalf("CancelWorkflow: %v", err)
	}

	afterCancel, err := e.ListWorkflows(ctx)
	if err != nil {
		t.Fatalf("ListWorkflows after cancel: %v", err)
	}
	if len(afterCancel) != 8 {
		t.Errorf("cancel should not remove from list: expected 8, got %d", len(afterCancel))
	}

	// Approve another — also remains in the list.
	if _, err := e.ApproveWorkflow(ctx, "count-001", "admin"); err != nil {
		t.Fatalf("ApproveWorkflow: %v", err)
	}

	afterApprove, err := e.ListWorkflows(ctx)
	if err != nil {
		t.Fatalf("ListWorkflows after approve: %v", err)
	}
	if len(afterApprove) != 8 {
		t.Errorf("approve should not remove from list: expected 8, got %d", len(afterApprove))
	}
}

func TestListWorkflows_OrderPreservedAfterMutations(t *testing.T) {
	e := newMemoryEngine()
	ctx := context.Background()

	// Add and approve — list should still be sorted by CreatedAt descending.
	wf := &Workflow{
		ID:        "order-001",
		Name:      "Order Test",
		Type:      TypeRemediation,
		Priority:  1,
		Initiator: "test",
		Steps:     []Step{{ID: "s1", Name: "Step", Status: StatusPending}},
	}
	if _, err := e.StartWorkflow(ctx, wf); err != nil {
		t.Fatalf("StartWorkflow: %v", err)
	}
	if _, err := e.ApproveWorkflow(ctx, "order-001", "admin"); err != nil {
		t.Fatalf("ApproveWorkflow: %v", err)
	}

	wfs, err := e.ListWorkflows(ctx)
	if err != nil {
		t.Fatalf("ListWorkflows: %v", err)
	}

	for i := 1; i < len(wfs); i++ {
		if wfs[i].CreatedAt.After(wfs[i-1].CreatedAt) {
			t.Errorf("list not sorted desc at index %d: %v > %v",
				i, wfs[i].CreatedAt, wfs[i-1].CreatedAt)
		}
	}
}

// ─── NewEngine factory ─────────────────────────────────────────────────────

func TestNewEngine_MemoryProvider(t *testing.T) {
	eng, err := NewEngine("memory")
	if err != nil {
		t.Fatalf("NewEngine(memory): %v", err)
	}
	if eng == nil {
		t.Fatal("engine must not be nil")
	}

	// Verify it works by listing workflows.
	wfs, err := eng.ListWorkflows(context.Background())
	if err != nil {
		t.Fatalf("ListWorkflows: %v", err)
	}
	if len(wfs) < 5 {
		t.Errorf("expected at least 5 seed workflows, got %d", len(wfs))
	}
}

func TestNewEngine_EmptyProvider_DefaultsToMemory(t *testing.T) {
	eng, err := NewEngine("")
	if err != nil {
		t.Fatalf("NewEngine(''): %v", err)
	}
	if eng == nil {
		t.Fatal("engine must not be nil for empty provider")
	}
}

// ─── Copy isolation: mutations to returned workflow must not affect store ───

func TestCopyIsolation_GetWorkflow(t *testing.T) {
	e := newMemoryEngine()
	ctx := context.Background()

	wf, err := e.GetWorkflow(ctx, "wf-001")
	if err != nil {
		t.Fatalf("GetWorkflow: %v", err)
	}

	// Mutate the returned copy.
	wf.Name = "MUTATED"
	wf.Status = StatusFailed

	// Fetch again — should be unmodified.
	original, err := e.GetWorkflow(ctx, "wf-001")
	if err != nil {
		t.Fatalf("GetWorkflow (second): %v", err)
	}
	if original.Name == "MUTATED" {
		t.Error("mutation of returned workflow leaked into store")
	}
	if original.Status == StatusFailed {
		t.Error("status mutation leaked into store")
	}
}

func TestCopyIsolation_StartWorkflow(t *testing.T) {
	e := newMemoryEngine()
	ctx := context.Background()

	wf := &Workflow{
		ID:        "iso-start",
		Name:      "Isolation Start",
		Type:      TypeApproval,
		Priority:  3,
		Initiator: "test",
		Metadata:  map[string]string{"key": "value"},
	}
	created, err := e.StartWorkflow(ctx, wf)
	if err != nil {
		t.Fatalf("StartWorkflow: %v", err)
	}

	// Mutate returned copy.
	created.Metadata["key"] = "MUTATED"

	// Fetch — should retain original.
	fetched, err := e.GetWorkflow(ctx, "iso-start")
	if err != nil {
		t.Fatalf("GetWorkflow: %v", err)
	}
	if fetched.Metadata["key"] != "value" {
		t.Errorf("metadata mutation leaked: got %q", fetched.Metadata["key"])
	}
}
