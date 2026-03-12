package workflow

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestMemoryEngine_ListWorkflows_ReturnsSeedData(t *testing.T) {
	e := newMemoryEngine()
	wfs, err := e.ListWorkflows(context.Background())
	if err != nil {
		t.Fatalf("ListWorkflows: unexpected error: %v", err)
	}
	if len(wfs) < 5 {
		t.Errorf("expected at least 5 seed workflows, got %d", len(wfs))
	}
}

func TestMemoryEngine_ListWorkflows_SortedDescending(t *testing.T) {
	e := newMemoryEngine()
	wfs, err := e.ListWorkflows(context.Background())
	if err != nil {
		t.Fatalf("ListWorkflows: unexpected error: %v", err)
	}
	for i := 1; i < len(wfs); i++ {
		if wfs[i].CreatedAt.After(wfs[i-1].CreatedAt) {
			t.Errorf("results not sorted by CreatedAt desc at index %d", i)
		}
	}
}

func TestMemoryEngine_GetWorkflow_HappyPath(t *testing.T) {
	e := newMemoryEngine()
	wf, err := e.GetWorkflow(context.Background(), "wf-001")
	if err != nil {
		t.Fatalf("GetWorkflow: unexpected error: %v", err)
	}
	if wf.ID != "wf-001" {
		t.Errorf("expected ID wf-001, got %q", wf.ID)
	}
	if wf.Name != "Critical CVE Remediation" {
		t.Errorf("unexpected name: %q", wf.Name)
	}
	if wf.Type != TypeRemediation {
		t.Errorf("expected type %q, got %q", TypeRemediation, wf.Type)
	}
	if wf.Status != StatusPending {
		t.Errorf("expected status pending, got %q", wf.Status)
	}
	if wf.Priority != 1 {
		t.Errorf("expected priority 1, got %d", wf.Priority)
	}
	if len(wf.Steps) != 5 {
		t.Errorf("expected 5 steps, got %d", len(wf.Steps))
	}
}

func TestMemoryEngine_GetWorkflow_NotFound(t *testing.T) {
	e := newMemoryEngine()
	_, err := e.GetWorkflow(context.Background(), "does-not-exist")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestMemoryEngine_StartWorkflow_CreatesNew(t *testing.T) {
	e := newMemoryEngine()
	newWF := &Workflow{
		ID:        "wf-new",
		Name:      "Test Workflow",
		Type:      TypeApproval,
		Initiator: "test-user",
	}
	created, err := e.StartWorkflow(context.Background(), newWF)
	if err != nil {
		t.Fatalf("StartWorkflow: unexpected error: %v", err)
	}
	if created.Status != StatusPending {
		t.Errorf("expected status pending, got %q", created.Status)
	}
	if created.CreatedAt.IsZero() {
		t.Error("CreatedAt must not be zero")
	}
	if created.UpdatedAt.IsZero() {
		t.Error("UpdatedAt must not be zero")
	}

	// Verify it appears in list.
	wfs, err := e.ListWorkflows(context.Background())
	if err != nil {
		t.Fatalf("ListWorkflows after start: %v", err)
	}
	found := false
	for _, wf := range wfs {
		if wf.ID == "wf-new" {
			found = true
			break
		}
	}
	if !found {
		t.Error("newly started workflow not found in list")
	}
}

func TestMemoryEngine_StartWorkflow_EmptyID_Error(t *testing.T) {
	e := newMemoryEngine()
	_, err := e.StartWorkflow(context.Background(), &Workflow{Name: "No ID"})
	if err == nil {
		t.Error("expected error for empty ID, got nil")
	}
}

func TestMemoryEngine_StartWorkflow_EmptyName_Error(t *testing.T) {
	e := newMemoryEngine()
	_, err := e.StartWorkflow(context.Background(), &Workflow{ID: "wf-x"})
	if err == nil {
		t.Error("expected error for empty Name, got nil")
	}
}

func TestMemoryEngine_CancelWorkflow_Pending(t *testing.T) {
	e := newMemoryEngine()
	// wf-001 is seeded as pending.
	if err := e.CancelWorkflow(context.Background(), "wf-001"); err != nil {
		t.Fatalf("CancelWorkflow: unexpected error: %v", err)
	}
	wf, err := e.GetWorkflow(context.Background(), "wf-001")
	if err != nil {
		t.Fatalf("GetWorkflow after cancel: %v", err)
	}
	if wf.Status != StatusCancelled {
		t.Errorf("expected cancelled, got %q", wf.Status)
	}
}

func TestMemoryEngine_CancelWorkflow_Completed_Error(t *testing.T) {
	e := newMemoryEngine()
	// wf-003 is seeded as completed.
	err := e.CancelWorkflow(context.Background(), "wf-003")
	if err == nil {
		t.Error("expected error cancelling a completed workflow, got nil")
	}
}

func TestMemoryEngine_CancelWorkflow_NotFound(t *testing.T) {
	e := newMemoryEngine()
	err := e.CancelWorkflow(context.Background(), "no-such-wf")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestMemoryEngine_ApproveWorkflow_AdvancesState(t *testing.T) {
	e := newMemoryEngine()
	// wf-001 is seeded as pending.
	approved, err := e.ApproveWorkflow(context.Background(), "wf-001", "admin@example.com")
	if err != nil {
		t.Fatalf("ApproveWorkflow: unexpected error: %v", err)
	}
	if approved.Status != StatusCompleted {
		t.Errorf("expected completed, got %q", approved.Status)
	}
	if approved.Assignee != "admin@example.com" {
		t.Errorf("expected assignee admin@example.com, got %q", approved.Assignee)
	}
	if approved.CompletedAt == nil {
		t.Error("expected CompletedAt to be set")
	}
	for i, step := range approved.Steps {
		if step.Status != StatusCompleted {
			t.Errorf("step[%d] %q: expected completed, got %q", i, step.Name, step.Status)
		}
		if step.CompletedAt == nil {
			t.Errorf("step[%d] %q: CompletedAt must be set", i, step.Name)
		}
	}
}

func TestMemoryEngine_ApproveWorkflow_NotPending_Error(t *testing.T) {
	e := newMemoryEngine()
	// wf-002 is seeded as running, wf-003 as completed.
	for _, id := range []string{"wf-002", "wf-003"} {
		_, err := e.ApproveWorkflow(context.Background(), id, "approver@example.com")
		if err == nil {
			t.Errorf("expected error approving workflow %q in non-pending state, got nil", id)
		}
	}
}

func TestNewEngine_InvalidProvider(t *testing.T) {
	_, err := NewEngine("invalid-provider")
	if err == nil {
		t.Fatal("expected error for invalid provider, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("expected error message to contain 'unsupported', got: %v", err)
	}
}
