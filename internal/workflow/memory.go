package workflow

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

type memoryEngine struct {
	mu        sync.RWMutex
	workflows map[string]*Workflow
}

func newMemoryEngine() *memoryEngine {
	e := &memoryEngine{
		workflows: make(map[string]*Workflow),
	}
	e.seed()
	return e
}

func copyWorkflow(wf *Workflow) *Workflow {
	cp := *wf
	cp.Steps = make([]Step, len(wf.Steps))
	copy(cp.Steps, wf.Steps)
	if wf.Metadata != nil {
		cp.Metadata = make(map[string]string, len(wf.Metadata))
		for k, v := range wf.Metadata {
			cp.Metadata[k] = v
		}
	}
	if wf.CompletedAt != nil {
		t := *wf.CompletedAt
		cp.CompletedAt = &t
	}
	return &cp
}

func (e *memoryEngine) StartWorkflow(_ context.Context, wf *Workflow) (*Workflow, error) {
	if wf.ID == "" {
		return nil, fmt.Errorf("workflow ID must not be empty")
	}
	if wf.Name == "" {
		return nil, fmt.Errorf("workflow Name must not be empty")
	}
	now := time.Now()
	wf.Status = StatusPending
	wf.CreatedAt = now
	wf.UpdatedAt = now

	stored := copyWorkflow(wf)
	e.mu.Lock()
	e.workflows[wf.ID] = stored
	e.mu.Unlock()

	return copyWorkflow(wf), nil
}

func (e *memoryEngine) GetWorkflow(_ context.Context, id string) (*Workflow, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	wf, ok := e.workflows[id]
	if !ok {
		return nil, ErrNotFound
	}
	return copyWorkflow(wf), nil
}

func (e *memoryEngine) ListWorkflows(_ context.Context) ([]*Workflow, error) {
	e.mu.RLock()
	result := make([]*Workflow, 0, len(e.workflows))
	for _, wf := range e.workflows {
		result = append(result, copyWorkflow(wf))
	}
	e.mu.RUnlock()

	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})
	return result, nil
}

func (e *memoryEngine) CancelWorkflow(_ context.Context, id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	wf, ok := e.workflows[id]
	if !ok {
		return ErrNotFound
	}
	if wf.Status != StatusPending && wf.Status != StatusRunning {
		return fmt.Errorf("cannot cancel workflow in %s state", wf.Status)
	}
	wf.Status = StatusCancelled
	wf.UpdatedAt = time.Now()
	return nil
}

func (e *memoryEngine) ApproveWorkflow(_ context.Context, id, approver string) (*Workflow, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	wf, ok := e.workflows[id]
	if !ok {
		return nil, ErrNotFound
	}
	if wf.Status != StatusPending {
		return nil, fmt.Errorf("cannot approve workflow in %s state", wf.Status)
	}

	now := time.Now()
	wf.Status = StatusRunning
	wf.Assignee = approver

	// Mark first step as running.
	if len(wf.Steps) > 0 {
		wf.Steps[0].Status = StatusRunning
		t := now
		wf.Steps[0].StartedAt = &t
	}

	// Simulate completion: advance all steps and mark workflow completed.
	for i := range wf.Steps {
		wf.Steps[i].Status = StatusCompleted
		if wf.Steps[i].Output == "" {
			wf.Steps[i].Output = fmt.Sprintf("Step %s completed successfully", wf.Steps[i].Name)
		}
		if wf.Steps[i].StartedAt == nil {
			t := now
			wf.Steps[i].StartedAt = &t
		}
		t := now
		wf.Steps[i].CompletedAt = &t
	}

	wf.Status = StatusCompleted
	wf.UpdatedAt = now
	wf.CompletedAt = &now

	return copyWorkflow(wf), nil
}

func (e *memoryEngine) seed() {
	now := time.Now()
	demos := []*Workflow{
		{
			ID: "wf-001", Name: "Critical CVE Remediation",
			Type: TypeRemediation, Status: StatusPending, Priority: 1,
			Initiator:   "security-scanner",
			Description: "Remediate CVE-2024-21626 across production containers",
			Steps: []Step{
				{ID: "s1", Name: "Identify Affected Assets", Status: StatusCompleted, Output: "12 containers identified"},
				{ID: "s2", Name: "Generate Patches", Status: StatusCompleted, Output: "Patches generated for runc v1.1.12"},
				{ID: "s3", Name: "Approval Gate", Status: StatusPending},
				{ID: "s4", Name: "Rolling Deployment", Status: StatusPending},
				{ID: "s5", Name: "Verification Scan", Status: StatusPending},
			},
			CreatedAt: now.Add(-2 * time.Hour), UpdatedAt: now.Add(-30 * time.Minute),
		},
		{
			ID: "wf-002", Name: "Quarterly Access Review",
			Type: TypeAccessReview, Status: StatusRunning, Priority: 3,
			Initiator: "compliance-engine", Assignee: "alice@example.com",
			Description: "Review and certify access rights for Q1 2026",
			Steps: []Step{
				{ID: "s1", Name: "Collect Access Data", Status: StatusCompleted, Output: "847 entitlements collected"},
				{ID: "s2", Name: "Manager Review", Status: StatusRunning},
				{ID: "s3", Name: "Revoke Stale Access", Status: StatusPending},
				{ID: "s4", Name: "Generate Report", Status: StatusPending},
			},
			CreatedAt: now.Add(-24 * time.Hour), UpdatedAt: now.Add(-1 * time.Hour),
		},
		{
			ID: "wf-003", Name: "SOC2 Compliance Scan",
			Type: TypeComplianceScan, Status: StatusCompleted, Priority: 2,
			Initiator: "compliance-engine", Assignee: "bob@example.com",
			Description: "Automated SOC2 Type II evidence collection",
			Steps: []Step{
				{ID: "s1", Name: "Scan Infrastructure", Status: StatusCompleted, Output: "342 resources scanned"},
				{ID: "s2", Name: "Evaluate Controls", Status: StatusCompleted, Output: "96% control coverage"},
				{ID: "s3", Name: "Generate Evidence", Status: StatusCompleted, Output: "Evidence package created"},
			},
			CreatedAt: now.Add(-48 * time.Hour), UpdatedAt: now.Add(-24 * time.Hour),
		},
		{
			ID: "wf-004", Name: "Emergency WAF Rule Deployment",
			Type: TypeIncidentResponse, Status: StatusFailed, Priority: 1,
			Initiator: "soc-team", Assignee: "carol@example.com",
			Description: "Deploy emergency WAF rules for active exploitation of Log4Shell variant",
			Steps: []Step{
				{ID: "s1", Name: "Rule Generation", Status: StatusCompleted, Output: "3 rules generated"},
				{ID: "s2", Name: "Validation", Status: StatusCompleted, Output: "Rules validated against test traffic"},
				{ID: "s3", Name: "Deployment", Status: StatusFailed, Output: "Deployment failed: WAF capacity limit reached"},
			},
			CreatedAt: now.Add(-72 * time.Hour), UpdatedAt: now.Add(-71 * time.Hour),
		},
		{
			ID: "wf-005", Name: "Service Account Key Rotation",
			Type: TypeApproval, Status: StatusPending, Priority: 2,
			Initiator:   "secrets-manager",
			Description: "Rotate 15 service account keys expiring within 30 days",
			Steps: []Step{
				{ID: "s1", Name: "Identify Expiring Keys", Status: StatusCompleted, Output: "15 keys identified across 3 providers"},
				{ID: "s2", Name: "Security Review", Status: StatusPending},
				{ID: "s3", Name: "Rotate Keys", Status: StatusPending},
				{ID: "s4", Name: "Update Consumers", Status: StatusPending},
				{ID: "s5", Name: "Verify Connectivity", Status: StatusPending},
			},
			CreatedAt: now.Add(-6 * time.Hour), UpdatedAt: now.Add(-6 * time.Hour),
		},
	}
	for _, wf := range demos {
		e.workflows[wf.ID] = wf
	}
}
