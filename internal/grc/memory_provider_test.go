package grc

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestMemoryGRCProvider_CreateException(t *testing.T) {
	provider := NewMemoryGRCProvider()
	ctx := context.Background()

	req := &ExceptionRequest{
		ApplicationID:     "APP-001",
		RequestorEmail:    "dev@example.com",
		RequestType:       ExceptionTypeRegion,
		PolicyViolated:    "REGION-001",
		ResourceRequested: "us-west-2",
		BusinessCase:      "DR requirement",
	}

	result, err := provider.CreateException(ctx, req)
	if err != nil {
		t.Fatalf("CreateException failed: %v", err)
	}

	if result.ID == "" {
		t.Error("expected non-empty ID")
	}
	if result.Status != StatusPending {
		t.Errorf("expected status PENDING, got %s", result.Status)
	}
	if result.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be set")
	}
	if result.UpdatedAt.IsZero() {
		t.Error("expected UpdatedAt to be set")
	}
}

func TestMemoryGRCProvider_GetException(t *testing.T) {
	provider := NewMemoryGRCProvider()
	ctx := context.Background()

	req := &ExceptionRequest{
		ApplicationID:  "APP-001",
		RequestorEmail: "dev@example.com",
		PolicyViolated: "REGION-001",
	}

	created, _ := provider.CreateException(ctx, req)

	// Test successful retrieval
	retrieved, err := provider.GetException(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetException failed: %v", err)
	}
	if retrieved.ApplicationID != req.ApplicationID {
		t.Errorf("expected ApplicationID %s, got %s", req.ApplicationID, retrieved.ApplicationID)
	}

	// Test not found
	_, err = provider.GetException(ctx, "nonexistent-id")
	if err == nil {
		t.Error("expected error for nonexistent exception")
	}
}

func TestMemoryGRCProvider_UpdateException(t *testing.T) {
	provider := NewMemoryGRCProvider()
	ctx := context.Background()

	req := &ExceptionRequest{
		ApplicationID:  "APP-001",
		RequestorEmail: "dev@example.com",
		PolicyViolated: "REGION-001",
		BusinessCase:   "Original case",
	}

	created, _ := provider.CreateException(ctx, req)
	originalUpdatedAt := created.UpdatedAt

	// Wait a bit to ensure UpdatedAt changes
	time.Sleep(10 * time.Millisecond)

	created.BusinessCase = "Updated case"
	err := provider.UpdateException(ctx, created)
	if err != nil {
		t.Fatalf("UpdateException failed: %v", err)
	}

	retrieved, _ := provider.GetException(ctx, created.ID)
	if retrieved.BusinessCase != "Updated case" {
		t.Errorf("expected BusinessCase 'Updated case', got %s", retrieved.BusinessCase)
	}
	if !retrieved.UpdatedAt.After(originalUpdatedAt) {
		t.Error("expected UpdatedAt to be updated")
	}

	// Test update nonexistent
	nonexistent := &ExceptionRequest{ID: "nonexistent"}
	err = provider.UpdateException(ctx, nonexistent)
	if err == nil {
		t.Error("expected error for nonexistent exception update")
	}
}

func TestMemoryGRCProvider_ValidateException(t *testing.T) {
	provider := NewMemoryGRCProvider()
	ctx := context.Background()

	// Create approved exception
	future := time.Now().AddDate(0, 1, 0)
	req := &ExceptionRequest{
		ApplicationID:  "APP-001",
		PolicyViolated: "REGION-001",
		Status:         StatusApproved,
		ExpirationDate: &future,
	}
	provider.mu.Lock()
	req.ID = "test-1"
	provider.exceptions[req.ID] = req
	provider.mu.Unlock()

	// Test valid exception
	validation, err := provider.ValidateException(ctx, "APP-001", "REGION-001")
	if err != nil {
		t.Fatalf("ValidateException failed: %v", err)
	}
	if !validation.Valid {
		t.Error("expected valid exception")
	}
	if validation.ExceptionID != "test-1" {
		t.Errorf("expected ExceptionID test-1, got %s", validation.ExceptionID)
	}

	// Test no exception for policy
	validation, _ = provider.ValidateException(ctx, "APP-001", "OTHER-POLICY")
	if validation.Valid {
		t.Error("expected invalid for non-matching policy")
	}

	// Test expired exception
	past := time.Now().AddDate(0, 0, -1)
	expiredReq := &ExceptionRequest{
		ID:             "test-expired",
		ApplicationID:  "APP-002",
		PolicyViolated: "REGION-002",
		Status:         StatusApproved,
		ExpirationDate: &past,
	}
	provider.mu.Lock()
	provider.exceptions[expiredReq.ID] = expiredReq
	provider.mu.Unlock()

	validation, _ = provider.ValidateException(ctx, "APP-002", "REGION-002")
	if validation.Valid {
		t.Error("expected invalid for expired exception")
	}
}

func TestMemoryGRCProvider_SubmitApproval(t *testing.T) {
	provider := NewMemoryGRCProvider()
	ctx := context.Background()

	// Create exception with approval chain
	req := &ExceptionRequest{
		ApplicationID:  "APP-001",
		RequestorEmail: "dev@example.com",
		PolicyViolated: "REGION-001",
		ApproverChain: []Approver{
			{Email: "approver1@example.com", Role: "SECURITY_LEAD"},
			{Email: "approver2@example.com", Role: "GRC_ANALYST"},
		},
	}

	created, _ := provider.CreateException(ctx, req)

	// First approver approves
	approver1 := Approver{
		Email:    "approver1@example.com",
		Decision: StatusApproved,
		Comments: "Looks good",
	}

	err := provider.SubmitApproval(ctx, created.ID, approver1)
	if err != nil {
		t.Fatalf("SubmitApproval failed: %v", err)
	}

	retrieved, _ := provider.GetException(ctx, created.ID)
	if retrieved.Status != StatusPending {
		t.Errorf("expected status still PENDING, got %s", retrieved.Status)
	}

	// Second approver approves - should transition to APPROVED
	approver2 := Approver{
		Email:    "approver2@example.com",
		Decision: StatusApproved,
		Comments: "Agreed",
	}

	err = provider.SubmitApproval(ctx, created.ID, approver2)
	if err != nil {
		t.Fatalf("SubmitApproval failed: %v", err)
	}

	retrieved, _ = provider.GetException(ctx, created.ID)
	if retrieved.Status != StatusApproved {
		t.Errorf("expected status APPROVED, got %s", retrieved.Status)
	}

	// Test nonexistent exception
	err = provider.SubmitApproval(ctx, "nonexistent", approver1)
	if err == nil {
		t.Error("expected error for nonexistent exception")
	}
}

func TestMemoryGRCProvider_SubmitApproval_Rejection(t *testing.T) {
	provider := NewMemoryGRCProvider()
	ctx := context.Background()

	req := &ExceptionRequest{
		ApplicationID:  "APP-001",
		PolicyViolated: "REGION-001",
		ApproverChain: []Approver{
			{Email: "approver1@example.com", Role: "SECURITY_LEAD"},
			{Email: "approver2@example.com", Role: "GRC_ANALYST"},
		},
	}

	created, _ := provider.CreateException(ctx, req)

	// First approver rejects - should immediately set status to REJECTED
	rejector := Approver{
		Email:    "approver1@example.com",
		Decision: StatusRejected,
		Comments: "Risk too high",
	}

	provider.SubmitApproval(ctx, created.ID, rejector)

	retrieved, _ := provider.GetException(ctx, created.ID)
	if retrieved.Status != StatusRejected {
		t.Errorf("expected status REJECTED, got %s", retrieved.Status)
	}
}

func TestMemoryGRCProvider_GetPendingApprovals(t *testing.T) {
	provider := NewMemoryGRCProvider()
	ctx := context.Background()

	// Create exception awaiting approval
	req1 := &ExceptionRequest{
		ApplicationID:  "APP-001",
		PolicyViolated: "REGION-001",
		ApproverChain: []Approver{
			{Email: "approver@example.com", Role: "SECURITY_LEAD"},
		},
	}
	provider.CreateException(ctx, req1)

	// Create another exception with different approver
	req2 := &ExceptionRequest{
		ApplicationID:  "APP-002",
		PolicyViolated: "COST-001",
		ApproverChain: []Approver{
			{Email: "other@example.com", Role: "FINANCE"},
		},
	}
	provider.CreateException(ctx, req2)

	// Create approved exception (should not appear in pending)
	req3 := &ExceptionRequest{
		ApplicationID:  "APP-003",
		PolicyViolated: "SERVICE-001",
		Status:         StatusApproved,
		ApproverChain: []Approver{
			{Email: "approver@example.com", Role: "SECURITY_LEAD", Decision: StatusApproved},
		},
	}
	provider.mu.Lock()
	req3.ID = "approved-exception"
	provider.exceptions[req3.ID] = req3
	provider.mu.Unlock()

	pending, err := provider.GetPendingApprovals(ctx, "approver@example.com")
	if err != nil {
		t.Fatalf("GetPendingApprovals failed: %v", err)
	}

	if len(pending) != 1 {
		t.Errorf("expected 1 pending approval, got %d", len(pending))
	}

	if len(pending) > 0 && pending[0].ApplicationID != "APP-001" {
		t.Errorf("expected APP-001, got %s", pending[0].ApplicationID)
	}
}

func TestMemoryGRCProvider_GetExceptionsByApplication(t *testing.T) {
	provider := NewMemoryGRCProvider()
	ctx := context.Background()

	// Create multiple exceptions for same app
	for i := 0; i < 3; i++ {
		req := &ExceptionRequest{
			ApplicationID:  "APP-001",
			PolicyViolated: "POLICY-" + string(rune('A'+i)),
		}
		provider.CreateException(ctx, req)
	}

	// Create exception for different app
	provider.CreateException(ctx, &ExceptionRequest{
		ApplicationID:  "APP-002",
		PolicyViolated: "OTHER",
	})

	exceptions, err := provider.GetExceptionsByApplication(ctx, "APP-001")
	if err != nil {
		t.Fatalf("GetExceptionsByApplication failed: %v", err)
	}

	if len(exceptions) != 3 {
		t.Errorf("expected 3 exceptions, got %d", len(exceptions))
	}
}

func TestMemoryGRCProvider_GetExpiringExceptions(t *testing.T) {
	provider := NewMemoryGRCProvider()
	ctx := context.Background()

	now := time.Now()
	expIn10Days := now.AddDate(0, 0, 10)
	expIn60Days := now.AddDate(0, 0, 60)
	past := now.AddDate(0, 0, -5)

	// Exception expiring soon (within 30 days)
	soon := &ExceptionRequest{
		ID:             "exp-soon",
		ApplicationID:  "APP-001",
		Status:         StatusApproved,
		ExpirationDate: &expIn10Days,
	}

	// Exception expiring later (after 30 days)
	later := &ExceptionRequest{
		ID:             "exp-later",
		ApplicationID:  "APP-002",
		Status:         StatusApproved,
		ExpirationDate: &expIn60Days,
	}

	// Already expired
	expired := &ExceptionRequest{
		ID:             "already-expired",
		ApplicationID:  "APP-003",
		Status:         StatusApproved,
		ExpirationDate: &past,
	}

	// Pending (not approved)
	pending := &ExceptionRequest{
		ID:             "pending",
		ApplicationID:  "APP-004",
		Status:         StatusPending,
		ExpirationDate: &expIn10Days,
	}

	provider.mu.Lock()
	provider.exceptions["exp-soon"] = soon
	provider.exceptions["exp-later"] = later
	provider.exceptions["already-expired"] = expired
	provider.exceptions["pending"] = pending
	provider.mu.Unlock()

	expiring, err := provider.GetExpiringExceptions(ctx, 30)
	if err != nil {
		t.Fatalf("GetExpiringExceptions failed: %v", err)
	}

	// Should only return soon and already-expired (both before cutoff and approved)
	if len(expiring) != 2 {
		t.Errorf("expected 2 expiring exceptions, got %d", len(expiring))
	}

	// Verify the correct ones are returned
	ids := make(map[string]bool)
	for _, e := range expiring {
		ids[e.ID] = true
	}
	if !ids["exp-soon"] {
		t.Error("expected exp-soon in results")
	}
	if !ids["already-expired"] {
		t.Error("expected already-expired in results")
	}
}

func TestMemoryGRCProvider_SeedTestData(t *testing.T) {
	provider := NewMemoryGRCProvider()
	provider.SeedTestData()

	ctx := context.Background()

	// Verify seeded exceptions exist
	exc1, err := provider.GetException(ctx, "test-exc-001")
	if err != nil {
		t.Fatalf("expected seeded exception test-exc-001: %v", err)
	}
	if exc1.Status != StatusApproved {
		t.Errorf("expected StatusApproved, got %s", exc1.Status)
	}

	exc2, err := provider.GetException(ctx, "test-exc-002")
	if err != nil {
		t.Fatalf("expected seeded exception test-exc-002: %v", err)
	}
	if exc2.Status != StatusPending {
		t.Errorf("expected StatusPending, got %s", exc2.Status)
	}
}

func TestMemoryGRCProvider_Concurrency(t *testing.T) {
	provider := NewMemoryGRCProvider()
	ctx := context.Background()

	// Create base exception
	req := &ExceptionRequest{
		ApplicationID:  "APP-CONCURRENT",
		PolicyViolated: "REGION-001",
		ApproverChain: []Approver{
			{Email: "approver1@example.com"},
			{Email: "approver2@example.com"},
			{Email: "approver3@example.com"},
		},
	}
	created, _ := provider.CreateException(ctx, req)

	// Simulate concurrent approvals
	var wg sync.WaitGroup
	for i, email := range []string{"approver1@example.com", "approver2@example.com", "approver3@example.com"} {
		wg.Add(1)
		go func(email string, idx int) {
			defer wg.Done()
			approver := Approver{
				Email:    email,
				Decision: StatusApproved,
				Comments: "Concurrent approval",
			}
			provider.SubmitApproval(ctx, created.ID, approver)
		}(email, i)
	}

	wg.Wait()

	// All approvals submitted - should be approved
	retrieved, _ := provider.GetException(ctx, created.ID)
	if retrieved.Status != StatusApproved {
		t.Errorf("expected StatusApproved after concurrent approvals, got %s", retrieved.Status)
	}
}

func TestMemoryGRCProvider_ConcurrentReads(t *testing.T) {
	provider := NewMemoryGRCProvider()
	ctx := context.Background()

	// Seed some data
	for i := 0; i < 10; i++ {
		provider.CreateException(ctx, &ExceptionRequest{
			ApplicationID:  "APP-READ-TEST",
			PolicyViolated: "POLICY-" + string(rune('A'+i)),
		})
	}

	// Concurrent reads should not panic
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			provider.GetExceptionsByApplication(ctx, "APP-READ-TEST")
			provider.GetPendingApprovals(ctx, "anyone@example.com")
			provider.GetExpiringExceptions(ctx, 30)
		}()
	}
	wg.Wait()
}
