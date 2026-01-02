package grc

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MemoryGRCProvider is a simple in-memory implementation for testing and demos.
// NOT for production use - no persistence, no high availability.
type MemoryGRCProvider struct {
	mu         sync.RWMutex
	exceptions map[string]*ExceptionRequest
}

// NewMemoryGRCProvider creates a new in-memory GRC provider.
func NewMemoryGRCProvider() *MemoryGRCProvider {
	return &MemoryGRCProvider{
		exceptions: make(map[string]*ExceptionRequest),
	}
}

// CreateException creates a new exception in memory.
func (m *MemoryGRCProvider) CreateException(
	ctx context.Context,
	req *ExceptionRequest,
) (*ExceptionRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	req.ID = uuid.New().String()
	req.Status = StatusPending
	req.CreatedAt = time.Now()
	req.UpdatedAt = time.Now()

	m.exceptions[req.ID] = req

	return req, nil
}

// GetException retrieves an exception by ID.
func (m *MemoryGRCProvider) GetException(ctx context.Context, id string) (*ExceptionRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if exc, ok := m.exceptions[id]; ok {
		return exc, nil
	}
	return nil, fmt.Errorf("exception %s not found", id)
}

// UpdateException updates an existing exception.
func (m *MemoryGRCProvider) UpdateException(ctx context.Context, req *ExceptionRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.exceptions[req.ID]; !ok {
		return fmt.Errorf("exception %s not found", req.ID)
	}

	req.UpdatedAt = time.Now()
	m.exceptions[req.ID] = req

	return nil
}

// ValidateException checks if a valid exception exists for the given application and policy.
func (m *MemoryGRCProvider) ValidateException(
	ctx context.Context,
	applicationID, policyCode string,
) (*ExceptionValidation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, exc := range m.exceptions {
		if exc.ApplicationID == applicationID &&
			exc.PolicyViolated == policyCode &&
			exc.Status == StatusApproved {

			// Check expiration
			if exc.ExpirationDate != nil && exc.ExpirationDate.Before(time.Now()) {
				continue
			}

			return &ExceptionValidation{
				Valid:       true,
				ExceptionID: exc.ID,
				ExpiresAt:   exc.ExpirationDate,
			}, nil
		}
	}

	return &ExceptionValidation{
		Valid:  false,
		Reason: fmt.Sprintf("No approved exception for policy %s", policyCode),
	}, nil
}

// SubmitApproval records an approver's decision.
func (m *MemoryGRCProvider) SubmitApproval(
	ctx context.Context,
	exceptionID string,
	approver Approver,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	exc, ok := m.exceptions[exceptionID]
	if !ok {
		return fmt.Errorf("exception %s not found", exceptionID)
	}

	// Find approver in chain and update
	for i := range exc.ApproverChain {
		if exc.ApproverChain[i].Email == approver.Email {
			now := time.Now()
			exc.ApproverChain[i].Decision = approver.Decision
			exc.ApproverChain[i].Comments = approver.Comments
			exc.ApproverChain[i].DecidedAt = &now
			break
		}
	}

	// Check if all approvers have approved
	allApproved := true
	anyRejected := false
	for _, a := range exc.ApproverChain {
		if a.Decision == "" {
			allApproved = false
		}
		if a.Decision == StatusRejected {
			anyRejected = true
		}
	}

	if anyRejected {
		exc.Status = StatusRejected
	} else if allApproved {
		exc.Status = StatusApproved
	}

	exc.UpdatedAt = time.Now()

	return nil
}

// GetPendingApprovals returns exceptions awaiting approval from the given user.
func (m *MemoryGRCProvider) GetPendingApprovals(
	ctx context.Context,
	approverEmail string,
) ([]ExceptionRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var pending []ExceptionRequest

	for _, exc := range m.exceptions {
		if exc.Status != StatusPending {
			continue
		}
		for _, a := range exc.ApproverChain {
			if a.Email == approverEmail && a.Decision == "" {
				pending = append(pending, *exc)
				break
			}
		}
	}

	return pending, nil
}

// GetExceptionsByApplication returns all exceptions for an application.
func (m *MemoryGRCProvider) GetExceptionsByApplication(
	ctx context.Context,
	appID string,
) ([]ExceptionRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var results []ExceptionRequest
	for _, exc := range m.exceptions {
		if exc.ApplicationID == appID {
			results = append(results, *exc)
		}
	}

	return results, nil
}

// GetExpiringExceptions returns approved exceptions expiring within the given days.
func (m *MemoryGRCProvider) GetExpiringExceptions(
	ctx context.Context,
	withinDays int,
) ([]ExceptionRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cutoff := time.Now().AddDate(0, 0, withinDays)
	var expiring []ExceptionRequest

	for _, exc := range m.exceptions {
		if exc.Status == StatusApproved &&
			exc.ExpirationDate != nil &&
			exc.ExpirationDate.Before(cutoff) {
			expiring = append(expiring, *exc)
		}
	}

	return expiring, nil
}

// SeedTestData adds sample exceptions for demo purposes.
func (m *MemoryGRCProvider) SeedTestData() {
	now := time.Now()
	exp := now.AddDate(0, 3, 0) // 3 months from now
	decided := now.Add(-24 * time.Hour)

	m.exceptions["test-exc-001"] = &ExceptionRequest{
		ID:                "test-exc-001",
		ApplicationID:     "APP-001",
		RequestorEmail:    "developer@example.com",
		RequestType:       ExceptionTypeRegion,
		PolicyViolated:    "REGION-001",
		ResourceRequested: "us-west-2 deployment",
		BusinessCase:      "Disaster recovery requires secondary region",
		Status:            StatusApproved,
		ExpirationDate:    &exp,
		CreatedAt:         now.Add(-48 * time.Hour),
		UpdatedAt:         now.Add(-24 * time.Hour),
		ApproverChain: []Approver{
			{
				Email:     "security-lead@example.com",
				Role:      "SECURITY_LEAD",
				Decision:  StatusApproved,
				Comments:  "Approved with compensating controls",
				DecidedAt: &decided,
			},
		},
		RiskAssessment: &RiskAssessment{
			RiskLevel:    "MEDIUM",
			Impact:       "Limited data exposure in secondary region",
			Likelihood:   "Low",
			ResidualRisk: "Acceptable with encryption controls",
			AssessedBy:   "grc-analyst@example.com",
			AssessedAt:   now.Add(-36 * time.Hour),
		},
		CompensatingCtrls: []string{
			"Enable encryption at rest for all resources",
			"Implement VPC peering with no public endpoints",
			"Enable CloudTrail logging with 90-day retention",
		},
	}

	m.exceptions["test-exc-002"] = &ExceptionRequest{
		ID:                "test-exc-002",
		ApplicationID:     "APP-002",
		RequestorEmail:    "sre@example.com",
		RequestType:       ExceptionTypeInstanceSize,
		PolicyViolated:    "COST-001",
		ResourceRequested: "m6i.16xlarge for ML training",
		BusinessCase:      "ML model training requires high memory instance for monthly batch job",
		Status:            StatusPending,
		CreatedAt:         now.Add(-2 * time.Hour),
		UpdatedAt:         now.Add(-2 * time.Hour),
		ApproverChain: []Approver{
			{
				Email: "finance@example.com",
				Role:  "FINANCE_APPROVER",
			},
			{
				Email: "platform-lead@example.com",
				Role:  "PLATFORM_LEAD",
			},
		},
	}
}
