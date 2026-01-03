// Package workflow provides Temporal workflow orchestration for CloudForge
package workflow

import (
	"fmt"
	"time"

	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

const (
	ExceptionWorkflowTaskQueue = "cloudforge-exceptions"
	ProvisioningTaskQueue      = "cloudforge-provisioning"
)

// TemporalClient wraps the Temporal SDK client
type TemporalClient struct {
	client client.Client
}

// NewTemporalClient creates a new Temporal client
func NewTemporalClient(hostPort string) (*TemporalClient, error) {
	c, err := client.Dial(client.Options{
		HostPort: hostPort,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create temporal client: %w", err)
	}
	return &TemporalClient{client: c}, nil
}

// Close closes the Temporal client connection
func (t *TemporalClient) Close() {
	t.client.Close()
}

// ExceptionWorkflowInput contains the input for exception approval workflow
type ExceptionWorkflowInput struct {
	ExceptionID       string
	ApplicationID     string
	PolicyCode        string
	RequestedBy       string
	Justification     string
	RequestedDays     int
	RequiredApprovers []string
}

// ExceptionWorkflowResult contains the result of exception approval workflow
type ExceptionWorkflowResult struct {
	Approved     bool
	ApprovedBy   []string
	DeniedBy     string
	DenialReason string
	CompletedAt  time.Time
}

// ExceptionApprovalWorkflow orchestrates the multi-level approval process
func ExceptionApprovalWorkflow(ctx workflow.Context, input ExceptionWorkflowInput) (*ExceptionWorkflowResult, error) {
	logger := workflow.GetLogger(ctx)
	logger.Info("Starting exception approval workflow", "exceptionID", input.ExceptionID)

	// Retry policy for activities
	retryPolicy := &temporal.RetryPolicy{
		InitialInterval:    time.Second,
		BackoffCoefficient: 2.0,
		MaximumInterval:    time.Minute,
		MaximumAttempts:    3,
	}

	activityOptions := workflow.ActivityOptions{
		StartToCloseTimeout: 5 * time.Minute,
		RetryPolicy:         retryPolicy,
	}
	ctx = workflow.WithActivityOptions(ctx, activityOptions)

	result := &ExceptionWorkflowResult{
		ApprovedBy: make([]string, 0),
	}

	// Step 1: AI Risk Assessment
	var riskScore float64
	err := workflow.ExecuteActivity(ctx, PerformAIRiskAssessment, input).Get(ctx, &riskScore)
	if err != nil {
		logger.Error("AI risk assessment failed", "error", err)
		// Continue without AI assessment - non-blocking
	}

	// Step 2: Validate against OPA policies
	var policyResult PolicyValidationResult
	err = workflow.ExecuteActivity(ctx, ValidatePolicies, input).Get(ctx, &policyResult)
	if err != nil {
		return nil, fmt.Errorf("policy validation failed: %w", err)
	}

	if !policyResult.ExceptionAllowed {
		result.Approved = false
		result.DenialReason = "Policy does not allow exceptions for this control"
		result.CompletedAt = workflow.Now(ctx)
		return result, nil
	}

	// Step 3: Request approvals from each required approver
	approvalTimeout := 7 * 24 * time.Hour // 7 days
	approvalChannel := workflow.GetSignalChannel(ctx, "approval-signal")

	for _, approver := range input.RequiredApprovers {
		// Send notification to approver
		err := workflow.ExecuteActivity(ctx, NotifyApprover, NotifyApproverInput{
			ExceptionID:   input.ExceptionID,
			ApproverEmail: approver,
			RequestedBy:   input.RequestedBy,
			PolicyCode:    input.PolicyCode,
			Justification: input.Justification,
			RiskScore:     riskScore,
		}).Get(ctx, nil)
		if err != nil {
			logger.Warn("Failed to notify approver", "approver", approver, "error", err)
		}
	}

	// Wait for all approvals or timeout
	pendingApprovers := make(map[string]bool)
	for _, a := range input.RequiredApprovers {
		pendingApprovers[a] = true
	}

	timeoutCtx, cancelTimeout := workflow.WithCancel(ctx)
	defer cancelTimeout()

	timerFuture := workflow.NewTimer(timeoutCtx, approvalTimeout)

	for len(pendingApprovers) > 0 {
		selector := workflow.NewSelector(ctx)

		selector.AddReceive(approvalChannel, func(c workflow.ReceiveChannel, more bool) {
			var signal ApprovalSignal
			c.Receive(ctx, &signal)

			if pendingApprovers[signal.ApproverEmail] {
				if signal.Approved {
					result.ApprovedBy = append(result.ApprovedBy, signal.ApproverEmail)
					delete(pendingApprovers, signal.ApproverEmail)
				} else {
					result.Approved = false
					result.DeniedBy = signal.ApproverEmail
					result.DenialReason = signal.Reason
					result.CompletedAt = workflow.Now(ctx)
					// Clear pending to exit loop
					pendingApprovers = make(map[string]bool)
				}
			}
		})

		selector.AddFuture(timerFuture, func(f workflow.Future) {
			result.Approved = false
			result.DenialReason = "Approval timeout - required approvals not received within 7 days"
			result.CompletedAt = workflow.Now(ctx)
			pendingApprovers = make(map[string]bool)
		})

		selector.Select(ctx)

		if result.DeniedBy != "" || result.DenialReason != "" {
			break
		}
	}

	// All approvers approved
	if len(result.ApprovedBy) == len(input.RequiredApprovers) {
		result.Approved = true
		result.CompletedAt = workflow.Now(ctx)

		// Step 4: Record approval in GRC system
		err := workflow.ExecuteActivity(ctx, RecordApprovalInGRC, RecordApprovalInput{
			ExceptionID: input.ExceptionID,
			ApprovedBy:  result.ApprovedBy,
			ApprovedAt:  result.CompletedAt,
		}).Get(ctx, nil)
		if err != nil {
			logger.Error("Failed to record approval in GRC", "error", err)
			// Non-blocking - approval still valid
		}
	}

	return result, nil
}

// ApprovalSignal represents an approval decision from an approver
type ApprovalSignal struct {
	ApproverEmail string
	Approved      bool
	Reason        string
}

// PolicyValidationResult contains the result of OPA policy validation
type PolicyValidationResult struct {
	ExceptionAllowed bool
	Violations       []string
	Warnings         []string
}

// NotifyApproverInput contains input for approver notification
type NotifyApproverInput struct {
	ExceptionID   string
	ApproverEmail string
	RequestedBy   string
	PolicyCode    string
	Justification string
	RiskScore     float64
}

// RecordApprovalInput contains input for GRC recording
type RecordApprovalInput struct {
	ExceptionID string
	ApprovedBy  []string
	ApprovedAt  time.Time
}

// ProvisioningWorkflowInput contains input for infrastructure provisioning
type ProvisioningWorkflowInput struct {
	RequestID     string
	ApplicationID string
	ResourceType  string
	CloudProvider string
	Configuration map[string]interface{}
	RequestedBy   string
}

// ProvisioningWorkflowResult contains the result of provisioning
type ProvisioningWorkflowResult struct {
	Success       bool
	ResourceID    string
	ResourceARN   string
	ErrorMessage  string
	ProvisionedAt time.Time
}

// ProvisioningWorkflow orchestrates infrastructure provisioning with policy checks
func ProvisioningWorkflow(ctx workflow.Context, input ProvisioningWorkflowInput) (*ProvisioningWorkflowResult, error) {
	logger := workflow.GetLogger(ctx)
	logger.Info("Starting provisioning workflow", "requestID", input.RequestID)

	retryPolicy := &temporal.RetryPolicy{
		InitialInterval:    time.Second,
		BackoffCoefficient: 2.0,
		MaximumInterval:    time.Minute,
		MaximumAttempts:    3,
	}

	activityOptions := workflow.ActivityOptions{
		StartToCloseTimeout: 30 * time.Minute,
		RetryPolicy:         retryPolicy,
	}
	ctx = workflow.WithActivityOptions(ctx, activityOptions)

	result := &ProvisioningWorkflowResult{}

	// Step 1: Validate against OPA policies
	var policyResult OPAPolicyResult
	err := workflow.ExecuteActivity(ctx, EvaluateOPAPolicies, input).Get(ctx, &policyResult)
	if err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("Policy evaluation failed: %v", err)
		return result, nil
	}

	if !policyResult.Allowed {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("Policy violations: %v", policyResult.Denials)
		return result, nil
	}

	// Step 2: Check for required exceptions
	for _, warning := range policyResult.Warnings {
		var hasException bool
		err := workflow.ExecuteActivity(ctx, CheckException, CheckExceptionInput{
			ApplicationID: input.ApplicationID,
			PolicyCode:    warning,
		}).Get(ctx, &hasException)
		if err != nil || !hasException {
			result.Success = false
			result.ErrorMessage = fmt.Sprintf("Required exception not found for: %s", warning)
			return result, nil
		}
	}

	// Step 3: Run Terraform plan
	var planResult TerraformPlanResult
	err = workflow.ExecuteActivity(ctx, RunTerraformPlan, input).Get(ctx, &planResult)
	if err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("Terraform plan failed: %v", err)
		return result, nil
	}

	// Step 4: Run Terraform apply
	var applyResult TerraformApplyResult
	err = workflow.ExecuteActivity(ctx, RunTerraformApply, input).Get(ctx, &applyResult)
	if err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("Terraform apply failed: %v", err)
		return result, nil
	}

	// Step 5: Update CMDB
	err = workflow.ExecuteActivity(ctx, UpdateCMDB, UpdateCMDBInput{
		ApplicationID: input.ApplicationID,
		ResourceID:    applyResult.ResourceID,
		ResourceType:  input.ResourceType,
		CloudProvider: input.CloudProvider,
	}).Get(ctx, nil)
	if err != nil {
		logger.Warn("Failed to update CMDB", "error", err)
		// Non-blocking
	}

	result.Success = true
	result.ResourceID = applyResult.ResourceID
	result.ResourceARN = applyResult.ResourceARN
	result.ProvisionedAt = workflow.Now(ctx)

	return result, nil
}

// OPAPolicyResult contains OPA evaluation result
type OPAPolicyResult struct {
	Allowed  bool
	Denials  []string
	Warnings []string
}

// CheckExceptionInput contains input for exception check
type CheckExceptionInput struct {
	ApplicationID string
	PolicyCode    string
}

// TerraformPlanResult contains Terraform plan result
type TerraformPlanResult struct {
	PlanFile     string
	AddCount     int
	ChangeCount  int
	DestroyCount int
}

// TerraformApplyResult contains Terraform apply result
type TerraformApplyResult struct {
	ResourceID  string
	ResourceARN string
	Outputs     map[string]string
}

// UpdateCMDBInput contains input for CMDB update
type UpdateCMDBInput struct {
	ApplicationID string
	ResourceID    string
	ResourceType  string
	CloudProvider string
}
