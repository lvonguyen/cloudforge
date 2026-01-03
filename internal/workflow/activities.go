// Package workflow provides Temporal activities for CloudForge
package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.temporal.io/sdk/activity"
)

// ActivityDependencies holds dependencies for activities
type ActivityDependencies struct {
	OPAEndpoint   string
	GRCEndpoint   string
	AIEndpoint    string
	SMTPHost      string
	TerraformPath string
	HTTPClient    *http.Client
}

// NewActivityDependencies creates activity dependencies with defaults
func NewActivityDependencies() *ActivityDependencies {
	return &ActivityDependencies{
		OPAEndpoint:   "http://localhost:8181",
		GRCEndpoint:   "http://localhost:8080",
		TerraformPath: "/usr/local/bin/terraform",
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// PerformAIRiskAssessment analyzes exception risk using AI
func (d *ActivityDependencies) PerformAIRiskAssessment(ctx context.Context, input ExceptionWorkflowInput) (float64, error) {
	logger := activity.GetLogger(ctx)
	logger.Info("Performing AI risk assessment", "exceptionID", input.ExceptionID)

	reqBody := map[string]interface{}{
		"exception_id":   input.ExceptionID,
		"application_id": input.ApplicationID,
		"policy_code":    input.PolicyCode,
		"justification":  input.Justification,
		"requested_days": input.RequestedDays,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("%s/api/v1/exceptions/%s/ai-analysis", d.GRCEndpoint, input.ExceptionID),
		bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.HTTPClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("AI analysis request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("AI analysis returned status %d", resp.StatusCode)
	}

	var result struct {
		RiskScore float64 `json:"risk_score"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("failed to decode response: %w", err)
	}

	return result.RiskScore, nil
}

// ValidatePolicies validates the exception against OPA policies
func (d *ActivityDependencies) ValidatePolicies(ctx context.Context, input ExceptionWorkflowInput) (*PolicyValidationResult, error) {
	logger := activity.GetLogger(ctx)
	logger.Info("Validating policies", "policyCode", input.PolicyCode)

	reqBody := map[string]interface{}{
		"input": map[string]interface{}{
			"application_id": input.ApplicationID,
			"policy_code":    input.PolicyCode,
			"requested_days": input.RequestedDays,
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("%s/v1/data/cloudforge/exception/allow", d.OPAEndpoint),
		bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OPA request failed: %w", err)
	}
	defer resp.Body.Close()

	var opaResp struct {
		Result bool `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&opaResp); err != nil {
		return nil, fmt.Errorf("failed to decode OPA response: %w", err)
	}

	return &PolicyValidationResult{
		ExceptionAllowed: opaResp.Result,
	}, nil
}

// NotifyApprover sends notification to approver
func (d *ActivityDependencies) NotifyApprover(ctx context.Context, input NotifyApproverInput) error {
	logger := activity.GetLogger(ctx)
	logger.Info("Notifying approver", "approver", input.ApproverEmail, "exceptionID", input.ExceptionID)

	// In production, this would send email via Microsoft Graph or SMTP
	// For demo, just log
	logger.Info("Would send email notification",
		"to", input.ApproverEmail,
		"subject", fmt.Sprintf("Exception Approval Required: %s", input.ExceptionID),
		"riskScore", input.RiskScore,
	)

	return nil
}

// RecordApprovalInGRC records the approval in the GRC system
func (d *ActivityDependencies) RecordApprovalInGRC(ctx context.Context, input RecordApprovalInput) error {
	logger := activity.GetLogger(ctx)
	logger.Info("Recording approval in GRC", "exceptionID", input.ExceptionID)

	reqBody := map[string]interface{}{
		"approved_by": input.ApprovedBy,
		"approved_at": input.ApprovedAt,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("%s/api/v1/exceptions/%s/approve", d.GRCEndpoint, input.ExceptionID),
		bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("GRC request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GRC returned status %d", resp.StatusCode)
	}

	return nil
}

// EvaluateOPAPolicies evaluates provisioning request against OPA
func (d *ActivityDependencies) EvaluateOPAPolicies(ctx context.Context, input ProvisioningWorkflowInput) (*OPAPolicyResult, error) {
	logger := activity.GetLogger(ctx)
	logger.Info("Evaluating OPA policies", "resourceType", input.ResourceType)

	reqBody := map[string]interface{}{
		"input": map[string]interface{}{
			"application_id": input.ApplicationID,
			"resource_type":  input.ResourceType,
			"cloud_provider": input.CloudProvider,
			"configuration":  input.Configuration,
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("%s/v1/data/cloudforge/provisioning", d.OPAEndpoint),
		bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OPA request failed: %w", err)
	}
	defer resp.Body.Close()

	var opaResp struct {
		Result struct {
			Allow    bool     `json:"allow"`
			Deny     []string `json:"deny"`
			Warnings []string `json:"warnings"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&opaResp); err != nil {
		return nil, fmt.Errorf("failed to decode OPA response: %w", err)
	}

	return &OPAPolicyResult{
		Allowed:  opaResp.Result.Allow,
		Denials:  opaResp.Result.Deny,
		Warnings: opaResp.Result.Warnings,
	}, nil
}

// CheckException checks if a valid exception exists
func (d *ActivityDependencies) CheckException(ctx context.Context, input CheckExceptionInput) (bool, error) {
	logger := activity.GetLogger(ctx)
	logger.Info("Checking exception", "applicationID", input.ApplicationID, "policyCode", input.PolicyCode)

	req, err := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("%s/api/v1/validate/exception", d.GRCEndpoint),
		nil)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	q := req.URL.Query()
	q.Add("application_id", input.ApplicationID)
	q.Add("policy_code", input.PolicyCode)
	req.URL.RawQuery = q.Encode()

	resp, err := d.HTTPClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("GRC request failed: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Valid bool `json:"valid"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("failed to decode response: %w", err)
	}

	return result.Valid, nil
}

// RunTerraformPlan runs terraform plan
func (d *ActivityDependencies) RunTerraformPlan(ctx context.Context, input ProvisioningWorkflowInput) (*TerraformPlanResult, error) {
	logger := activity.GetLogger(ctx)
	logger.Info("Running Terraform plan", "requestID", input.RequestID)

	// In production, this would:
	// 1. Generate tfvars from input.Configuration
	// 2. Run terraform init
	// 3. Run terraform plan -out=planfile
	// 4. Parse plan output for counts

	// For demo, return mock result
	return &TerraformPlanResult{
		PlanFile:     fmt.Sprintf("/tmp/plans/%s.tfplan", input.RequestID),
		AddCount:     3,
		ChangeCount:  0,
		DestroyCount: 0,
	}, nil
}

// RunTerraformApply runs terraform apply
func (d *ActivityDependencies) RunTerraformApply(ctx context.Context, input ProvisioningWorkflowInput) (*TerraformApplyResult, error) {
	logger := activity.GetLogger(ctx)
	logger.Info("Running Terraform apply", "requestID", input.RequestID)

	// In production, this would:
	// 1. Run terraform apply planfile
	// 2. Parse outputs
	// 3. Return resource IDs

	// For demo, return mock result
	resourceID := fmt.Sprintf("%s-%s-%d", input.CloudProvider, input.ResourceType, time.Now().Unix())
	return &TerraformApplyResult{
		ResourceID:  resourceID,
		ResourceARN: fmt.Sprintf("arn:aws:ec2:us-east-1:123456789012:%s/%s", input.ResourceType, resourceID),
		Outputs: map[string]string{
			"resource_id": resourceID,
		},
	}, nil
}

// UpdateCMDB updates the CMDB with new resource
func (d *ActivityDependencies) UpdateCMDB(ctx context.Context, input UpdateCMDBInput) error {
	logger := activity.GetLogger(ctx)
	logger.Info("Updating CMDB", "resourceID", input.ResourceID)

	// In production, this would call ServiceNow CMDB API
	// For demo, just log
	logger.Info("Would update CMDB",
		"applicationID", input.ApplicationID,
		"resourceID", input.ResourceID,
		"resourceType", input.ResourceType,
		"cloudProvider", input.CloudProvider,
	)

	return nil
}

// DefaultDependencies is the package-level dependencies used by standalone activity functions
var DefaultDependencies = NewActivityDependencies()

// Standalone activity functions for Temporal registration

func PerformAIRiskAssessment(ctx context.Context, input ExceptionWorkflowInput) (float64, error) {
	return DefaultDependencies.PerformAIRiskAssessment(ctx, input)
}

func ValidatePolicies(ctx context.Context, input ExceptionWorkflowInput) (*PolicyValidationResult, error) {
	return DefaultDependencies.ValidatePolicies(ctx, input)
}

func NotifyApprover(ctx context.Context, input NotifyApproverInput) error {
	return DefaultDependencies.NotifyApprover(ctx, input)
}

func RecordApprovalInGRC(ctx context.Context, input RecordApprovalInput) error {
	return DefaultDependencies.RecordApprovalInGRC(ctx, input)
}

func EvaluateOPAPolicies(ctx context.Context, input ProvisioningWorkflowInput) (*OPAPolicyResult, error) {
	return DefaultDependencies.EvaluateOPAPolicies(ctx, input)
}

func CheckException(ctx context.Context, input CheckExceptionInput) (bool, error) {
	return DefaultDependencies.CheckException(ctx, input)
}

func RunTerraformPlan(ctx context.Context, input ProvisioningWorkflowInput) (*TerraformPlanResult, error) {
	return DefaultDependencies.RunTerraformPlan(ctx, input)
}

func RunTerraformApply(ctx context.Context, input ProvisioningWorkflowInput) (*TerraformApplyResult, error) {
	return DefaultDependencies.RunTerraformApply(ctx, input)
}

func UpdateCMDB(ctx context.Context, input UpdateCMDBInput) error {
	return DefaultDependencies.UpdateCMDB(ctx, input)
}
