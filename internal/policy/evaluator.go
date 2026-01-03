// Package policy provides OPA policy evaluation for CloudForge
package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Evaluator evaluates policies against OPA
type Evaluator struct {
	opaURL     string
	httpClient *http.Client
}

// NewEvaluator creates a new policy evaluator
func NewEvaluator(opaURL string) *Evaluator {
	return &Evaluator{
		opaURL: opaURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// PolicyInput represents input for policy evaluation
type PolicyInput struct {
	ApplicationID string                 `json:"application_id"`
	ResourceType  string                 `json:"resource_type"`
	CloudProvider string                 `json:"cloud_provider"`
	Region        string                 `json:"region"`
	Configuration map[string]interface{} `json:"configuration"`
	Tags          map[string]string      `json:"tags"`
	RequestedBy   string                 `json:"requested_by"`
}

// PolicyResult represents the result of policy evaluation
type PolicyResult struct {
	Allowed     bool              `json:"allowed"`
	Denials     []PolicyViolation `json:"denials"`
	Warnings    []PolicyViolation `json:"warnings"`
	Suggestions []string          `json:"suggestions"`
}

// PolicyViolation represents a policy violation
type PolicyViolation struct {
	Code        string `json:"code"`
	Message     string `json:"message"`
	Severity    string `json:"severity"`
	Remediation string `json:"remediation"`
}

// Evaluate evaluates the input against OPA policies
func (e *Evaluator) Evaluate(ctx context.Context, input PolicyInput) (*PolicyResult, error) {
	reqBody := map[string]interface{}{
		"input": input,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("%s/v1/data/cloudforge/provisioning", e.opaURL),
		bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OPA request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OPA returned status %d", resp.StatusCode)
	}

	var opaResp OPAResponse
	if err := json.NewDecoder(resp.Body).Decode(&opaResp); err != nil {
		return nil, fmt.Errorf("failed to decode OPA response: %w", err)
	}

	return e.parseOPAResponse(opaResp), nil
}

// OPAResponse represents the raw OPA response
type OPAResponse struct {
	Result struct {
		Allow bool     `json:"allow"`
		Deny  []string `json:"deny"`
		Warn  []string `json:"warn"`
	} `json:"result"`
}

func (e *Evaluator) parseOPAResponse(resp OPAResponse) *PolicyResult {
	result := &PolicyResult{
		Allowed:     resp.Result.Allow && len(resp.Result.Deny) == 0,
		Denials:     make([]PolicyViolation, 0, len(resp.Result.Deny)),
		Warnings:    make([]PolicyViolation, 0, len(resp.Result.Warn)),
		Suggestions: make([]string, 0),
	}

	for _, msg := range resp.Result.Deny {
		result.Denials = append(result.Denials, PolicyViolation{
			Code:        extractPolicyCode(msg),
			Message:     msg,
			Severity:    "high",
			Remediation: generateRemediation(msg),
		})
	}

	for _, msg := range resp.Result.Warn {
		result.Warnings = append(result.Warnings, PolicyViolation{
			Code:        extractPolicyCode(msg),
			Message:     msg,
			Severity:    "medium",
			Remediation: generateRemediation(msg),
		})
	}

	if !result.Allowed {
		result.Suggestions = append(result.Suggestions,
			"Request an exception at: /exceptions/new",
			"Contact security team for policy clarification",
		)
	}

	return result
}

// EvaluateException checks if an exception request is valid
func (e *Evaluator) EvaluateException(ctx context.Context, applicationID, policyCode string, requestedDays int) (*ExceptionEvaluationResult, error) {
	reqBody := map[string]interface{}{
		"input": map[string]interface{}{
			"application_id": applicationID,
			"policy_code":    policyCode,
			"requested_days": requestedDays,
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("%s/v1/data/cloudforge/exception", e.opaURL),
		bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OPA request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OPA returned status %d", resp.StatusCode)
	}

	var opaResp struct {
		Result struct {
			Allowed           bool     `json:"allowed"`
			MaxDays           int      `json:"max_days"`
			RequiredApprovers []string `json:"required_approvers"`
			Deny              []string `json:"deny"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&opaResp); err != nil {
		return nil, fmt.Errorf("failed to decode OPA response: %w", err)
	}

	return &ExceptionEvaluationResult{
		Allowed:           opaResp.Result.Allowed && len(opaResp.Result.Deny) == 0,
		MaxDays:           opaResp.Result.MaxDays,
		RequiredApprovers: opaResp.Result.RequiredApprovers,
		Denials:           opaResp.Result.Deny,
	}, nil
}

// ExceptionEvaluationResult contains exception policy evaluation result
type ExceptionEvaluationResult struct {
	Allowed           bool     `json:"allowed"`
	MaxDays           int      `json:"max_days"`
	RequiredApprovers []string `json:"required_approvers"`
	Denials           []string `json:"denials"`
}

// extractPolicyCode extracts policy code from message (e.g., "AWS-001: ...")
func extractPolicyCode(msg string) string {
	if len(msg) > 8 && msg[3] == '-' {
		return msg[:7]
	}
	return "UNKNOWN"
}

// generateRemediation generates remediation suggestion from violation message
func generateRemediation(msg string) string {
	// In production, this would use a lookup table or AI
	return fmt.Sprintf("Violation: %s. Review policy requirements and update configuration. If exception needed, request at /exceptions/new", msg)
}
