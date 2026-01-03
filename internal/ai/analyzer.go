// Package ai provides AI-powered analysis for CloudForge
package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// ExceptionAnalyzer analyzes security exceptions using AI
type ExceptionAnalyzer struct {
	provider Provider
}

// NewExceptionAnalyzer creates a new exception analyzer
func NewExceptionAnalyzer(provider Provider) *ExceptionAnalyzer {
	return &ExceptionAnalyzer{provider: provider}
}

// ExceptionAnalysisInput contains input for exception analysis
type ExceptionAnalysisInput struct {
	ExceptionID     string           `json:"exception_id"`
	ApplicationID   string           `json:"application_id"`
	ApplicationName string           `json:"application_name"`
	PolicyCode      string           `json:"policy_code"`
	PolicyTitle     string           `json:"policy_title"`
	Justification   string           `json:"justification"`
	RequestedDays   int              `json:"requested_days"`
	ResourceType    string           `json:"resource_type"`
	CloudProvider   string           `json:"cloud_provider"`
	Environment     string           `json:"environment"`
	DataClass       string           `json:"data_classification"`
	PriorExceptions []PriorException `json:"prior_exceptions"`
}

// PriorException represents a historical exception
type PriorException struct {
	ID          string `json:"id"`
	PolicyCode  string `json:"policy_code"`
	Status      string `json:"status"`
	RequestedAt string `json:"requested_at"`
	Duration    int    `json:"duration_days"`
}

// ExceptionAnalysisResult contains AI analysis results
type ExceptionAnalysisResult struct {
	RiskScore         float64      `json:"risk_score"`
	RiskLevel         string       `json:"risk_level"`
	RiskFactors       []RiskFactor `json:"risk_factors"`
	Recommendation    string       `json:"recommendation"`
	SuggestedDuration int          `json:"suggested_duration_days"`
	RequiredControls  []string     `json:"required_controls"`
	SimilarIncidents  []string     `json:"similar_incidents"`
	ApproverGuidance  string       `json:"approver_guidance"`
	RemediationPlan   string       `json:"remediation_plan"`
}

// RiskFactor represents a specific risk factor
type RiskFactor struct {
	Factor     string  `json:"factor"`
	Impact     string  `json:"impact"`
	Weight     float64 `json:"weight"`
	Mitigation string  `json:"mitigation"`
}

// Analyze performs AI-powered analysis of an exception request
func (a *ExceptionAnalyzer) Analyze(ctx context.Context, input ExceptionAnalysisInput) (*ExceptionAnalysisResult, error) {
	systemPrompt := `You are a senior cloud security architect reviewing exception requests.
Your role is to:
1. Assess the risk level of granting the exception
2. Identify specific risk factors and their potential impact
3. Recommend compensating controls
4. Provide guidance to approvers
5. Suggest a remediation timeline

Respond in JSON format matching the ExceptionAnalysisResult schema.
Be specific and actionable in your recommendations.
Consider: data classification, environment, prior exceptions, and industry best practices.`

	userPrompt := fmt.Sprintf(`Analyze this security exception request:

Application: %s (%s)
Policy: %s - %s
Environment: %s
Data Classification: %s
Cloud Provider: %s
Resource Type: %s

Justification provided:
%s

Requested Duration: %d days

Prior Exceptions for this application:
%s

Provide your risk assessment and recommendations in JSON format.`,
		input.ApplicationName,
		input.ApplicationID,
		input.PolicyCode,
		input.PolicyTitle,
		input.Environment,
		input.DataClass,
		input.CloudProvider,
		input.ResourceType,
		input.Justification,
		input.RequestedDays,
		formatPriorExceptions(input.PriorExceptions),
	)

	response, err := a.provider.CompleteWithSystem(ctx, systemPrompt, userPrompt)
	if err != nil {
		return nil, fmt.Errorf("AI analysis failed: %w", err)
	}

	// Parse JSON response
	result, err := parseAnalysisResponse(response)
	if err != nil {
		// If parsing fails, create a structured response from the text
		return createFallbackResult(response, input), nil
	}

	return result, nil
}

// AnalyzeBatch analyzes multiple exceptions in batch
func (a *ExceptionAnalyzer) AnalyzeBatch(ctx context.Context, inputs []ExceptionAnalysisInput) ([]ExceptionAnalysisResult, error) {
	results := make([]ExceptionAnalysisResult, len(inputs))

	for i, input := range inputs {
		result, err := a.Analyze(ctx, input)
		if err != nil {
			// Log error but continue with other analyses
			results[i] = ExceptionAnalysisResult{
				RiskScore:      0.5,
				RiskLevel:      "UNKNOWN",
				Recommendation: fmt.Sprintf("Analysis failed: %v", err),
			}
			continue
		}
		results[i] = *result
	}

	return results, nil
}

// GenerateRemediationPlan generates a detailed remediation plan
func (a *ExceptionAnalyzer) GenerateRemediationPlan(ctx context.Context, input ExceptionAnalysisInput) (string, error) {
	systemPrompt := `You are a cloud security engineer creating remediation plans.
Generate a detailed, step-by-step remediation plan to eliminate the need for this exception.
Include: specific technical steps, timeline estimates, and success criteria.`

	userPrompt := fmt.Sprintf(`Create a remediation plan for:

Application: %s
Policy: %s - %s
Cloud Provider: %s
Resource Type: %s

Current exception justification:
%s

Provide a detailed plan to properly implement the control and eliminate the exception.`,
		input.ApplicationName,
		input.PolicyCode,
		input.PolicyTitle,
		input.CloudProvider,
		input.ResourceType,
		input.Justification,
	)

	return a.provider.CompleteWithSystem(ctx, systemPrompt, userPrompt)
}

func formatPriorExceptions(exceptions []PriorException) string {
	if len(exceptions) == 0 {
		return "None"
	}

	var sb strings.Builder
	for _, e := range exceptions {
		sb.WriteString(fmt.Sprintf("- %s: %s (%s, %d days)\n", e.ID, e.PolicyCode, e.Status, e.Duration))
	}
	return sb.String()
}

func parseAnalysisResponse(response string) (*ExceptionAnalysisResult, error) {
	// Try to extract JSON from response (may be wrapped in markdown)
	jsonStart := strings.Index(response, "{")
	jsonEnd := strings.LastIndex(response, "}")

	if jsonStart == -1 || jsonEnd == -1 || jsonEnd <= jsonStart {
		return nil, fmt.Errorf("no JSON found in response")
	}

	jsonStr := response[jsonStart : jsonEnd+1]

	var result ExceptionAnalysisResult
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return &result, nil
}

func createFallbackResult(response string, input ExceptionAnalysisInput) *ExceptionAnalysisResult {
	// Create a basic result from unstructured response
	riskScore := 0.5
	riskLevel := "MEDIUM"

	// Adjust based on data classification
	switch strings.ToLower(input.DataClass) {
	case "confidential", "restricted":
		riskScore = 0.8
		riskLevel = "HIGH"
	case "public":
		riskScore = 0.3
		riskLevel = "LOW"
	}

	// Adjust based on environment
	if strings.ToLower(input.Environment) == "production" {
		riskScore += 0.1
		if riskScore > 0.7 {
			riskLevel = "HIGH"
		}
	}

	return &ExceptionAnalysisResult{
		RiskScore:         riskScore,
		RiskLevel:         riskLevel,
		Recommendation:    response,
		SuggestedDuration: min(input.RequestedDays, 90),
		RiskFactors: []RiskFactor{
			{
				Factor:     "Data Classification",
				Impact:     input.DataClass,
				Weight:     0.3,
				Mitigation: "Implement compensating controls appropriate for data sensitivity",
			},
			{
				Factor:     "Environment",
				Impact:     input.Environment,
				Weight:     0.2,
				Mitigation: "Consider additional monitoring for production environments",
			},
		},
		RequiredControls: []string{
			"Enhanced logging and monitoring",
			"Quarterly review of exception status",
		},
		ApproverGuidance: "Review the AI analysis and verify compensating controls are in place.",
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
