// Package compliance provides compliance framework mapping and assessment
package compliance

import (
	"context"
	"fmt"
	"strings"

	"go.uber.org/zap"
)

// AIAnalyzer provides AI-powered analysis for security findings
type AIAnalyzer struct {
	provider AIProvider
	logger   *zap.Logger
	config   AIAnalyzerConfig
}

// AIProvider interface for AI providers
type AIProvider interface {
	Analyze(ctx context.Context, prompt string) (string, error)
	AnalyzeJSON(ctx context.Context, prompt string, result interface{}) error
}

// AIAnalyzerConfig configures the AI analyzer
type AIAnalyzerConfig struct {
	Enabled              bool    `yaml:"enabled"`
	Provider             string  `yaml:"provider"` // anthropic, openai
	Model                string  `yaml:"model"`
	MaxTokens            int     `yaml:"max_tokens"`
	ContextualRiskWeight float64 `yaml:"contextual_risk_weight"` // How much AI risk affects final score
}

// AIRiskAssessment represents the AI's risk assessment
type AIRiskAssessment struct {
	RiskScore       float64  `json:"risk_score"`        // 0.0 - 10.0
	RiskLevel       string   `json:"risk_level"`        // critical, high, medium, low
	Rationale       string   `json:"rationale"`
	ContextualFactors []string `json:"contextual_factors"`
	AttackVectors   []string `json:"attack_vectors"`
	ToxicCombos     []ToxicComboCandidate `json:"toxic_combos"`
	Recommendations []string `json:"recommendations"`
	Confidence      float64  `json:"confidence"` // 0.0 - 1.0
}

// ToxicComboCandidate represents a potential toxic combination
type ToxicComboCandidate struct {
	RelatedFindingIDs []string `json:"related_finding_ids"`
	Description       string   `json:"description"`
	AttackPath        []string `json:"attack_path"`
	Severity          string   `json:"severity"`
}

// MisconfigAnalysis represents misconfiguration analysis results
type MisconfigAnalysis struct {
	IsMisconfiguration bool     `json:"is_misconfiguration"`
	Category           string   `json:"category"`
	RootCause          string   `json:"root_cause"`
	Impact             string   `json:"impact"`
	BlastRadius        string   `json:"blast_radius"`
	RemediationSteps   []string `json:"remediation_steps"`
}

// VulnerabilityAnalysis represents vulnerability analysis results
type VulnerabilityAnalysis struct {
	IsVulnerability   bool     `json:"is_vulnerability"`
	ExploitLikelihood string   `json:"exploit_likelihood"`
	ExploitComplexity string   `json:"exploit_complexity"`
	PrerequisiteAccess string  `json:"prerequisite_access"`
	PotentialImpact   string   `json:"potential_impact"`
	AttackSurface     string   `json:"attack_surface"`
	RemediationPriority string `json:"remediation_priority"`
}

// NewAIAnalyzer creates a new AI analyzer
func NewAIAnalyzer(provider AIProvider, cfg AIAnalyzerConfig, logger *zap.Logger) *AIAnalyzer {
	return &AIAnalyzer{
		provider: provider,
		logger:   logger,
		config:   cfg,
	}
}

// AnalyzeFinding performs comprehensive AI analysis on a finding
func (a *AIAnalyzer) AnalyzeFinding(ctx context.Context, finding *Finding, relatedFindings []*Finding) (*Finding, error) {
	if !a.config.Enabled || a.provider == nil {
		return finding, nil
	}

	// Perform risk assessment
	assessment, err := a.assessContextualRisk(ctx, finding, relatedFindings)
	if err != nil {
		a.logger.Warn("AI risk assessment failed",
			zap.String("finding_id", finding.ID),
			zap.Error(err),
		)
		// Continue without AI analysis
		return finding, nil
	}

	// Apply AI assessment to finding
	finding.AIRiskScore = assessment.RiskScore
	finding.AIRiskLevel = assessment.RiskLevel
	finding.AIRiskRationale = assessment.Rationale
	finding.AIContextualFactors = assessment.ContextualFactors

	// Check for toxic combinations
	if len(assessment.ToxicCombos) > 0 {
		combo := assessment.ToxicCombos[0] // Take the most significant
		finding.Type = FindingTypeToxicCombo
		finding.ToxicComboDetails = &ToxicComboDetails{
			ComboType:       "ai_detected",
			Description:     combo.Description,
			RelatedFindings: combo.RelatedFindingIDs,
			AttackPath:      combo.AttackPath,
			ExploitPotential: combo.Severity,
		}
	}

	// Analyze for misconfigurations
	if finding.Type == FindingTypeMisconfiguration || finding.Type == "" {
		misconfigAnalysis, err := a.analyzeMisconfiguration(ctx, finding)
		if err == nil && misconfigAnalysis.IsMisconfiguration {
			finding.Type = FindingTypeMisconfiguration
			if finding.Remediation == "" {
				finding.Remediation = strings.Join(misconfigAnalysis.RemediationSteps, "\n")
			}
		}
	}

	// Analyze vulnerabilities
	if len(finding.CVEs) > 0 {
		vulnAnalysis, err := a.analyzeVulnerability(ctx, finding)
		if err == nil && vulnAnalysis.IsVulnerability {
			// Enrich finding with vulnerability context
			if vulnAnalysis.ExploitLikelihood == "high" {
				finding.ExploitAvailable = true
				finding.AIContextualFactors = append(finding.AIContextualFactors, "high_exploit_likelihood")
			}
		}
	}

	return finding, nil
}

// assessContextualRisk uses AI to assess contextual risk
func (a *AIAnalyzer) assessContextualRisk(ctx context.Context, finding *Finding, relatedFindings []*Finding) (*AIRiskAssessment, error) {
	prompt := a.buildRiskAssessmentPrompt(finding, relatedFindings)

	var assessment AIRiskAssessment
	if err := a.provider.AnalyzeJSON(ctx, prompt, &assessment); err != nil {
		return nil, fmt.Errorf("risk assessment failed: %w", err)
	}

	return &assessment, nil
}

// buildRiskAssessmentPrompt builds the prompt for risk assessment
func (a *AIAnalyzer) buildRiskAssessmentPrompt(finding *Finding, relatedFindings []*Finding) string {
	var sb strings.Builder

	sb.WriteString("You are a security analyst assessing the contextual risk of a security finding.\n\n")
	sb.WriteString("FINDING:\n")
	sb.WriteString(fmt.Sprintf("Title: %s\n", finding.Title))
	sb.WriteString(fmt.Sprintf("Description: %s\n", finding.Description))
	sb.WriteString(fmt.Sprintf("Resource: %s (%s)\n", finding.ResourceName, finding.ResourceType))
	sb.WriteString(fmt.Sprintf("Environment: %s\n", finding.EnvironmentType))
	sb.WriteString(fmt.Sprintf("Platform: %s / %s\n", finding.Platform, finding.CloudProvider))
	sb.WriteString(fmt.Sprintf("Static Severity: %s\n", finding.StaticSeverity))

	if len(finding.CVEs) > 0 {
		sb.WriteString("\nCVEs:\n")
		for _, cve := range finding.CVEs {
			sb.WriteString(fmt.Sprintf("- %s (CVSS: %.1f)\n", cve.ID, cve.CVSS))
		}
	}

	if len(finding.ComplianceMappings) > 0 {
		sb.WriteString("\nCompliance Violations:\n")
		for _, cm := range finding.ComplianceMappings[:min(5, len(finding.ComplianceMappings))] {
			sb.WriteString(fmt.Sprintf("- %s %s: %s\n", cm.FrameworkName, cm.ControlID, cm.ControlTitle))
		}
	}

	if len(relatedFindings) > 0 {
		sb.WriteString("\nRELATED FINDINGS ON SAME/CONNECTED RESOURCES:\n")
		for _, rf := range relatedFindings[:min(10, len(relatedFindings))] {
			sb.WriteString(fmt.Sprintf("- [%s] %s on %s\n", rf.Severity, rf.Title, rf.ResourceName))
		}
	}

	sb.WriteString(`
TASK:
Analyze this finding and provide a JSON response with:
1. risk_score: Contextual risk score from 0.0 to 10.0 considering environment, exploitability, and blast radius
2. risk_level: "critical", "high", "medium", or "low"
3. rationale: Brief explanation of the risk assessment
4. contextual_factors: List of factors affecting the risk (e.g., "production_environment", "internet_facing", "data_store")
5. attack_vectors: Potential attack vectors enabled by this finding
6. toxic_combos: If combined with related findings creates a more severe issue, describe the combination
7. recommendations: Prioritized remediation recommendations
8. confidence: Your confidence in this assessment (0.0-1.0)

Consider:
- Environment type (production vs non-production)
- Resource type and criticality
- Network exposure
- Data sensitivity
- Exploit availability
- Combination with other findings (toxic combos)
- Industry context

Respond with valid JSON only.`)

	return sb.String()
}

// analyzeMisconfiguration analyzes a finding for misconfiguration details
func (a *AIAnalyzer) analyzeMisconfiguration(ctx context.Context, finding *Finding) (*MisconfigAnalysis, error) {
	prompt := fmt.Sprintf(`Analyze this security finding for misconfiguration details:

Title: %s
Description: %s
Resource Type: %s
Cloud Provider: %s

Is this a misconfiguration? If so, provide:
1. is_misconfiguration: true/false
2. category: Type of misconfiguration (network, iam, encryption, logging, etc.)
3. root_cause: What configuration is incorrect
4. impact: What is the security impact
5. blast_radius: How many resources/users could be affected
6. remediation_steps: Ordered list of steps to fix

Respond with valid JSON only.`, finding.Title, finding.Description, finding.ResourceType, finding.CloudProvider)

	var analysis MisconfigAnalysis
	if err := a.provider.AnalyzeJSON(ctx, prompt, &analysis); err != nil {
		return nil, err
	}

	return &analysis, nil
}

// analyzeVulnerability analyzes a finding for vulnerability details
func (a *AIAnalyzer) analyzeVulnerability(ctx context.Context, finding *Finding) (*VulnerabilityAnalysis, error) {
	cveList := ""
	for _, cve := range finding.CVEs {
		cveList += fmt.Sprintf("- %s (CVSS: %.1f): %s\n", cve.ID, cve.CVSS, cve.Description)
	}

	prompt := fmt.Sprintf(`Analyze this vulnerability finding:

Title: %s
Description: %s
Resource: %s (%s)
Environment: %s

CVEs:
%s

Provide vulnerability analysis:
1. is_vulnerability: true/false
2. exploit_likelihood: "high", "medium", "low" - how likely is exploitation
3. exploit_complexity: "low", "medium", "high" - complexity to exploit
4. prerequisite_access: What access is needed to exploit
5. potential_impact: What could an attacker achieve
6. attack_surface: Is it internet-facing, internal-only, etc.
7. remediation_priority: "immediate", "urgent", "scheduled", "low"

Respond with valid JSON only.`, finding.Title, finding.Description, finding.ResourceName, finding.ResourceType, finding.EnvironmentType, cveList)

	var analysis VulnerabilityAnalysis
	if err := a.provider.AnalyzeJSON(ctx, prompt, &analysis); err != nil {
		return nil, err
	}

	return &analysis, nil
}

// DetectToxicCombinations analyzes findings for toxic combinations
func (a *AIAnalyzer) DetectToxicCombinations(ctx context.Context, findings []*Finding) ([]*Finding, error) {
	if !a.config.Enabled || a.provider == nil || len(findings) < 2 {
		return findings, nil
	}

	// Group findings by resource and related resources
	resourceGroups := make(map[string][]*Finding)
	for _, f := range findings {
		key := f.ResourceID
		resourceGroups[key] = append(resourceGroups[key], f)

		// Also group by impacted resources
		for _, ir := range f.ImpactedResources {
			resourceGroups[ir.ResourceID] = append(resourceGroups[ir.ResourceID], f)
		}
	}

	// Check each group for toxic combinations
	for _, group := range resourceGroups {
		if len(group) < 2 {
			continue
		}

		combos, err := a.detectCombosInGroup(ctx, group)
		if err != nil {
			a.logger.Warn("Failed to detect toxic combos in group", zap.Error(err))
			continue
		}

		// Apply detected toxic combos to findings
		for _, combo := range combos {
			// Create a new toxic combo finding or enhance existing
			for _, fid := range combo.RelatedFindingIDs {
				for _, f := range findings {
					if f.ID == fid {
						if f.ToxicComboDetails == nil {
							f.ToxicComboDetails = &ToxicComboDetails{
								ComboType:       "ai_detected",
								Description:     combo.Description,
								RelatedFindings: combo.RelatedFindingIDs,
								AttackPath:      combo.AttackPath,
								ExploitPotential: combo.Severity,
							}
							f.Type = FindingTypeToxicCombo
						}
					}
				}
			}
		}
	}

	return findings, nil
}

// detectCombosInGroup detects toxic combinations within a group
func (a *AIAnalyzer) detectCombosInGroup(ctx context.Context, group []*Finding) ([]ToxicComboCandidate, error) {
	var sb strings.Builder
	sb.WriteString("Analyze these related security findings for toxic combinations:\n\n")

	for i, f := range group {
		sb.WriteString(fmt.Sprintf("Finding %d:\n", i+1))
		sb.WriteString(fmt.Sprintf("  ID: %s\n", f.ID))
		sb.WriteString(fmt.Sprintf("  Title: %s\n", f.Title))
		sb.WriteString(fmt.Sprintf("  Severity: %s\n", f.Severity))
		sb.WriteString(fmt.Sprintf("  Resource: %s\n", f.ResourceName))
		sb.WriteString("\n")
	}

	sb.WriteString(`
Identify any TOXIC COMBINATIONS where multiple findings together create a more severe risk than individually.

Examples of toxic combos:
- Public S3 bucket + sensitive data stored = data breach risk
- Open security group + outdated software = easily exploitable
- Overly permissive IAM + lack of logging = undetectable privilege abuse
- Missing MFA + admin access = account takeover risk

Return a JSON array of toxic_combos with:
- related_finding_ids: IDs of findings in the combo
- description: How the combo creates elevated risk
- attack_path: Steps an attacker could take
- severity: Combined severity (critical/high/medium/low)

Return empty array [] if no toxic combinations found.
Respond with valid JSON array only.`)

	var combos []ToxicComboCandidate
	if err := a.provider.AnalyzeJSON(ctx, sb.String(), &combos); err != nil {
		return nil, err
	}

	return combos, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

