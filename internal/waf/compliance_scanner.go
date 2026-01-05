// Package waf provides WAF configuration management and compliance scanning
package waf

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// ComplianceScanner scans WAF configurations for compliance with golden templates
type ComplianceScanner struct {
	templates *GoldenTemplateManager
	logger    *zap.Logger
}

// ScanResult represents the result of a compliance scan
type ScanResult struct {
	ResourceID      string           `json:"resource_id"`
	ResourceType    string           `json:"resource_type"`
	Provider        string           `json:"provider"`
	Environment     string           `json:"environment"`
	Exposure        string           `json:"exposure"`
	TemplateID      string           `json:"template_id"`
	ComplianceScore float64          `json:"compliance_score"` // 0-100
	Status          string           `json:"status"`           // compliant, non_compliant, warning
	Findings        []Finding        `json:"findings"`
	ScannedAt       time.Time        `json:"scanned_at"`
	Recommendations []Recommendation `json:"recommendations"`
}

// Finding represents a compliance finding
type Finding struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"` // critical, high, medium, low
	Category    string   `json:"category"` // managed_rules, rate_limiting, etc.
	Description string   `json:"description"`
	Expected    string   `json:"expected"`
	Actual      string   `json:"actual"`
	Remediation string   `json:"remediation"`
	Compliance  []string `json:"compliance"` // PCI-DSS, SOC2, etc.
}

// Recommendation represents a remediation recommendation
type Recommendation struct {
	Priority    int    `json:"priority"`
	Action      string `json:"action"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
	Effort      string `json:"effort"` // low, medium, high
}

// WAFConfig represents a WAF configuration to scan
type WAFConfig struct {
	ResourceID   string                 `json:"resource_id"`
	ResourceType string                 `json:"resource_type"` // aws_wafv2, azure_waf, cloudflare_waf
	Provider     string                 `json:"provider"`
	Environment  string                 `json:"environment"`
	Exposure     string                 `json:"exposure"`
	Config       map[string]interface{} `json:"config"`
}

// NewComplianceScanner creates a new compliance scanner
func NewComplianceScanner(templates *GoldenTemplateManager, logger *zap.Logger) *ComplianceScanner {
	return &ComplianceScanner{
		templates: templates,
		logger:    logger,
	}
}

// Scan compares a WAF configuration against the golden template
func (cs *ComplianceScanner) Scan(ctx context.Context, config WAFConfig) (*ScanResult, error) {
	// Get the appropriate golden template
	template, err := cs.templates.SelectTemplate(ctx, config.Provider, config.Environment, config.Exposure)
	if err != nil {
		return nil, fmt.Errorf("selecting template: %w", err)
	}

	result := &ScanResult{
		ResourceID:   config.ResourceID,
		ResourceType: config.ResourceType,
		Provider:     config.Provider,
		Environment:  config.Environment,
		Exposure:     config.Exposure,
		TemplateID:   template.ID,
		Findings:     make([]Finding, 0),
		ScannedAt:    time.Now(),
	}

	// Run compliance checks
	cs.checkManagedRules(template, &config, result)
	cs.checkCustomRules(template, &config, result)
	cs.checkRateLimiting(template, &config, result)
	cs.checkIPBlocking(template, &config, result)
	cs.checkGeoBlocking(template, &config, result)
	cs.checkBotProtection(template, &config, result)

	// Calculate compliance score
	result.ComplianceScore = cs.calculateScore(result.Findings)

	// Determine status
	if result.ComplianceScore >= 90 {
		result.Status = "compliant"
	} else if result.ComplianceScore >= 70 {
		result.Status = "warning"
	} else {
		result.Status = "non_compliant"
	}

	// Generate recommendations
	result.Recommendations = cs.generateRecommendations(result.Findings)

	cs.logger.Info("WAF compliance scan completed",
		zap.String("resource_id", config.ResourceID),
		zap.Float64("score", result.ComplianceScore),
		zap.String("status", result.Status),
		zap.Int("findings", len(result.Findings)),
	)

	return result, nil
}

func (cs *ComplianceScanner) checkManagedRules(template *GoldenTemplate, config *WAFConfig, result *ScanResult) {
	// Check if required managed rules are present
	for _, requiredRule := range template.RuleSet.ManagedRules {
		found := false
		// TODO: Parse config.Config to check for rule presence
		// This is a stub implementation

		if !found {
			result.Findings = append(result.Findings, Finding{
				ID:          fmt.Sprintf("MISSING_MANAGED_RULE_%s", requiredRule.Name),
				Severity:    "high",
				Category:    "managed_rules",
				Description: fmt.Sprintf("Required managed rule '%s' is not enabled", requiredRule.Name),
				Expected:    fmt.Sprintf("Rule %s with action %s", requiredRule.Name, requiredRule.Action),
				Actual:      "Rule not found",
				Remediation: fmt.Sprintf("Enable %s managed rule set with action set to %s", requiredRule.Name, requiredRule.Action),
				Compliance:  template.Metadata.Compliance,
			})
		}
	}
}

func (cs *ComplianceScanner) checkCustomRules(template *GoldenTemplate, config *WAFConfig, result *ScanResult) {
	// Check if required custom rules are present
	for _, requiredRule := range template.RuleSet.CustomRules {
		found := false
		// TODO: Check for rule presence

		if !found {
			result.Findings = append(result.Findings, Finding{
				ID:          fmt.Sprintf("MISSING_CUSTOM_RULE_%s", requiredRule.ID),
				Severity:    "medium",
				Category:    "custom_rules",
				Description: fmt.Sprintf("Required custom rule '%s' is not configured", requiredRule.Name),
				Expected:    requiredRule.Description,
				Actual:      "Rule not found",
				Remediation: fmt.Sprintf("Add custom rule: %s", requiredRule.Description),
				Compliance:  template.Metadata.Compliance,
			})
		}
	}
}

func (cs *ComplianceScanner) checkRateLimiting(template *GoldenTemplate, config *WAFConfig, result *ScanResult) {
	if !template.RuleSet.RateLimiting.Enabled {
		return
	}

	// Check if rate limiting is configured
	// TODO: Parse config.Config to check rate limiting

	// Example finding for missing rate limiting
	rateLimitConfigured := false // Placeholder
	if !rateLimitConfigured {
		result.Findings = append(result.Findings, Finding{
			ID:          "MISSING_RATE_LIMITING",
			Severity:    "high",
			Category:    "rate_limiting",
			Description: "Rate limiting is required but not configured",
			Expected:    fmt.Sprintf("%d requests per %d seconds", template.RuleSet.RateLimiting.DefaultLimit, template.RuleSet.RateLimiting.WindowSeconds),
			Actual:      "Rate limiting not configured",
			Remediation: "Configure rate limiting to prevent abuse and DDoS attacks",
			Compliance:  []string{"PCI-DSS", "OWASP-Top10"},
		})
	}
}

func (cs *ComplianceScanner) checkIPBlocking(template *GoldenTemplate, config *WAFConfig, result *ScanResult) {
	if !template.RuleSet.IPBlocking.Enabled {
		return
	}

	// Check if IP blocking is configured
	// TODO: Parse config.Config to check IP blocking

	ipBlockingConfigured := false // Placeholder
	if !ipBlockingConfigured {
		result.Findings = append(result.Findings, Finding{
			ID:          "MISSING_IP_BLOCKING",
			Severity:    "medium",
			Category:    "ip_blocking",
			Description: "IP reputation blocking is required but not configured",
			Expected:    "IP blocking with threat feeds enabled",
			Actual:      "IP blocking not configured",
			Remediation: "Enable IP reputation lists and threat feeds",
			Compliance:  []string{"SOC2"},
		})
	}
}

func (cs *ComplianceScanner) checkGeoBlocking(template *GoldenTemplate, config *WAFConfig, result *ScanResult) {
	if !template.RuleSet.GeoBlocking.Enabled {
		return
	}

	// Check if geo-blocking is configured
	geoBlockingConfigured := false // Placeholder
	if !geoBlockingConfigured {
		result.Findings = append(result.Findings, Finding{
			ID:          "MISSING_GEO_BLOCKING",
			Severity:    "medium",
			Category:    "geo_blocking",
			Description: "Geo-blocking is required but not configured",
			Expected:    fmt.Sprintf("Block countries: %v", template.RuleSet.GeoBlocking.BlockedCountries),
			Actual:      "Geo-blocking not configured",
			Remediation: "Configure geo-blocking for sanctioned countries",
			Compliance:  []string{"OFAC"},
		})
	}
}

func (cs *ComplianceScanner) checkBotProtection(template *GoldenTemplate, config *WAFConfig, result *ScanResult) {
	if !template.RuleSet.BotProtection.Enabled {
		return
	}

	// Check if bot protection is configured
	botProtectionConfigured := false // Placeholder
	if !botProtectionConfigured {
		result.Findings = append(result.Findings, Finding{
			ID:          "MISSING_BOT_PROTECTION",
			Severity:    "medium",
			Category:    "bot_protection",
			Description: "Bot protection is required but not configured",
			Expected:    fmt.Sprintf("Bot protection in %s mode", template.RuleSet.BotProtection.Mode),
			Actual:      "Bot protection not configured",
			Remediation: "Enable bot protection with appropriate challenge settings",
			Compliance:  []string{"OWASP-Top10"},
		})
	}
}

func (cs *ComplianceScanner) calculateScore(findings []Finding) float64 {
	if len(findings) == 0 {
		return 100.0
	}

	// Weight findings by severity
	weights := map[string]float64{
		"critical": 25.0,
		"high":     15.0,
		"medium":   10.0,
		"low":      5.0,
	}

	totalDeduction := 0.0
	for _, f := range findings {
		if weight, ok := weights[f.Severity]; ok {
			totalDeduction += weight
		}
	}

	score := 100.0 - totalDeduction
	if score < 0 {
		score = 0
	}

	return score
}

func (cs *ComplianceScanner) generateRecommendations(findings []Finding) []Recommendation {
	recommendations := make([]Recommendation, 0)

	// Sort by severity and generate prioritized recommendations
	priority := 1
	severityOrder := []string{"critical", "high", "medium", "low"}

	for _, severity := range severityOrder {
		for _, f := range findings {
			if f.Severity == severity {
				effort := "low"
				if f.Category == "managed_rules" {
					effort = "low"
				} else if f.Category == "custom_rules" {
					effort = "medium"
				}

				recommendations = append(recommendations, Recommendation{
					Priority:    priority,
					Action:      f.Remediation,
					Description: f.Description,
					Impact:      fmt.Sprintf("Addresses %s severity finding", f.Severity),
					Effort:      effort,
				})
				priority++
			}
		}
	}

	return recommendations
}

// ScanBatch scans multiple WAF configurations
func (cs *ComplianceScanner) ScanBatch(ctx context.Context, configs []WAFConfig) ([]*ScanResult, error) {
	results := make([]*ScanResult, 0, len(configs))

	for _, config := range configs {
		result, err := cs.Scan(ctx, config)
		if err != nil {
			cs.logger.Error("Scan failed for resource",
				zap.String("resource_id", config.ResourceID),
				zap.Error(err),
			)
			continue
		}
		results = append(results, result)
	}

	return results, nil
}

// GenerateReport generates a summary report for multiple scan results
func (cs *ComplianceScanner) GenerateReport(results []*ScanResult) *ComplianceReport {
	report := &ComplianceReport{
		GeneratedAt:     time.Now(),
		TotalResources:  len(results),
		OverallScore:    0,
		StatusSummary:   make(map[string]int),
		CategorySummary: make(map[string]int),
		Results:         results,
	}

	var totalScore float64
	for _, r := range results {
		totalScore += r.ComplianceScore
		report.StatusSummary[r.Status]++

		for _, f := range r.Findings {
			report.CategorySummary[f.Category]++
		}
	}

	if len(results) > 0 {
		report.OverallScore = totalScore / float64(len(results))
	}

	return report
}

// ComplianceReport represents a summary report
type ComplianceReport struct {
	GeneratedAt     time.Time         `json:"generated_at"`
	TotalResources  int               `json:"total_resources"`
	OverallScore    float64           `json:"overall_score"`
	StatusSummary   map[string]int    `json:"status_summary"`
	CategorySummary map[string]int    `json:"category_summary"`
	Results         []*ScanResult     `json:"results"`
}

