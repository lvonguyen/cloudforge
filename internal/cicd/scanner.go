// Package cicd provides CI/CD pipeline security scanning
package cicd

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Scanner scans CI/CD pipeline configurations for security issues
type Scanner struct {
	logger  *zap.Logger
	config  ScannerConfig
	rules   []*SecurityRule
}

// ScannerConfig configures the CI/CD scanner
type ScannerConfig struct {
	FailOnHighSeverity    bool     `yaml:"fail_on_high_severity"`
	FailOnMediumSeverity  bool     `yaml:"fail_on_medium_severity"`
	AllowedRunners        []string `yaml:"allowed_runners"`
	RequireApprovals      bool     `yaml:"require_approvals"`
	MinApprovers          int      `yaml:"min_approvers"`
	RequireSignedCommits  bool     `yaml:"require_signed_commits"`
	BlockedActions        []string `yaml:"blocked_actions"`
	AllowedRegistries     []string `yaml:"allowed_registries"`
}

// PipelineConfig represents a CI/CD pipeline configuration
type PipelineConfig struct {
	Type       string                 `json:"type"` // github_actions, gitlab_ci, azure_devops
	Name       string                 `json:"name"`
	FilePath   string                 `json:"file_path"`
	Content    string                 `json:"content"`
	Repository string                 `json:"repository"`
	Branch     string                 `json:"branch"`
	Raw        map[string]interface{} `json:"raw,omitempty"`
}

// ScanResult represents the result of a pipeline scan
type ScanResult struct {
	PipelineName  string        `json:"pipeline_name"`
	PipelineType  string        `json:"pipeline_type"`
	FilePath      string        `json:"file_path"`
	ScannedAt     time.Time     `json:"scanned_at"`
	Status        string        `json:"status"` // passed, failed, warning
	Score         float64       `json:"score"`  // 0-100
	Findings      []Finding     `json:"findings"`
	Summary       ScanSummary   `json:"summary"`
}

// Finding represents a security finding
type Finding struct {
	ID          string `json:"id"`
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"` // critical, high, medium, low, info
	Category    string `json:"category"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Line        int    `json:"line,omitempty"`
	Remediation string `json:"remediation"`
	Reference   string `json:"reference,omitempty"`
}

// ScanSummary provides a summary of findings
type ScanSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

// SecurityRule defines a security rule for scanning
type SecurityRule struct {
	ID          string
	Name        string
	Description string
	Severity    string
	Category    string
	Pattern     *regexp.Regexp
	Check       func(config *PipelineConfig, content string) []Finding
}

// NewScanner creates a new CI/CD security scanner
func NewScanner(cfg ScannerConfig, logger *zap.Logger) *Scanner {
	s := &Scanner{
		logger: logger,
		config: cfg,
		rules:  make([]*SecurityRule, 0),
	}

	s.loadDefaultRules()
	return s
}

// Scan scans a pipeline configuration for security issues
func (s *Scanner) Scan(ctx context.Context, config *PipelineConfig) (*ScanResult, error) {
	s.logger.Info("Scanning pipeline",
		zap.String("name", config.Name),
		zap.String("type", config.Type),
	)

	result := &ScanResult{
		PipelineName: config.Name,
		PipelineType: config.Type,
		FilePath:     config.FilePath,
		ScannedAt:    time.Now(),
		Findings:     make([]Finding, 0),
	}

	// Run type-specific checks
	switch config.Type {
	case "github_actions":
		result.Findings = append(result.Findings, s.scanGitHubActions(config)...)
	case "gitlab_ci":
		result.Findings = append(result.Findings, s.scanGitLabCI(config)...)
	case "azure_devops":
		result.Findings = append(result.Findings, s.scanAzureDevOps(config)...)
	default:
		// Run generic checks
		result.Findings = append(result.Findings, s.scanGeneric(config)...)
	}

	// Run all pattern-based rules
	for _, rule := range s.rules {
		if rule.Pattern != nil {
			matches := rule.Pattern.FindAllStringIndex(config.Content, -1)
			for _, match := range matches {
				line := s.getLineNumber(config.Content, match[0])
				result.Findings = append(result.Findings, Finding{
					RuleID:      rule.ID,
					Severity:    rule.Severity,
					Category:    rule.Category,
					Title:       rule.Name,
					Description: rule.Description,
					Line:        line,
				})
			}
		}
		if rule.Check != nil {
			result.Findings = append(result.Findings, rule.Check(config, config.Content)...)
		}
	}

	// Calculate summary
	result.Summary = s.calculateSummary(result.Findings)

	// Calculate score
	result.Score = s.calculateScore(result.Findings)

	// Determine status
	result.Status = s.determineStatus(result)

	s.logger.Info("Pipeline scan completed",
		zap.String("name", config.Name),
		zap.String("status", result.Status),
		zap.Float64("score", result.Score),
		zap.Int("findings", len(result.Findings)),
	)

	return result, nil
}

func (s *Scanner) scanGitHubActions(config *PipelineConfig) []Finding {
	findings := make([]Finding, 0)

	// Check for potentially dangerous patterns
	checks := []struct {
		pattern     *regexp.Regexp
		id          string
		title       string
		description string
		severity    string
		remediation string
	}{
		{
			pattern:     regexp.MustCompile(`(?i)secrets\.[A-Z_]+`),
			id:          "GHA-SECRETS-001",
			title:       "Secrets Usage Detected",
			description: "Pipeline uses GitHub secrets - ensure secrets are properly scoped",
			severity:    "info",
			remediation: "Review secret scoping and ensure least privilege",
		},
		{
			pattern:     regexp.MustCompile(`(?i)\$\{\{\s*github\.event\.(issue|pull_request|comment)\.body`),
			id:          "GHA-INJECTION-001",
			title:       "Potential Script Injection",
			description: "Using user-controlled input in workflow expression may lead to script injection",
			severity:    "critical",
			remediation: "Use intermediate environment variables and proper input validation",
		},
		{
			pattern:     regexp.MustCompile(`(?i)actions/checkout@v[12]`),
			id:          "GHA-OUTDATED-001",
			title:       "Outdated Action Version",
			description: "Using outdated version of actions/checkout",
			severity:    "low",
			remediation: "Update to actions/checkout@v4",
		},
		{
			pattern:     regexp.MustCompile(`(?i)run:\s*\|?\s*curl.*\|\s*(sh|bash)`),
			id:          "GHA-CURL-PIPE-001",
			title:       "Curl Pipe to Shell",
			description: "Piping curl output to shell is dangerous",
			severity:    "high",
			remediation: "Download script first, verify checksum, then execute",
		},
		{
			pattern:     regexp.MustCompile(`(?i)permissions:\s*write-all`),
			id:          "GHA-PERMS-001",
			title:       "Overly Permissive Workflow",
			description: "Workflow has write-all permissions",
			severity:    "high",
			remediation: "Use least privilege - specify only needed permissions",
		},
		{
			pattern:     regexp.MustCompile(`(?i)GITHUB_TOKEN.*write`),
			id:          "GHA-TOKEN-001",
			title:       "GITHUB_TOKEN with Write Access",
			description: "GITHUB_TOKEN has write permissions",
			severity:    "medium",
			remediation: "Verify write access is necessary",
		},
		{
			pattern:     regexp.MustCompile(`(?i)pull_request_target`),
			id:          "GHA-PR-TARGET-001",
			title:       "pull_request_target Event",
			description: "Using pull_request_target can be dangerous if checking out PR code",
			severity:    "high",
			remediation: "Use pull_request event or carefully handle checkout",
		},
		{
			pattern:     regexp.MustCompile(`(?i)workflow_dispatch`),
			id:          "GHA-DISPATCH-001",
			title:       "Manual Workflow Trigger",
			description: "Workflow can be triggered manually",
			severity:    "info",
			remediation: "Ensure proper access controls for manual triggers",
		},
	}

	for _, check := range checks {
		matches := check.pattern.FindAllStringIndex(config.Content, -1)
		for _, match := range matches {
			line := s.getLineNumber(config.Content, match[0])
			findings = append(findings, Finding{
				ID:          fmt.Sprintf("%s-%d", check.id, line),
				RuleID:      check.id,
				Severity:    check.severity,
				Category:    "github_actions",
				Title:       check.title,
				Description: check.description,
				Line:        line,
				Remediation: check.remediation,
			})
		}
	}

	// Check for blocked actions
	for _, blocked := range s.config.BlockedActions {
		if strings.Contains(config.Content, blocked) {
			findings = append(findings, Finding{
				ID:          fmt.Sprintf("GHA-BLOCKED-%s", blocked),
				RuleID:      "GHA-BLOCKED",
				Severity:    "high",
				Category:    "github_actions",
				Title:       "Blocked Action Used",
				Description: fmt.Sprintf("Action '%s' is on the blocked list", blocked),
				Remediation: "Remove or replace with approved action",
			})
		}
	}

	return findings
}

func (s *Scanner) scanGitLabCI(config *PipelineConfig) []Finding {
	findings := make([]Finding, 0)

	checks := []struct {
		pattern     *regexp.Regexp
		id          string
		title       string
		description string
		severity    string
		remediation string
	}{
		{
			pattern:     regexp.MustCompile(`(?i)CI_JOB_TOKEN`),
			id:          "GLB-TOKEN-001",
			title:       "CI Job Token Usage",
			description: "Using CI_JOB_TOKEN - ensure proper scoping",
			severity:    "info",
			remediation: "Review token permissions and scope",
		},
		{
			pattern:     regexp.MustCompile(`(?i)when:\s*manual`),
			id:          "GLB-MANUAL-001",
			title:       "Manual Job",
			description: "Job requires manual trigger",
			severity:    "info",
			remediation: "Ensure proper access controls for manual jobs",
		},
		{
			pattern:     regexp.MustCompile(`(?i)allow_failure:\s*true`),
			id:          "GLB-FAILURE-001",
			title:       "Allow Failure Enabled",
			description: "Job is configured to allow failure",
			severity:    "low",
			remediation: "Review if allowing failure is appropriate for security jobs",
		},
		{
			pattern:     regexp.MustCompile(`(?i)curl.*\|\s*(sh|bash)`),
			id:          "GLB-CURL-001",
			title:       "Curl Pipe to Shell",
			description: "Piping curl output to shell is dangerous",
			severity:    "high",
			remediation: "Download script first, verify checksum, then execute",
		},
		{
			pattern:     regexp.MustCompile(`(?i)protected:\s*false`),
			id:          "GLB-PROTECTED-001",
			title:       "Unprotected Variable",
			description: "Variable is not protected",
			severity:    "medium",
			remediation: "Protect sensitive variables",
		},
	}

	for _, check := range checks {
		matches := check.pattern.FindAllStringIndex(config.Content, -1)
		for _, match := range matches {
			line := s.getLineNumber(config.Content, match[0])
			findings = append(findings, Finding{
				ID:          fmt.Sprintf("%s-%d", check.id, line),
				RuleID:      check.id,
				Severity:    check.severity,
				Category:    "gitlab_ci",
				Title:       check.title,
				Description: check.description,
				Line:        line,
				Remediation: check.remediation,
			})
		}
	}

	return findings
}

func (s *Scanner) scanAzureDevOps(config *PipelineConfig) []Finding {
	findings := make([]Finding, 0)

	checks := []struct {
		pattern     *regexp.Regexp
		id          string
		title       string
		description string
		severity    string
		remediation string
	}{
		{
			pattern:     regexp.MustCompile(`(?i)\$\(System\.AccessToken\)`),
			id:          "AZD-TOKEN-001",
			title:       "System Access Token Usage",
			description: "Using System.AccessToken - ensure proper scoping",
			severity:    "info",
			remediation: "Review token permissions",
		},
		{
			pattern:     regexp.MustCompile(`(?i)continueOnError:\s*true`),
			id:          "AZD-CONTINUE-001",
			title:       "Continue on Error",
			description: "Task continues on error",
			severity:    "low",
			remediation: "Review if continuing on error is appropriate",
		},
		{
			pattern:     regexp.MustCompile(`(?i)curl.*\|\s*(sh|bash|pwsh)`),
			id:          "AZD-CURL-001",
			title:       "Curl Pipe to Shell",
			description: "Piping curl output to shell is dangerous",
			severity:    "high",
			remediation: "Download script first, verify checksum, then execute",
		},
		{
			pattern:     regexp.MustCompile(`(?i)isSecret:\s*false`),
			id:          "AZD-SECRET-001",
			title:       "Non-Secret Variable",
			description: "Sensitive-looking variable is not marked as secret",
			severity:    "medium",
			remediation: "Mark sensitive variables as secrets",
		},
	}

	for _, check := range checks {
		matches := check.pattern.FindAllStringIndex(config.Content, -1)
		for _, match := range matches {
			line := s.getLineNumber(config.Content, match[0])
			findings = append(findings, Finding{
				ID:          fmt.Sprintf("%s-%d", check.id, line),
				RuleID:      check.id,
				Severity:    check.severity,
				Category:    "azure_devops",
				Title:       check.title,
				Description: check.description,
				Line:        line,
				Remediation: check.remediation,
			})
		}
	}

	return findings
}

func (s *Scanner) scanGeneric(config *PipelineConfig) []Finding {
	findings := make([]Finding, 0)

	// Generic patterns that apply to all CI/CD systems
	patterns := []struct {
		pattern     *regexp.Regexp
		id          string
		title       string
		description string
		severity    string
		remediation string
	}{
		// Hardcoded secrets
		{
			pattern:     regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[=:]\s*['"][^'"]+['"]`),
			id:          "GEN-SECRET-001",
			title:       "Potential Hardcoded Password",
			description: "Possible hardcoded password in pipeline configuration",
			severity:    "critical",
			remediation: "Use secret management - never hardcode passwords",
		},
		{
			pattern:     regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[=:]\s*['"][^'"]+['"]`),
			id:          "GEN-SECRET-002",
			title:       "Potential Hardcoded API Key",
			description: "Possible hardcoded API key in pipeline configuration",
			severity:    "critical",
			remediation: "Use secret management - never hardcode API keys",
		},
		{
			pattern:     regexp.MustCompile(`(?i)(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*['"][^'"]+['"]`),
			id:          "GEN-SECRET-003",
			title:       "Hardcoded AWS Credentials",
			description: "AWS credentials appear to be hardcoded",
			severity:    "critical",
			remediation: "Use IAM roles or secret management",
		},
		// Dangerous commands
		{
			pattern:     regexp.MustCompile(`(?i)sudo\s+chmod\s+777`),
			id:          "GEN-PERMS-001",
			title:       "Overly Permissive chmod",
			description: "Setting 777 permissions is dangerous",
			severity:    "medium",
			remediation: "Use least privilege file permissions",
		},
		{
			pattern:     regexp.MustCompile(`(?i)--disable-ssl-verify`),
			id:          "GEN-SSL-001",
			title:       "SSL Verification Disabled",
			description: "SSL verification is disabled",
			severity:    "high",
			remediation: "Enable SSL verification",
		},
		{
			pattern:     regexp.MustCompile(`(?i)-k\s+`),
			id:          "GEN-SSL-002",
			title:       "Insecure Curl",
			description: "Curl with -k flag ignores SSL errors",
			severity:    "medium",
			remediation: "Remove -k flag and fix certificate issues",
		},
		// Docker security
		{
			pattern:     regexp.MustCompile(`(?i)docker\s+run.*--privileged`),
			id:          "GEN-DOCKER-001",
			title:       "Privileged Docker Container",
			description: "Running container in privileged mode",
			severity:    "high",
			remediation: "Avoid privileged mode - use specific capabilities instead",
		},
		{
			pattern:     regexp.MustCompile(`(?i)docker\s+run.*:latest`),
			id:          "GEN-DOCKER-002",
			title:       "Using Latest Tag",
			description: "Using :latest tag is not reproducible",
			severity:    "low",
			remediation: "Use specific version tags for reproducibility",
		},
	}

	for _, p := range patterns {
		matches := p.pattern.FindAllStringIndex(config.Content, -1)
		for _, match := range matches {
			line := s.getLineNumber(config.Content, match[0])
			findings = append(findings, Finding{
				ID:          fmt.Sprintf("%s-%d", p.id, line),
				RuleID:      p.id,
				Severity:    p.severity,
				Category:    "generic",
				Title:       p.title,
				Description: p.description,
				Line:        line,
				Remediation: p.remediation,
			})
		}
	}

	return findings
}

func (s *Scanner) getLineNumber(content string, position int) int {
	return strings.Count(content[:position], "\n") + 1
}

func (s *Scanner) calculateSummary(findings []Finding) ScanSummary {
	summary := ScanSummary{}

	for _, f := range findings {
		switch f.Severity {
		case "critical":
			summary.Critical++
		case "high":
			summary.High++
		case "medium":
			summary.Medium++
		case "low":
			summary.Low++
		case "info":
			summary.Info++
		}
		summary.Total++
	}

	return summary
}

func (s *Scanner) calculateScore(findings []Finding) float64 {
	if len(findings) == 0 {
		return 100.0
	}

	weights := map[string]float64{
		"critical": 25.0,
		"high":     15.0,
		"medium":   10.0,
		"low":      5.0,
		"info":     0.0,
	}

	deduction := 0.0
	for _, f := range findings {
		if w, ok := weights[f.Severity]; ok {
			deduction += w
		}
	}

	score := 100.0 - deduction
	if score < 0 {
		score = 0
	}

	return score
}

func (s *Scanner) determineStatus(result *ScanResult) string {
	if s.config.FailOnHighSeverity && (result.Summary.Critical > 0 || result.Summary.High > 0) {
		return "failed"
	}
	if s.config.FailOnMediumSeverity && result.Summary.Medium > 0 {
		return "failed"
	}
	if result.Summary.Critical > 0 || result.Summary.High > 0 {
		return "warning"
	}
	return "passed"
}

func (s *Scanner) loadDefaultRules() {
	// Rules are loaded in the scan methods above
	s.logger.Info("CI/CD security rules loaded")
}

// ScanBatch scans multiple pipeline configurations
func (s *Scanner) ScanBatch(ctx context.Context, configs []*PipelineConfig) ([]*ScanResult, error) {
	results := make([]*ScanResult, 0, len(configs))

	for _, config := range configs {
		result, err := s.Scan(ctx, config)
		if err != nil {
			s.logger.Error("Failed to scan pipeline",
				zap.String("name", config.Name),
				zap.Error(err),
			)
			continue
		}
		results = append(results, result)
	}

	return results, nil
}

// GenerateReport generates a summary report for multiple scans
func (s *Scanner) GenerateReport(results []*ScanResult) *PipelineSecurityReport {
	report := &PipelineSecurityReport{
		GeneratedAt:    time.Now(),
		TotalPipelines: len(results),
		Results:        results,
	}

	for _, r := range results {
		report.TotalFindings += r.Summary.Total
		report.Summary.Critical += r.Summary.Critical
		report.Summary.High += r.Summary.High
		report.Summary.Medium += r.Summary.Medium
		report.Summary.Low += r.Summary.Low
		report.Summary.Info += r.Summary.Info

		switch r.Status {
		case "passed":
			report.Passed++
		case "failed":
			report.Failed++
		case "warning":
			report.Warnings++
		}
	}

	if report.TotalPipelines > 0 {
		total := 0.0
		for _, r := range results {
			total += r.Score
		}
		report.AverageScore = total / float64(report.TotalPipelines)
	}

	return report
}

// PipelineSecurityReport represents a summary security report
type PipelineSecurityReport struct {
	GeneratedAt    time.Time     `json:"generated_at"`
	TotalPipelines int           `json:"total_pipelines"`
	Passed         int           `json:"passed"`
	Failed         int           `json:"failed"`
	Warnings       int           `json:"warnings"`
	AverageScore   float64       `json:"average_score"`
	TotalFindings  int           `json:"total_findings"`
	Summary        ScanSummary   `json:"summary"`
	Results        []*ScanResult `json:"results"`
}

