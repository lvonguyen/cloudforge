// Package sast provides SAST/DAST security scanning tool integrations
package sast

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"go.uber.org/zap"
)

// CheckovProvider implements the Provider interface for Checkov IaC scanning
type CheckovProvider struct {
	checkovPath string
	logger      *zap.Logger
	config      CheckovConfig
}

// CheckovConfig configures the Checkov provider
type CheckovConfig struct {
	CheckovPath   string   `yaml:"checkov_path"`
	Frameworks    []string `yaml:"frameworks"`      // terraform, cloudformation, kubernetes, etc.
	SkipChecks    []string `yaml:"skip_checks"`     // checks to skip
	HardFailOn    []string `yaml:"hard_fail_on"`    // severity levels to fail on
	OutputFormat  string   `yaml:"output_format"`   // json, sarif
}

// NewCheckovProvider creates a new Checkov provider
func NewCheckovProvider(cfg CheckovConfig, logger *zap.Logger) (*CheckovProvider, error) {
	checkovPath := cfg.CheckovPath
	if checkovPath == "" {
		checkovPath = "checkov"
	}

	// Verify checkov is available
	if _, err := exec.LookPath(checkovPath); err != nil {
		return nil, fmt.Errorf("checkov not found: %w", err)
	}

	return &CheckovProvider{
		checkovPath: checkovPath,
		logger:      logger,
		config:      cfg,
	}, nil
}

func (p *CheckovProvider) Name() string { return "checkov" }
func (p *CheckovProvider) Type() string { return "iac" }

// Scan runs Checkov scan on the specified path
func (p *CheckovProvider) Scan(ctx context.Context, req *ScanRequest) (*ScanResult, error) {
	args := []string{
		"-d", req.SourcePath,
		"-o", "json",
		"--compact",
	}

	// Add frameworks if specified
	for _, fw := range p.config.Frameworks {
		args = append(args, "--framework", fw)
	}

	// Add skip checks
	for _, check := range p.config.SkipChecks {
		args = append(args, "--skip-check", check)
	}

	cmd := exec.CommandContext(ctx, p.checkovPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	startTime := time.Now()

	// Checkov returns non-zero exit on findings, which is expected
	_ = cmd.Run()

	scanID := fmt.Sprintf("checkov-%d", startTime.Unix())

	return &ScanResult{
		ScanID:    scanID,
		Status:    "completed",
		StartedAt: startTime,
	}, nil
}

// GetScanStatus gets scan status (Checkov runs synchronously)
func (p *CheckovProvider) GetScanStatus(ctx context.Context, scanID string) (*ScanStatus, error) {
	return &ScanStatus{
		ScanID: scanID,
		Status: "completed",
	}, nil
}

// GetFindings parses Checkov JSON output
func (p *CheckovProvider) GetFindings(ctx context.Context, scanPath string) ([]*Finding, error) {
	args := []string{
		"-d", scanPath,
		"-o", "json",
		"--compact",
	}

	for _, fw := range p.config.Frameworks {
		args = append(args, "--framework", fw)
	}

	for _, check := range p.config.SkipChecks {
		args = append(args, "--skip-check", check)
	}

	cmd := exec.CommandContext(ctx, p.checkovPath, args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	// Run and ignore exit code (non-zero on findings)
	_ = cmd.Run()

	// Parse JSON output
	var result struct {
		Results struct {
			FailedChecks []struct {
				CheckID      string `json:"check_id"`
				CheckName    string `json:"check_name"`
				CheckResult  struct {
					Result string `json:"result"`
				} `json:"check_result"`
				FilePath     string `json:"file_path"`
				FileLineRange []int  `json:"file_line_range"`
				ResourceAddress string `json:"resource_address"`
				Guideline    string `json:"guideline"`
				Severity     string `json:"severity"`
			} `json:"failed_checks"`
		} `json:"results"`
	}

	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		// Try parsing as array (multiple framework results)
		var results []struct {
			CheckType string `json:"check_type"`
			Results   struct {
				FailedChecks []struct {
					CheckID      string `json:"check_id"`
					CheckName    string `json:"check_name"`
					FilePath     string `json:"file_path"`
					FileLineRange []int  `json:"file_line_range"`
					ResourceAddress string `json:"resource_address"`
					Guideline    string `json:"guideline"`
					Severity     string `json:"severity"`
				} `json:"failed_checks"`
			} `json:"results"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &results); err != nil {
			return nil, fmt.Errorf("parsing checkov output: %w", err)
		}

		// Flatten results from all frameworks
		var findings []*Finding
		for _, r := range results {
			for _, check := range r.Results.FailedChecks {
				startLine := 1
				endLine := 1
				if len(check.FileLineRange) >= 2 {
					startLine = check.FileLineRange[0]
					endLine = check.FileLineRange[1]
				}

				findings = append(findings, &Finding{
					ID:          check.CheckID,
					Type:        "iac_misconfiguration",
					Category:    r.CheckType,
					Severity:    mapCheckovSeverity(check.Severity),
					Title:       check.CheckName,
					Description: check.CheckName,
					FilePath:    check.FilePath,
					StartLine:   startLine,
					EndLine:     endLine,
					Remediation: check.Guideline,
					Status:      "open",
					CreatedAt:   time.Now(),
				})
			}
		}
		return findings, nil
	}

	findings := make([]*Finding, 0, len(result.Results.FailedChecks))
	for _, check := range result.Results.FailedChecks {
		startLine := 1
		endLine := 1
		if len(check.FileLineRange) >= 2 {
			startLine = check.FileLineRange[0]
			endLine = check.FileLineRange[1]
		}

		findings = append(findings, &Finding{
			ID:          check.CheckID,
			Type:        "iac_misconfiguration",
			Category:    "infrastructure",
			Severity:    mapCheckovSeverity(check.Severity),
			Title:       check.CheckName,
			Description: check.CheckName,
			FilePath:    check.FilePath,
			StartLine:   startLine,
			EndLine:     endLine,
			Remediation: check.Guideline,
			Status:      "open",
			CreatedAt:   time.Now(),
		})
	}

	return findings, nil
}

// GetProjects returns empty (Checkov doesn't have a project concept)
func (p *CheckovProvider) GetProjects(_ context.Context) ([]*Project, error) {
	return []*Project{}, nil
}

func mapCheckovSeverity(severity string) string {
	switch severity {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	default:
		return "medium"
	}
}

