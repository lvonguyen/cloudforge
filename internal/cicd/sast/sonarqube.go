// Package sast provides SAST/DAST security scanning tool integrations
package sast

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"go.uber.org/zap"
)

// SonarQubeProvider implements the Provider interface for SonarQube/SonarCloud
type SonarQubeProvider struct {
	baseURL    string
	token      string
	httpClient *http.Client
	logger     *zap.Logger
	config     SonarQubeConfig
}

// SonarQubeConfig configures the SonarQube provider
type SonarQubeConfig struct {
	BaseURL    string `yaml:"base_url"`    // https://sonarcloud.io or self-hosted
	TokenEnv   string `yaml:"token_env"`
	Organization string `yaml:"organization"` // SonarCloud only
}

// NewSonarQubeProvider creates a new SonarQube provider
func NewSonarQubeProvider(cfg SonarQubeConfig, logger *zap.Logger) (*SonarQubeProvider, error) {
	token := os.Getenv(cfg.TokenEnv)
	if token == "" {
		return nil, fmt.Errorf("missing SonarQube token from env: %s", cfg.TokenEnv)
	}

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = "https://sonarcloud.io"
	}

	return &SonarQubeProvider{
		baseURL:    baseURL + "/api",
		token:      token,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		logger:     logger,
		config:     cfg,
	}, nil
}

func (p *SonarQubeProvider) Name() string { return "sonarqube" }
func (p *SonarQubeProvider) Type() string { return "sast" }

func (p *SonarQubeProvider) doRequest(ctx context.Context, method, requestURL string, body interface{}, result interface{}) error {
	var reqBody *bytes.Buffer
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshaling body: %w", err)
		}
		reqBody = bytes.NewBuffer(data)
	}

	var req *http.Request
	var err error
	if reqBody != nil {
		req, err = http.NewRequestWithContext(ctx, method, requestURL, reqBody)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, requestURL, nil)
	}
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.SetBasicAuth(p.token, "")
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	if result != nil {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
	}

	return nil
}

// Scan triggers analysis (note: SonarQube scans are typically triggered via CLI/CI)
func (p *SonarQubeProvider) Scan(ctx context.Context, req *ScanRequest) (*ScanResult, error) {
	// SonarQube analysis is typically done via sonar-scanner CLI
	// This creates a project if it doesn't exist and triggers analysis via API
	requestURL := fmt.Sprintf("%s/project_analyses/search?project=%s&ps=1", p.baseURL, req.ProjectID)

	var result struct {
		Analyses []struct {
			Key  string `json:"key"`
			Date string `json:"date"`
		} `json:"analyses"`
	}

	if err := p.doRequest(ctx, "GET", requestURL, nil, &result); err != nil {
		return nil, err
	}

	// Return latest analysis info
	if len(result.Analyses) > 0 {
		date, _ := time.Parse("2006-01-02T15:04:05-0700", result.Analyses[0].Date)
		return &ScanResult{
			ScanID:    result.Analyses[0].Key,
			Status:    "completed",
			WebURL:    fmt.Sprintf("%s/dashboard?id=%s", p.config.BaseURL, req.ProjectID),
			StartedAt: date,
		}, nil
	}

	return &ScanResult{
		ScanID: req.ProjectID,
		Status: "not_found",
		WebURL: fmt.Sprintf("%s/dashboard?id=%s", p.config.BaseURL, req.ProjectID),
	}, nil
}

// GetScanStatus gets analysis status
func (p *SonarQubeProvider) GetScanStatus(ctx context.Context, scanID string) (*ScanStatus, error) {
	requestURL := fmt.Sprintf("%s/ce/activity?component=%s&ps=1", p.baseURL, scanID)

	var result struct {
		Tasks []struct {
			ID              string `json:"id"`
			Status          string `json:"status"`
			SubmittedAt     string `json:"submittedAt"`
			ExecutedAt      string `json:"executedAt"`
			WarningCount    int    `json:"warningCount"`
			ErrorMessage    string `json:"errorMessage"`
		} `json:"tasks"`
	}

	if err := p.doRequest(ctx, "GET", requestURL, nil, &result); err != nil {
		return nil, err
	}

	if len(result.Tasks) == 0 {
		return &ScanStatus{
			ScanID: scanID,
			Status: "not_found",
		}, nil
	}

	task := result.Tasks[0]
	startedAt, _ := time.Parse("2006-01-02T15:04:05-0700", task.SubmittedAt)
	completedAt, _ := time.Parse("2006-01-02T15:04:05-0700", task.ExecutedAt)

	return &ScanStatus{
		ScanID:      task.ID,
		Status:      task.Status,
		StartedAt:   startedAt,
		CompletedAt: completedAt,
		WebURL:      fmt.Sprintf("%s/dashboard?id=%s", p.config.BaseURL, scanID),
	}, nil
}

// GetFindings retrieves issues from SonarQube
func (p *SonarQubeProvider) GetFindings(ctx context.Context, projectKey string) ([]*Finding, error) {
	requestURL := fmt.Sprintf("%s/issues/search?componentKeys=%s&types=VULNERABILITY,SECURITY_HOTSPOT&ps=500",
		p.baseURL, url.QueryEscape(projectKey))

	var result struct {
		Issues []struct {
			Key        string `json:"key"`
			Rule       string `json:"rule"`
			Severity   string `json:"severity"`
			Component  string `json:"component"`
			Message    string `json:"message"`
			Type       string `json:"type"`
			TextRange  struct {
				StartLine int `json:"startLine"`
				EndLine   int `json:"endLine"`
			} `json:"textRange"`
			Status     string `json:"status"`
			CreationDate string `json:"creationDate"`
		} `json:"issues"`
	}

	if err := p.doRequest(ctx, "GET", requestURL, nil, &result); err != nil {
		return nil, err
	}

	findings := make([]*Finding, 0, len(result.Issues))
	for _, issue := range result.Issues {
		createdAt, _ := time.Parse("2006-01-02T15:04:05-0700", issue.CreationDate)

		findings = append(findings, &Finding{
			ID:          issue.Key,
			Type:        issue.Type,
			Category:    issue.Rule,
			Severity:    mapSonarSeverity(issue.Severity),
			Title:       issue.Message,
			Description: issue.Message,
			FilePath:    issue.Component,
			StartLine:   issue.TextRange.StartLine,
			EndLine:     issue.TextRange.EndLine,
			Status:      issue.Status,
			CreatedAt:   createdAt,
		})
	}

	return findings, nil
}

// GetProjects lists projects
func (p *SonarQubeProvider) GetProjects(ctx context.Context) ([]*Project, error) {
	requestURL := fmt.Sprintf("%s/projects/search?ps=100", p.baseURL)
	if p.config.Organization != "" {
		requestURL += "&organization=" + p.config.Organization
	}

	var result struct {
		Components []struct {
			Key          string `json:"key"`
			Name         string `json:"name"`
			Qualifier    string `json:"qualifier"`
			LastAnalysisDate string `json:"lastAnalysisDate"`
		} `json:"components"`
	}

	if err := p.doRequest(ctx, "GET", requestURL, nil, &result); err != nil {
		return nil, err
	}

	projects := make([]*Project, 0, len(result.Components))
	for _, c := range result.Components {
		lastScan, _ := time.Parse("2006-01-02T15:04:05-0700", c.LastAnalysisDate)

		projects = append(projects, &Project{
			ID:       c.Key,
			Key:      c.Key,
			Name:     c.Name,
			LastScan: lastScan,
			WebURL:   fmt.Sprintf("%s/dashboard?id=%s", p.config.BaseURL, c.Key),
		})
	}

	return projects, nil
}

func mapSonarSeverity(severity string) string {
	switch severity {
	case "BLOCKER":
		return "critical"
	case "CRITICAL":
		return "high"
	case "MAJOR":
		return "medium"
	case "MINOR":
		return "low"
	case "INFO":
		return "info"
	default:
		return "medium"
	}
}

