// Package sast provides SAST/DAST security scanning tool integrations
package sast

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
)

// VeracodeProvider implements the Provider interface for Veracode
type VeracodeProvider struct {
	apiID      string
	apiKey     string
	httpClient *http.Client
	logger     *zap.Logger
	config     VeracodeConfig
}

// VeracodeConfig configures the Veracode provider
type VeracodeConfig struct {
	APIIDEnv   string `yaml:"api_id_env"`
	APIKeyEnv  string `yaml:"api_key_env"`
	Region     string `yaml:"region"`     // us, eu
	ScanType   string `yaml:"scan_type"`  // static, dynamic, sca
}

// NewVeracodeProvider creates a new Veracode provider
func NewVeracodeProvider(cfg VeracodeConfig, logger *zap.Logger) (*VeracodeProvider, error) {
	apiID := os.Getenv(cfg.APIIDEnv)
	apiKey := os.Getenv(cfg.APIKeyEnv)

	if apiID == "" || apiKey == "" {
		return nil, fmt.Errorf("missing Veracode credentials from env: %s, %s", cfg.APIIDEnv, cfg.APIKeyEnv)
	}

	return &VeracodeProvider{
		apiID:      apiID,
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: 60 * time.Second},
		logger:     logger,
		config:     cfg,
	}, nil
}

func (p *VeracodeProvider) Name() string { return "veracode" }
func (p *VeracodeProvider) Type() string { return p.config.ScanType }

func (p *VeracodeProvider) baseURL() string {
	if p.config.Region == "eu" {
		return "https://api.veracode.eu"
	}
	return "https://api.veracode.com"
}

// generateAuthHeader creates Veracode HMAC authentication header
func (p *VeracodeProvider) generateAuthHeader(method, path string) string {
	nonce := fmt.Sprintf("%x", time.Now().UnixNano())
	timestamp := fmt.Sprintf("%d", time.Now().Unix()*1000)

	// Create signing data
	signingData := fmt.Sprintf("id=%s&host=%s&url=%s&method=%s",
		p.apiID, p.baseURL(), path, strings.ToUpper(method))

	// HMAC signature
	h := hmac.New(sha256.New, []byte(p.apiKey))
	h.Write([]byte(nonce + timestamp))
	keySignature := hex.EncodeToString(h.Sum(nil))

	h2 := hmac.New(sha256.New, []byte(keySignature))
	h2.Write([]byte(signingData))
	signature := hex.EncodeToString(h2.Sum(nil))

	return fmt.Sprintf("VERACODE-HMAC-SHA-256 id=%s,ts=%s,nonce=%s,sig=%s",
		p.apiID, timestamp, nonce, signature)
}

func (p *VeracodeProvider) doRequest(ctx context.Context, method, path string, body interface{}, result interface{}) error {
	fullURL := p.baseURL() + path

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
		req, err = http.NewRequestWithContext(ctx, method, fullURL, reqBody)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, fullURL, nil)
	}
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", p.generateAuthHeader(method, path))
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

// Scan triggers a scan (creates a scan for an application)
func (p *VeracodeProvider) Scan(ctx context.Context, req *ScanRequest) (*ScanResult, error) {
	path := "/appsec/v1/applications/" + req.ProjectID + "/scans"

	body := map[string]interface{}{
		"scan_type": p.config.ScanType,
	}

	var result struct {
		ID     string `json:"id"`
		Status string `json:"status"`
		Links  struct {
			Details struct {
				Href string `json:"href"`
			} `json:"details"`
		} `json:"_links"`
	}

	if err := p.doRequest(ctx, "POST", path, body, &result); err != nil {
		return nil, err
	}

	return &ScanResult{
		ScanID:    result.ID,
		Status:    result.Status,
		WebURL:    "https://analysiscenter.veracode.com",
		StartedAt: time.Now(),
	}, nil
}

// GetScanStatus gets scan status
func (p *VeracodeProvider) GetScanStatus(ctx context.Context, scanID string) (*ScanStatus, error) {
	path := "/appsec/v1/scans/" + scanID

	var result struct {
		ID          string `json:"id"`
		Status      string `json:"status"`
		CreatedDate string `json:"created_date"`
		ModifiedDate string `json:"modified_date"`
		Summary     struct {
			VeryHigh int `json:"very_high"`
			High     int `json:"high"`
			Medium   int `json:"medium"`
			Low      int `json:"low"`
			VeryLow  int `json:"very_low"`
		} `json:"scan_summary"`
	}

	if err := p.doRequest(ctx, "GET", path, nil, &result); err != nil {
		return nil, err
	}

	createdAt, _ := time.Parse(time.RFC3339, result.CreatedDate)
	completedAt, _ := time.Parse(time.RFC3339, result.ModifiedDate)

	return &ScanStatus{
		ScanID:      result.ID,
		Status:      result.Status,
		StartedAt:   createdAt,
		CompletedAt: completedAt,
		Summary: &FindingSummary{
			Critical: result.Summary.VeryHigh,
			High:     result.Summary.High,
			Medium:   result.Summary.Medium,
			Low:      result.Summary.Low,
			Info:     result.Summary.VeryLow,
			Total:    result.Summary.VeryHigh + result.Summary.High + result.Summary.Medium + result.Summary.Low + result.Summary.VeryLow,
		},
	}, nil
}

// GetFindings retrieves findings for an application
func (p *VeracodeProvider) GetFindings(ctx context.Context, applicationID string) ([]*Finding, error) {
	path := "/appsec/v2/applications/" + applicationID + "/findings?size=500"

	var result struct {
		Embedded struct {
			Findings []struct {
				IssueID            int    `json:"issue_id"`
				ScanType           string `json:"scan_type"`
				CWE                struct {
					ID          int    `json:"id"`
					Name        string `json:"name"`
					Description string `json:"description"`
				} `json:"cwe"`
				Severity           int    `json:"severity"`
				SeverityDesc       string `json:"severity_desc"`
				FindingStatus      struct {
					Status string `json:"status"`
				} `json:"finding_status"`
				FindingDetails struct {
					FileName   string `json:"file_name"`
					FilePath   string `json:"file_path"`
					LineNumber int    `json:"line_number"`
					AttackVector string `json:"attack_vector"`
				} `json:"finding_details"`
				Description    string `json:"description"`
				Recommendations string `json:"recommendations"`
			} `json:"findings"`
		} `json:"_embedded"`
	}

	if err := p.doRequest(ctx, "GET", path, nil, &result); err != nil {
		return nil, err
	}

	findings := make([]*Finding, 0, len(result.Embedded.Findings))
	for _, f := range result.Embedded.Findings {
		findings = append(findings, &Finding{
			ID:          fmt.Sprintf("%d", f.IssueID),
			Type:        f.ScanType,
			Category:    f.CWE.Name,
			Severity:    mapVeracodeSeverity(f.Severity),
			Title:       f.CWE.Name,
			Description: f.Description,
			FilePath:    f.FindingDetails.FilePath + "/" + f.FindingDetails.FileName,
			StartLine:   f.FindingDetails.LineNumber,
			EndLine:     f.FindingDetails.LineNumber,
			CWE:         fmt.Sprintf("CWE-%d", f.CWE.ID),
			Remediation: f.Recommendations,
			Status:      f.FindingStatus.Status,
			CreatedAt:   time.Now(),
		})
	}

	return findings, nil
}

// GetProjects lists applications
func (p *VeracodeProvider) GetProjects(ctx context.Context) ([]*Project, error) {
	path := "/appsec/v1/applications?size=100"

	var result struct {
		Embedded struct {
			Applications []struct {
				GUID    string `json:"guid"`
				Profile struct {
					Name        string `json:"name"`
					Description string `json:"description"`
				} `json:"profile"`
				LastCompletedScanDate string `json:"last_completed_scan_date"`
			} `json:"applications"`
		} `json:"_embedded"`
	}

	if err := p.doRequest(ctx, "GET", path, nil, &result); err != nil {
		return nil, err
	}

	projects := make([]*Project, 0, len(result.Embedded.Applications))
	for _, app := range result.Embedded.Applications {
		lastScan, _ := time.Parse(time.RFC3339, app.LastCompletedScanDate)

		projects = append(projects, &Project{
			ID:          app.GUID,
			Name:        app.Profile.Name,
			Key:         app.GUID,
			Description: app.Profile.Description,
			LastScan:    lastScan,
			WebURL:      "https://analysiscenter.veracode.com",
		})
	}

	return projects, nil
}

func mapVeracodeSeverity(severity int) string {
	switch severity {
	case 5:
		return "critical"
	case 4:
		return "high"
	case 3:
		return "medium"
	case 2:
		return "low"
	case 1:
		return "info"
	default:
		return "medium"
	}
}

