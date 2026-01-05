// Package sast provides SAST/DAST security scanning tool integrations
package sast

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// Provider defines the interface for SAST/DAST tools
type Provider interface {
	// Name returns the provider name
	Name() string

	// Type returns the tool type (sast, dast, sca, iac)
	Type() string

	// Scan initiates a scan
	Scan(ctx context.Context, req *ScanRequest) (*ScanResult, error)

	// GetScanStatus gets the status of a scan
	GetScanStatus(ctx context.Context, scanID string) (*ScanStatus, error)

	// GetFindings retrieves findings from a scan
	GetFindings(ctx context.Context, scanID string) ([]*Finding, error)

	// GetProjects lists available projects/applications
	GetProjects(ctx context.Context) ([]*Project, error)
}

// ScanRequest represents a scan request
type ScanRequest struct {
	ProjectID   string            `json:"project_id"`
	ProjectName string            `json:"project_name"`
	Branch      string            `json:"branch"`
	CommitSHA   string            `json:"commit_sha"`
	RepoURL     string            `json:"repo_url"`
	SourcePath  string            `json:"source_path"`
	Config      map[string]string `json:"config"`
}

// ScanResult represents the result of initiating a scan
type ScanResult struct {
	ScanID    string    `json:"scan_id"`
	Status    string    `json:"status"`
	WebURL    string    `json:"web_url"`
	StartedAt time.Time `json:"started_at"`
}

// ScanStatus represents the status of a scan
type ScanStatus struct {
	ScanID      string    `json:"scan_id"`
	Status      string    `json:"status"` // queued, running, completed, failed
	Progress    int       `json:"progress"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
	WebURL      string    `json:"web_url"`
	Summary     *FindingSummary `json:"summary"`
}

// FindingSummary summarizes findings
type FindingSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

// Finding represents a security finding
type Finding struct {
	ID           string    `json:"id"`
	Type         string    `json:"type"`      // vulnerability, code_smell, bug, security_hotspot
	Category     string    `json:"category"`
	Severity     string    `json:"severity"`
	Title        string    `json:"title"`
	Description  string    `json:"description"`
	FilePath     string    `json:"file_path"`
	StartLine    int       `json:"start_line"`
	EndLine      int       `json:"end_line"`
	Snippet      string    `json:"snippet"`
	CWE          string    `json:"cwe"`
	CVE          string    `json:"cve"`
	CVSS         float64   `json:"cvss"`
	Remediation  string    `json:"remediation"`
	Status       string    `json:"status"` // open, confirmed, fixed, false_positive
	CreatedAt    time.Time `json:"created_at"`
}

// Project represents a project/application in the SAST tool
type Project struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Key         string    `json:"key"`
	Description string    `json:"description"`
	LastScan    time.Time `json:"last_scan"`
	WebURL      string    `json:"web_url"`
}

// Manager manages SAST/DAST providers
type Manager struct {
	providers map[string]Provider
	logger    *zap.Logger
}

// NewManager creates a new SAST manager
func NewManager(logger *zap.Logger) *Manager {
	return &Manager{
		providers: make(map[string]Provider),
		logger:    logger,
	}
}

// RegisterProvider registers a provider
func (m *Manager) RegisterProvider(provider Provider) {
	m.providers[provider.Name()] = provider
	m.logger.Info("Registered SAST/DAST provider",
		zap.String("provider", provider.Name()),
		zap.String("type", provider.Type()),
	)
}

// GetProvider returns a provider by name
func (m *Manager) GetProvider(name string) (Provider, bool) {
	p, ok := m.providers[name]
	return p, ok
}

// GetProvidersByType returns providers by type
func (m *Manager) GetProvidersByType(toolType string) []Provider {
	var providers []Provider
	for _, p := range m.providers {
		if p.Type() == toolType {
			providers = append(providers, p)
		}
	}
	return providers
}

// ScanAll runs scans across all registered providers
func (m *Manager) ScanAll(ctx context.Context, req *ScanRequest) ([]*ScanResult, error) {
	var results []*ScanResult

	for _, p := range m.providers {
		result, err := p.Scan(ctx, req)
		if err != nil {
			m.logger.Warn("Scan failed for provider",
				zap.String("provider", p.Name()),
				zap.Error(err),
			)
			continue
		}
		results = append(results, result)
	}

	return results, nil
}

