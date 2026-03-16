// Package secrets provides secrets management and scanning capabilities
package secrets

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"go.uber.org/zap"
)

// ErrNotImplemented is returned by cloud provider stubs that are not yet implemented.
var ErrNotImplemented = errors.New("not implemented")

// Manager provides secrets management capabilities
type Manager struct {
	providers map[string]Provider
	scanner   *Scanner
	logger    *zap.Logger
}

// Provider defines the interface for secrets providers
type Provider interface {
	Name() string
	GetSecret(ctx context.Context, path string) (*Secret, error)
	SetSecret(ctx context.Context, path string, value []byte) error
	DeleteSecret(ctx context.Context, path string) error
	ListSecrets(ctx context.Context, prefix string) ([]string, error)
	RotateSecret(ctx context.Context, path string) error
}

// Secret represents a secret
type Secret struct {
	Path        string            `json:"path"`
	Value       []byte            `json:"-"` // Never serialize
	Version     string            `json:"version"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty"`
	Metadata    map[string]string `json:"metadata"`
	RotationDue bool              `json:"rotation_due"`
}

// NewManager creates a new secrets manager
func NewManager(logger *zap.Logger) *Manager {
	return &Manager{
		providers: make(map[string]Provider),
		scanner:   NewScanner(logger),
		logger:    logger,
	}
}

// RegisterProvider registers a secrets provider
func (m *Manager) RegisterProvider(provider Provider) {
	m.providers[provider.Name()] = provider
	m.logger.Info("Registered secrets provider",
		zap.String("provider", provider.Name()),
	)
}

// GetSecret retrieves a secret from the specified provider
func (m *Manager) GetSecret(ctx context.Context, providerName, path string) (*Secret, error) {
	provider, ok := m.providers[providerName]
	if !ok {
		return nil, fmt.Errorf("provider not found: %s", providerName)
	}

	return provider.GetSecret(ctx, path)
}

// ScanForSecrets scans content for exposed secrets
func (m *Manager) ScanForSecrets(content string) []SecretFinding {
	return m.scanner.Scan(content)
}

// Scanner scans for exposed secrets in content
type Scanner struct {
	patterns []SecretPattern
	logger   *zap.Logger
}

// SecretPattern defines a pattern for detecting secrets
type SecretPattern struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Regex       *regexp.Regexp `json:"-"`
	Pattern     string         `json:"pattern"`
	Severity    string         `json:"severity"`
	Type        string         `json:"type"`
}

// SecretFinding represents a found secret
type SecretFinding struct {
	PatternID   string `json:"pattern_id"`
	PatternName string `json:"pattern_name"`
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Line        int    `json:"line"`
	Column      int    `json:"column"`
	Match       string `json:"match"`   // Redacted match
	Context     string `json:"context"` // Surrounding context
	File        string `json:"file,omitempty"`
}

// NewScanner creates a new secrets scanner
func NewScanner(logger *zap.Logger) *Scanner {
	s := &Scanner{
		patterns: make([]SecretPattern, 0),
		logger:   logger,
	}

	s.loadDefaultPatterns()
	return s
}

func (s *Scanner) loadDefaultPatterns() {
	patterns := []struct {
		id          string
		name        string
		description string
		pattern     string
		severity    string
		secretType  string
	}{
		// AWS
		{
			id:          "AWS_ACCESS_KEY",
			name:        "AWS Access Key ID",
			description: "AWS Access Key ID",
			pattern:     `(?i)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[0-9A-Z]{16}`,
			severity:    "critical",
			secretType:  "aws_credentials",
		},
		{
			id:          "AWS_SECRET_KEY",
			name:        "AWS Secret Access Key",
			description: "AWS Secret Access Key",
			pattern:     `(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?`,
			severity:    "critical",
			secretType:  "aws_credentials",
		},

		// Azure
		{
			id:          "AZURE_CONNECTION_STRING",
			name:        "Azure Storage Connection String",
			description: "Azure Storage account connection string",
			pattern:     `(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}`,
			severity:    "critical",
			secretType:  "azure_credentials",
		},
		{
			id:          "AZURE_CLIENT_SECRET",
			name:        "Azure Client Secret",
			description: "Azure AD client secret",
			pattern:     `(?i)azure[_-]?client[_-]?secret\s*[=:]\s*['\"]?([A-Za-z0-9~._-]{34,})['\"]?`,
			severity:    "critical",
			secretType:  "azure_credentials",
		},

		// GCP
		{
			id:          "GCP_SERVICE_ACCOUNT",
			name:        "GCP Service Account Key",
			description: "Google Cloud service account key",
			pattern:     `(?s)"type"\s*:\s*"service_account".*"private_key"`,
			severity:    "critical",
			secretType:  "gcp_credentials",
		},

		// API Keys
		{
			id:          "GENERIC_API_KEY",
			name:        "Generic API Key",
			description: "Generic API key pattern",
			pattern:     `(?i)(api[_-]?key|apikey|api_secret)\s*[=:]\s*['\"]?([A-Za-z0-9_-]{20,})['\"]?`,
			severity:    "high",
			secretType:  "api_key",
		},

		// Anthropic
		{
			id:          "ANTHROPIC_API_KEY",
			name:        "Anthropic API Key",
			description: "Anthropic Claude API key",
			pattern:     `sk-ant-[A-Za-z0-9_-]{40,}`,
			severity:    "critical",
			secretType:  "api_key",
		},

		// OpenAI
		{
			id:          "OPENAI_API_KEY",
			name:        "OpenAI API Key",
			description: "OpenAI API key",
			pattern:     `sk-[A-Za-z0-9]{48}`,
			severity:    "critical",
			secretType:  "api_key",
		},

		// GitHub
		{
			id:          "GITHUB_TOKEN",
			name:        "GitHub Token",
			description: "GitHub personal access token or app token",
			pattern:     `(?i)(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}`,
			severity:    "critical",
			secretType:  "github_token",
		},

		// Private Keys
		{
			id:          "PRIVATE_KEY",
			name:        "Private Key",
			description: "RSA/EC private key",
			pattern:     `-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`,
			severity:    "critical",
			secretType:  "private_key",
		},

		// Database
		{
			id:          "DATABASE_URL",
			name:        "Database Connection String",
			description: "Database connection string with credentials",
			pattern:     `(?i)(postgres|mysql|mongodb|redis)://[^:]+:[^@]+@[^\s]+`,
			severity:    "critical",
			secretType:  "database_credentials",
		},

		// JWT
		{
			id:          "JWT_SECRET",
			name:        "JWT Secret",
			description: "JWT signing secret",
			pattern:     `(?i)jwt[_-]?secret\s*[=:]\s*['\"]?([A-Za-z0-9_-]{32,})['\"]?`,
			severity:    "high",
			secretType:  "jwt_secret",
		},

		// Slack
		{
			id:          "SLACK_TOKEN",
			name:        "Slack Token",
			description: "Slack bot or user token",
			pattern:     `xox[baprs]-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24}`,
			severity:    "high",
			secretType:  "slack_token",
		},

		// Generic Password
		{
			id:          "PASSWORD_IN_URL",
			name:        "Password in URL",
			description: "Password embedded in URL",
			pattern:     `(?i)://[^:]+:[^@]+@`,
			severity:    "high",
			secretType:  "password",
		},
	}

	for _, p := range patterns {
		compiled, err := regexp.Compile(p.pattern)
		if err != nil {
			s.logger.Error("Failed to compile pattern",
				zap.String("id", p.id),
				zap.Error(err),
			)
			continue
		}

		s.patterns = append(s.patterns, SecretPattern{
			ID:          p.id,
			Name:        p.name,
			Description: p.description,
			Regex:       compiled,
			Pattern:     p.pattern,
			Severity:    p.severity,
			Type:        p.secretType,
		})
	}

	s.logger.Info("Loaded secret patterns",
		zap.Int("count", len(s.patterns)),
	)
}

// Scan scans content for secrets
func (s *Scanner) Scan(content string) []SecretFinding {
	findings := make([]SecretFinding, 0)

	lines := splitLines(content)

	for _, pattern := range s.patterns {
		for lineNum, line := range lines {
			matches := pattern.Regex.FindAllStringIndex(line, -1)
			for _, match := range matches {
				finding := SecretFinding{
					PatternID:   pattern.ID,
					PatternName: pattern.Name,
					Type:        pattern.Type,
					Severity:    pattern.Severity,
					Line:        lineNum + 1,
					Column:      match[0] + 1,
					Match:       redactSecret(line[match[0]:match[1]]),
					Context:     getContext(lines, lineNum),
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// ScanFile scans a file for secrets
func (s *Scanner) ScanFile(ctx context.Context, filepath string, content string) []SecretFinding {
	findings := s.Scan(content)
	for i := range findings {
		findings[i].File = filepath
	}
	return findings
}

func splitLines(content string) []string {
	lines := make([]string, 0)
	start := 0
	for i, c := range content {
		if c == '\n' {
			lines = append(lines, content[start:i])
			start = i + 1
		}
	}
	if start < len(content) {
		lines = append(lines, content[start:])
	}
	return lines
}

func redactSecret(secret string) string { return "***REDACTED***" }

func getContext(lines []string, lineNum int) string {
	start := lineNum - 1
	if start < 0 {
		start = 0
	}
	end := lineNum + 2
	if end > len(lines) {
		end = len(lines)
	}

	context := ""
	for i := start; i < end; i++ {
		if i == lineNum {
			context += ">>> " + lines[i] + "\n"
		} else {
			context += "    " + lines[i] + "\n"
		}
	}
	return context
}

// =============================================================================
// Secrets Provider Implementations
// =============================================================================

// AWSSecretsProvider implements secrets provider for AWS Secrets Manager
type AWSSecretsProvider struct {
	region string
	logger *zap.Logger
}

// NewAWSSecretsProvider creates a new AWS Secrets Manager provider
func NewAWSSecretsProvider(region string, logger *zap.Logger) *AWSSecretsProvider {
	return &AWSSecretsProvider{
		region: region,
		logger: logger,
	}
}

func (p *AWSSecretsProvider) Name() string { return "aws" }

func (p *AWSSecretsProvider) GetSecret(ctx context.Context, path string) (*Secret, error) {
	// TODO: Implement AWS Secrets Manager integration
	return nil, fmt.Errorf("not implemented: %w", ErrNotImplemented)
}

func (p *AWSSecretsProvider) SetSecret(ctx context.Context, path string, value []byte) error {
	// TODO: Implement AWS Secrets Manager integration
	return fmt.Errorf("not implemented: %w", ErrNotImplemented)
}

func (p *AWSSecretsProvider) DeleteSecret(ctx context.Context, path string) error {
	// TODO: Implement AWS Secrets Manager integration
	return fmt.Errorf("not implemented: %w", ErrNotImplemented)
}

func (p *AWSSecretsProvider) ListSecrets(ctx context.Context, prefix string) ([]string, error) {
	// TODO: Implement AWS Secrets Manager integration
	return nil, fmt.Errorf("not implemented: %w", ErrNotImplemented)
}

func (p *AWSSecretsProvider) RotateSecret(ctx context.Context, path string) error {
	// TODO: Implement AWS Secrets Manager integration
	return fmt.Errorf("not implemented: %w", ErrNotImplemented)
}

// AzureKeyVaultProvider implements secrets provider for Azure Key Vault
type AzureKeyVaultProvider struct {
	vaultURL string
	logger   *zap.Logger
}

// NewAzureKeyVaultProvider creates a new Azure Key Vault provider
func NewAzureKeyVaultProvider(vaultURL string, logger *zap.Logger) *AzureKeyVaultProvider {
	return &AzureKeyVaultProvider{
		vaultURL: vaultURL,
		logger:   logger,
	}
}

func (p *AzureKeyVaultProvider) Name() string { return "azure" }

func (p *AzureKeyVaultProvider) GetSecret(ctx context.Context, path string) (*Secret, error) {
	// TODO: Implement Azure Key Vault integration
	return nil, fmt.Errorf("not implemented: %w", ErrNotImplemented)
}

func (p *AzureKeyVaultProvider) SetSecret(ctx context.Context, path string, value []byte) error {
	// TODO: Implement Azure Key Vault integration
	return fmt.Errorf("not implemented: %w", ErrNotImplemented)
}

func (p *AzureKeyVaultProvider) DeleteSecret(ctx context.Context, path string) error {
	// TODO: Implement Azure Key Vault integration
	return fmt.Errorf("not implemented: %w", ErrNotImplemented)
}

func (p *AzureKeyVaultProvider) ListSecrets(ctx context.Context, prefix string) ([]string, error) {
	// TODO: Implement Azure Key Vault integration
	return nil, fmt.Errorf("not implemented: %w", ErrNotImplemented)
}

func (p *AzureKeyVaultProvider) RotateSecret(ctx context.Context, path string) error {
	// TODO: Implement Azure Key Vault integration
	return fmt.Errorf("not implemented: %w", ErrNotImplemented)
}

// GCPSecretManagerProvider implements secrets provider for GCP Secret Manager
type GCPSecretManagerProvider struct {
	projectID string
	logger    *zap.Logger
}

// NewGCPSecretManagerProvider creates a new GCP Secret Manager provider
func NewGCPSecretManagerProvider(projectID string, logger *zap.Logger) *GCPSecretManagerProvider {
	return &GCPSecretManagerProvider{
		projectID: projectID,
		logger:    logger,
	}
}

func (p *GCPSecretManagerProvider) Name() string { return "gcp" }

func (p *GCPSecretManagerProvider) GetSecret(ctx context.Context, path string) (*Secret, error) {
	// TODO: Implement GCP Secret Manager integration
	return nil, fmt.Errorf("not implemented: %w", ErrNotImplemented)
}

func (p *GCPSecretManagerProvider) SetSecret(ctx context.Context, path string, value []byte) error {
	// TODO: Implement GCP Secret Manager integration
	return fmt.Errorf("not implemented: %w", ErrNotImplemented)
}

func (p *GCPSecretManagerProvider) DeleteSecret(ctx context.Context, path string) error {
	// TODO: Implement GCP Secret Manager integration
	return fmt.Errorf("not implemented: %w", ErrNotImplemented)
}

func (p *GCPSecretManagerProvider) ListSecrets(ctx context.Context, prefix string) ([]string, error) {
	// TODO: Implement GCP Secret Manager integration
	return nil, fmt.Errorf("not implemented: %w", ErrNotImplemented)
}

func (p *GCPSecretManagerProvider) RotateSecret(ctx context.Context, path string) error {
	// TODO: Implement GCP Secret Manager integration
	return fmt.Errorf("not implemented: %w", ErrNotImplemented)
}
