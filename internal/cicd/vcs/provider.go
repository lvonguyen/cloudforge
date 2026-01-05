// Package vcs provides version control system integrations
package vcs

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// Provider defines the interface for VCS providers
type Provider interface {
	// Name returns the provider name
	Name() string

	// GetRepositories lists repositories
	GetRepositories(ctx context.Context) ([]*Repository, error)

	// GetRepository gets a specific repository
	GetRepository(ctx context.Context, owner, repo string) (*Repository, error)

	// GetBranches lists branches for a repository
	GetBranches(ctx context.Context, owner, repo string) ([]*Branch, error)

	// GetCommits gets recent commits
	GetCommits(ctx context.Context, owner, repo, branch string, limit int) ([]*Commit, error)

	// GetPullRequests lists pull/merge requests
	GetPullRequests(ctx context.Context, owner, repo string, state string) ([]*PullRequest, error)

	// GetPipelines gets CI/CD pipelines
	GetPipelines(ctx context.Context, owner, repo string) ([]*Pipeline, error)

	// GetSecurityAlerts gets security alerts/vulnerabilities
	GetSecurityAlerts(ctx context.Context, owner, repo string) ([]*SecurityAlert, error)

	// CreateComment creates a comment on a PR/MR
	CreateComment(ctx context.Context, owner, repo string, prNumber int, comment string) error

	// CreateCheckRun creates a check run (GitHub) or pipeline status
	CreateCheckRun(ctx context.Context, owner, repo, sha string, check *CheckRun) error
}

// Repository represents a code repository
type Repository struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	FullName      string    `json:"full_name"`
	Description   string    `json:"description"`
	DefaultBranch string    `json:"default_branch"`
	Private       bool      `json:"private"`
	URL           string    `json:"url"`
	CloneURL      string    `json:"clone_url"`
	Language      string    `json:"language"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Branch represents a git branch
type Branch struct {
	Name      string `json:"name"`
	SHA       string `json:"sha"`
	Protected bool   `json:"protected"`
}

// Commit represents a git commit
type Commit struct {
	SHA       string    `json:"sha"`
	Message   string    `json:"message"`
	Author    string    `json:"author"`
	Email     string    `json:"email"`
	Timestamp time.Time `json:"timestamp"`
	URL       string    `json:"url"`
}

// PullRequest represents a pull/merge request
type PullRequest struct {
	ID          int       `json:"id"`
	Number      int       `json:"number"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	State       string    `json:"state"`
	Author      string    `json:"author"`
	SourceBranch string   `json:"source_branch"`
	TargetBranch string   `json:"target_branch"`
	URL         string    `json:"url"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Pipeline represents a CI/CD pipeline
type Pipeline struct {
	ID         int       `json:"id"`
	Name       string    `json:"name"`
	Status     string    `json:"status"`
	Ref        string    `json:"ref"`
	SHA        string    `json:"sha"`
	WebURL     string    `json:"web_url"`
	CreatedAt  time.Time `json:"created_at"`
	FinishedAt time.Time `json:"finished_at"`
	Duration   int       `json:"duration"`
}

// SecurityAlert represents a security vulnerability alert
type SecurityAlert struct {
	ID               string    `json:"id"`
	Severity         string    `json:"severity"`
	Summary          string    `json:"summary"`
	Description      string    `json:"description"`
	Package          string    `json:"package"`
	VulnerableVersion string   `json:"vulnerable_version"`
	PatchedVersion   string    `json:"patched_version"`
	CVE              string    `json:"cve"`
	URL              string    `json:"url"`
	State            string    `json:"state"`
	CreatedAt        time.Time `json:"created_at"`
}

// CheckRun represents a CI check run
type CheckRun struct {
	Name        string            `json:"name"`
	Status      string            `json:"status"`      // queued, in_progress, completed
	Conclusion  string            `json:"conclusion"`  // success, failure, neutral, cancelled, timed_out, action_required
	Title       string            `json:"title"`
	Summary     string            `json:"summary"`
	Text        string            `json:"text"`
	Annotations []CheckAnnotation `json:"annotations"`
}

// CheckAnnotation represents an annotation on a check run
type CheckAnnotation struct {
	Path            string `json:"path"`
	StartLine       int    `json:"start_line"`
	EndLine         int    `json:"end_line"`
	AnnotationLevel string `json:"annotation_level"` // notice, warning, failure
	Message         string `json:"message"`
	Title           string `json:"title"`
}

// Manager manages VCS providers
type Manager struct {
	providers map[string]Provider
	logger    *zap.Logger
}

// NewManager creates a new VCS manager
func NewManager(logger *zap.Logger) *Manager {
	return &Manager{
		providers: make(map[string]Provider),
		logger:    logger,
	}
}

// RegisterProvider registers a VCS provider
func (m *Manager) RegisterProvider(provider Provider) {
	m.providers[provider.Name()] = provider
	m.logger.Info("Registered VCS provider",
		zap.String("provider", provider.Name()),
	)
}

// GetProvider returns a provider by name
func (m *Manager) GetProvider(name string) (Provider, bool) {
	p, ok := m.providers[name]
	return p, ok
}

// GetAllProviders returns all registered providers
func (m *Manager) GetAllProviders() []Provider {
	providers := make([]Provider, 0, len(m.providers))
	for _, p := range m.providers {
		providers = append(providers, p)
	}
	return providers
}

