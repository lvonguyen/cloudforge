// Package vcs provides version control system integrations
package vcs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"go.uber.org/zap"
)

// GitHubProvider implements the Provider interface for GitHub/GitHub Enterprise
type GitHubProvider struct {
	baseURL    string
	token      string
	httpClient *http.Client
	logger     *zap.Logger
	config     GitHubConfig
}

// GitHubConfig configures the GitHub provider
type GitHubConfig struct {
	BaseURL   string `yaml:"base_url"`   // https://api.github.com or enterprise URL
	TokenEnv  string `yaml:"token_env"`
	Org       string `yaml:"org"`
	Enterprise bool  `yaml:"enterprise"`
}

// NewGitHubProvider creates a new GitHub provider
func NewGitHubProvider(cfg GitHubConfig, logger *zap.Logger) (*GitHubProvider, error) {
	token := os.Getenv(cfg.TokenEnv)
	if token == "" {
		return nil, fmt.Errorf("missing GitHub token from env: %s", cfg.TokenEnv)
	}

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}

	return &GitHubProvider{
		baseURL:    baseURL,
		token:      token,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		logger:     logger,
		config:     cfg,
	}, nil
}

func (p *GitHubProvider) Name() string {
	if p.config.Enterprise {
		return "github-enterprise"
	}
	return "github"
}

func (p *GitHubProvider) doRequest(ctx context.Context, method, url string, body interface{}, result interface{}) error {
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
		req, err = http.NewRequestWithContext(ctx, method, url, reqBody)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, url, nil)
	}
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
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

// GetRepositories lists repositories for the org
func (p *GitHubProvider) GetRepositories(ctx context.Context) ([]*Repository, error) {
	url := fmt.Sprintf("%s/orgs/%s/repos?per_page=100", p.baseURL, p.config.Org)

	var ghRepos []struct {
		ID            int    `json:"id"`
		Name          string `json:"name"`
		FullName      string `json:"full_name"`
		Description   string `json:"description"`
		DefaultBranch string `json:"default_branch"`
		Private       bool   `json:"private"`
		HTMLURL       string `json:"html_url"`
		CloneURL      string `json:"clone_url"`
		Language      string `json:"language"`
		CreatedAt     string `json:"created_at"`
		UpdatedAt     string `json:"updated_at"`
	}

	if err := p.doRequest(ctx, "GET", url, nil, &ghRepos); err != nil {
		return nil, err
	}

	repos := make([]*Repository, 0, len(ghRepos))
	for _, r := range ghRepos {
		createdAt, _ := time.Parse(time.RFC3339, r.CreatedAt)
		updatedAt, _ := time.Parse(time.RFC3339, r.UpdatedAt)

		repos = append(repos, &Repository{
			ID:            fmt.Sprintf("%d", r.ID),
			Name:          r.Name,
			FullName:      r.FullName,
			Description:   r.Description,
			DefaultBranch: r.DefaultBranch,
			Private:       r.Private,
			URL:           r.HTMLURL,
			CloneURL:      r.CloneURL,
			Language:      r.Language,
			CreatedAt:     createdAt,
			UpdatedAt:     updatedAt,
		})
	}

	return repos, nil
}

// GetRepository gets a specific repository
func (p *GitHubProvider) GetRepository(ctx context.Context, owner, repo string) (*Repository, error) {
	url := fmt.Sprintf("%s/repos/%s/%s", p.baseURL, owner, repo)

	var r struct {
		ID            int    `json:"id"`
		Name          string `json:"name"`
		FullName      string `json:"full_name"`
		Description   string `json:"description"`
		DefaultBranch string `json:"default_branch"`
		Private       bool   `json:"private"`
		HTMLURL       string `json:"html_url"`
		CloneURL      string `json:"clone_url"`
		Language      string `json:"language"`
	}

	if err := p.doRequest(ctx, "GET", url, nil, &r); err != nil {
		return nil, err
	}

	return &Repository{
		ID:            fmt.Sprintf("%d", r.ID),
		Name:          r.Name,
		FullName:      r.FullName,
		Description:   r.Description,
		DefaultBranch: r.DefaultBranch,
		Private:       r.Private,
		URL:           r.HTMLURL,
		CloneURL:      r.CloneURL,
		Language:      r.Language,
	}, nil
}

// GetBranches lists branches
func (p *GitHubProvider) GetBranches(ctx context.Context, owner, repo string) ([]*Branch, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/branches", p.baseURL, owner, repo)

	var ghBranches []struct {
		Name      string `json:"name"`
		Commit    struct {
			SHA string `json:"sha"`
		} `json:"commit"`
		Protected bool `json:"protected"`
	}

	if err := p.doRequest(ctx, "GET", url, nil, &ghBranches); err != nil {
		return nil, err
	}

	branches := make([]*Branch, 0, len(ghBranches))
	for _, b := range ghBranches {
		branches = append(branches, &Branch{
			Name:      b.Name,
			SHA:       b.Commit.SHA,
			Protected: b.Protected,
		})
	}

	return branches, nil
}

// GetCommits gets recent commits
func (p *GitHubProvider) GetCommits(ctx context.Context, owner, repo, branch string, limit int) ([]*Commit, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/commits?sha=%s&per_page=%d", p.baseURL, owner, repo, branch, limit)

	var ghCommits []struct {
		SHA    string `json:"sha"`
		Commit struct {
			Message string `json:"message"`
			Author  struct {
				Name  string `json:"name"`
				Email string `json:"email"`
				Date  string `json:"date"`
			} `json:"author"`
		} `json:"commit"`
		HTMLURL string `json:"html_url"`
	}

	if err := p.doRequest(ctx, "GET", url, nil, &ghCommits); err != nil {
		return nil, err
	}

	commits := make([]*Commit, 0, len(ghCommits))
	for _, c := range ghCommits {
		ts, _ := time.Parse(time.RFC3339, c.Commit.Author.Date)
		commits = append(commits, &Commit{
			SHA:       c.SHA,
			Message:   c.Commit.Message,
			Author:    c.Commit.Author.Name,
			Email:     c.Commit.Author.Email,
			Timestamp: ts,
			URL:       c.HTMLURL,
		})
	}

	return commits, nil
}

// GetPullRequests lists pull requests
func (p *GitHubProvider) GetPullRequests(ctx context.Context, owner, repo string, state string) ([]*PullRequest, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/pulls?state=%s", p.baseURL, owner, repo, state)

	var ghPRs []struct {
		ID        int    `json:"id"`
		Number    int    `json:"number"`
		Title     string `json:"title"`
		Body      string `json:"body"`
		State     string `json:"state"`
		User      struct {
			Login string `json:"login"`
		} `json:"user"`
		Head struct {
			Ref string `json:"ref"`
		} `json:"head"`
		Base struct {
			Ref string `json:"ref"`
		} `json:"base"`
		HTMLURL   string `json:"html_url"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
	}

	if err := p.doRequest(ctx, "GET", url, nil, &ghPRs); err != nil {
		return nil, err
	}

	prs := make([]*PullRequest, 0, len(ghPRs))
	for _, pr := range ghPRs {
		createdAt, _ := time.Parse(time.RFC3339, pr.CreatedAt)
		updatedAt, _ := time.Parse(time.RFC3339, pr.UpdatedAt)

		prs = append(prs, &PullRequest{
			ID:           pr.ID,
			Number:       pr.Number,
			Title:        pr.Title,
			Description:  pr.Body,
			State:        pr.State,
			Author:       pr.User.Login,
			SourceBranch: pr.Head.Ref,
			TargetBranch: pr.Base.Ref,
			URL:          pr.HTMLURL,
			CreatedAt:    createdAt,
			UpdatedAt:    updatedAt,
		})
	}

	return prs, nil
}

// GetPipelines gets workflow runs (GitHub Actions)
func (p *GitHubProvider) GetPipelines(ctx context.Context, owner, repo string) ([]*Pipeline, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/actions/runs?per_page=50", p.baseURL, owner, repo)

	var result struct {
		WorkflowRuns []struct {
			ID           int    `json:"id"`
			Name         string `json:"name"`
			Status       string `json:"status"`
			Conclusion   string `json:"conclusion"`
			HeadBranch   string `json:"head_branch"`
			HeadSHA      string `json:"head_sha"`
			HTMLURL      string `json:"html_url"`
			CreatedAt    string `json:"created_at"`
			UpdatedAt    string `json:"updated_at"`
			RunStartedAt string `json:"run_started_at"`
		} `json:"workflow_runs"`
	}

	if err := p.doRequest(ctx, "GET", url, nil, &result); err != nil {
		return nil, err
	}

	pipelines := make([]*Pipeline, 0, len(result.WorkflowRuns))
	for _, run := range result.WorkflowRuns {
		createdAt, _ := time.Parse(time.RFC3339, run.CreatedAt)
		updatedAt, _ := time.Parse(time.RFC3339, run.UpdatedAt)

		status := run.Status
		if run.Conclusion != "" {
			status = run.Conclusion
		}

		pipelines = append(pipelines, &Pipeline{
			ID:         run.ID,
			Name:       run.Name,
			Status:     status,
			Ref:        run.HeadBranch,
			SHA:        run.HeadSHA,
			WebURL:     run.HTMLURL,
			CreatedAt:  createdAt,
			FinishedAt: updatedAt,
		})
	}

	return pipelines, nil
}

// GetSecurityAlerts gets Dependabot alerts
func (p *GitHubProvider) GetSecurityAlerts(ctx context.Context, owner, repo string) ([]*SecurityAlert, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/dependabot/alerts", p.baseURL, owner, repo)

	var ghAlerts []struct {
		Number         int    `json:"number"`
		State          string `json:"state"`
		SecurityAdvisory struct {
			GHSAID      string `json:"ghsa_id"`
			CVEId       string `json:"cve_id"`
			Summary     string `json:"summary"`
			Description string `json:"description"`
			Severity    string `json:"severity"`
		} `json:"security_advisory"`
		SecurityVulnerability struct {
			Package struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			VulnerableVersionRange string `json:"vulnerable_version_range"`
			FirstPatchedVersion    struct {
				Identifier string `json:"identifier"`
			} `json:"first_patched_version"`
		} `json:"security_vulnerability"`
		HTMLURL   string `json:"html_url"`
		CreatedAt string `json:"created_at"`
	}

	if err := p.doRequest(ctx, "GET", url, nil, &ghAlerts); err != nil {
		return nil, err
	}

	alerts := make([]*SecurityAlert, 0, len(ghAlerts))
	for _, a := range ghAlerts {
		createdAt, _ := time.Parse(time.RFC3339, a.CreatedAt)

		alerts = append(alerts, &SecurityAlert{
			ID:                fmt.Sprintf("%d", a.Number),
			Severity:          a.SecurityAdvisory.Severity,
			Summary:           a.SecurityAdvisory.Summary,
			Description:       a.SecurityAdvisory.Description,
			Package:           a.SecurityVulnerability.Package.Name,
			VulnerableVersion: a.SecurityVulnerability.VulnerableVersionRange,
			PatchedVersion:    a.SecurityVulnerability.FirstPatchedVersion.Identifier,
			CVE:               a.SecurityAdvisory.CVEId,
			URL:               a.HTMLURL,
			State:             a.State,
			CreatedAt:         createdAt,
		})
	}

	return alerts, nil
}

// CreateComment creates a comment on a PR
func (p *GitHubProvider) CreateComment(ctx context.Context, owner, repo string, prNumber int, comment string) error {
	url := fmt.Sprintf("%s/repos/%s/%s/issues/%d/comments", p.baseURL, owner, repo, prNumber)

	body := map[string]string{"body": comment}
	return p.doRequest(ctx, "POST", url, body, nil)
}

// CreateCheckRun creates a check run
func (p *GitHubProvider) CreateCheckRun(ctx context.Context, owner, repo, sha string, check *CheckRun) error {
	url := fmt.Sprintf("%s/repos/%s/%s/check-runs", p.baseURL, owner, repo)

	body := map[string]interface{}{
		"name":       check.Name,
		"head_sha":   sha,
		"status":     check.Status,
		"conclusion": check.Conclusion,
		"output": map[string]interface{}{
			"title":       check.Title,
			"summary":     check.Summary,
			"text":        check.Text,
			"annotations": check.Annotations,
		},
	}

	return p.doRequest(ctx, "POST", url, body, nil)
}

