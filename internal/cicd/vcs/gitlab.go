// Package vcs provides version control system integrations
package vcs

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

// GitLabProvider implements the Provider interface for GitLab
type GitLabProvider struct {
	baseURL    string
	token      string
	httpClient *http.Client
	logger     *zap.Logger
	config     GitLabConfig
}

// GitLabConfig configures the GitLab provider
type GitLabConfig struct {
	BaseURL  string `yaml:"base_url"` // https://gitlab.com or self-hosted
	TokenEnv string `yaml:"token_env"`
	GroupID  string `yaml:"group_id"`
}

// NewGitLabProvider creates a new GitLab provider
func NewGitLabProvider(cfg GitLabConfig, logger *zap.Logger) (*GitLabProvider, error) {
	token := os.Getenv(cfg.TokenEnv)
	if token == "" {
		return nil, fmt.Errorf("missing GitLab token from env: %s", cfg.TokenEnv)
	}

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = "https://gitlab.com"
	}

	return &GitLabProvider{
		baseURL:    baseURL + "/api/v4",
		token:      token,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		logger:     logger,
		config:     cfg,
	}, nil
}

func (p *GitLabProvider) Name() string { return "gitlab" }

func (p *GitLabProvider) doRequest(ctx context.Context, method, requestURL string, body interface{}, result interface{}) error {
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

	req.Header.Set("PRIVATE-TOKEN", p.token)
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

// GetRepositories lists projects in the group
func (p *GitLabProvider) GetRepositories(ctx context.Context) ([]*Repository, error) {
	requestURL := fmt.Sprintf("%s/groups/%s/projects?per_page=100", p.baseURL, p.config.GroupID)

	var glProjects []struct {
		ID             int    `json:"id"`
		Name           string `json:"name"`
		PathWithNamespace string `json:"path_with_namespace"`
		Description    string `json:"description"`
		DefaultBranch  string `json:"default_branch"`
		Visibility     string `json:"visibility"`
		WebURL         string `json:"web_url"`
		HTTPURLToRepo  string `json:"http_url_to_repo"`
		CreatedAt      string `json:"created_at"`
		LastActivityAt string `json:"last_activity_at"`
	}

	if err := p.doRequest(ctx, "GET", requestURL, nil, &glProjects); err != nil {
		return nil, err
	}

	repos := make([]*Repository, 0, len(glProjects))
	for _, r := range glProjects {
		createdAt, _ := time.Parse(time.RFC3339, r.CreatedAt)
		updatedAt, _ := time.Parse(time.RFC3339, r.LastActivityAt)

		repos = append(repos, &Repository{
			ID:            fmt.Sprintf("%d", r.ID),
			Name:          r.Name,
			FullName:      r.PathWithNamespace,
			Description:   r.Description,
			DefaultBranch: r.DefaultBranch,
			Private:       r.Visibility == "private",
			URL:           r.WebURL,
			CloneURL:      r.HTTPURLToRepo,
			CreatedAt:     createdAt,
			UpdatedAt:     updatedAt,
		})
	}

	return repos, nil
}

// GetRepository gets a specific project
func (p *GitLabProvider) GetRepository(ctx context.Context, owner, repo string) (*Repository, error) {
	projectPath := url.PathEscape(owner + "/" + repo)
	requestURL := fmt.Sprintf("%s/projects/%s", p.baseURL, projectPath)

	var r struct {
		ID             int    `json:"id"`
		Name           string `json:"name"`
		PathWithNamespace string `json:"path_with_namespace"`
		Description    string `json:"description"`
		DefaultBranch  string `json:"default_branch"`
		Visibility     string `json:"visibility"`
		WebURL         string `json:"web_url"`
		HTTPURLToRepo  string `json:"http_url_to_repo"`
	}

	if err := p.doRequest(ctx, "GET", requestURL, nil, &r); err != nil {
		return nil, err
	}

	return &Repository{
		ID:            fmt.Sprintf("%d", r.ID),
		Name:          r.Name,
		FullName:      r.PathWithNamespace,
		Description:   r.Description,
		DefaultBranch: r.DefaultBranch,
		Private:       r.Visibility == "private",
		URL:           r.WebURL,
		CloneURL:      r.HTTPURLToRepo,
	}, nil
}

// GetBranches lists branches
func (p *GitLabProvider) GetBranches(ctx context.Context, owner, repo string) ([]*Branch, error) {
	projectPath := url.PathEscape(owner + "/" + repo)
	requestURL := fmt.Sprintf("%s/projects/%s/repository/branches", p.baseURL, projectPath)

	var glBranches []struct {
		Name      string `json:"name"`
		Commit    struct {
			ID string `json:"id"`
		} `json:"commit"`
		Protected bool `json:"protected"`
	}

	if err := p.doRequest(ctx, "GET", requestURL, nil, &glBranches); err != nil {
		return nil, err
	}

	branches := make([]*Branch, 0, len(glBranches))
	for _, b := range glBranches {
		branches = append(branches, &Branch{
			Name:      b.Name,
			SHA:       b.Commit.ID,
			Protected: b.Protected,
		})
	}

	return branches, nil
}

// GetCommits gets recent commits
func (p *GitLabProvider) GetCommits(ctx context.Context, owner, repo, branch string, limit int) ([]*Commit, error) {
	projectPath := url.PathEscape(owner + "/" + repo)
	requestURL := fmt.Sprintf("%s/projects/%s/repository/commits?ref_name=%s&per_page=%d", p.baseURL, projectPath, branch, limit)

	var glCommits []struct {
		ID             string `json:"id"`
		ShortID        string `json:"short_id"`
		Title          string `json:"title"`
		Message        string `json:"message"`
		AuthorName     string `json:"author_name"`
		AuthorEmail    string `json:"author_email"`
		CommittedDate  string `json:"committed_date"`
		WebURL         string `json:"web_url"`
	}

	if err := p.doRequest(ctx, "GET", requestURL, nil, &glCommits); err != nil {
		return nil, err
	}

	commits := make([]*Commit, 0, len(glCommits))
	for _, c := range glCommits {
		ts, _ := time.Parse(time.RFC3339, c.CommittedDate)
		commits = append(commits, &Commit{
			SHA:       c.ID,
			Message:   c.Message,
			Author:    c.AuthorName,
			Email:     c.AuthorEmail,
			Timestamp: ts,
			URL:       c.WebURL,
		})
	}

	return commits, nil
}

// GetPullRequests lists merge requests
func (p *GitLabProvider) GetPullRequests(ctx context.Context, owner, repo string, state string) ([]*PullRequest, error) {
	projectPath := url.PathEscape(owner + "/" + repo)
	requestURL := fmt.Sprintf("%s/projects/%s/merge_requests?state=%s", p.baseURL, projectPath, state)

	var glMRs []struct {
		ID           int    `json:"id"`
		IID          int    `json:"iid"`
		Title        string `json:"title"`
		Description  string `json:"description"`
		State        string `json:"state"`
		Author       struct {
			Username string `json:"username"`
		} `json:"author"`
		SourceBranch string `json:"source_branch"`
		TargetBranch string `json:"target_branch"`
		WebURL       string `json:"web_url"`
		CreatedAt    string `json:"created_at"`
		UpdatedAt    string `json:"updated_at"`
	}

	if err := p.doRequest(ctx, "GET", requestURL, nil, &glMRs); err != nil {
		return nil, err
	}

	prs := make([]*PullRequest, 0, len(glMRs))
	for _, mr := range glMRs {
		createdAt, _ := time.Parse(time.RFC3339, mr.CreatedAt)
		updatedAt, _ := time.Parse(time.RFC3339, mr.UpdatedAt)

		prs = append(prs, &PullRequest{
			ID:           mr.ID,
			Number:       mr.IID,
			Title:        mr.Title,
			Description:  mr.Description,
			State:        mr.State,
			Author:       mr.Author.Username,
			SourceBranch: mr.SourceBranch,
			TargetBranch: mr.TargetBranch,
			URL:          mr.WebURL,
			CreatedAt:    createdAt,
			UpdatedAt:    updatedAt,
		})
	}

	return prs, nil
}

// GetPipelines gets CI/CD pipelines
func (p *GitLabProvider) GetPipelines(ctx context.Context, owner, repo string) ([]*Pipeline, error) {
	projectPath := url.PathEscape(owner + "/" + repo)
	requestURL := fmt.Sprintf("%s/projects/%s/pipelines?per_page=50", p.baseURL, projectPath)

	var glPipelines []struct {
		ID         int    `json:"id"`
		Status     string `json:"status"`
		Ref        string `json:"ref"`
		SHA        string `json:"sha"`
		WebURL     string `json:"web_url"`
		CreatedAt  string `json:"created_at"`
		UpdatedAt  string `json:"updated_at"`
		FinishedAt string `json:"finished_at"`
		Duration   int    `json:"duration"`
	}

	if err := p.doRequest(ctx, "GET", requestURL, nil, &glPipelines); err != nil {
		return nil, err
	}

	pipelines := make([]*Pipeline, 0, len(glPipelines))
	for _, pl := range glPipelines {
		createdAt, _ := time.Parse(time.RFC3339, pl.CreatedAt)
		finishedAt, _ := time.Parse(time.RFC3339, pl.FinishedAt)

		pipelines = append(pipelines, &Pipeline{
			ID:         pl.ID,
			Status:     pl.Status,
			Ref:        pl.Ref,
			SHA:        pl.SHA,
			WebURL:     pl.WebURL,
			CreatedAt:  createdAt,
			FinishedAt: finishedAt,
			Duration:   pl.Duration,
		})
	}

	return pipelines, nil
}

// GetSecurityAlerts gets vulnerability report
func (p *GitLabProvider) GetSecurityAlerts(ctx context.Context, owner, repo string) ([]*SecurityAlert, error) {
	projectPath := url.PathEscape(owner + "/" + repo)
	requestURL := fmt.Sprintf("%s/projects/%s/vulnerability_findings", p.baseURL, projectPath)

	var glVulns []struct {
		ID          int    `json:"id"`
		Severity    string `json:"severity"`
		Name        string `json:"name"`
		Description string `json:"description"`
		State       string `json:"state"`
		Identifiers []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"identifiers"`
	}

	if err := p.doRequest(ctx, "GET", requestURL, nil, &glVulns); err != nil {
		// GitLab Ultimate required - gracefully handle
		p.logger.Debug("Vulnerability findings requires GitLab Ultimate")
		return []*SecurityAlert{}, nil
	}

	alerts := make([]*SecurityAlert, 0, len(glVulns))
	for _, v := range glVulns {
		var cve string
		for _, id := range v.Identifiers {
			if id.Type == "cve" {
				cve = id.Value
				break
			}
		}

		alerts = append(alerts, &SecurityAlert{
			ID:          fmt.Sprintf("%d", v.ID),
			Severity:    v.Severity,
			Summary:     v.Name,
			Description: v.Description,
			CVE:         cve,
			State:       v.State,
		})
	}

	return alerts, nil
}

// CreateComment creates a comment on an MR
func (p *GitLabProvider) CreateComment(ctx context.Context, owner, repo string, mrNumber int, comment string) error {
	projectPath := url.PathEscape(owner + "/" + repo)
	requestURL := fmt.Sprintf("%s/projects/%s/merge_requests/%d/notes", p.baseURL, projectPath, mrNumber)

	body := map[string]string{"body": comment}
	return p.doRequest(ctx, "POST", requestURL, body, nil)
}

// CreateCheckRun creates a commit status (GitLab equivalent)
func (p *GitLabProvider) CreateCheckRun(ctx context.Context, owner, repo, sha string, check *CheckRun) error {
	projectPath := url.PathEscape(owner + "/" + repo)
	requestURL := fmt.Sprintf("%s/projects/%s/statuses/%s", p.baseURL, projectPath, sha)

	// Map check status/conclusion to GitLab state
	state := "pending"
	switch check.Conclusion {
	case "success":
		state = "success"
	case "failure", "action_required":
		state = "failed"
	case "cancelled", "timed_out":
		state = "canceled"
	}

	body := map[string]string{
		"state":       state,
		"name":        check.Name,
		"description": check.Summary,
	}

	return p.doRequest(ctx, "POST", requestURL, body, nil)
}

