// Package vcs provides version control system integrations
package vcs

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"go.uber.org/zap"
)

// AzureDevOpsProvider implements the Provider interface for Azure DevOps
type AzureDevOpsProvider struct {
	organization string
	project      string
	token        string
	httpClient   *http.Client
	logger       *zap.Logger
	config       AzureDevOpsConfig
}

// AzureDevOpsConfig configures the Azure DevOps provider
type AzureDevOpsConfig struct {
	Organization string `yaml:"organization"`
	Project      string `yaml:"project"`
	TokenEnv     string `yaml:"token_env"` // PAT token
}

// NewAzureDevOpsProvider creates a new Azure DevOps provider
func NewAzureDevOpsProvider(cfg AzureDevOpsConfig, logger *zap.Logger) (*AzureDevOpsProvider, error) {
	token := os.Getenv(cfg.TokenEnv)
	if token == "" {
		return nil, fmt.Errorf("missing Azure DevOps token from env: %s", cfg.TokenEnv)
	}

	return &AzureDevOpsProvider{
		organization: cfg.Organization,
		project:      cfg.Project,
		token:        token,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		logger:       logger,
		config:       cfg,
	}, nil
}

func (p *AzureDevOpsProvider) Name() string { return "azure-devops" }

func (p *AzureDevOpsProvider) baseURL() string {
	return fmt.Sprintf("https://dev.azure.com/%s/%s/_apis", p.organization, p.project)
}

func (p *AzureDevOpsProvider) doRequest(ctx context.Context, method, url string, body interface{}, result interface{}) error {
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

	// Azure DevOps uses Basic auth with PAT
	auth := base64.StdEncoding.EncodeToString([]byte(":" + p.token))
	req.Header.Set("Authorization", "Basic "+auth)
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

// GetRepositories lists repositories
func (p *AzureDevOpsProvider) GetRepositories(ctx context.Context) ([]*Repository, error) {
	url := fmt.Sprintf("%s/git/repositories?api-version=7.0", p.baseURL())

	var result struct {
		Value []struct {
			ID            string `json:"id"`
			Name          string `json:"name"`
			DefaultBranch string `json:"defaultBranch"`
			WebURL        string `json:"webUrl"`
			RemoteURL     string `json:"remoteUrl"`
			Project       struct {
				Name string `json:"name"`
			} `json:"project"`
		} `json:"value"`
	}

	if err := p.doRequest(ctx, "GET", url, nil, &result); err != nil {
		return nil, err
	}

	repos := make([]*Repository, 0, len(result.Value))
	for _, r := range result.Value {
		repos = append(repos, &Repository{
			ID:            r.ID,
			Name:          r.Name,
			FullName:      r.Project.Name + "/" + r.Name,
			DefaultBranch: r.DefaultBranch,
			Private:       true, // Azure DevOps repos are private by default
			URL:           r.WebURL,
			CloneURL:      r.RemoteURL,
		})
	}

	return repos, nil
}

// GetRepository gets a specific repository
func (p *AzureDevOpsProvider) GetRepository(ctx context.Context, _, repo string) (*Repository, error) {
	url := fmt.Sprintf("%s/git/repositories/%s?api-version=7.0", p.baseURL(), repo)

	var r struct {
		ID            string `json:"id"`
		Name          string `json:"name"`
		DefaultBranch string `json:"defaultBranch"`
		WebURL        string `json:"webUrl"`
		RemoteURL     string `json:"remoteUrl"`
	}

	if err := p.doRequest(ctx, "GET", url, nil, &r); err != nil {
		return nil, err
	}

	return &Repository{
		ID:            r.ID,
		Name:          r.Name,
		FullName:      p.project + "/" + r.Name,
		DefaultBranch: r.DefaultBranch,
		Private:       true,
		URL:           r.WebURL,
		CloneURL:      r.RemoteURL,
	}, nil
}

// GetBranches lists branches
func (p *AzureDevOpsProvider) GetBranches(ctx context.Context, _, repo string) ([]*Branch, error) {
	url := fmt.Sprintf("%s/git/repositories/%s/refs?filter=heads&api-version=7.0", p.baseURL(), repo)

	var result struct {
		Value []struct {
			Name     string `json:"name"`
			ObjectID string `json:"objectId"`
			IsLocked bool   `json:"isLocked"`
		} `json:"value"`
	}

	if err := p.doRequest(ctx, "GET", url, nil, &result); err != nil {
		return nil, err
	}

	branches := make([]*Branch, 0, len(result.Value))
	for _, b := range result.Value {
		// Remove "refs/heads/" prefix
		name := b.Name
		if len(name) > 11 && name[:11] == "refs/heads/" {
			name = name[11:]
		}

		branches = append(branches, &Branch{
			Name:      name,
			SHA:       b.ObjectID,
			Protected: b.IsLocked,
		})
	}

	return branches, nil
}

// GetCommits gets recent commits
func (p *AzureDevOpsProvider) GetCommits(ctx context.Context, _, repo, branch string, limit int) ([]*Commit, error) {
	url := fmt.Sprintf("%s/git/repositories/%s/commits?searchCriteria.itemVersion.version=%s&$top=%d&api-version=7.0",
		p.baseURL(), repo, branch, limit)

	var result struct {
		Value []struct {
			CommitID  string `json:"commitId"`
			Comment   string `json:"comment"`
			Author    struct {
				Name  string `json:"name"`
				Email string `json:"email"`
				Date  string `json:"date"`
			} `json:"author"`
			RemoteURL string `json:"remoteUrl"`
		} `json:"value"`
	}

	if err := p.doRequest(ctx, "GET", url, nil, &result); err != nil {
		return nil, err
	}

	commits := make([]*Commit, 0, len(result.Value))
	for _, c := range result.Value {
		ts, _ := time.Parse(time.RFC3339, c.Author.Date)
		commits = append(commits, &Commit{
			SHA:       c.CommitID,
			Message:   c.Comment,
			Author:    c.Author.Name,
			Email:     c.Author.Email,
			Timestamp: ts,
			URL:       c.RemoteURL,
		})
	}

	return commits, nil
}

// GetPullRequests lists pull requests
func (p *AzureDevOpsProvider) GetPullRequests(ctx context.Context, _, repo string, state string) ([]*PullRequest, error) {
	// Map state to Azure DevOps status
	status := "all"
	switch state {
	case "open":
		status = "active"
	case "closed", "merged":
		status = "completed"
	}

	url := fmt.Sprintf("%s/git/repositories/%s/pullrequests?searchCriteria.status=%s&api-version=7.0",
		p.baseURL(), repo, status)

	var result struct {
		Value []struct {
			PullRequestID int    `json:"pullRequestId"`
			Title         string `json:"title"`
			Description   string `json:"description"`
			Status        string `json:"status"`
			CreatedBy     struct {
				DisplayName string `json:"displayName"`
			} `json:"createdBy"`
			SourceRefName string `json:"sourceRefName"`
			TargetRefName string `json:"targetRefName"`
			CreationDate  string `json:"creationDate"`
		} `json:"value"`
	}

	if err := p.doRequest(ctx, "GET", url, nil, &result); err != nil {
		return nil, err
	}

	prs := make([]*PullRequest, 0, len(result.Value))
	for _, pr := range result.Value {
		createdAt, _ := time.Parse(time.RFC3339, pr.CreationDate)

		// Strip refs/heads/ prefix
		sourceBranch := pr.SourceRefName
		if len(sourceBranch) > 11 {
			sourceBranch = sourceBranch[11:]
		}
		targetBranch := pr.TargetRefName
		if len(targetBranch) > 11 {
			targetBranch = targetBranch[11:]
		}

		prs = append(prs, &PullRequest{
			ID:           pr.PullRequestID,
			Number:       pr.PullRequestID,
			Title:        pr.Title,
			Description:  pr.Description,
			State:        pr.Status,
			Author:       pr.CreatedBy.DisplayName,
			SourceBranch: sourceBranch,
			TargetBranch: targetBranch,
			CreatedAt:    createdAt,
		})
	}

	return prs, nil
}

// GetPipelines gets pipeline runs
func (p *AzureDevOpsProvider) GetPipelines(ctx context.Context, _, _ string) ([]*Pipeline, error) {
	url := fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/pipelines/runs?api-version=7.0",
		p.organization, p.project)

	var result struct {
		Value []struct {
			ID           int    `json:"id"`
			Name         string `json:"name"`
			State        string `json:"state"`
			Result       string `json:"result"`
			CreatedDate  string `json:"createdDate"`
			FinishedDate string `json:"finishedDate"`
			Pipeline     struct {
				Name string `json:"name"`
			} `json:"pipeline"`
			Resources struct {
				Repositories struct {
					Self struct {
						RefName string `json:"refName"`
						Version string `json:"version"`
					} `json:"self"`
				} `json:"repositories"`
			} `json:"resources"`
		} `json:"value"`
	}

	if err := p.doRequest(ctx, "GET", url, nil, &result); err != nil {
		return nil, err
	}

	pipelines := make([]*Pipeline, 0, len(result.Value))
	for _, run := range result.Value {
		createdAt, _ := time.Parse(time.RFC3339, run.CreatedDate)
		finishedAt, _ := time.Parse(time.RFC3339, run.FinishedDate)

		status := run.State
		if run.Result != "" {
			status = run.Result
		}

		pipelines = append(pipelines, &Pipeline{
			ID:         run.ID,
			Name:       run.Pipeline.Name,
			Status:     status,
			Ref:        run.Resources.Repositories.Self.RefName,
			SHA:        run.Resources.Repositories.Self.Version,
			CreatedAt:  createdAt,
			FinishedAt: finishedAt,
		})
	}

	return pipelines, nil
}

// GetSecurityAlerts gets security alerts (requires Advanced Security)
func (p *AzureDevOpsProvider) GetSecurityAlerts(ctx context.Context, _, repo string) ([]*SecurityAlert, error) {
	// Azure DevOps Advanced Security API
	url := fmt.Sprintf("https://advsec.dev.azure.com/%s/%s/_apis/alert/repositories/%s/alerts?api-version=7.0-preview.1",
		p.organization, p.project, repo)

	var result struct {
		Value []struct {
			AlertID           int    `json:"alertId"`
			Severity          string `json:"severity"`
			Title             string `json:"title"`
			Description       string `json:"description"`
			State             string `json:"state"`
			FirstSeenDate     string `json:"firstSeenDate"`
			LogicalLocations  []struct {
				FullyQualifiedName string `json:"fullyQualifiedName"`
			} `json:"logicalLocations"`
		} `json:"value"`
	}

	if err := p.doRequest(ctx, "GET", url, nil, &result); err != nil {
		// Advanced Security may not be enabled
		p.logger.Debug("Security alerts requires Azure DevOps Advanced Security")
		return []*SecurityAlert{}, nil
	}

	alerts := make([]*SecurityAlert, 0, len(result.Value))
	for _, a := range result.Value {
		createdAt, _ := time.Parse(time.RFC3339, a.FirstSeenDate)

		var location string
		if len(a.LogicalLocations) > 0 {
			location = a.LogicalLocations[0].FullyQualifiedName
		}

		alerts = append(alerts, &SecurityAlert{
			ID:          fmt.Sprintf("%d", a.AlertID),
			Severity:    a.Severity,
			Summary:     a.Title,
			Description: a.Description,
			Package:     location,
			State:       a.State,
			CreatedAt:   createdAt,
		})
	}

	return alerts, nil
}

// CreateComment creates a comment on a PR
func (p *AzureDevOpsProvider) CreateComment(ctx context.Context, _, repo string, prNumber int, comment string) error {
	url := fmt.Sprintf("%s/git/repositories/%s/pullRequests/%d/threads?api-version=7.0",
		p.baseURL(), repo, prNumber)

	body := map[string]interface{}{
		"comments": []map[string]string{
			{"content": comment},
		},
		"status": "active",
	}

	return p.doRequest(ctx, "POST", url, body, nil)
}

// CreateCheckRun creates a build status
func (p *AzureDevOpsProvider) CreateCheckRun(ctx context.Context, _, repo, sha string, check *CheckRun) error {
	url := fmt.Sprintf("%s/git/repositories/%s/commits/%s/statuses?api-version=7.0",
		p.baseURL(), repo, sha)

	// Map conclusion to state
	state := "pending"
	switch check.Conclusion {
	case "success":
		state = "succeeded"
	case "failure", "action_required":
		state = "failed"
	case "cancelled":
		state = "notApplicable"
	}

	body := map[string]string{
		"state":       state,
		"description": check.Summary,
		"context": map[string]string{
			"name":  check.Name,
			"genre": "cloudforge-security",
		}["name"],
	}

	return p.doRequest(ctx, "POST", url, body, nil)
}

