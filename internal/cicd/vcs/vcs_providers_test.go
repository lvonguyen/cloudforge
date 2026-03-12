package vcs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// =============================================================================
// GitHub Provider Tests
// =============================================================================

func newGitHubTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/orgs/test-org/repos", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"id": 1, "name": "repo1", "full_name": "test-org/repo1",
				"description": "Test repo", "default_branch": "main",
				"private": false, "html_url": "https://github.com/test-org/repo1",
				"clone_url": "https://github.com/test-org/repo1.git",
				"language": "Go", "created_at": "2025-01-01T00:00:00Z", "updated_at": "2025-06-01T00:00:00Z",
			},
			{
				"id": 2, "name": "repo2", "full_name": "test-org/repo2",
				"default_branch": "develop", "private": true,
				"html_url": "https://github.com/test-org/repo2",
			},
		})
	})

	mux.HandleFunc("/repos/owner/repo", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && !strings.Contains(r.URL.Path, "/") || r.URL.Path == "/repos/owner/repo" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id": 42, "name": "repo", "full_name": "owner/repo",
				"description": "A test repository", "default_branch": "main",
				"private": true, "html_url": "https://github.com/owner/repo",
				"clone_url": "https://github.com/owner/repo.git", "language": "Go",
			})
		}
	})

	mux.HandleFunc("/repos/owner/repo/branches", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{"name": "main", "commit": map[string]string{"sha": "abc123"}, "protected": true},
			{"name": "develop", "commit": map[string]string{"sha": "def456"}, "protected": false},
		})
	})

	mux.HandleFunc("/repos/owner/repo/commits", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"sha": "abc123def456",
				"commit": map[string]interface{}{
					"message": "feat: add feature",
					"author":  map[string]string{"name": "Test User", "email": "test@example.com", "date": "2025-06-01T12:00:00Z"},
				},
				"html_url": "https://github.com/owner/repo/commit/abc123def456",
			},
		})
	})

	mux.HandleFunc("/repos/owner/repo/pulls", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"id": 100, "number": 1, "title": "Add feature", "body": "Description",
				"state": "open", "user": map[string]string{"login": "testuser"},
				"head": map[string]string{"ref": "feature-branch"},
				"base": map[string]string{"ref": "main"},
				"html_url":   "https://github.com/owner/repo/pull/1",
				"created_at": "2025-06-01T00:00:00Z", "updated_at": "2025-06-02T00:00:00Z",
			},
		})
	})

	mux.HandleFunc("/repos/owner/repo/actions/runs", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"workflow_runs": []map[string]interface{}{
				{
					"id": 1001, "name": "CI", "status": "completed", "conclusion": "success",
					"head_branch": "main", "head_sha": "abc123",
					"html_url":      "https://github.com/owner/repo/actions/runs/1001",
					"created_at":    "2025-06-01T00:00:00Z",
					"updated_at":    "2025-06-01T00:05:00Z",
					"run_started_at": "2025-06-01T00:00:30Z",
				},
			},
		})
	})

	mux.HandleFunc("/repos/owner/repo/dependabot/alerts", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"number": 1, "state": "open",
				"security_advisory": map[string]interface{}{
					"ghsa_id": "GHSA-1234", "cve_id": "CVE-2025-0001",
					"summary": "Critical vuln", "description": "A critical vulnerability",
					"severity": "critical",
				},
				"security_vulnerability": map[string]interface{}{
					"package":                  map[string]string{"name": "lodash", "ecosystem": "npm"},
					"vulnerable_version_range": "< 4.17.21",
					"first_patched_version":    map[string]string{"identifier": "4.17.21"},
				},
				"html_url":   "https://github.com/owner/repo/security/dependabot/1",
				"created_at": "2025-05-01T00:00:00Z",
			},
		})
	})

	mux.HandleFunc("/repos/owner/repo/issues/1/comments", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusCreated)
	})

	mux.HandleFunc("/repos/owner/repo/check-runs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusCreated)
	})

	return httptest.NewServer(mux)
}

func TestGitHub_Name(t *testing.T) {
	p := newGitHubProviderForTest("http://localhost", "tok", "org")
	if p.Name() != "github" {
		t.Errorf("Name() = %q, want github", p.Name())
	}
}

func TestGitHub_GetRepositories(t *testing.T) {
	srv := newGitHubTestServer(t)
	defer srv.Close()

	p := newGitHubProviderForTest(srv.URL, "test-token", "test-org")
	repos, err := p.GetRepositories(context.Background())
	if err != nil {
		t.Fatalf("GetRepositories: %v", err)
	}
	if len(repos) != 2 {
		t.Fatalf("expected 2 repos, got %d", len(repos))
	}
	if repos[0].Name != "repo1" {
		t.Errorf("repos[0].Name = %q, want repo1", repos[0].Name)
	}
	if repos[0].Language != "Go" {
		t.Errorf("repos[0].Language = %q, want Go", repos[0].Language)
	}
	if repos[1].Private != true {
		t.Error("expected repos[1] to be private")
	}
}

func TestGitHub_GetRepository(t *testing.T) {
	srv := newGitHubTestServer(t)
	defer srv.Close()

	p := newGitHubProviderForTest(srv.URL, "test-token", "test-org")
	repo, err := p.GetRepository(context.Background(), "owner", "repo")
	if err != nil {
		t.Fatalf("GetRepository: %v", err)
	}
	if repo.Name != "repo" {
		t.Errorf("Name = %q, want repo", repo.Name)
	}
	if repo.FullName != "owner/repo" {
		t.Errorf("FullName = %q", repo.FullName)
	}
}

func TestGitHub_GetBranches(t *testing.T) {
	srv := newGitHubTestServer(t)
	defer srv.Close()

	p := newGitHubProviderForTest(srv.URL, "test-token", "test-org")
	branches, err := p.GetBranches(context.Background(), "owner", "repo")
	if err != nil {
		t.Fatalf("GetBranches: %v", err)
	}
	if len(branches) != 2 {
		t.Fatalf("expected 2 branches, got %d", len(branches))
	}
	if branches[0].Name != "main" || !branches[0].Protected {
		t.Errorf("unexpected branch[0]: %+v", branches[0])
	}
	if branches[1].SHA != "def456" {
		t.Errorf("branch[1].SHA = %q", branches[1].SHA)
	}
}

func TestGitHub_GetCommits(t *testing.T) {
	srv := newGitHubTestServer(t)
	defer srv.Close()

	p := newGitHubProviderForTest(srv.URL, "test-token", "test-org")
	commits, err := p.GetCommits(context.Background(), "owner", "repo", "main", 10)
	if err != nil {
		t.Fatalf("GetCommits: %v", err)
	}
	if len(commits) != 1 {
		t.Fatalf("expected 1 commit, got %d", len(commits))
	}
	if commits[0].SHA != "abc123def456" {
		t.Errorf("SHA = %q", commits[0].SHA)
	}
	if commits[0].Author != "Test User" {
		t.Errorf("Author = %q", commits[0].Author)
	}
}

func TestGitHub_GetPullRequests(t *testing.T) {
	srv := newGitHubTestServer(t)
	defer srv.Close()

	p := newGitHubProviderForTest(srv.URL, "test-token", "test-org")
	prs, err := p.GetPullRequests(context.Background(), "owner", "repo", "open")
	if err != nil {
		t.Fatalf("GetPullRequests: %v", err)
	}
	if len(prs) != 1 {
		t.Fatalf("expected 1 PR, got %d", len(prs))
	}
	if prs[0].Number != 1 {
		t.Errorf("Number = %d", prs[0].Number)
	}
	if prs[0].Author != "testuser" {
		t.Errorf("Author = %q", prs[0].Author)
	}
	if prs[0].SourceBranch != "feature-branch" {
		t.Errorf("SourceBranch = %q", prs[0].SourceBranch)
	}
}

func TestGitHub_GetPipelines(t *testing.T) {
	srv := newGitHubTestServer(t)
	defer srv.Close()

	p := newGitHubProviderForTest(srv.URL, "test-token", "test-org")
	pipelines, err := p.GetPipelines(context.Background(), "owner", "repo")
	if err != nil {
		t.Fatalf("GetPipelines: %v", err)
	}
	if len(pipelines) != 1 {
		t.Fatalf("expected 1 pipeline, got %d", len(pipelines))
	}
	if pipelines[0].Name != "CI" {
		t.Errorf("Name = %q", pipelines[0].Name)
	}
	if pipelines[0].Status != "success" {
		t.Errorf("Status = %q, want success (conclusion overrides status)", pipelines[0].Status)
	}
}

func TestGitHub_GetSecurityAlerts(t *testing.T) {
	srv := newGitHubTestServer(t)
	defer srv.Close()

	p := newGitHubProviderForTest(srv.URL, "test-token", "test-org")
	alerts, err := p.GetSecurityAlerts(context.Background(), "owner", "repo")
	if err != nil {
		t.Fatalf("GetSecurityAlerts: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].CVE != "CVE-2025-0001" {
		t.Errorf("CVE = %q", alerts[0].CVE)
	}
	if alerts[0].Package != "lodash" {
		t.Errorf("Package = %q", alerts[0].Package)
	}
	if alerts[0].Severity != "critical" {
		t.Errorf("Severity = %q", alerts[0].Severity)
	}
}

func TestGitHub_CreateComment(t *testing.T) {
	srv := newGitHubTestServer(t)
	defer srv.Close()

	p := newGitHubProviderForTest(srv.URL, "test-token", "test-org")
	err := p.CreateComment(context.Background(), "owner", "repo", 1, "LGTM")
	if err != nil {
		t.Fatalf("CreateComment: %v", err)
	}
}

func TestGitHub_CreateCheckRun(t *testing.T) {
	srv := newGitHubTestServer(t)
	defer srv.Close()

	p := newGitHubProviderForTest(srv.URL, "test-token", "test-org")
	err := p.CreateCheckRun(context.Background(), "owner", "repo", "abc123", &CheckRun{
		Name:       "security-scan",
		Status:     "completed",
		Conclusion: "success",
		Title:      "Security Scan",
		Summary:    "All checks passed",
	})
	if err != nil {
		t.Fatalf("CreateCheckRun: %v", err)
	}
}

func TestGitHub_ErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := newGitHubProviderForTest(srv.URL, "bad-token", "test-org")

	_, err := p.GetRepositories(context.Background())
	if err == nil {
		t.Fatal("expected error for 401")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error = %q, want to contain 401", err.Error())
	}
}

func TestGitHub_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := newGitHubProviderForTest(srv.URL, "test-token", "test-org")

	_, err := p.GetRepository(context.Background(), "owner", "repo")
	if err == nil {
		t.Fatal("expected error for 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error = %q, want to contain 500", err.Error())
	}
}

// =============================================================================
// GitLab Provider Tests
// =============================================================================

func newGitLabTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.RawPath // use RawPath for URL-encoded segments
		if path == "" {
			path = r.URL.Path
		}

		switch {
		case strings.Contains(path, "/groups/42/projects"):
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"id": 101, "name": "project1", "path_with_namespace": "group/project1",
					"description": "Test project", "default_branch": "main",
					"visibility": "private", "web_url": "https://gitlab.com/group/project1",
					"http_url_to_repo": "https://gitlab.com/group/project1.git",
					"created_at": "2025-01-01T00:00:00Z", "last_activity_at": "2025-06-01T00:00:00Z",
				},
			})
		case strings.HasSuffix(path, "/repository/branches"):
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"name": "main", "commit": map[string]string{"id": "sha-main"}, "protected": true},
			})
		case strings.HasSuffix(path, "/repository/commits"):
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"id": "sha-commit1", "short_id": "sha-com",
					"title": "Initial commit", "message": "Initial commit",
					"author_name": "Dev", "author_email": "dev@example.com",
					"committed_date": "2025-06-01T00:00:00Z",
					"web_url":        "https://gitlab.com/group/project1/-/commit/sha-commit1",
				},
			})
		case strings.Contains(path, "/merge_requests") && strings.Contains(path, "/notes"):
			if r.Method == "POST" {
				w.WriteHeader(http.StatusCreated)
				return
			}
		case strings.Contains(path, "/merge_requests"):
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"id": 200, "iid": 1, "title": "MR Title", "description": "MR Desc",
					"state": "opened", "author": map[string]string{"username": "dev"},
					"source_branch": "feature", "target_branch": "main",
					"web_url": "https://gitlab.com/group/project1/-/merge_requests/1",
					"created_at": "2025-06-01T00:00:00Z", "updated_at": "2025-06-02T00:00:00Z",
				},
			})
		case strings.HasSuffix(path, "/pipelines"):
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"id": 301, "status": "success", "ref": "main", "sha": "sha-pipeline",
					"web_url": "https://gitlab.com/group/project1/-/pipelines/301",
					"created_at": "2025-06-01T00:00:00Z", "finished_at": "2025-06-01T00:05:00Z",
					"duration": 300,
				},
			})
		case strings.HasSuffix(path, "/vulnerability_findings"):
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"id": 401, "severity": "high", "name": "SQL Injection",
					"description": "SQL injection found", "state": "detected",
					"identifiers": []map[string]string{
						{"type": "cve", "value": "CVE-2025-9999"},
					},
				},
			})
		case strings.Contains(path, "/statuses/"):
			if r.Method == "POST" {
				w.WriteHeader(http.StatusCreated)
				return
			}
		case strings.Contains(path, "/projects/"):
			// GetRepository (catch-all for project paths)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id": 101, "name": "repo", "path_with_namespace": "owner/repo",
				"description": "A project", "default_branch": "main",
				"visibility": "private", "web_url": "https://gitlab.com/owner/repo",
				"http_url_to_repo": "https://gitlab.com/owner/repo.git",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestGitLab_Name(t *testing.T) {
	p := newGitLabProviderForTest("http://localhost", "tok", "42")
	if p.Name() != "gitlab" {
		t.Errorf("Name() = %q, want gitlab", p.Name())
	}
}

func TestGitLab_GetRepositories(t *testing.T) {
	srv := newGitLabTestServer(t)
	defer srv.Close()

	p := newGitLabProviderForTest(srv.URL, "test-token", "42")
	repos, err := p.GetRepositories(context.Background())
	if err != nil {
		t.Fatalf("GetRepositories: %v", err)
	}
	if len(repos) != 1 {
		t.Fatalf("expected 1 repo, got %d", len(repos))
	}
	if repos[0].Name != "project1" {
		t.Errorf("Name = %q", repos[0].Name)
	}
	if repos[0].FullName != "group/project1" {
		t.Errorf("FullName = %q", repos[0].FullName)
	}
}

func TestGitLab_GetRepository(t *testing.T) {
	srv := newGitLabTestServer(t)
	defer srv.Close()

	p := newGitLabProviderForTest(srv.URL, "test-token", "42")
	repo, err := p.GetRepository(context.Background(), "owner", "repo")
	if err != nil {
		t.Fatalf("GetRepository: %v", err)
	}
	if repo.Name != "repo" {
		t.Errorf("Name = %q", repo.Name)
	}
}

func TestGitLab_GetBranches(t *testing.T) {
	srv := newGitLabTestServer(t)
	defer srv.Close()

	p := newGitLabProviderForTest(srv.URL, "test-token", "42")
	branches, err := p.GetBranches(context.Background(), "owner", "repo")
	if err != nil {
		t.Fatalf("GetBranches: %v", err)
	}
	if len(branches) != 1 {
		t.Fatalf("expected 1 branch, got %d", len(branches))
	}
	if branches[0].Name != "main" || !branches[0].Protected {
		t.Errorf("unexpected branch: %+v", branches[0])
	}
}

func TestGitLab_GetCommits(t *testing.T) {
	srv := newGitLabTestServer(t)
	defer srv.Close()

	p := newGitLabProviderForTest(srv.URL, "test-token", "42")
	commits, err := p.GetCommits(context.Background(), "owner", "repo", "main", 10)
	if err != nil {
		t.Fatalf("GetCommits: %v", err)
	}
	if len(commits) != 1 {
		t.Fatalf("expected 1 commit, got %d", len(commits))
	}
	if commits[0].Author != "Dev" {
		t.Errorf("Author = %q", commits[0].Author)
	}
}

func TestGitLab_GetPullRequests(t *testing.T) {
	srv := newGitLabTestServer(t)
	defer srv.Close()

	p := newGitLabProviderForTest(srv.URL, "test-token", "42")
	prs, err := p.GetPullRequests(context.Background(), "owner", "repo", "opened")
	if err != nil {
		t.Fatalf("GetPullRequests: %v", err)
	}
	if len(prs) != 1 {
		t.Fatalf("expected 1 MR, got %d", len(prs))
	}
	if prs[0].Title != "MR Title" {
		t.Errorf("Title = %q", prs[0].Title)
	}
	if prs[0].SourceBranch != "feature" {
		t.Errorf("SourceBranch = %q", prs[0].SourceBranch)
	}
}

func TestGitLab_GetPipelines(t *testing.T) {
	srv := newGitLabTestServer(t)
	defer srv.Close()

	p := newGitLabProviderForTest(srv.URL, "test-token", "42")
	pipelines, err := p.GetPipelines(context.Background(), "owner", "repo")
	if err != nil {
		t.Fatalf("GetPipelines: %v", err)
	}
	if len(pipelines) != 1 {
		t.Fatalf("expected 1 pipeline, got %d", len(pipelines))
	}
	if pipelines[0].Status != "success" {
		t.Errorf("Status = %q", pipelines[0].Status)
	}
	if pipelines[0].Duration != 300 {
		t.Errorf("Duration = %d", pipelines[0].Duration)
	}
}

func TestGitLab_GetSecurityAlerts(t *testing.T) {
	srv := newGitLabTestServer(t)
	defer srv.Close()

	p := newGitLabProviderForTest(srv.URL, "test-token", "42")
	alerts, err := p.GetSecurityAlerts(context.Background(), "owner", "repo")
	if err != nil {
		t.Fatalf("GetSecurityAlerts: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].CVE != "CVE-2025-9999" {
		t.Errorf("CVE = %q", alerts[0].CVE)
	}
	if alerts[0].Severity != "high" {
		t.Errorf("Severity = %q", alerts[0].Severity)
	}
}

func TestGitLab_GetSecurityAlerts_UltimateRequired(t *testing.T) {
	// When the server returns 403, GitLab gracefully returns empty list
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	p := newGitLabProviderForTest(srv.URL, "test-token", "42")
	alerts, err := p.GetSecurityAlerts(context.Background(), "owner", "repo")
	if err != nil {
		t.Fatalf("expected graceful degradation, got error: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts, got %d", len(alerts))
	}
}

func TestGitLab_CreateComment(t *testing.T) {
	srv := newGitLabTestServer(t)
	defer srv.Close()

	p := newGitLabProviderForTest(srv.URL, "test-token", "42")
	err := p.CreateComment(context.Background(), "owner", "repo", 1, "Nice work")
	if err != nil {
		t.Fatalf("CreateComment: %v", err)
	}
}

func TestGitLab_CreateCheckRun(t *testing.T) {
	srv := newGitLabTestServer(t)
	defer srv.Close()

	p := newGitLabProviderForTest(srv.URL, "test-token", "42")
	tests := []struct {
		name       string
		conclusion string
	}{
		{"success", "success"},
		{"failure", "failure"},
		{"cancelled", "cancelled"},
		{"timed_out", "timed_out"},
		{"action_required", "action_required"},
		{"neutral", "neutral"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.CreateCheckRun(context.Background(), "owner", "repo", "sha123", &CheckRun{
				Name:       "scan",
				Status:     "completed",
				Conclusion: tt.conclusion,
				Summary:    "Done",
			})
			if err != nil {
				t.Fatalf("CreateCheckRun(%s): %v", tt.conclusion, err)
			}
		})
	}
}

func TestGitLab_ErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := newGitLabProviderForTest(srv.URL, "bad-token", "42")
	_, err := p.GetRepositories(context.Background())
	if err == nil {
		t.Fatal("expected error for 401")
	}
}

// =============================================================================
// Azure DevOps Provider Tests
// =============================================================================

func newAzureDevOpsTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		case strings.Contains(path, "/pipelines/runs"):
			json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"id": 501, "name": "Build", "state": "completed", "result": "succeeded",
						"createdDate": "2025-06-01T00:00:00Z", "finishedDate": "2025-06-01T00:10:00Z",
						"pipeline": map[string]string{"name": "Build Pipeline"},
						"resources": map[string]interface{}{
							"repositories": map[string]interface{}{
								"self": map[string]string{"refName": "refs/heads/main", "version": "sha-pipe"},
							},
						},
					},
				},
			})
		case strings.Contains(path, "/alert/repositories/"):
			json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"alertId": 601, "severity": "high", "title": "Secret exposed",
						"description": "An API key was found", "state": "active",
						"firstSeenDate": "2025-05-01T00:00:00Z",
						"logicalLocations": []map[string]string{
							{"fullyQualifiedName": "src/config.go"},
						},
					},
				},
			})
		case strings.Contains(path, "/threads"):
			// CreateComment on PR
			if r.Method == "POST" {
				w.WriteHeader(http.StatusCreated)
				return
			}
		case strings.Contains(path, "/statuses"):
			// CreateCheckRun
			if r.Method == "POST" {
				w.WriteHeader(http.StatusCreated)
				return
			}
		case strings.Contains(path, "/refs"):
			// GetBranches
			json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{"name": "refs/heads/main", "objectId": "sha-main", "isLocked": false},
					{"name": "refs/heads/develop", "objectId": "sha-dev", "isLocked": true},
				},
			})
		case strings.Contains(path, "/commits"):
			json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"commitId": "sha-ado-123", "comment": "ado commit",
						"author":    map[string]string{"name": "ADO Dev", "email": "dev@ado.com", "date": "2025-06-01T00:00:00Z"},
						"remoteUrl": "https://dev.azure.com/org/proj/_git/repo/commit/sha-ado-123",
					},
				},
			})
		case strings.Contains(path, "/pullrequests") || strings.Contains(path, "/pullRequests"):
			json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"pullRequestId": 42, "title": "ADO PR", "description": "ADO PR desc",
						"status": "active",
						"createdBy":     map[string]string{"displayName": "Dev"},
						"sourceRefName": "refs/heads/feature", "targetRefName": "refs/heads/main",
						"creationDate": "2025-06-01T00:00:00Z",
					},
				},
			})
		case strings.Contains(path, "/git/repositories"):
			// Check if it looks like a specific repo request (has a repo name after repositories/)
			afterRepos := strings.TrimPrefix(path, "/git/repositories/")
			afterRepos = strings.TrimPrefix(afterRepos, "/git/repositories")
			if afterRepos != "" && !strings.HasPrefix(afterRepos, "?") {
				repoName := strings.Split(afterRepos, "?")[0]
				// GetRepository
				json.NewEncoder(w).Encode(map[string]interface{}{
					"id": "repo-uuid-1", "name": repoName, "defaultBranch": "refs/heads/main",
					"webUrl":    "https://dev.azure.com/org/proj/_git/" + repoName,
					"remoteUrl": "https://org@dev.azure.com/org/proj/_git/" + repoName,
				})
				return
			}
			// GetRepositories (list)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"id": "repo-uuid-1", "name": "ado-repo", "defaultBranch": "refs/heads/main",
						"webUrl":    "https://dev.azure.com/org/proj/_git/ado-repo",
						"remoteUrl": "https://org@dev.azure.com/org/proj/_git/ado-repo",
						"project":   map[string]string{"name": "test-project"},
					},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestAzureDevOps_Name(t *testing.T) {
	p := newAzureDevOpsProviderForTest("http://localhost", "tok", "proj")
	if p.Name() != "azure-devops" {
		t.Errorf("Name() = %q, want azure-devops", p.Name())
	}
}

func TestAzureDevOps_BaseURLOverride(t *testing.T) {
	p := newAzureDevOpsProviderForTest("http://test-server/api", "tok", "proj")
	if p.baseURL() != "http://test-server/api" {
		t.Errorf("baseURL() = %q, want http://test-server/api", p.baseURL())
	}

	// Without override, constructs from org/project
	p2 := &AzureDevOpsProvider{organization: "myorg", project: "myproj"}
	expected := "https://dev.azure.com/myorg/myproj/_apis"
	if p2.baseURL() != expected {
		t.Errorf("baseURL() = %q, want %q", p2.baseURL(), expected)
	}
}

func TestAzureDevOps_GetRepositories(t *testing.T) {
	srv := newAzureDevOpsTestServer(t)
	defer srv.Close()

	p := newAzureDevOpsProviderForTest(srv.URL, "test-token", "test-project")
	repos, err := p.GetRepositories(context.Background())
	if err != nil {
		t.Fatalf("GetRepositories: %v", err)
	}
	if len(repos) != 1 {
		t.Fatalf("expected 1 repo, got %d", len(repos))
	}
	if repos[0].Name != "ado-repo" {
		t.Errorf("Name = %q", repos[0].Name)
	}
	if !repos[0].Private {
		t.Error("expected repo to be private")
	}
}

func TestAzureDevOps_GetRepository(t *testing.T) {
	srv := newAzureDevOpsTestServer(t)
	defer srv.Close()

	p := newAzureDevOpsProviderForTest(srv.URL, "test-token", "test-project")
	repo, err := p.GetRepository(context.Background(), "", "myrepo")
	if err != nil {
		t.Fatalf("GetRepository: %v", err)
	}
	if repo.Name != "myrepo" {
		t.Errorf("Name = %q", repo.Name)
	}
}

func TestAzureDevOps_GetBranches(t *testing.T) {
	srv := newAzureDevOpsTestServer(t)
	defer srv.Close()

	p := newAzureDevOpsProviderForTest(srv.URL, "test-token", "test-project")
	branches, err := p.GetBranches(context.Background(), "", "myrepo")
	if err != nil {
		t.Fatalf("GetBranches: %v", err)
	}
	if len(branches) != 2 {
		t.Fatalf("expected 2 branches, got %d", len(branches))
	}
	if branches[0].Name != "main" {
		t.Errorf("branch[0].Name = %q, want main (refs/heads/ stripped)", branches[0].Name)
	}
	if branches[1].Protected != true {
		t.Error("expected branch[1] to be protected (isLocked)")
	}
}

func TestAzureDevOps_GetCommits(t *testing.T) {
	srv := newAzureDevOpsTestServer(t)
	defer srv.Close()

	p := newAzureDevOpsProviderForTest(srv.URL, "test-token", "test-project")
	commits, err := p.GetCommits(context.Background(), "", "myrepo", "main", 10)
	if err != nil {
		t.Fatalf("GetCommits: %v", err)
	}
	if len(commits) != 1 {
		t.Fatalf("expected 1 commit, got %d", len(commits))
	}
	if commits[0].SHA != "sha-ado-123" {
		t.Errorf("SHA = %q", commits[0].SHA)
	}
}

func TestAzureDevOps_GetPullRequests(t *testing.T) {
	srv := newAzureDevOpsTestServer(t)
	defer srv.Close()

	p := newAzureDevOpsProviderForTest(srv.URL, "test-token", "test-project")

	// Test state mapping
	for _, state := range []string{"open", "closed", "merged", "all"} {
		prs, err := p.GetPullRequests(context.Background(), "", "myrepo", state)
		if err != nil {
			t.Fatalf("GetPullRequests(state=%s): %v", state, err)
		}
		if len(prs) != 1 {
			t.Fatalf("state=%s: expected 1 PR, got %d", state, len(prs))
		}
		if prs[0].Title != "ADO PR" {
			t.Errorf("Title = %q", prs[0].Title)
		}
		// Verify refs/heads/ stripped
		if prs[0].SourceBranch != "feature" {
			t.Errorf("SourceBranch = %q, want feature", prs[0].SourceBranch)
		}
	}
}

func TestAzureDevOps_GetPipelines(t *testing.T) {
	srv := newAzureDevOpsTestServer(t)
	defer srv.Close()

	p := newAzureDevOpsProviderForTest(srv.URL, "test-token", "test-project")
	pipelines, err := p.GetPipelines(context.Background(), "", "")
	if err != nil {
		t.Fatalf("GetPipelines: %v", err)
	}
	if len(pipelines) != 1 {
		t.Fatalf("expected 1 pipeline, got %d", len(pipelines))
	}
	if pipelines[0].Name != "Build Pipeline" {
		t.Errorf("Name = %q", pipelines[0].Name)
	}
	if pipelines[0].Status != "succeeded" {
		t.Errorf("Status = %q, want succeeded (result overrides state)", pipelines[0].Status)
	}
}

func TestAzureDevOps_GetSecurityAlerts(t *testing.T) {
	srv := newAzureDevOpsTestServer(t)
	defer srv.Close()

	p := newAzureDevOpsProviderForTest(srv.URL, "test-token", "test-project")
	alerts, err := p.GetSecurityAlerts(context.Background(), "", "myrepo")
	if err != nil {
		t.Fatalf("GetSecurityAlerts: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Summary != "Secret exposed" {
		t.Errorf("Summary = %q", alerts[0].Summary)
	}
	if alerts[0].Package != "src/config.go" {
		t.Errorf("Package = %q", alerts[0].Package)
	}
}

func TestAzureDevOps_GetSecurityAlerts_AdvSecNotEnabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	p := newAzureDevOpsProviderForTest(srv.URL, "test-token", "test-project")
	alerts, err := p.GetSecurityAlerts(context.Background(), "", "myrepo")
	if err != nil {
		t.Fatalf("expected graceful degradation, got: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts, got %d", len(alerts))
	}
}

func TestAzureDevOps_CreateComment(t *testing.T) {
	srv := newAzureDevOpsTestServer(t)
	defer srv.Close()

	p := newAzureDevOpsProviderForTest(srv.URL, "test-token", "test-project")
	err := p.CreateComment(context.Background(), "", "myrepo", 42, "Good PR")
	if err != nil {
		t.Fatalf("CreateComment: %v", err)
	}
}

func TestAzureDevOps_CreateCheckRun(t *testing.T) {
	srv := newAzureDevOpsTestServer(t)
	defer srv.Close()

	p := newAzureDevOpsProviderForTest(srv.URL, "test-token", "test-project")
	tests := []struct {
		conclusion string
	}{
		{"success"},
		{"failure"},
		{"cancelled"},
		{"action_required"},
		{"neutral"},
	}
	for _, tt := range tests {
		t.Run(tt.conclusion, func(t *testing.T) {
			err := p.CreateCheckRun(context.Background(), "", "myrepo", "sha-abc", &CheckRun{
				Name:       "scan",
				Conclusion: tt.conclusion,
				Summary:    "done",
			})
			if err != nil {
				t.Fatalf("CreateCheckRun(%s): %v", tt.conclusion, err)
			}
		})
	}
}

func TestAzureDevOps_ErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := newAzureDevOpsProviderForTest(srv.URL, "bad-token", "test-project")
	_, err := p.GetRepositories(context.Background())
	if err == nil {
		t.Fatal("expected error for 401")
	}
}

// =============================================================================
// VCS Manager Tests
// =============================================================================

func TestManager_RegisterAndGet(t *testing.T) {
	m := NewManager(zap.NewNop())

	gh := newGitHubProviderForTest("http://localhost", "tok", "org")
	gl := newGitLabProviderForTest("http://localhost", "tok", "42")
	ado := newAzureDevOpsProviderForTest("http://localhost", "tok", "proj")

	m.RegisterProvider(gh)
	m.RegisterProvider(gl)
	m.RegisterProvider(ado)

	if p, ok := m.GetProvider("github"); !ok || p.Name() != "github" {
		t.Error("expected github provider")
	}
	if p, ok := m.GetProvider("gitlab"); !ok || p.Name() != "gitlab" {
		t.Error("expected gitlab provider")
	}
	if p, ok := m.GetProvider("azure-devops"); !ok || p.Name() != "azure-devops" {
		t.Error("expected azure-devops provider")
	}
	if _, ok := m.GetProvider("nonexistent"); ok {
		t.Error("expected not found")
	}

	all := m.GetAllProviders()
	if len(all) != 3 {
		t.Errorf("expected 3 providers, got %d", len(all))
	}
}
