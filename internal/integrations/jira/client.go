// Package jira provides a TicketProvider adapter backed by the Jira REST API v3.
package jira

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"time"

	"go.uber.org/zap"
)

// Config holds Jira connection parameters (all from env vars).
type Config struct {
	BaseURL          string
	Username         string
	APIToken         string
	ProjectKey       string
	DefaultIssueType string
}

// ConfigFromEnv builds Config from standard environment variables.
func ConfigFromEnv() Config {
	issueType := os.Getenv("JIRA_ISSUE_TYPE")
	if issueType == "" {
		issueType = "Task"
	}
	return Config{
		BaseURL:          os.Getenv("JIRA_URL"),
		Username:         os.Getenv("JIRA_USERNAME"),
		APIToken:         os.Getenv("JIRA_API_TOKEN"),
		ProjectKey:       os.Getenv("JIRA_PROJECT_KEY"),
		DefaultIssueType: issueType,
	}
}

// Client is a thin REST client for the Jira REST API v3.
type Client struct {
	baseURL    string
	username   string
	apiToken   string
	projectKey string
	issueType  string
	client     *http.Client
	logger     *zap.Logger
}

// NewClient creates a Jira REST client. Returns an error if BaseURL or APIToken is empty.
func NewClient(cfg Config, logger *zap.Logger) (*Client, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("JIRA_URL is required")
	}
	if cfg.APIToken == "" {
		return nil, fmt.Errorf("JIRA_API_TOKEN is required")
	}
	return &Client{
		baseURL:    cfg.BaseURL,
		username:   cfg.Username,
		apiToken:   cfg.APIToken,
		projectKey: cfg.ProjectKey,
		issueType:  cfg.DefaultIssueType,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}, nil
}

// --- Jira REST API v3 types ---

type jiraCreateIssueRequest struct {
	Fields jiraCreateFields `json:"fields"`
}

type jiraCreateFields struct {
	Project   jiraProject   `json:"project"`
	Summary   string        `json:"summary"`
	Issuetype jiraIssueType `json:"issuetype"`
	Desc      *jiraADFDoc   `json:"description,omitempty"`
	Priority  *jiraPriority `json:"priority,omitempty"`
	Assignee  *jiraAssignee `json:"assignee,omitempty"`
	Labels    []string      `json:"labels,omitempty"`
	DueDate   string        `json:"duedate,omitempty"`
}

type jiraProject struct {
	Key string `json:"key"`
}

type jiraIssueType struct {
	Name string `json:"name"`
}

type jiraPriority struct {
	Name string `json:"name"`
}

type jiraAssignee struct {
	AccountID string `json:"accountId"`
}

// jiraADFDoc is an Atlassian Document Format root node.
type jiraADFDoc struct {
	Type    string        `json:"type"`
	Version int           `json:"version"`
	Content []jiraADFNode `json:"content"`
}

type jiraADFNode struct {
	Type    string        `json:"type"`
	Content []jiraADFLeaf `json:"content,omitempty"`
}

type jiraADFLeaf struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type jiraIssueResponse struct {
	Key    string          `json:"key"`
	ID     string          `json:"id"`
	Self   string          `json:"self"`
	Fields jiraIssueFields `json:"fields"`
}

type jiraIssueFields struct {
	Summary  string            `json:"summary"`
	Status   jiraStatus        `json:"status"`
	Priority *jiraPriority     `json:"priority,omitempty"`
	Assignee *jiraAssigneeResp `json:"assignee,omitempty"`
	Created  string            `json:"created"`
	Updated  string            `json:"updated"`
}

type jiraStatus struct {
	Name           string             `json:"name"`
	StatusCategory jiraStatusCategory `json:"statusCategory"`
}

type jiraStatusCategory struct {
	Key string `json:"key"`
}

type jiraAssigneeResp struct {
	DisplayName string `json:"displayName"`
}

type jiraCommentRequest struct {
	Body *jiraADFDoc `json:"body"`
}

type jiraCommentResponse struct {
	ID      string            `json:"id"`
	Body    *jiraADFDoc       `json:"body,omitempty"`
	Author  *jiraAssigneeResp `json:"author,omitempty"`
	Created string            `json:"created"`
}

type jiraTransitionsResponse struct {
	Transitions []jiraTransition `json:"transitions"`
}

type jiraTransition struct {
	ID   string     `json:"id"`
	Name string     `json:"name"`
	To   jiraStatus `json:"to"`
}

// --- Helper: build ADF document from plain text ---

func newADFText(text string) *jiraADFDoc {
	return &jiraADFDoc{
		Type:    "doc",
		Version: 1,
		Content: []jiraADFNode{
			{
				Type: "paragraph",
				Content: []jiraADFLeaf{
					{Type: "text", Text: text},
				},
			},
		},
	}
}

// --- Public methods ---

// CreateIssue creates an issue in Jira.
func (c *Client) CreateIssue(ctx context.Context, summary, description, priority, assigneeID string, labels []string, dueDate *time.Time) (*jiraIssueResponse, error) {
	payload := jiraCreateIssueRequest{
		Fields: jiraCreateFields{
			Project:   jiraProject{Key: c.projectKey},
			Summary:   summary,
			Issuetype: jiraIssueType{Name: c.issueType},
			Desc:      newADFText(description),
		},
	}
	if priority != "" {
		payload.Fields.Priority = &jiraPriority{Name: priority}
	}
	if assigneeID != "" {
		payload.Fields.Assignee = &jiraAssignee{AccountID: assigneeID}
	}
	if len(labels) > 0 {
		payload.Fields.Labels = labels
	}
	if dueDate != nil {
		payload.Fields.DueDate = dueDate.Format("2006-01-02")
	}

	var resp jiraIssueResponse
	if err := c.doJSON(ctx, http.MethodPost, "/rest/api/3/issue", payload, &resp); err != nil {
		return nil, fmt.Errorf("creating issue: %w", err)
	}
	return &resp, nil
}

// GetIssue retrieves an issue by key or ID.
func (c *Client) GetIssue(ctx context.Context, issueKey string) (*jiraIssueResponse, error) {
	var resp jiraIssueResponse
	if err := c.doJSON(ctx, http.MethodGet, "/rest/api/3/issue/"+issueKey, nil, &resp); err != nil {
		return nil, fmt.Errorf("getting issue %s: %w", issueKey, err)
	}
	return &resp, nil
}

// AddComment adds a comment to an issue.
func (c *Client) AddComment(ctx context.Context, issueKey, text string) (*jiraCommentResponse, error) {
	payload := jiraCommentRequest{
		Body: newADFText(text),
	}

	var resp jiraCommentResponse
	if err := c.doJSON(ctx, http.MethodPost, "/rest/api/3/issue/"+issueKey+"/comment", payload, &resp); err != nil {
		return nil, fmt.Errorf("adding comment to %s: %w", issueKey, err)
	}
	return &resp, nil
}

// GetTransitions retrieves available transitions for an issue (for future status sync).
func (c *Client) GetTransitions(ctx context.Context, issueKey string) ([]jiraTransition, error) {
	var resp jiraTransitionsResponse
	if err := c.doJSON(ctx, http.MethodGet, "/rest/api/3/issue/"+issueKey+"/transitions", nil, &resp); err != nil {
		return nil, fmt.Errorf("getting transitions for %s: %w", issueKey, err)
	}
	return resp.Transitions, nil
}

// --- HTTP plumbing with exponential backoff ---

func (c *Client) doJSON(ctx context.Context, method, path string, body, dst interface{}) error {
	const maxRetries = 3

	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshalling request: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
		if err != nil {
			return err
		}
		creds := base64.StdEncoding.EncodeToString([]byte(c.username + ":" + c.apiToken))
		req.Header.Set("Authorization", "Basic "+creds)
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.client.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			resp.Body.Close()
			if attempt < maxRetries {
				backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
				c.logger.Warn("Jira API retrying",
					zap.Int("status", resp.StatusCode),
					zap.Duration("backoff", backoff),
					zap.Int("attempt", attempt+1),
				)
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(backoff):
				}

				// Re-create the reader for retry
				if body != nil {
					b, _ := json.Marshal(body)
					reqBody = bytes.NewReader(b)
				}
				continue
			}
			return fmt.Errorf("jira API %s %s: HTTP %d after %d retries", method, path, resp.StatusCode, maxRetries)
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			resp.Body.Close()
			return fmt.Errorf("jira API %s %s: HTTP %d: %s", method, path, resp.StatusCode, string(errBody))
		}

		if dst != nil {
			err = json.NewDecoder(resp.Body).Decode(dst)
			resp.Body.Close()
			if err != nil {
				return fmt.Errorf("decoding response: %w", err)
			}
		} else {
			resp.Body.Close()
		}
		return nil
	}
	return fmt.Errorf("unreachable")
}
