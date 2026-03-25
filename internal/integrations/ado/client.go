// Package ado provides a TicketProvider adapter backed by the Azure DevOps REST API v7.1.
package ado

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"math"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// workItemIDPattern validates ADO work item IDs (integers) to prevent path traversal.
var workItemIDPattern = regexp.MustCompile(`^\d+$`)

func validateWorkItemID(id string) error {
	if !workItemIDPattern.MatchString(id) {
		return fmt.Errorf("invalid ADO work item ID: %q", id)
	}
	return nil
}

// Config holds Azure DevOps connection parameters (all from env vars).
type Config struct {
	OrgURL       string // e.g. https://dev.azure.com/my-org
	PAT          string // Personal Access Token
	Project      string // e.g. TFT
	WorkItemType string // e.g. Task, Bug (default: Task)
}

// ConfigFromEnv builds Config from standard environment variables.
func ConfigFromEnv() Config {
	wit := os.Getenv("ADO_WORK_ITEM_TYPE")
	if wit == "" {
		wit = "Task"
	}
	return Config{
		OrgURL:       os.Getenv("ADO_ORG_URL"),
		PAT:          os.Getenv("ADO_PAT"),
		Project:      os.Getenv("ADO_PROJECT"),
		WorkItemType: wit,
	}
}

// Client is a thin REST client for the Azure DevOps Work Items API.
type Client struct {
	orgURL       string
	pat          string
	project      string
	workItemType string
	client       *http.Client
	logger       *zap.Logger
}

// NewClient creates an ADO REST client.
func NewClient(cfg Config, logger *zap.Logger) (*Client, error) {
	if cfg.OrgURL == "" {
		return nil, fmt.Errorf("ADO_ORG_URL is required")
	}
	if cfg.PAT == "" {
		return nil, fmt.Errorf("ADO_PAT is required")
	}
	if cfg.Project == "" {
		return nil, fmt.Errorf("ADO_PROJECT is required")
	}
	return &Client{
		orgURL:       cfg.OrgURL,
		pat:          cfg.PAT,
		project:      cfg.Project,
		workItemType: cfg.WorkItemType,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}, nil
}

// --- ADO REST API types ---

// patchOp is a single JSON Patch operation for work item creation/update.
type patchOp struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value"`
}

type workItemResponse struct {
	ID     int                    `json:"id"`
	Rev    int                    `json:"rev"`
	Fields map[string]interface{} `json:"fields"`
	URL    string                 `json:"url"`
	Links  struct {
		HTML struct {
			Href string `json:"href"`
		} `json:"html"`
	} `json:"_links"`
}

func (w *workItemResponse) title() string {
	if v, ok := w.Fields["System.Title"].(string); ok {
		return v
	}
	return ""
}

func (w *workItemResponse) state() string {
	if v, ok := w.Fields["System.State"].(string); ok {
		return v
	}
	return ""
}

func (w *workItemResponse) priority() int {
	if v, ok := w.Fields["Microsoft.VSTS.Common.Priority"].(float64); ok {
		return int(v)
	}
	return 3
}

func (w *workItemResponse) assignee() string {
	if m, ok := w.Fields["System.AssignedTo"].(map[string]interface{}); ok {
		if name, ok := m["displayName"].(string); ok {
			return name
		}
	}
	return ""
}

func (w *workItemResponse) createdDate() time.Time {
	return parseADOTime(w.Fields["System.CreatedDate"])
}

func (w *workItemResponse) changedDate() time.Time {
	return parseADOTime(w.Fields["System.ChangedDate"])
}

func (w *workItemResponse) htmlURL() string { return w.Links.HTML.Href }

func parseADOTime(v interface{}) time.Time {
	s, ok := v.(string)
	if !ok {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t, _ = time.Parse("2006-01-02T15:04:05.999Z", s)
	}
	return t
}

type commentRequest struct {
	Text string `json:"text"`
}

type commentResponse struct {
	ID          int         `json:"id"`
	WorkItemID  int         `json:"workItemId"`
	Text        string      `json:"text"`
	CreatedBy   adoIdentity `json:"createdBy"`
	CreatedDate string      `json:"createdDate"`
}

type adoIdentity struct {
	DisplayName string `json:"displayName"`
	UniqueName  string `json:"uniqueName"`
	ID          string `json:"id"`
}

// --- Public methods ---

// CreateWorkItem creates a work item in ADO using JSON Patch.
func (c *Client) CreateWorkItem(ctx context.Context, title, description string, priority int, assignee string, tags []string, dueDate *time.Time) (*workItemResponse, error) {
	if title == "" {
		return nil, fmt.Errorf("title is required for ADO work item creation")
	}
	ops := []patchOp{
		{Op: "add", Path: "/fields/System.Title", Value: title},
	}
	if description != "" {
		ops = append(ops, patchOp{Op: "add", Path: "/fields/System.Description", Value: "<div>" + html.EscapeString(description) + "</div>"})
	}
	if priority >= 1 && priority <= 4 {
		ops = append(ops, patchOp{Op: "add", Path: "/fields/Microsoft.VSTS.Common.Priority", Value: priority})
	}
	if assignee != "" {
		ops = append(ops, patchOp{Op: "add", Path: "/fields/System.AssignedTo", Value: assignee})
	}
	if len(tags) > 0 {
		ops = append(ops, patchOp{Op: "add", Path: "/fields/System.Tags", Value: strings.Join(tags, "; ")})
	}
	if dueDate != nil {
		ops = append(ops, patchOp{Op: "add", Path: "/fields/Microsoft.VSTS.Scheduling.DueDate", Value: dueDate.Format("2006-01-02")})
	}

	path := fmt.Sprintf("/%s/_apis/wit/workitems/$%s?api-version=7.1", c.project, c.workItemType)

	var resp workItemResponse
	if err := c.doRequest(ctx, http.MethodPost, path, "application/json-patch+json", ops, &resp); err != nil {
		return nil, fmt.Errorf("creating work item: %w", err)
	}
	return &resp, nil
}

// GetWorkItem retrieves a work item by ID.
func (c *Client) GetWorkItem(ctx context.Context, id string) (*workItemResponse, error) {
	if err := validateWorkItemID(id); err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/%s/_apis/wit/workitems/%s?api-version=7.1", c.project, id)

	var resp workItemResponse
	if err := c.doRequest(ctx, http.MethodGet, path, "", nil, &resp); err != nil {
		return nil, fmt.Errorf("getting work item %s: %w", id, err)
	}
	return &resp, nil
}

// AddComment adds a comment to a work item.
func (c *Client) AddComment(ctx context.Context, id, text string) (*commentResponse, error) {
	if err := validateWorkItemID(id); err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/%s/_apis/wit/workitems/%s/comments?api-version=7.1-preview.4", c.project, id)

	var resp commentResponse
	if err := c.doRequest(ctx, http.MethodPost, path, "application/json", commentRequest{Text: "<div>" + html.EscapeString(text) + "</div>"}, &resp); err != nil {
		return nil, fmt.Errorf("adding comment to %s: %w", id, err)
	}
	return &resp, nil
}

// --- HTTP plumbing with exponential backoff ---

func (c *Client) doRequest(ctx context.Context, method, path, contentType string, body, dst interface{}) error {
	const maxRetries = 3

	var bodyBytes []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshalling request: %w", err)
		}
		bodyBytes = b
	}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		var reqBody io.Reader
		if bodyBytes != nil {
			reqBody = bytes.NewReader(bodyBytes)
		}

		req, err := http.NewRequestWithContext(ctx, method, c.orgURL+path, reqBody)
		if err != nil {
			return err
		}
		req.SetBasicAuth("", c.pat)
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}

		resp, err := c.client.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			resp.Body.Close()
			if attempt < maxRetries {
				backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
				c.logger.Warn("ADO API retrying",
					zap.Int("status", resp.StatusCode),
					zap.Duration("backoff", backoff),
					zap.Int("attempt", attempt+1),
				)
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(backoff):
				}
				continue
			}
			return fmt.Errorf("ADO API %s %s: HTTP %d after %d retries", method, path, resp.StatusCode, maxRetries)
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			resp.Body.Close()
			return fmt.Errorf("ADO API %s %s: HTTP %d: %s", method, path, resp.StatusCode, string(errBody))
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
	return fmt.Errorf("ADO API %s %s: exhausted %d retries", method, path, maxRetries)
}

// ExternalID returns the string form of a work item ID for use as the TicketProvider external ID.
func ExternalID(id int) string {
	return strconv.Itoa(id)
}
