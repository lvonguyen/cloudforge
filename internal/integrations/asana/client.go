// Package asana provides a TicketProvider adapter backed by the Asana REST API.
package asana

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"time"

	"go.uber.org/zap"
)

// Config holds Asana connection parameters (all from env vars).
type Config struct {
	PAT              string // Personal Access Token
	WorkspaceGID     string
	DefaultProjectID string
}

// ConfigFromEnv builds Config from standard environment variables.
func ConfigFromEnv() Config {
	return Config{
		PAT:              os.Getenv("ASANA_PAT"),
		WorkspaceGID:     os.Getenv("ASANA_WORKSPACE_GID"),
		DefaultProjectID: os.Getenv("ASANA_DEFAULT_PROJECT_GID"),
	}
}

// Client is a thin REST client for the Asana API.
type Client struct {
	baseURL   string
	pat       string
	workspace string
	projectID string
	client    *http.Client
	logger    *zap.Logger
}

// NewClient creates an Asana REST client. Returns an error if PAT is empty.
func NewClient(cfg Config, logger *zap.Logger) (*Client, error) {
	if cfg.PAT == "" {
		return nil, fmt.Errorf("ASANA_PAT is required")
	}
	return &Client{
		baseURL:   "https://app.asana.com/api/1.0",
		pat:       cfg.PAT,
		workspace: cfg.WorkspaceGID,
		projectID: cfg.DefaultProjectID,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}, nil
}

// --- Asana API types ---

type asanaTaskRequest struct {
	Data asanaTaskData `json:"data"`
}

type asanaTaskData struct {
	Name      string   `json:"name"`
	Notes     string   `json:"notes,omitempty"`
	Workspace string   `json:"workspace,omitempty"`
	Projects  []string `json:"projects,omitempty"`
	Assignee  string   `json:"assignee,omitempty"`
	DueOn     string   `json:"due_on,omitempty"`
}

type asanaTaskResponse struct {
	Data struct {
		GID       string `json:"gid"`
		Name      string `json:"name"`
		Notes     string `json:"notes"`
		Completed bool   `json:"completed"`
		Permalink string `json:"permalink_url"`
		CreatedAt string `json:"created_at"`
	} `json:"data"`
}

type asanaStoryRequest struct {
	Data struct {
		Text string `json:"text"`
	} `json:"data"`
}

type asanaStoryResponse struct {
	Data struct {
		GID       string `json:"gid"`
		Text      string `json:"text"`
		CreatedAt string `json:"created_at"`
		CreatedBy struct {
			Name string `json:"name"`
		} `json:"created_by"`
	} `json:"data"`
}

// --- Public methods ---

// CreateTask creates a task in Asana.
func (c *Client) CreateTask(ctx context.Context, name, notes, assignee string, dueOn *time.Time) (*asanaTaskResponse, error) {
	payload := asanaTaskRequest{
		Data: asanaTaskData{
			Name:      name,
			Notes:     notes,
			Workspace: c.workspace,
			Assignee:  assignee,
		},
	}
	if c.projectID != "" {
		payload.Data.Projects = []string{c.projectID}
	}
	if dueOn != nil {
		payload.Data.DueOn = dueOn.Format("2006-01-02")
	}

	var resp asanaTaskResponse
	if err := c.doJSON(ctx, http.MethodPost, "/tasks", payload, &resp); err != nil {
		return nil, fmt.Errorf("creating task: %w", err)
	}
	return &resp, nil
}

// GetTask retrieves a task by GID.
func (c *Client) GetTask(ctx context.Context, gid string) (*asanaTaskResponse, error) {
	var resp asanaTaskResponse
	if err := c.doJSON(ctx, http.MethodGet, "/tasks/"+gid, nil, &resp); err != nil {
		return nil, fmt.Errorf("getting task %s: %w", gid, err)
	}
	return &resp, nil
}

// AddStory adds a comment (story) to a task.
func (c *Client) AddStory(ctx context.Context, taskGID, text string) (*asanaStoryResponse, error) {
	payload := asanaStoryRequest{}
	payload.Data.Text = text

	var resp asanaStoryResponse
	if err := c.doJSON(ctx, http.MethodPost, "/tasks/"+taskGID+"/stories", payload, &resp); err != nil {
		return nil, fmt.Errorf("adding story to %s: %w", taskGID, err)
	}
	return &resp, nil
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
		req.Header.Set("Authorization", "Bearer "+c.pat)
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.client.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			resp.Body.Close()
			if attempt < maxRetries {
				backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
				c.logger.Warn("Asana API retrying",
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
			return fmt.Errorf("asana API %s %s: HTTP %d after %d retries", method, path, resp.StatusCode, maxRetries)
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			resp.Body.Close()
			return fmt.Errorf("asana API %s %s: HTTP %d: %s", method, path, resp.StatusCode, string(errBody))
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
