// Package graph provides a client for querying PuppyGraph's Gremlin and openCypher endpoints.
package graph

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// Client wraps PuppyGraph's HTTP query endpoints.
// Gremlin queries are sent via the HTTP API (not WebSocket) for simplicity.
type Client struct {
	baseURL string
	client  *http.Client
	logger  *zap.Logger
}

// NewClient creates a PuppyGraph client. baseURL should be the root URL
// (e.g. "http://localhost:8081") without trailing slash.
func NewClient(baseURL string, logger *zap.Logger) *Client {
	return &Client{
		baseURL: baseURL,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}
}

// QueryRequest is the input for a graph query.
type QueryRequest struct {
	Language string `json:"language"` // "gremlin" or "cypher"
	Query    string `json:"query"`
}

// QueryResult is the raw response from PuppyGraph.
type QueryResult struct {
	Data    json.RawMessage `json:"data"`
	Elapsed time.Duration   `json:"elapsed"`
}

// Query executes a graph query against PuppyGraph.
// For Gremlin, it uses the HTTP Gremlin endpoint (port 8182).
// For openCypher, it uses the Cypher HTTP endpoint (port 8184).
func (c *Client) Query(ctx context.Context, req QueryRequest) (*QueryResult, error) {
	start := time.Now()

	var result json.RawMessage
	var err error

	switch req.Language {
	case "gremlin":
		result, err = c.queryGremlin(ctx, req.Query)
	case "cypher":
		result, err = c.queryCypher(ctx, req.Query)
	default:
		return nil, fmt.Errorf("unsupported query language: %q (expected gremlin or cypher)", req.Language)
	}
	if err != nil {
		return nil, err
	}

	return &QueryResult{
		Data:    result,
		Elapsed: time.Since(start),
	}, nil
}

// Ping checks if PuppyGraph is reachable.
func (c *Client) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/health", nil)
	if err != nil {
		return fmt.Errorf("creating health request: %w", err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("pinging PuppyGraph: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("PuppyGraph health check returned %d", resp.StatusCode)
	}
	return nil
}

// gremlinRequest is the Gremlin Server HTTP API request format.
type gremlinRequest struct {
	Gremlin string `json:"gremlin"`
}

func (c *Client) queryGremlin(ctx context.Context, query string) (json.RawMessage, error) {
	body, err := json.Marshal(gremlinRequest{Gremlin: query})
	if err != nil {
		return nil, fmt.Errorf("marshalling gremlin request: %w", err)
	}

	// PuppyGraph Gremlin HTTP API is on port 8182 by default.
	// The baseURL points to the main service; we derive the Gremlin URL.
	url := c.baseURL + "/gremlin"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating gremlin request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing gremlin query: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10MB limit
	if err != nil {
		return nil, fmt.Errorf("reading gremlin response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("gremlin query failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	return json.RawMessage(respBody), nil
}

// cypherRequest is the openCypher HTTP API request format.
type cypherRequest struct {
	Statement string `json:"statement"`
}

func (c *Client) queryCypher(ctx context.Context, query string) (json.RawMessage, error) {
	body, err := json.Marshal(cypherRequest{Statement: query})
	if err != nil {
		return nil, fmt.Errorf("marshalling cypher request: %w", err)
	}

	url := c.baseURL + "/cypher"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating cypher request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing cypher query: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10MB limit
	if err != nil {
		return nil, fmt.Errorf("reading cypher response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("cypher query failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	return json.RawMessage(respBody), nil
}
