// Package graph provides a client for querying PuppyGraph's Gremlin and openCypher endpoints.
package graph

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

// Client wraps PuppyGraph's query endpoints.
// Gremlin queries use WebSocket (port 8182). Cypher uses HTTP.
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
// For Gremlin, it connects via WebSocket on port 8182.
// For openCypher, it uses the Cypher HTTP endpoint.
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

// Ping checks if PuppyGraph is reachable by hitting the root URL.
// PuppyGraph does not expose /health, so we use GET / instead.
func (c *Client) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/", nil)
	if err != nil {
		return fmt.Errorf("creating ping request: %w", err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("pinging PuppyGraph: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("PuppyGraph ping returned %d", resp.StatusCode)
	}
	return nil
}

// gremlinWSRequest is the TinkerPop Gremlin Server WebSocket request format.
type gremlinWSRequest struct {
	RequestID string           `json:"requestId"`
	Op        string           `json:"op"`
	Processor string           `json:"processor"`
	Args      gremlinWSReqArgs `json:"args"`
}

type gremlinWSReqArgs struct {
	Gremlin  string `json:"gremlin"`
	Language string `json:"language"`
}

// gremlinWSResponse is the TinkerPop Gremlin Server WebSocket response envelope.
type gremlinWSResponse struct {
	Result struct {
		Data json.RawMessage `json:"data"`
	} `json:"result"`
	Status struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"status"`
}

// gremlinWSURL derives the WebSocket Gremlin endpoint from the base HTTP URL.
// Base URL like "http://host:8081" becomes "ws://host:8182/gremlin".
func gremlinWSURL(baseURL string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parsing base URL: %w", err)
	}

	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	default:
		u.Scheme = "ws"
	}

	host := u.Hostname()
	u.Host = host + ":8182"
	u.Path = "/gremlin"
	return u.String(), nil
}

// newUUID generates a random UUID v4 using crypto/rand.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", fmt.Errorf("generating UUID: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func (c *Client) queryGremlin(ctx context.Context, query string) (json.RawMessage, error) {
	wsURL, err := gremlinWSURL(c.baseURL)
	if err != nil {
		return nil, fmt.Errorf("deriving gremlin WebSocket URL: %w", err)
	}

	reqID, err := newUUID()
	if err != nil {
		return nil, err
	}

	conn, httpResp, err := websocket.DefaultDialer.DialContext(ctx, wsURL, nil)
	if httpResp != nil && httpResp.Body != nil {
		httpResp.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("dialing gremlin WebSocket %s: %w", wsURL, err)
	}
	defer conn.Close()

	msg := gremlinWSRequest{
		RequestID: reqID,
		Op:        "eval",
		Processor: "",
		Args: gremlinWSReqArgs{
			Gremlin:  query,
			Language: "gremlin-groovy",
		},
	}

	payload, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshalling gremlin request: %w", err)
	}

	// Propagate context deadline to WebSocket read/write to prevent indefinite blocking.
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetWriteDeadline(deadline)
		conn.SetReadDeadline(deadline)
	}

	if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
		return nil, fmt.Errorf("sending gremlin query: %w", err)
	}

	// Read loop: TinkerPop uses status 206 for multi-message (partial) responses.
	// Accumulate data from all 206 messages, return on 200 (final batch).
	var allData []json.RawMessage
	for {
		_, respPayload, err := conn.ReadMessage()
		if err != nil {
			return nil, fmt.Errorf("reading gremlin response: %w", err)
		}

		var resp gremlinWSResponse
		if err := json.Unmarshal(respPayload, &resp); err != nil {
			return nil, fmt.Errorf("unmarshalling gremlin response: %w", err)
		}

		if resp.Status.Code < 200 || resp.Status.Code >= 300 {
			return nil, fmt.Errorf("gremlin query failed (status %d): %s", resp.Status.Code, resp.Status.Message)
		}

		allData = append(allData, resp.Result.Data)

		if resp.Status.Code != 206 {
			break // 200 = final batch
		}
	}

	// Single message: return data directly (common case).
	if len(allData) == 1 {
		return allData[0], nil
	}

	// Multiple messages: merge JSON arrays.
	merged, err := mergeJSONArrays(allData)
	if err != nil {
		return nil, fmt.Errorf("merging gremlin partial responses: %w", err)
	}
	return merged, nil
}

// mergeJSONArrays combines multiple JSON array responses into a single array.
// If any element is not an array, it is wrapped in one.
func mergeJSONArrays(parts []json.RawMessage) (json.RawMessage, error) {
	var merged []json.RawMessage
	for _, part := range parts {
		var arr []json.RawMessage
		if err := json.Unmarshal(part, &arr); err != nil {
			// Not an array — wrap as single element
			merged = append(merged, part)
			continue
		}
		merged = append(merged, arr...)
	}
	return json.Marshal(merged)
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

	cypherURL := c.baseURL + "/cypher"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cypherURL, bytes.NewReader(body))
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
