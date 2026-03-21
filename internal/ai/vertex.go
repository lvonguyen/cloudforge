package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/oauth2/google"
)

const (
	// VertexModelSonnet is the fast-tier Claude model on Vertex AI.
	VertexModelSonnet = "claude-sonnet-4-6@20250514"
	// VertexModelOpus is the premium-tier Claude model on Vertex AI.
	VertexModelOpus = "claude-opus-4-6@20250514"

	vertexDefaultRegion = "us-central1"
	vertexScope         = "https://www.googleapis.com/auth/cloud-platform"
)

// VertexProvider implements Provider using GCP Vertex AI rawPredict for Claude models.
type VertexProvider struct {
	projectID  string
	region     string
	model      string
	baseURL    string
	httpClient *http.Client
}

// NewVertexProvider creates a VertexProvider using Application Default Credentials.
func NewVertexProvider(projectID, region, model string) (*VertexProvider, error) {
	if region == "" {
		region = vertexDefaultRegion
	}
	if model == "" {
		model = VertexModelSonnet
	}

	creds, err := google.FindDefaultCredentials(context.Background(), vertexScope)
	if err != nil {
		return nil, fmt.Errorf("finding GCP default credentials: %w", err)
	}

	return &VertexProvider{
		projectID: projectID,
		region:    region,
		model:     model,
		httpClient: &http.Client{
			Timeout:   120 * time.Second,
			Transport: &oauth2Transport{base: http.DefaultTransport, creds: creds},
		},
	}, nil
}

// Complete sends a single-turn prompt to Vertex AI.
func (p *VertexProvider) Complete(ctx context.Context, prompt string) (string, error) {
	return p.CompleteWithSystem(ctx, "", prompt)
}

// CompleteWithSystem sends a system + user prompt pair to Vertex AI via rawPredict.
func (p *VertexProvider) CompleteWithSystem(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	ctx, span := otel.Tracer("aegis.ai").Start(ctx, "ai.analyze")
	defer span.End()
	span.SetAttributes(
		attribute.String("ai.model", p.model),
		attribute.String("ai.provider", "vertex"),
		attribute.Int("ai.input_length", len(userPrompt)),
	)

	endpoint := p.baseURL
	if endpoint == "" {
		endpoint = fmt.Sprintf(
			"https://%s-aiplatform.googleapis.com/v1/projects/%s/locations/%s/publishers/anthropic/models/%s:rawPredict",
			p.region, p.projectID, p.region, p.model,
		)
	}

	reqBody := anthropicRequest{
		Model:     p.model,
		MaxTokens: 4096,
		Messages: []message{
			{Role: "user", Content: userPrompt},
		},
	}
	if systemPrompt != "" {
		reqBody.System = systemPrompt
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshaling vertex request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("creating vertex request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("vertex rawPredict request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10 MB safety limit
	if err != nil {
		return "", fmt.Errorf("reading vertex response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("vertex API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var anthropicResp anthropicResponse
	if err := json.Unmarshal(respBody, &anthropicResp); err != nil {
		return "", fmt.Errorf("decoding vertex response: %w", err)
	}

	if anthropicResp.Error != nil {
		return "", fmt.Errorf("vertex API error: %s", anthropicResp.Error.Message)
	}

	if len(anthropicResp.Content) == 0 {
		return "", fmt.Errorf("empty response from vertex")
	}

	span.SetAttributes(attribute.Int("ai.response_length", len(anthropicResp.Content[0].Text)))

	return anthropicResp.Content[0].Text, nil
}

// oauth2Transport attaches a bearer token from GCP credentials to each request.
type oauth2Transport struct {
	base  http.RoundTripper
	creds *google.Credentials
}

func (t *oauth2Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := t.creds.TokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("getting GCP token: %w", err)
	}

	// Clone request to avoid mutating the original.
	clone := req.Clone(req.Context())
	clone.Header.Set("Authorization", "Bearer "+token.AccessToken)
	return t.base.RoundTrip(clone)
}
