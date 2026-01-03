// Package ai provides LLM integration for CloudForge
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Provider defines the interface for LLM providers
type Provider interface {
	Complete(ctx context.Context, prompt string) (string, error)
	CompleteWithSystem(ctx context.Context, systemPrompt, userPrompt string) (string, error)
}

// AnthropicProvider implements Provider for Anthropic Claude
type AnthropicProvider struct {
	apiKey     string
	model      string
	httpClient *http.Client
}

// NewAnthropicProvider creates a new Anthropic provider
func NewAnthropicProvider(apiKey string) *AnthropicProvider {
	return &AnthropicProvider{
		apiKey: apiKey,
		model:  "claude-opus-4-5-20250514",
		httpClient: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

// anthropicRequest represents the Anthropic API request
type anthropicRequest struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	Messages  []message `json:"messages"`
	System    string    `json:"system,omitempty"`
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// anthropicResponse represents the Anthropic API response
type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Complete sends a prompt to Claude and returns the response
func (p *AnthropicProvider) Complete(ctx context.Context, prompt string) (string, error) {
	return p.CompleteWithSystem(ctx, "", prompt)
}

// CompleteWithSystem sends a prompt with system context to Claude
func (p *AnthropicProvider) CompleteWithSystem(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
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
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://api.anthropic.com/v1/messages",
		bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", p.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var anthropicResp anthropicResponse
	if err := json.Unmarshal(respBody, &anthropicResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if anthropicResp.Error != nil {
		return "", fmt.Errorf("API error: %s", anthropicResp.Error.Message)
	}

	if len(anthropicResp.Content) == 0 {
		return "", fmt.Errorf("empty response from API")
	}

	return anthropicResp.Content[0].Text, nil
}

// MockProvider implements Provider for testing
type MockProvider struct {
	responses map[string]string
}

// NewMockProvider creates a mock provider for testing
func NewMockProvider() *MockProvider {
	return &MockProvider{
		responses: map[string]string{
			"default": "This is a mock AI response for testing purposes.",
		},
	}
}

// Complete returns a mock response
func (p *MockProvider) Complete(ctx context.Context, prompt string) (string, error) {
	return p.responses["default"], nil
}

// CompleteWithSystem returns a mock response
func (p *MockProvider) CompleteWithSystem(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	return p.responses["default"], nil
}
