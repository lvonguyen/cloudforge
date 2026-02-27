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

const (
	// OpenAIModelGPT4o is the standard Azure/OpenAI model.
	OpenAIModelGPT4o = "gpt-4o"
	// OpenAIModelGPT4oMini is the cost-optimized Azure/OpenAI model.
	OpenAIModelGPT4oMini = "gpt-4o-mini"
	// OpenAIModelLocal is the local LM Studio / Ollama model.
	OpenAIModelLocal = "qwen-32b"
)

// openaiRequest is the OpenAI chat completions request body.
type openaiRequest struct {
	Model     string          `json:"model"`
	Messages  []openaiMessage `json:"messages"`
	MaxTokens int             `json:"max_tokens,omitempty"`
}

type openaiMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// openaiResponse is the OpenAI chat completions response body.
type openaiResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// OpenAIProvider implements Provider for OpenAI-compatible endpoints (Azure, LM Studio, Ollama).
type OpenAIProvider struct {
	baseURL    string
	apiKey     string
	model      string
	isAzure    bool
	httpClient *http.Client
}

// NewOpenAIProvider creates a provider for any OpenAI-compatible API.
// For Azure: pass the full completions URL including api-version query param.
// For local (LM Studio): pass http://localhost:1234/v1/chat/completions.
// Set isAzure=true to use the "api-key" header instead of "Authorization: Bearer".
func NewOpenAIProvider(baseURL, apiKey, model string) *OpenAIProvider {
	// Detect Azure by URL pattern (contains .openai.azure.com).
	isAzure := containsAzureDomain(baseURL)

	return &OpenAIProvider{
		baseURL: baseURL,
		apiKey:  apiKey,
		model:   model,
		isAzure: isAzure,
		httpClient: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

// Complete sends a single-turn prompt.
func (p *OpenAIProvider) Complete(ctx context.Context, prompt string) (string, error) {
	return p.CompleteWithSystem(ctx, "", prompt)
}

// CompleteWithSystem sends a system + user message pair using the chat completions format.
func (p *OpenAIProvider) CompleteWithSystem(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	msgs := make([]openaiMessage, 0, 2)
	if systemPrompt != "" {
		msgs = append(msgs, openaiMessage{Role: "system", Content: systemPrompt})
	}
	msgs = append(msgs, openaiMessage{Role: "user", Content: userPrompt})

	reqBody := openaiRequest{
		Model:     p.model,
		Messages:  msgs,
		MaxTokens: 4096,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshaling openai request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", p.baseURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("creating openai request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if p.isAzure {
		req.Header.Set("api-key", p.apiKey)
	} else {
		req.Header.Set("Authorization", "Bearer "+p.apiKey)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("openai request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10 MB safety limit
	if err != nil {
		return "", fmt.Errorf("reading openai response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("openai API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var openaiResp openaiResponse
	if err := json.Unmarshal(respBody, &openaiResp); err != nil {
		return "", fmt.Errorf("decoding openai response: %w", err)
	}

	if openaiResp.Error != nil {
		return "", fmt.Errorf("openai API error: %s", openaiResp.Error.Message)
	}

	if len(openaiResp.Choices) == 0 {
		return "", fmt.Errorf("empty response from openai")
	}

	return openaiResp.Choices[0].Message.Content, nil
}

func containsAzureDomain(url string) bool {
	for i := 0; i < len(url)-len(".openai.azure.com"); i++ {
		if url[i:i+len(".openai.azure.com")] == ".openai.azure.com" {
			return true
		}
	}
	return false
}
