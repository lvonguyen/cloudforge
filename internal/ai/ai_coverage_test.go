package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// --- OpenAI Provider HTTP tests (not covered by existing mock-based tests) ---

func TestCovOpenAI_Complete_HTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := openaiResponse{
			Choices: []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			}{{Message: struct {
				Content string `json:"content"`
			}{Content: "test response"}}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := NewOpenAIProvider(srv.URL, "test-key", "gpt-4o")
	result, err := p.Complete(context.Background(), "test prompt")
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if result != "test response" {
		t.Errorf("got %q, want %q", result, "test response")
	}
}

func TestCovOpenAI_CompleteWithSystem_HTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req openaiRequest
		json.NewDecoder(r.Body).Decode(&req)
		if len(req.Messages) != 2 {
			t.Errorf("expected 2 messages, got %d", len(req.Messages))
		}
		resp := openaiResponse{
			Choices: []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			}{{Message: struct {
				Content string `json:"content"`
			}{Content: "system response"}}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := NewOpenAIProvider(srv.URL, "test-key", "gpt-4o")
	result, err := p.CompleteWithSystem(context.Background(), "system prompt", "user prompt")
	if err != nil {
		t.Fatalf("CompleteWithSystem: %v", err)
	}
	if result != "system response" {
		t.Errorf("got %q", result)
	}
}

func TestCovOpenAI_ErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte("rate limited"))
	}))
	defer srv.Close()

	p := NewOpenAIProvider(srv.URL, "test-key", "gpt-4o")
	_, err := p.Complete(context.Background(), "test")
	if err == nil {
		t.Error("expected error on non-200 status")
	}
}

func TestCovOpenAI_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := openaiResponse{
			Error: &struct {
				Message string `json:"message"`
			}{Message: "quota exceeded"},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := NewOpenAIProvider(srv.URL, "test-key", "gpt-4o")
	_, err := p.Complete(context.Background(), "test")
	if err == nil {
		t.Error("expected error on API error response")
	}
}

func TestCovOpenAI_EmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := openaiResponse{Choices: nil}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := NewOpenAIProvider(srv.URL, "test-key", "gpt-4o")
	_, err := p.Complete(context.Background(), "test")
	if err == nil {
		t.Error("expected error on empty choices")
	}
}

func TestCovOpenAI_AzureHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("api-key") == "" {
			t.Error("expected api-key header for Azure")
		}
		resp := openaiResponse{
			Choices: []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			}{{Message: struct {
				Content string `json:"content"`
			}{Content: "ok"}}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	// Force Azure detection by setting isAzure manually
	p := NewOpenAIProvider(srv.URL, "azure-key", "gpt-4o")
	p.isAzure = true
	_, err := p.Complete(context.Background(), "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- Mock Provider ---

func TestCovMockProvider(t *testing.T) {
	p := NewMockProvider()
	result, err := p.Complete(context.Background(), "test")
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty mock response")
	}

	result2, err := p.CompleteWithSystem(context.Background(), "sys", "user")
	if err != nil {
		t.Fatalf("CompleteWithSystem: %v", err)
	}
	if result2 == "" {
		t.Error("expected non-empty mock response")
	}
}

// --- Config coverage extras ---

func TestCovLoadAIConfig_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad.yaml")
	os.WriteFile(cfgPath, []byte("{{invalid yaml"), 0644)
	_, err := LoadAIConfig(cfgPath)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestCovNewProviderFromConfig_LocalWithCustom(t *testing.T) {
	cfg := ProviderConfig{
		Type:    ProviderLocal,
		BaseURL: "http://custom:8080",
		Model:   "custom-model",
	}
	p, err := NewProviderFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewProviderFromConfig: %v", err)
	}
	if p == nil {
		t.Error("expected non-nil provider")
	}
}

func TestCovNewRoutingProviderFromConfig(t *testing.T) {
	cfg := AIConfig{
		DefaultTier: TierFast,
		Providers: map[string]ProviderConfig{
			"fast": {
				Type:    ProviderOpenAI,
				BaseURL: "http://localhost:1234/v1/chat/completions",
				Model:   "gpt-4o-mini",
			},
		},
		FallbackOrder: []string{"fast", "nonexistent"},
	}

	rp, err := NewRoutingProviderFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewRoutingProviderFromConfig: %v", err)
	}
	if rp == nil {
		t.Error("expected non-nil routing provider")
	}
}

func TestCovNewProviderFromConfig_WithEnvVar(t *testing.T) {
	t.Setenv("TEST_AI_KEY_COV", "test-key-value")
	cfg := ProviderConfig{
		Type:         ProviderAnthropic,
		APIKeyEnvVar: "TEST_AI_KEY_COV",
	}
	p, err := NewProviderFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewProviderFromConfig: %v", err)
	}
	if p == nil {
		t.Error("expected non-nil provider")
	}
}

func TestCovRoutingProvider_MissingTier(t *testing.T) {
	mock := NewMockProvider()
	tiers := map[ModelTier]Provider{TierFast: mock}
	rp := NewRoutingProvider(tiers, TierFast, []Provider{mock})

	result, err := rp.CompleteWithTier(context.Background(), TierPremium, "", "test")
	if err != nil {
		t.Fatalf("expected fallback for missing tier: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty result from fallback")
	}
}

func TestCovRoutingProvider_RecordUsage_MissingTier(t *testing.T) {
	mock := NewMockProvider()
	tiers := map[ModelTier]Provider{TierFast: mock}
	rp := NewRoutingProvider(tiers, TierFast, nil)
	// Calling recordUsage with a tier that has no usage entry should not panic
	rp.recordUsage(TierLocal, "test prompt")
}
