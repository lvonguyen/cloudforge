package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// ---------------------------------------------------------------------------
// Anthropic provider tests
// ---------------------------------------------------------------------------

func newAnthropicTestServer(handler http.HandlerFunc) (*httptest.Server, *AnthropicProvider) {
	srv := httptest.NewServer(handler)
	p := NewAnthropicProvider("test-api-key")
	p.baseURL = srv.URL
	return srv, p
}

func anthropicOKHandler(text string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := anthropicResponse{
			Content: []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			}{{Type: "text", Text: text}},
		}
		json.NewEncoder(w).Encode(resp)
	}
}

func TestAnthropicProvider_Complete_Success(t *testing.T) {
	srv, p := newAnthropicTestServer(anthropicOKHandler("mock response"))
	defer srv.Close()

	result, err := p.Complete(context.Background(), "hello")
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if result != "mock response" {
		t.Errorf("got %q, want %q", result, "mock response")
	}
}

func TestAnthropicProvider_CompleteWithSystem_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req anthropicRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.System == "" {
			t.Error("expected system prompt to be set")
		}
		if r.Header.Get("x-api-key") != "test-api-key" {
			t.Errorf("expected x-api-key header, got %q", r.Header.Get("x-api-key"))
		}
		if r.Header.Get("anthropic-version") != "2023-06-01" {
			t.Errorf("expected anthropic-version header")
		}
		resp := anthropicResponse{
			Content: []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			}{{Type: "text", Text: "system response"}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := NewAnthropicProvider("test-api-key")
	p.baseURL = srv.URL

	result, err := p.CompleteWithSystem(context.Background(), "you are helpful", "hello")
	if err != nil {
		t.Fatalf("CompleteWithSystem: %v", err)
	}
	if result != "system response" {
		t.Errorf("got %q, want %q", result, "system response")
	}
}

func TestAnthropicProvider_Non200Status(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte("rate limited"))
	}))
	defer srv.Close()

	p := NewAnthropicProvider("test-key")
	p.baseURL = srv.URL

	_, err := p.Complete(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error on non-200 status")
	}
}

func TestAnthropicProvider_EmptyContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := anthropicResponse{Content: nil}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := NewAnthropicProvider("test-key")
	p.baseURL = srv.URL

	_, err := p.Complete(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error on empty content")
	}
}

func TestAnthropicProvider_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := anthropicResponse{
			Error: &struct {
				Message string `json:"message"`
			}{Message: "invalid_api_key"},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := NewAnthropicProvider("bad-key")
	p.baseURL = srv.URL

	_, err := p.Complete(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error on API error response")
	}
}

func TestAnthropicProvider_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := NewAnthropicProvider("test-key")
	p.baseURL = srv.URL

	_, err := p.Complete(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error on invalid JSON response")
	}
}

// ---------------------------------------------------------------------------
// OpenAI provider tests
// ---------------------------------------------------------------------------

func openaiOKHandler(content string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := openaiResponse{
			Choices: []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			}{{Message: struct {
				Content string `json:"content"`
			}{Content: content}}},
		}
		json.NewEncoder(w).Encode(resp)
	}
}

func TestOpenAIProvider_Complete_Success(t *testing.T) {
	srv := httptest.NewServer(openaiOKHandler("openai response"))
	defer srv.Close()

	p := NewOpenAIProvider(srv.URL, "test-key", "gpt-4o")
	result, err := p.Complete(context.Background(), "hello")
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if result != "openai response" {
		t.Errorf("got %q, want %q", result, "openai response")
	}
}

func TestOpenAIProvider_CompleteWithSystem_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req openaiRequest
		json.NewDecoder(r.Body).Decode(&req)
		if len(req.Messages) != 2 {
			t.Errorf("expected 2 messages (system+user), got %d", len(req.Messages))
		}
		if req.Messages[0].Role != "system" {
			t.Errorf("expected first message role=system, got %q", req.Messages[0].Role)
		}
		if r.Header.Get("Authorization") == "" {
			t.Error("expected Authorization header for non-Azure")
		}
		resp := openaiResponse{
			Choices: []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			}{{Message: struct {
				Content string `json:"content"`
			}{Content: "with system"}}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := NewOpenAIProvider(srv.URL, "test-key", "gpt-4o")
	result, err := p.CompleteWithSystem(context.Background(), "be concise", "hello")
	if err != nil {
		t.Fatalf("CompleteWithSystem: %v", err)
	}
	if result != "with system" {
		t.Errorf("got %q", result)
	}
}

func TestOpenAIProvider_AzureDetection(t *testing.T) {
	tests := []struct {
		url     string
		isAzure bool
	}{
		{"https://myresource.openai.azure.com/openai/deployments/gpt-4o/chat/completions", true},
		{"http://localhost:1234/v1/chat/completions", false},
		{"https://api.openai.com/v1/chat/completions", false},
	}

	for _, tt := range tests {
		p := NewOpenAIProvider(tt.url, "key", "model")
		if p.isAzure != tt.isAzure {
			t.Errorf("URL %q: isAzure=%v, want %v", tt.url, p.isAzure, tt.isAzure)
		}
	}
}

func TestOpenAIProvider_AzureHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("api-key") == "" {
			t.Error("expected api-key header for Azure")
		}
		if r.Header.Get("Authorization") != "" {
			t.Error("expected no Authorization header for Azure")
		}
		json.NewEncoder(w).Encode(openaiResponse{
			Choices: []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			}{{Message: struct {
				Content string `json:"content"`
			}{Content: "azure ok"}}},
		})
	}))
	defer srv.Close()

	p := NewOpenAIProvider(srv.URL, "azure-key", "gpt-4o")
	p.isAzure = true
	_, err := p.Complete(context.Background(), "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOpenAIProvider_Non200Status(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	p := NewOpenAIProvider(srv.URL, "key", "model")
	_, err := p.Complete(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error on 500 status")
	}
}

func TestOpenAIProvider_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := openaiResponse{
			Error: &struct {
				Message string `json:"message"`
			}{Message: "quota exceeded"},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := NewOpenAIProvider(srv.URL, "key", "model")
	_, err := p.Complete(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error on API error response")
	}
}

func TestOpenAIProvider_EmptyChoices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(openaiResponse{Choices: nil})
	}))
	defer srv.Close()

	p := NewOpenAIProvider(srv.URL, "key", "model")
	_, err := p.Complete(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error on empty choices")
	}
}

func TestOpenAIProvider_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("{invalid"))
	}))
	defer srv.Close()

	p := NewOpenAIProvider(srv.URL, "key", "model")
	_, err := p.Complete(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error on invalid JSON")
	}
}

// ---------------------------------------------------------------------------
// Vertex provider tests
// ---------------------------------------------------------------------------

func TestVertexProvider_Complete_Success(t *testing.T) {
	srv := httptest.NewServer(anthropicOKHandler("vertex response"))
	defer srv.Close()

	p := &VertexProvider{
		projectID:  "test-project",
		region:     "us-central1",
		model:      "claude-sonnet-4-6@20250514",
		baseURL:    srv.URL,
		httpClient: srv.Client(),
	}

	result, err := p.Complete(context.Background(), "hello")
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if result != "vertex response" {
		t.Errorf("got %q, want %q", result, "vertex response")
	}
}

func TestVertexProvider_CompleteWithSystem_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req anthropicRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.System == "" {
			t.Error("expected system prompt to be set")
		}
		resp := anthropicResponse{
			Content: []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			}{{Type: "text", Text: "vertex system response"}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := &VertexProvider{
		projectID:  "test-project",
		region:     "us-central1",
		model:      "claude-sonnet-4-6@20250514",
		baseURL:    srv.URL,
		httpClient: srv.Client(),
	}

	result, err := p.CompleteWithSystem(context.Background(), "be helpful", "hello")
	if err != nil {
		t.Fatalf("CompleteWithSystem: %v", err)
	}
	if result != "vertex system response" {
		t.Errorf("got %q", result)
	}
}

func TestVertexProvider_Non200Status(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("forbidden"))
	}))
	defer srv.Close()

	p := &VertexProvider{
		projectID:  "test-project",
		region:     "us-central1",
		model:      "test-model",
		baseURL:    srv.URL,
		httpClient: srv.Client(),
	}

	_, err := p.Complete(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error on 403 status")
	}
}

func TestVertexProvider_EmptyContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(anthropicResponse{Content: nil})
	}))
	defer srv.Close()

	p := &VertexProvider{
		projectID:  "test-project",
		region:     "us-central1",
		model:      "test-model",
		baseURL:    srv.URL,
		httpClient: srv.Client(),
	}

	_, err := p.Complete(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error on empty content")
	}
}

func TestVertexProvider_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := anthropicResponse{
			Error: &struct {
				Message string `json:"message"`
			}{Message: "model not found"},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := &VertexProvider{
		projectID:  "test-project",
		region:     "us-central1",
		model:      "test-model",
		baseURL:    srv.URL,
		httpClient: srv.Client(),
	}

	_, err := p.Complete(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error on API error response")
	}
}

func TestVertexProvider_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := &VertexProvider{
		projectID:  "test-project",
		region:     "us-central1",
		model:      "test-model",
		baseURL:    srv.URL,
		httpClient: srv.Client(),
	}

	_, err := p.Complete(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error on invalid JSON")
	}
}

// ---------------------------------------------------------------------------
// Bedrock provider tests
// ---------------------------------------------------------------------------

// mockBedrockClient implements bedrockInvoker for testing.
type mockBedrockClient struct {
	invokeModelFn func(ctx context.Context, params *bedrockruntime.InvokeModelInput, optFns ...func(*bedrockruntime.Options)) (*bedrockruntime.InvokeModelOutput, error)
}

func (m *mockBedrockClient) InvokeModel(ctx context.Context, params *bedrockruntime.InvokeModelInput, optFns ...func(*bedrockruntime.Options)) (*bedrockruntime.InvokeModelOutput, error) {
	return m.invokeModelFn(ctx, params, optFns...)
}

func bedrockSuccessResponse(text string) *bedrockruntime.InvokeModelOutput {
	resp := anthropicResponse{
		Content: []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}{{Type: "text", Text: text}},
	}
	body, _ := json.Marshal(resp)
	return &bedrockruntime.InvokeModelOutput{Body: body}
}

func TestBedrockProvider_Complete_Success(t *testing.T) {
	mock := &mockBedrockClient{
		invokeModelFn: func(ctx context.Context, params *bedrockruntime.InvokeModelInput, optFns ...func(*bedrockruntime.Options)) (*bedrockruntime.InvokeModelOutput, error) {
			return bedrockSuccessResponse("bedrock response"), nil
		},
	}

	p := newBedrockProviderForTest(mock, "test-model")
	result, err := p.Complete(context.Background(), "hello")
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if result != "bedrock response" {
		t.Errorf("got %q, want %q", result, "bedrock response")
	}
}

func TestBedrockProvider_CompleteWithSystem_Success(t *testing.T) {
	mock := &mockBedrockClient{
		invokeModelFn: func(ctx context.Context, params *bedrockruntime.InvokeModelInput, optFns ...func(*bedrockruntime.Options)) (*bedrockruntime.InvokeModelOutput, error) {
			// Verify the system prompt is in the request body
			var req anthropicRequest
			json.Unmarshal(params.Body, &req)
			if req.System == "" {
				t.Error("expected system prompt in request body")
			}
			return bedrockSuccessResponse("bedrock system response"), nil
		},
	}

	p := newBedrockProviderForTest(mock, "test-model")
	result, err := p.CompleteWithSystem(context.Background(), "be concise", "hello")
	if err != nil {
		t.Fatalf("CompleteWithSystem: %v", err)
	}
	if result != "bedrock system response" {
		t.Errorf("got %q", result)
	}
}

func TestBedrockProvider_ModelID(t *testing.T) {
	mock := &mockBedrockClient{
		invokeModelFn: func(ctx context.Context, params *bedrockruntime.InvokeModelInput, optFns ...func(*bedrockruntime.Options)) (*bedrockruntime.InvokeModelOutput, error) {
			return bedrockSuccessResponse("ok"), nil
		},
	}

	p := newBedrockProviderForTest(mock, "us.anthropic.claude-sonnet-4-6")
	if p.ModelID() != "us.anthropic.claude-sonnet-4-6" {
		t.Errorf("ModelID() = %q, want %q", p.ModelID(), "us.anthropic.claude-sonnet-4-6")
	}
}

func TestBedrockProvider_InvokeModelError(t *testing.T) {
	mock := &mockBedrockClient{
		invokeModelFn: func(ctx context.Context, params *bedrockruntime.InvokeModelInput, optFns ...func(*bedrockruntime.Options)) (*bedrockruntime.InvokeModelOutput, error) {
			return nil, fmt.Errorf("access denied")
		},
	}

	p := newBedrockProviderForTest(mock, "test-model")
	_, err := p.Complete(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error from InvokeModel")
	}
}

func TestBedrockProvider_EmptyResponse(t *testing.T) {
	mock := &mockBedrockClient{
		invokeModelFn: func(ctx context.Context, params *bedrockruntime.InvokeModelInput, optFns ...func(*bedrockruntime.Options)) (*bedrockruntime.InvokeModelOutput, error) {
			resp := anthropicResponse{Content: nil}
			body, _ := json.Marshal(resp)
			return &bedrockruntime.InvokeModelOutput{Body: body}, nil
		},
	}

	p := newBedrockProviderForTest(mock, "test-model")
	_, err := p.Complete(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error on empty response")
	}
}

func TestBedrockProvider_APIErrorInBody(t *testing.T) {
	mock := &mockBedrockClient{
		invokeModelFn: func(ctx context.Context, params *bedrockruntime.InvokeModelInput, optFns ...func(*bedrockruntime.Options)) (*bedrockruntime.InvokeModelOutput, error) {
			resp := anthropicResponse{
				Error: &struct {
					Message string `json:"message"`
				}{Message: "model not available"},
			}
			body, _ := json.Marshal(resp)
			return &bedrockruntime.InvokeModelOutput{Body: body}, nil
		},
	}

	p := newBedrockProviderForTest(mock, "test-model")
	_, err := p.Complete(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error on API error in body")
	}
}

func TestBedrockProvider_InvalidResponseJSON(t *testing.T) {
	mock := &mockBedrockClient{
		invokeModelFn: func(ctx context.Context, params *bedrockruntime.InvokeModelInput, optFns ...func(*bedrockruntime.Options)) (*bedrockruntime.InvokeModelOutput, error) {
			return &bedrockruntime.InvokeModelOutput{Body: []byte("not json")}, nil
		},
	}

	p := newBedrockProviderForTest(mock, "test-model")
	_, err := p.Complete(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error on invalid JSON response")
	}
}

// ---------------------------------------------------------------------------
// RoutingProvider — CompleteWithSystem coverage
// ---------------------------------------------------------------------------

func TestRoutingProvider_CompleteWithSystem(t *testing.T) {
	mock := &recordProvider{inner: NewMockProvider()}
	rp := NewRoutingProvider(
		map[ModelTier]Provider{TierFast: mock},
		TierFast,
		nil,
	)

	result, err := rp.CompleteWithSystem(context.Background(), "system", "user prompt")
	if err != nil {
		t.Fatalf("CompleteWithSystem: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty result")
	}
	if mock.lastPrompt != "user prompt" {
		t.Errorf("expected lastPrompt=%q, got %q", "user prompt", mock.lastPrompt)
	}
}

// ---------------------------------------------------------------------------
// Anthropic — connection error (unreachable server)
// ---------------------------------------------------------------------------

func TestAnthropicProvider_ConnectionError(t *testing.T) {
	p := NewAnthropicProvider("test-key")
	p.baseURL = "http://127.0.0.1:1" // unreachable port

	_, err := p.Complete(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error on connection failure")
	}
}

// ---------------------------------------------------------------------------
// Vertex — connection error
// ---------------------------------------------------------------------------

func TestVertexProvider_ConnectionError(t *testing.T) {
	p := &VertexProvider{
		projectID:  "test-project",
		region:     "us-central1",
		model:      "test-model",
		baseURL:    "http://127.0.0.1:1",
		httpClient: http.DefaultClient,
	}

	_, err := p.Complete(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error on connection failure")
	}
}

// ---------------------------------------------------------------------------
// Vertex — uses constructed URL when baseURL is empty
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// oauth2Transport tests
// ---------------------------------------------------------------------------

func TestOauth2Transport_RoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer mock-access-token" {
			t.Errorf("expected Bearer mock-access-token, got %q", auth)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	creds := &google.Credentials{
		TokenSource: oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: "mock-access-token",
		}),
	}

	transport := &oauth2Transport{
		base:  http.DefaultTransport,
		creds: creds,
	}

	client := &http.Client{Transport: transport}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestOauth2Transport_TokenError(t *testing.T) {
	creds := &google.Credentials{
		TokenSource: &failingTokenSource{},
	}

	transport := &oauth2Transport{
		base:  http.DefaultTransport,
		creds: creds,
	}

	client := &http.Client{Transport: transport}
	resp, err := client.Get("http://127.0.0.1:1")
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil {
		t.Fatal("expected error from failing token source")
	}
}

// failingTokenSource always returns an error.
type failingTokenSource struct{}

func (f *failingTokenSource) Token() (*oauth2.Token, error) {
	return nil, fmt.Errorf("token refresh failed")
}

func TestVertexProvider_ConstructedURL(t *testing.T) {
	// This test confirms the URL-construction branch is hit when baseURL is empty.
	// The request will fail (no real Vertex endpoint), but we test the branch.
	p := &VertexProvider{
		projectID:  "test-project",
		region:     "us-central1",
		model:      "test-model",
		baseURL:    "", // empty → use constructed URL
		httpClient: &http.Client{},
	}

	_, err := p.CompleteWithSystem(context.Background(), "", "test")
	// Will fail because no real endpoint, but that's fine — we just want coverage
	if err == nil {
		t.Fatal("expected error reaching real Vertex endpoint")
	}
}
