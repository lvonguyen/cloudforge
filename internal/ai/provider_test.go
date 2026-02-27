package ai

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// failProvider always returns an error — used to exercise the fallback chain.
type failProvider struct{ name string }

func (f *failProvider) Complete(_ context.Context, _ string) (string, error) {
	return "", errors.New(f.name + ": provider unavailable")
}
func (f *failProvider) CompleteWithSystem(_ context.Context, _, _ string) (string, error) {
	return "", errors.New(f.name + ": provider unavailable")
}

// recordProvider records the last prompt it received and delegates to an inner provider.
type recordProvider struct {
	inner      Provider
	lastPrompt string
}

func (r *recordProvider) Complete(ctx context.Context, prompt string) (string, error) {
	r.lastPrompt = prompt
	return r.inner.Complete(ctx, prompt)
}
func (r *recordProvider) CompleteWithSystem(ctx context.Context, sys, user string) (string, error) {
	r.lastPrompt = user
	return r.inner.CompleteWithSystem(ctx, sys, user)
}

// --- RoutingProvider tests --------------------------------------------------

func TestRoutingProvider_TierSelection(t *testing.T) {
	fast := &recordProvider{inner: NewMockProvider()}
	premium := &recordProvider{inner: NewMockProvider()}
	local := &recordProvider{inner: NewMockProvider()}

	rp := NewRoutingProvider(
		map[ModelTier]Provider{
			TierFast:    fast,
			TierPremium: premium,
			TierLocal:   local,
		},
		TierFast,
		nil,
	)

	ctx := context.Background()

	// Fast tier.
	if _, err := rp.CompleteWithTier(ctx, TierFast, "", "fast prompt"); err != nil {
		t.Fatalf("TierFast: unexpected error: %v", err)
	}
	if fast.lastPrompt != "fast prompt" {
		t.Errorf("TierFast: expected fast provider to be called, got lastPrompt=%q", fast.lastPrompt)
	}

	// Premium tier.
	if _, err := rp.CompleteWithTier(ctx, TierPremium, "", "premium prompt"); err != nil {
		t.Fatalf("TierPremium: unexpected error: %v", err)
	}
	if premium.lastPrompt != "premium prompt" {
		t.Errorf("TierPremium: expected premium provider to be called, got lastPrompt=%q", premium.lastPrompt)
	}

	// Local tier.
	if _, err := rp.CompleteWithTier(ctx, TierLocal, "", "local prompt"); err != nil {
		t.Fatalf("TierLocal: unexpected error: %v", err)
	}
	if local.lastPrompt != "local prompt" {
		t.Errorf("TierLocal: expected local provider to be called, got lastPrompt=%q", local.lastPrompt)
	}
}

func TestRoutingProvider_FallbackChain(t *testing.T) {
	fallback := NewMockProvider()

	rp := NewRoutingProvider(
		map[ModelTier]Provider{
			TierFast: &failProvider{name: "primary"},
		},
		TierFast,
		[]Provider{
			&failProvider{name: "fallback-1"},
			fallback,
		},
	)

	ctx := context.Background()
	got, err := rp.CompleteWithTier(ctx, TierFast, "", "hello")
	if err != nil {
		t.Fatalf("expected fallback to succeed, got error: %v", err)
	}
	if got == "" {
		t.Error("expected non-empty response from fallback provider")
	}
}

func TestRoutingProvider_AllFail(t *testing.T) {
	rp := NewRoutingProvider(
		map[ModelTier]Provider{
			TierFast: &failProvider{name: "primary"},
		},
		TierFast,
		[]Provider{&failProvider{name: "fallback-1"}},
	)

	_, err := rp.CompleteWithTier(context.Background(), TierFast, "", "hello")
	if err == nil {
		t.Fatal("expected error when all providers fail, got nil")
	}
}

func TestRoutingProvider_DefaultTier(t *testing.T) {
	fast := &recordProvider{inner: NewMockProvider()}

	rp := NewRoutingProvider(
		map[ModelTier]Provider{TierFast: fast},
		TierFast,
		nil,
	)

	ctx := context.Background()
	if _, err := rp.Complete(ctx, "via default"); err != nil {
		t.Fatalf("Complete: unexpected error: %v", err)
	}
	if fast.lastPrompt != "via default" {
		t.Errorf("expected default tier (TierFast) to handle Complete call")
	}
}

// --- Usage stats tests ------------------------------------------------------

func TestRoutingProvider_UsageStats(t *testing.T) {
	rp := NewRoutingProvider(
		map[ModelTier]Provider{TierFast: NewMockProvider()},
		TierFast,
		nil,
	)

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := rp.CompleteWithTier(ctx, TierFast, "", "test"); err != nil {
			t.Fatalf("call %d failed: %v", i, err)
		}
	}

	stats := rp.GetUsageStats()
	if len(stats) == 0 {
		t.Fatal("expected usage stats, got empty slice")
	}

	var fastStats *UsageStats
	for i := range stats {
		if stats[i].Tier == TierFast {
			fastStats = &stats[i]
			break
		}
	}

	if fastStats == nil {
		t.Fatal("no stats found for TierFast")
	}
	if fastStats.CallCount != 3 {
		t.Errorf("expected CallCount=3, got %d", fastStats.CallCount)
	}
}

// --- Config loading tests ---------------------------------------------------

func TestLoadAIConfig(t *testing.T) {
	content := `
default_tier: 0
fallback_order:
  - fast-anthropic
  - local
providers:
  fast-anthropic:
    type: anthropic
    model: claude-sonnet-4-6
    api_key_env_var: ANTHROPIC_API_KEY
  local:
    type: local
    base_url: http://localhost:1234/v1/chat/completions
    model: qwen-32b
`
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "ai-config.yaml")
	if err := os.WriteFile(cfgPath, []byte(content), 0600); err != nil {
		t.Fatalf("writing temp config: %v", err)
	}

	cfg, err := LoadAIConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadAIConfig: %v", err)
	}

	if len(cfg.Providers) != 2 {
		t.Errorf("expected 2 providers, got %d", len(cfg.Providers))
	}
	if len(cfg.FallbackOrder) != 2 {
		t.Errorf("expected 2 fallback entries, got %d", len(cfg.FallbackOrder))
	}
	if cfg.DefaultTier != TierFast {
		t.Errorf("expected DefaultTier=TierFast(0), got %d", cfg.DefaultTier)
	}

	p, ok := cfg.Providers["fast-anthropic"]
	if !ok {
		t.Fatal("missing provider 'fast-anthropic'")
	}
	if p.Type != ProviderAnthropic {
		t.Errorf("expected type=anthropic, got %q", p.Type)
	}
}

func TestLoadAIConfig_MissingFile(t *testing.T) {
	_, err := LoadAIConfig("/nonexistent/path/ai-config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

// --- NewProviderFromConfig tests --------------------------------------------

func TestNewProviderFromConfig_Anthropic(t *testing.T) {
	t.Setenv("TEST_API_KEY", "test-key-123")

	p, err := NewProviderFromConfig(ProviderConfig{
		Type:         ProviderAnthropic,
		APIKeyEnvVar: "TEST_API_KEY",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := p.(*AnthropicProvider); !ok {
		t.Errorf("expected *AnthropicProvider, got %T", p)
	}
}

func TestNewProviderFromConfig_OpenAI(t *testing.T) {
	p, err := NewProviderFromConfig(ProviderConfig{
		Type:    ProviderOpenAI,
		BaseURL: "http://localhost:1234/v1/chat/completions",
		Model:   "qwen-32b",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := p.(*OpenAIProvider); !ok {
		t.Errorf("expected *OpenAIProvider, got %T", p)
	}
}

func TestNewProviderFromConfig_Local(t *testing.T) {
	p, err := NewProviderFromConfig(ProviderConfig{
		Type: ProviderLocal,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := p.(*OpenAIProvider); !ok {
		t.Errorf("expected *OpenAIProvider for local type, got %T", p)
	}
}

func TestNewProviderFromConfig_Unknown(t *testing.T) {
	_, err := NewProviderFromConfig(ProviderConfig{Type: "unknown-type"})
	if err == nil {
		t.Fatal("expected error for unknown provider type, got nil")
	}
}

// --- tierForName tests -------------------------------------------------------

func TestTierForName(t *testing.T) {
	cases := []struct {
		name string
		want ModelTier
	}{
		{"fast-anthropic", TierFast},
		{"bedrock-sonnet", TierFast},
		{"premium-opus", TierPremium},
		{"vertex-opus", TierPremium},
		{"local-lmstudio", TierLocal},
		{"unknown-provider", TierFast}, // defaults to TierFast
	}

	for _, tc := range cases {
		got := tierForName(tc.name)
		if got != tc.want {
			t.Errorf("tierForName(%q) = %d, want %d", tc.name, got, tc.want)
		}
	}
}

// --- OpenAI Azure detection test --------------------------------------------

func TestContainsAzureDomain(t *testing.T) {
	cases := []struct {
		url     string
		isAzure bool
	}{
		{"https://myresource.openai.azure.com/openai/deployments/gpt-4o/chat/completions?api-version=2024-02-15-preview", true},
		{"http://localhost:1234/v1/chat/completions", false},
		{"https://api.openai.com/v1/chat/completions", false},
	}

	for _, tc := range cases {
		p := NewOpenAIProvider(tc.url, "key", "model")
		if p.isAzure != tc.isAzure {
			t.Errorf("URL %q: isAzure=%v, want %v", tc.url, p.isAzure, tc.isAzure)
		}
	}
}
