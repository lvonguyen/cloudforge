package ai

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ProviderType enumerates supported provider backends.
type ProviderType string

const (
	ProviderAnthropic ProviderType = "anthropic"
	ProviderBedrock   ProviderType = "bedrock"
	ProviderVertex    ProviderType = "vertex"
	ProviderOpenAI    ProviderType = "openai"
	ProviderLocal     ProviderType = "local"
)

// ProviderConfig holds configuration for a single AI provider.
type ProviderConfig struct {
	Type        ProviderType `yaml:"type"`
	Region      string       `yaml:"region,omitempty"`
	ProjectID   string       `yaml:"project_id,omitempty"`
	Model       string       `yaml:"model,omitempty"`
	BaseURL     string       `yaml:"base_url,omitempty"`
	APIKeyEnvVar string      `yaml:"api_key_env_var,omitempty"`
}

// AIConfig is the top-level AI routing configuration.
type AIConfig struct {
	DefaultTier   ModelTier                 `yaml:"default_tier"`
	Providers     map[string]ProviderConfig `yaml:"providers"`
	FallbackOrder []string                  `yaml:"fallback_order"`
}

// LoadAIConfig reads an AIConfig from a YAML file at path.
func LoadAIConfig(path string) (*AIConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading AI config %s: %w", path, err)
	}

	var cfg AIConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing AI config %s: %w", path, err)
	}

	return &cfg, nil
}

// NewProviderFromConfig constructs a Provider from a ProviderConfig.
// Secrets are read from the environment variable named by APIKeyEnvVar.
func NewProviderFromConfig(cfg ProviderConfig) (Provider, error) {
	apiKey := ""
	if cfg.APIKeyEnvVar != "" {
		apiKey = os.Getenv(cfg.APIKeyEnvVar)
	}

	switch cfg.Type {
	case ProviderAnthropic:
		return NewAnthropicProvider(apiKey), nil

	case ProviderBedrock:
		return NewBedrockProvider(cfg.Region, cfg.Model)

	case ProviderVertex:
		return NewVertexProvider(cfg.ProjectID, cfg.Region, cfg.Model)

	case ProviderOpenAI:
		return NewOpenAIProvider(cfg.BaseURL, apiKey, cfg.Model), nil

	case ProviderLocal:
		baseURL := cfg.BaseURL
		if baseURL == "" {
			baseURL = "http://localhost:1234/v1/chat/completions"
		}
		model := cfg.Model
		if model == "" {
			model = OpenAIModelLocal
		}
		return NewOpenAIProvider(baseURL, apiKey, model), nil

	default:
		return nil, fmt.Errorf("unknown provider type: %q", cfg.Type)
	}
}

// tierForName maps provider name conventions to ModelTier.
// Names containing "fast" or "sonnet" map to TierFast; "premium" or "opus" to TierPremium;
// "local" to TierLocal.
func tierForName(name string) ModelTier {
	for _, kw := range []string{"fast", "sonnet"} {
		if containsSubstring(name, kw) {
			return TierFast
		}
	}
	for _, kw := range []string{"premium", "opus"} {
		if containsSubstring(name, kw) {
			return TierPremium
		}
	}
	if containsSubstring(name, "local") {
		return TierLocal
	}
	return TierFast
}

// NewRoutingProviderFromConfig builds a fully wired RoutingProvider from AIConfig.
// Provider names in FallbackOrder that cannot be constructed are skipped with a warning.
func NewRoutingProviderFromConfig(cfg AIConfig) (*RoutingProvider, error) {
	tiers := make(map[ModelTier]Provider)

	// Build primary tier providers from the Providers map.
	allProviders := make(map[string]Provider)
	for name, pcfg := range cfg.Providers {
		p, err := NewProviderFromConfig(pcfg)
		if err != nil {
			return nil, fmt.Errorf("building provider %q: %w", name, err)
		}
		allProviders[name] = p
		tier := tierForName(name)
		// First provider wins for a given tier.
		if _, exists := tiers[tier]; !exists {
			tiers[tier] = p
		}
	}

	// Build ordered fallback chain.
	fallback := make([]Provider, 0, len(cfg.FallbackOrder))
	for _, name := range cfg.FallbackOrder {
		p, ok := allProviders[name]
		if !ok {
			// Skip unknown names — not a hard error so partial configs still work.
			continue
		}
		fallback = append(fallback, p)
	}

	return NewRoutingProvider(tiers, cfg.DefaultTier, fallback), nil
}

func containsSubstring(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
