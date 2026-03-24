package identity

import (
	"fmt"

	"go.uber.org/zap"
)

// ProviderType represents the type of identity provider to use.
type ProviderType string

const (
	ProviderTypeMockOkta  ProviderType = "mock-okta"
	ProviderTypeMockEntra ProviderType = "mock-entra"
	ProviderTypeOkta      ProviderType = "okta"
	ProviderTypeEntraID   ProviderType = "entra_id"
)

// Config contains configuration for creating identity providers.
type Config struct {
	Type    ProviderType
	Okta    *OktaConfig
	EntraID *EntraIDConfig
	Logger  *zap.Logger
}

// NewProviders creates the standard identity provider map based on configuration.
// Returns a map keyed by provider name ("okta", "entra_id") with either real or
// mock implementations depending on the configured types and available credentials.
func NewProviders(cfgs []Config) (map[string]Provider, error) {
	providers := make(map[string]Provider, len(cfgs))
	for _, cfg := range cfgs {
		p, err := NewProvider(cfg)
		if err != nil {
			return nil, fmt.Errorf("creating %s provider: %w", cfg.Type, err)
		}
		providers[p.Name()] = p
	}
	return providers, nil
}

// NewProvider creates a single identity provider based on configuration.
func NewProvider(cfg Config) (Provider, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	switch cfg.Type {
	case ProviderTypeMockOkta:
		return NewMockOktaProvider(), nil

	case ProviderTypeMockEntra:
		return NewMockEntraIDProvider(), nil

	case ProviderTypeOkta:
		if cfg.Okta == nil {
			return nil, fmt.Errorf("okta config required for okta provider")
		}
		p, err := NewOktaProvider(*cfg.Okta, logger)
		if err != nil {
			return nil, fmt.Errorf("initializing okta provider: %w", err)
		}
		return p, nil

	case ProviderTypeEntraID:
		if cfg.EntraID == nil {
			return nil, fmt.Errorf("entra_id config required for entra_id provider")
		}
		p, err := NewEntraIDProvider(*cfg.EntraID, logger)
		if err != nil {
			return nil, fmt.Errorf("initializing entra_id provider: %w", err)
		}
		return p, nil

	default:
		return nil, fmt.Errorf("unknown identity provider type: %s", cfg.Type)
	}
}

// ProviderFromString converts a string to ProviderType.
func ProviderFromString(s string) (ProviderType, error) {
	switch s {
	case "mock-okta":
		return ProviderTypeMockOkta, nil
	case "mock-entra":
		return ProviderTypeMockEntra, nil
	case "okta":
		return ProviderTypeOkta, nil
	case "entra_id":
		return ProviderTypeEntraID, nil
	default:
		return "", fmt.Errorf("unknown identity provider type: %s", s)
	}
}

// DefaultProviderConfigs returns the default identity provider configurations.
// Uses mock providers for both Okta and Entra ID. Pass real OktaConfig/EntraIDConfig
// to override with production providers.
func DefaultProviderConfigs(logger *zap.Logger) []Config {
	return []Config{
		{Type: ProviderTypeMockOkta, Logger: logger},
		{Type: ProviderTypeMockEntra, Logger: logger},
	}
}
