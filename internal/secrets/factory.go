package secrets

import (
	"fmt"
	"strings"

	"go.uber.org/zap"
)

// ProviderType represents the type of secrets provider.
type ProviderType string

const (
	ProviderTypeMemory ProviderType = "memory"
	ProviderTypeAWS    ProviderType = "aws"
	ProviderTypeAzure  ProviderType = "azure"
	ProviderTypeGCP    ProviderType = "gcp"
)

// ProviderConfig contains configuration for creating a secrets provider.
type ProviderConfig struct {
	Type     ProviderType
	Name     string // Provider display name (default: type value)
	Region   string // AWS region
	VaultURL string // Azure Key Vault URL
	Project  string // GCP project ID
	Logger   *zap.Logger
}

// NewProviderFromConfig creates a secrets provider based on configuration.
func NewProviderFromConfig(cfg ProviderConfig) (Provider, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	name := cfg.Name
	if name == "" {
		name = string(cfg.Type)
	}

	switch cfg.Type {
	case ProviderTypeMemory, "":
		return NewMemoryProvider(name), nil
	case ProviderTypeAWS:
		if strings.TrimSpace(cfg.Region) == "" {
			return nil, fmt.Errorf("aws secrets provider requires region")
		}
		provider := NewAWSSecretsProvider(cfg.Region, logger)
		if provider.client == nil {
			return nil, fmt.Errorf("aws secrets provider initialization failed")
		}
		return provider, nil
	case ProviderTypeAzure:
		if strings.TrimSpace(cfg.VaultURL) == "" {
			return nil, fmt.Errorf("azure secrets provider requires vault URL")
		}
		provider := NewAzureKeyVaultProvider(cfg.VaultURL, logger)
		if provider.client == nil {
			return nil, fmt.Errorf("azure secrets provider initialization failed")
		}
		return provider, nil
	case ProviderTypeGCP:
		if strings.TrimSpace(cfg.Project) == "" {
			return nil, fmt.Errorf("gcp secrets provider requires project ID")
		}
		provider := NewGCPSecretManagerProvider(cfg.Project, logger)
		if provider.client == nil {
			return nil, fmt.Errorf("gcp secrets provider initialization failed")
		}
		return provider, nil
	default:
		return nil, fmt.Errorf("unknown secrets provider type: %s", cfg.Type)
	}
}

// ProviderFromString converts a string to ProviderType.
func ProviderFromString(s string) (ProviderType, error) {
	switch s {
	case "memory", "":
		return ProviderTypeMemory, nil
	case "aws":
		return ProviderTypeAWS, nil
	case "azure":
		return ProviderTypeAzure, nil
	case "gcp":
		return ProviderTypeGCP, nil
	default:
		return "", fmt.Errorf("unknown secrets provider type: %s", s)
	}
}
